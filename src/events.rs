//! Usage: which briq used which secret against which host, batched per (briq, host, method,
//! status class, secrets) and sent to the API every 30 seconds; that is the team's audit log, and
//! what tells the API the briq and the gateway are in use. A batch the API does not take is kept
//! for the next send.
//!
//! An event that put a secret in is never dropped for room: the method is one of a known few, so
//! a briq cannot make up keys to push those out. Requests that used none are kept up to
//! `MAX_PLAIN`; they only say the briq is in use.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::config::Api;

/// Events without a secret kept between sends.
const MAX_PLAIN: usize = 1_000;
/// Events in one send: the API reads that many from a batch.
const BATCH: usize = 500;
const METHODS: [&str; 9] = [
    "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE",
];

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    pub briq_id: Option<String>,
    pub host: String,
    pub method: String,
    pub status: u16,
    pub secrets: Vec<String>,
    pub count: u64,
    pub first_at: String,
    pub last_at: String,
}

impl Event {
    fn key(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            self.briq_id.as_deref().unwrap_or(""),
            self.host,
            self.method,
            self.status / 100,
            self.secrets.join(",")
        )
    }
}

pub struct Events {
    api: Arc<Api>,
    pending: Mutex<HashMap<String, Event>>,
}

impl Events {
    pub fn new(api: Arc<Api>) -> Arc<Self> {
        Arc::new(Self {
            api,
            pending: Mutex::new(HashMap::new()),
        })
    }

    /// Sends what is pending every `every`, for as long as the process runs.
    pub fn start(self: &Arc<Self>, every: Duration) {
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(every).await;
                me.flush().await;
            }
        });
    }

    pub fn record(
        &self,
        briq_id: Option<&str>,
        host: &str,
        method: &str,
        status: u16,
        mut secrets: Vec<String>,
    ) {
        secrets.sort();
        secrets.dedup();
        let method = METHODS
            .iter()
            .find(|m| m.eq_ignore_ascii_case(method))
            .copied()
            .unwrap_or("OTHER");
        let now = now();
        self.add(Event {
            briq_id: briq_id.map(str::to_string),
            host: host.to_string(),
            method: method.to_string(),
            status,
            secrets,
            count: 1,
            first_at: now.clone(),
            last_at: now,
        });
    }

    /// `e` into what is pending: merged with its key, or kept when there is room for it.
    fn add(&self, e: Event) {
        let mut pending = self.pending.lock().unwrap();
        let plain = pending.values().filter(|p| p.secrets.is_empty()).count();
        let key = e.key();
        match pending.get_mut(&key) {
            Some(had) if had.first_at <= e.first_at => {
                had.count += e.count;
                had.last_at = had.last_at.clone().max(e.last_at);
                had.status = e.status;
            }
            Some(had) => {
                had.count += e.count;
                had.first_at = e.first_at;
            }
            None if !e.secrets.is_empty() || plain < MAX_PLAIN => {
                pending.insert(key, e);
            }
            None => {}
        }
    }

    /// Sends what is pending, the events that put a secret in first, `BATCH` at a time; what
    /// the API does not take is kept for the next time.
    pub async fn flush(&self) {
        let mut all: Vec<Event> = {
            let mut pending = self.pending.lock().unwrap();
            std::mem::take(&mut *pending).into_values().collect()
        };
        all.sort_by_key(|e| e.secrets.is_empty());
        let mut rest = all.into_iter();
        loop {
            let batch: Vec<Event> = rest.by_ref().take(BATCH).collect();
            if batch.is_empty() {
                return;
            }
            let body = serde_json::to_value(&batch).unwrap_or_default();
            if let Err(err) = self.api.events(body).await {
                crate::log!(Warn, "events not delivered, kept for the next flush",
                    "err": err.to_string(), "count": batch.len());
                for e in batch.into_iter().chain(rest) {
                    self.add(e);
                }
                return;
            }
        }
    }
}

fn now() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}

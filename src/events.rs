//! Usage: which briq used which secret against which host, batched per (briq, host, method,
//! status class, secrets) and sent to the API every 30 seconds; that is the team's audit log. A
//! batch the API does not take is kept for the next send, up to `MAX_PENDING` entries.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::config::Api;

const MAX_PENDING: usize = 1_000;

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
        let now = now();
        let e = Event {
            briq_id: briq_id.map(str::to_string),
            host: host.to_string(),
            method: method.to_string(),
            status,
            secrets,
            count: 1,
            first_at: now.clone(),
            last_at: now,
        };
        let mut pending = self.pending.lock().unwrap();
        let len = pending.len();
        match pending.get_mut(&e.key()) {
            Some(had) => {
                had.count += 1;
                had.last_at = e.last_at;
                had.status = e.status;
            }
            None if len < MAX_PENDING => {
                pending.insert(e.key(), e);
            }
            None => {}
        }
    }

    pub async fn flush(&self) {
        let batch: Vec<Event> = {
            let mut pending = self.pending.lock().unwrap();
            if pending.is_empty() {
                return;
            }
            std::mem::take(&mut *pending).into_values().collect()
        };
        let body = serde_json::to_value(&batch).unwrap_or_default();
        if let Err(err) = self.api.events(body).await {
            crate::log!(Warn, "events not delivered, kept for the next flush",
                "err": err.to_string(), "count": batch.len());
            let mut pending = self.pending.lock().unwrap();
            for e in batch {
                let len = pending.len();
                match pending.get_mut(&e.key()) {
                    Some(later) => {
                        later.count += e.count;
                        later.first_at = e.first_at;
                    }
                    None if len < MAX_PENDING => {
                        pending.insert(e.key(), e);
                    }
                    None => {}
                }
            }
        }
    }
}

fn now() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}

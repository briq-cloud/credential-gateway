//! Bounded volatile usage reporting. Potential secret use reserves capacity before forwarding;
//! leases cover pending, in-flight, batch and retry ownership. Failed batches are retained.
use crate::config::Api;
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

mod admission;
mod request;
pub(crate) use admission::Charge;
use admission::{Lease, Pool, charge};
pub(crate) use request::RequestAudit;
#[derive(Debug)]
pub(crate) struct AuditFull;
const MAX_SECRET: usize = 1024;
const SECRET_BYTES: usize = 2 * 1024 * 1024;
const MAX_PLAIN: usize = 1000;
const PLAIN_BYTES: usize = 256 * 1024;
const BATCH: usize = 64;
const BATCH_BYTES: usize = 128 * 1024;
const METHODS: [&str; 9] = [
    "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE",
];
fn method(value: &str) -> &'static str {
    METHODS
        .iter()
        .find(|m| m.eq_ignore_ascii_case(value))
        .copied()
        .unwrap_or("OTHER")
}

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
        serde_json::to_string(&(
            self.briq_id.as_deref(),
            &self.host,
            &self.method,
            self.status / 100,
            &self.secrets,
        ))
        .expect("event keys are serializable")
    }
}
struct Entry {
    event: Event,
    lease: Arc<Lease>,
}
pub struct Events {
    api: Arc<Api>,
    pending: Mutex<HashMap<String, Entry>>,
    secret: Pool,
    plain: Pool,
    flushing: tokio::sync::Mutex<()>,
}
impl Events {
    pub fn new(api: Arc<Api>) -> Arc<Self> {
        Self::with_limits(api, MAX_SECRET, SECRET_BYTES, MAX_PLAIN, PLAIN_BYTES)
    }
    fn with_limits(
        api: Arc<Api>,
        secret_count: usize,
        secret_bytes: usize,
        plain_count: usize,
        plain_bytes: usize,
    ) -> Arc<Self> {
        Arc::new(Self {
            api,
            pending: Mutex::new(HashMap::new()),
            secret: Pool::new(secret_count, secret_bytes),
            plain: Pool::new(plain_count, plain_bytes),
            flushing: tokio::sync::Mutex::new(()),
        })
    }
    pub fn start(self: &Arc<Self>, every: Duration) {
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(every).await;
                me.flush().await;
            }
        });
    }
    /// Must precede any credential forwarding; no metadata is cloned until admission succeeds.
    pub(crate) fn admit<'a>(
        self: &Arc<Self>,
        briq: Option<&str>,
        host: &str,
        request_method: &str,
        names: impl Iterator<Item = &'a str>,
    ) -> Result<Option<Arc<RequestAudit>>, AuditFull> {
        let mut charge = Self::estimate(briq, host, request_method);
        for name in names {
            charge.name(name);
        }
        self.admit_estimated(briq, host, request_method, charge)
    }
    pub(crate) fn estimate(briq: Option<&str>, host: &str, request_method: &str) -> Charge {
        Charge::new(briq, host, method(request_method))
    }
    pub(crate) fn admit_estimated(
        self: &Arc<Self>,
        briq: Option<&str>,
        host: &str,
        request_method: &str,
        charge: Charge,
    ) -> Result<Option<Arc<RequestAudit>>, AuditFull> {
        let secret = charge.secret;
        let method = method(request_method);
        let lease = charge.bytes.and_then(|bytes| {
            if secret {
                self.secret.reserve(bytes)
            } else {
                self.plain.reserve(bytes)
            }
        });
        match lease {
            Some(lease) => Ok(Some(RequestAudit::new(
                self.clone(),
                lease,
                briq,
                host,
                method,
                secret,
            ))),
            None if secret => Err(AuditFull),
            None => Ok(None),
        }
    }
    /// Direct reporting returns false on failed admission. Credential-forwarding callers must
    /// reserve with `admit` first; the proxy does not use this post-fact entry point.
    pub fn record(
        self: &Arc<Self>,
        briq: Option<&str>,
        host: &str,
        request_method: &str,
        status: u16,
        secrets: Vec<String>,
    ) -> bool {
        let Ok(Some(audit)) = self.admit(
            briq,
            host,
            request_method,
            secrets.iter().map(String::as_str),
        ) else {
            return false;
        };
        audit.used(secrets);
        audit.arm();
        audit.finish(status);
        true
    }
    fn add_plain(&self, event: Event) {
        let Some(lease) = charge(
            event.briq_id.as_deref(),
            &event.host,
            &event.method,
            std::iter::empty(),
        )
        .and_then(|bytes| self.plain.reserve(bytes)) else {
            return;
        };
        self.add(Entry { event, lease });
    }
    fn add(&self, entry: Entry) {
        let mut pending = self.pending.lock().unwrap();
        let key = entry.event.key();
        match pending.get_mut(&key) {
            Some(had) if had.event.first_at <= entry.event.first_at => {
                had.event.count += entry.event.count;
                had.event.last_at = had.event.last_at.clone().max(entry.event.last_at);
                had.event.status = entry.event.status;
            }
            Some(had) => {
                had.event.count += entry.event.count;
                had.event.first_at = entry.event.first_at;
            }
            None => {
                pending.insert(key, entry);
            }
        }
    }
    /// One byte-bounded batch at a time. Pending entries never surrender leases to flush/retry.
    pub async fn flush(&self) {
        let _serial = self.flushing.lock().await;
        let mut entries: Vec<Entry> = std::mem::take(&mut *self.pending.lock().unwrap())
            .into_values()
            .collect();
        entries.sort_by_key(|entry| entry.event.secrets.is_empty());
        let mut restore = Restore {
            events: self,
            entries: entries.into(),
        };
        while !restore.entries.is_empty() {
            let mut bytes = 0usize;
            let batch: Vec<&Event> = restore
                .entries
                .iter()
                .take(BATCH)
                .take_while(|entry| {
                    let fits = bytes + entry.lease.charge <= BATCH_BYTES;
                    if fits {
                        bytes += entry.lease.charge;
                    }
                    fits
                })
                .map(|entry| &entry.event)
                .collect();
            let count = batch.len();
            let body = serde_json::to_value(batch).expect("events are serializable");
            if let Err(err) = self.api.events(body).await {
                crate::log!(Warn, "events not delivered, kept for the next flush", "err": err.to_string(), "count": count);
                return;
            }
            for _ in 0..count {
                restore.entries.pop_front();
            }
        }
    }
}
/// Async cancellation must requeue unsent events just like an API error does.
struct Restore<'a> {
    events: &'a Events,
    entries: VecDeque<Entry>,
}
impl Drop for Restore<'_> {
    fn drop(&mut self) {
        for entry in self.entries.drain(..) {
            self.events.add(entry);
        }
    }
}
fn now() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}

#[cfg(test)]
#[path = "events/tests.rs"]
mod tests;

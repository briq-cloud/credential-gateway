//! One admitted request; its last upload/context owner records cancellation synchronously.
use super::{Event, Events, admission::Lease, now};
use crate::rewrite::Hits;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Use {
    armed: bool,
    finished: bool,
    names: Vec<String>,
    body: Option<(Hits, Vec<String>)>,
}
pub(crate) struct RequestAudit {
    events: Arc<Events>,
    metadata: Event,
    lease: Arc<Lease>,
    secret: bool,
    usage: Mutex<Use>,
}
impl RequestAudit {
    pub(super) fn new(
        events: Arc<Events>,
        lease: Arc<Lease>,
        briq: Option<&str>,
        host: &str,
        method: &str,
        secret: bool,
    ) -> Arc<Self> {
        let now = now();
        Arc::new(Self {
            events,
            lease,
            secret,
            metadata: Event {
                briq_id: briq.map(str::to_string),
                host: host.into(),
                method: method.into(),
                status: 502,
                secrets: Vec::new(),
                count: 1,
                first_at: now.clone(),
                last_at: now,
            },
            usage: Mutex::new(Use::default()),
        })
    }
    pub(crate) fn used(&self, names: Vec<String>) {
        self.usage.lock().unwrap().names = names;
    }
    pub(crate) fn body<'a>(&self, hits: Hits, names: impl Iterator<Item = &'a str>) {
        self.usage.lock().unwrap().body = Some((hits, names.map(str::to_string).collect()));
    }
    pub(crate) fn arm(&self) {
        self.usage.lock().unwrap().armed = true;
    }
    pub(crate) fn finish(&self, status: u16) {
        let mut usage = self.usage.lock().unwrap();
        if !usage.armed || usage.finished {
            return;
        }
        usage.finished = true;
        let mut event = self.metadata.clone();
        event.status = status;
        // Keep the existing observation point: response headers/error. Later body hits after
        // an early upstream response are not retrospectively added to that event.
        event.first_at = now();
        event.last_at = event.first_at.clone();
        event.secrets = std::mem::take(&mut usage.names);
        if let Some((hits, names)) = usage.body.take() {
            event.secrets.extend(
                names
                    .into_iter()
                    .enumerate()
                    .filter_map(|(index, name)| hits.get(index).then_some(name)),
            );
        }
        event.secrets.sort();
        event.secrets.dedup();
        drop(usage);
        if event.secrets.is_empty() && self.secret {
            self.events.add_plain(event);
        } else {
            self.events.add(super::Entry {
                event,
                lease: self.lease.clone(),
            });
        }
    }
}
impl Drop for RequestAudit {
    fn drop(&mut self) {
        self.finish(502);
    }
}

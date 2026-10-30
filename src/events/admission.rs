//! Count and conservative byte admission shared by requests, queued events, and retries.
use crate::budget::{Budget, Reservation};
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub(super) const MAX_EVENT_BYTES: usize = 32 * 1024;
pub(super) struct Pool {
    pub(super) bytes: Arc<Budget>,
    pub(super) slots: Arc<Semaphore>,
}
impl Pool {
    pub(super) fn new(count: usize, bytes: usize) -> Self {
        Self {
            bytes: Budget::new(bytes),
            slots: Arc::new(Semaphore::new(count)),
        }
    }
    pub(super) fn reserve(&self, bytes: usize) -> Option<Arc<Lease>> {
        if bytes > MAX_EVENT_BYTES {
            return None;
        }
        let slot = self.slots.clone().try_acquire_owned().ok()?;
        let memory = self.bytes.reserve(bytes)?;
        Some(Arc::new(Lease {
            charge: bytes,
            _memory: memory,
            _slot: slot,
        }))
    }
}
pub(super) struct Lease {
    pub(super) charge: usize,
    _memory: Arc<Reservation>,
    _slot: OwnedSemaphorePermit,
}

/// Context, Event and key copies, Vec/String headers, and worst-case JSON escaping. This is
/// conservative admission accounting, not an allocator or a process-RSS theorem.
pub(crate) struct Charge {
    pub(super) bytes: Option<usize>,
    pub(super) secret: bool,
}
impl Charge {
    pub(super) fn new(briq: Option<&str>, host: &str, method: &str) -> Self {
        let bytes = || {
            2048usize
                .checked_add(briq.map_or(0, str::len).checked_mul(20)?)?
                .checked_add(host.len().checked_mul(20)?)?
                .checked_add(method.len().checked_mul(20)?)
        };
        Self {
            bytes: bytes().filter(|&n| n <= MAX_EVENT_BYTES),
            secret: false,
        }
    }
    pub(crate) fn name(&mut self, name: &str) {
        self.secret = true;
        self.bytes = self
            .bytes
            .and_then(|bytes| {
                bytes
                    .checked_add(256)?
                    .checked_add(name.len().checked_mul(20)?)
            })
            .filter(|&n| n <= MAX_EVENT_BYTES);
    }
}
pub(super) fn charge<'a>(
    briq: Option<&str>,
    host: &str,
    method: &str,
    names: impl Iterator<Item = &'a str>,
) -> Option<usize> {
    let mut charge = Charge::new(briq, host, method);
    for name in names {
        charge.name(name);
    }
    charge.bytes
}

//! Immediate admission for estimated matcher construction and retained rewrite memory.
//! This is deliberately conservative accounting, not an allocator or a process RSS ceiling.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::config::Secret;

pub const DEFAULT_REWRITE_BUDGET: usize = 64 * 1024 * 1024;

pub(crate) struct Budget {
    limit: usize,
    used: AtomicUsize,
}

impl Budget {
    pub(crate) fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            limit,
            used: AtomicUsize::new(0),
        })
    }

    #[cfg(test)]
    pub(crate) fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }

    pub(crate) fn reserve(self: &Arc<Self>, bytes: usize) -> Option<Arc<Reservation>> {
        let mut used = self.used.load(Ordering::Relaxed);
        loop {
            let next = used.checked_add(bytes).filter(|&n| n <= self.limit)?;
            match self
                .used
                .compare_exchange_weak(used, next, Ordering::AcqRel, Ordering::Relaxed)
            {
                Ok(_) => break,
                Err(current) => used = current,
            }
        }
        Some(Arc::new(Reservation {
            budget: self.clone(),
            bytes,
        }))
    }
}

pub(crate) struct Reservation {
    budget: Arc<Budget>,
    bytes: usize,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.bytes, Ordering::Release);
    }
}

#[derive(Default)]
struct Matcher {
    patterns: usize,
    copies: usize,
    rules: usize,
}

impl Matcher {
    fn add(&mut self, from: &str, to: &str) -> Option<()> {
        if from.is_empty() {
            return Some(());
        }
        self.patterns = self.patterns.checked_add(from.len())?;
        self.copies = self.copies.checked_add(from.len())?.checked_add(to.len())?;
        self.rules = self.rules.checked_add(1)?;
        Some(())
    }

    fn estimated(&self) -> Option<usize> {
        if self.rules == 0 {
            return Some(0);
        }
        // aho-corasick 1.1.5 builds a noncontiguous NFA before compacting it. Account for
        // state/transition vectors and their temporary growth; shallow dense rows need a
        // rule term even for very short patterns. Include owned from/to vectors and their
        // Vec headers separately. Probed against distinct, shared, suffix and Unicode sets.
        // This is an admission estimate, not a proven bound on every library allocation.
        self.patterns
            .checked_mul(128)?
            .checked_add(self.rules.checked_mul(4096)?)?
            .checked_add(16 * 1024)?
            .checked_add(self.copies)?
            .checked_add(self.rules.checked_mul(2 * std::mem::size_of::<Vec<u8>>())?)
    }
}

/// All three possible matchers and the deep-cloned request config, before either is built.
/// Summing construction estimates also covers overlap between upload and response bodies.
pub(crate) fn estimate(secrets: &mut dyn Iterator<Item = &Secret>) -> Option<usize> {
    let (mut header, mut body, mut response) =
        (Matcher::default(), Matcher::default(), Matcher::default());
    let mut owned = 0usize;
    for s in secrets {
        owned = owned
            .checked_add(std::mem::size_of::<Secret>())?
            .checked_add(s.name.len())?
            .checked_add(s.placeholder.len())?
            .checked_add(s.value.len())?;
        for value in s.hosts.iter().chain(&s.locations) {
            owned = owned
                .checked_add(std::mem::size_of::<String>())?
                .checked_add(value.len())?;
        }
        if s.allows("header") {
            header.add(&s.placeholder, &s.value)?;
        }
        if s.allows("body") {
            body.add(&s.placeholder, &s.value)?;
        }
        response.add(&s.value, &s.placeholder)?;
    }
    owned
        .checked_add(header.estimated()?)?
        .checked_add(body.estimated()?)?
        .checked_add(response.estimated()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weighted_admission_is_immediate_and_released_by_the_last_owner() {
        let budget = Budget::new(10);
        let first = budget.reserve(7).unwrap();
        let other = first.clone();
        assert!(budget.reserve(4).is_none());
        let second = budget.reserve(3).unwrap();
        drop(first);
        assert!(budget.reserve(1).is_none());
        drop(other);
        assert!(budget.reserve(7).is_some());
        drop(second);
        assert!(budget.reserve(10).is_some());
        assert!(budget.reserve(usize::MAX).is_none());
    }

    #[test]
    fn every_matcher_direction_and_config_clone_is_charged() {
        let mut s = Secret {
            name: "key".into(),
            placeholder: "token".into(),
            value: "value".repeat(100),
            hosts: vec!["example.com".into()],
            locations: vec![],
        };
        let response = estimate(&mut std::iter::once(&s)).unwrap();
        s.locations.push("header".into());
        let header = estimate(&mut std::iter::once(&s)).unwrap();
        s.locations.push("body".into());
        let body = estimate(&mut std::iter::once(&s)).unwrap();
        assert!(response > s.value.len() * 128);
        assert!(header > response + 16 * 1024);
        assert!(body > header + 16 * 1024);
        assert_eq!(estimate(&mut std::iter::empty()), Some(0));
    }
}

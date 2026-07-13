//! In-memory per-IP failure tracking.
//!
//! Complements the per-account counter in the database: the account counter
//! stops a targeted attack on one user, this stops one machine from spraying
//! attempts across many accounts. State is in-memory by design — a restart
//! forgets IPs, which is acceptable because the per-account counters and the
//! 250–300 ms failure delay persist regardless.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

const WINDOW_SECS: i64 = 15 * 60;
const MAX_FAILURES_PER_WINDOW: usize = 20;

#[derive(Default)]
pub struct IpLimiter {
    failures: Mutex<HashMap<IpAddr, Vec<i64>>>,
}

impl IpLimiter {
    /// Returns `Some(retry_after_secs)` if this IP has exhausted its budget.
    pub fn check(&self, ip: IpAddr, now: i64) -> Option<i64> {
        let mut map = self.failures.lock().expect("limiter mutex poisoned");
        let times = map.get_mut(&ip)?;
        times.retain(|t| now - *t < WINDOW_SECS);
        if times.is_empty() {
            map.remove(&ip);
            return None;
        }
        if times.len() >= MAX_FAILURES_PER_WINDOW {
            let oldest = times.iter().copied().min().unwrap_or(now);
            Some((oldest + WINDOW_SECS - now).max(1))
        } else {
            None
        }
    }

    pub fn record_failure(&self, ip: IpAddr, now: i64) {
        let mut map = self.failures.lock().expect("limiter mutex poisoned");
        // Opportunistic garbage collection so the map can't grow unbounded.
        if map.len() > 10_000 {
            map.retain(|_, times| times.iter().any(|t| now - *t < WINDOW_SECS));
        }
        map.entry(ip).or_default().push(now);
    }
}

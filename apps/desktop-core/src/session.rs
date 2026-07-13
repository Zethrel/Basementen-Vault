//! Auto-lock policy: pure time arithmetic, driven by the shell's timer.

use std::time::{Duration, Instant};

/// Tracks user activity and decides when the vault must lock. The shell
/// calls [`AutoLock::touch`] on every user-initiated command and polls
/// [`AutoLock::should_lock`] from a timer.
#[derive(Debug)]
pub struct AutoLock {
    timeout: Duration,
    last_activity: Instant,
}

impl AutoLock {
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15 * 60);

    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            last_activity: Instant::now(),
        }
    }

    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    pub fn should_lock(&self) -> bool {
        self.last_activity.elapsed() >= self.timeout
    }

    pub fn remaining(&self) -> Duration {
        self.timeout.saturating_sub(self.last_activity.elapsed())
    }

    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }
}

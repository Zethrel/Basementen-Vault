//! Process hardening: best-effort core-dump suppression.
//!
//! A crash that produced a core dump could write key-bearing memory (the Vault
//! Key, master-password-derived keys, decrypted items) to disk, defeating the
//! in-memory scrubbing and page-locking (`secmem`). Call [`suppress_core_dumps`]
//! once at process start, before any secret exists.
//!
//! Mechanism per platform:
//! - **Linux:** `RLIMIT_CORE = 0` *and* `PR_SET_DUMPABLE = 0`. The rlimit alone
//!   is **not** enough — the kernel ignores it when `/proc/sys/kernel/core_pattern`
//!   pipes to a handler (systemd-coredump, apport), which is the common desktop
//!   setup; `PR_SET_DUMPABLE = 0` suppresses the dump regardless and, as a bonus,
//!   blocks same-user `ptrace` attach.
//! - **Other unix (macOS/BSD):** `RLIMIT_CORE = 0`.
//! - **Windows:** not suppressed here — Windows Error Reporting may still capture
//!   a crash dump; operators disable it via policy/registry (see RUNBOOK).
//!
//! Best-effort: a failure never aborts startup. The syscalls live inside the
//! `rlimit` / `prctl` crates, so the workspace's `forbid(unsafe)` is unaffected.

/// Disable core dumps for this process (and its children). Returns `true` if
/// suppression was fully applied on this platform. Safe to call more than once.
pub fn suppress_core_dumps() -> bool {
    #[cfg(target_os = "linux")]
    {
        let rlimit_ok = rlimit::setrlimit(rlimit::Resource::CORE, 0, 0).is_ok();
        // Guards the core_pattern-pipe case the rlimit can't.
        let dumpable_ok = prctl::set_dumpable(false).is_ok();
        rlimit_ok && dumpable_ok
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        rlimit::setrlimit(rlimit::Resource::CORE, 0, 0).is_ok()
    }
    #[cfg(not(unix))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_dump_limit_is_zeroed() {
        // Idempotent and non-panicking.
        let _ = suppress_core_dumps();
        let _ = suppress_core_dumps();

        #[cfg(unix)]
        {
            // The effect is observable: the soft CORE limit is now 0.
            let (soft, _hard) = rlimit::getrlimit(rlimit::Resource::CORE).unwrap();
            assert_eq!(soft, 0, "core dump soft limit must be zeroed");
        }
    }
}

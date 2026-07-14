//! Page-locked secret memory.
//!
//! [`SecretBytes`] holds a fixed-size secret in a heap allocation whose backing
//! page is locked out of swap (`mlock` / `VirtualLock`, via the `region` crate)
//! and zeroized on drop. This is what backs every key type (`keys.rs`), so key
//! material is pinned in RAM for its whole lifetime and never written to a swap
//! file or hibernation image.
//!
//! **Best-effort.** If the OS refuses to lock (e.g. `RLIMIT_MEMLOCK` on Linux,
//! or a platform without locking), the secret still functions — it simply isn't
//! pinned. The syscall's `unsafe` lives entirely inside `region`, so the
//! workspace's `forbid(unsafe)` posture is unchanged.
//!
//! **Neighbour safety.** We allocate two pages and lock the single page that
//! lies fully inside them. Because that page is entirely owned by this
//! allocation, locking and (on drop) unlocking it can never touch memory
//! belonging to another secret — which would otherwise risk unlocking a
//! neighbour's key when one of them drops.

use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::keys::KEY_LEN;

pub(crate) struct SecretBytes {
    // Declared first so it unlocks *before* `buf` is freed on drop.
    _lock: Option<region::LockGuard>,
    buf: Vec<u8>,
    offset: usize,
}

impl SecretBytes {
    /// Copy `bytes` into a fresh page-locked, zeroizing allocation.
    pub(crate) fn new(bytes: &[u8; KEY_LEN]) -> Self {
        let page = region::page::size();
        // Two pages guarantee one whole page lies fully inside the allocation,
        // regardless of where the allocator places the buffer.
        let mut buf = vec![0u8; 2 * page];
        let base = buf.as_ptr() as usize;
        let offset = base.next_multiple_of(page) - base; // in 0..page
        buf[offset..offset + KEY_LEN].copy_from_slice(bytes);
        // Lock exactly the fully-owned page. Best-effort: failure => not pinned.
        let lock = region::lock(buf[offset..offset + page].as_ptr(), page).ok();
        Self {
            _lock: lock,
            buf,
            offset,
        }
    }

    pub(crate) fn as_array(&self) -> &[u8; KEY_LEN] {
        self.buf[self.offset..self.offset + KEY_LEN]
            .try_into()
            .expect("slice is exactly KEY_LEN")
    }
}

impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        Self::new(self.as_array())
    }
}

impl ConstantTimeEq for SecretBytes {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.as_array().ct_eq(other.as_array())
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        // Scrub while still locked; `_lock` (declared first) unlocks afterwards.
        self.buf.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_independent_clone() {
        let bytes = [7u8; KEY_LEN];
        let a = SecretBytes::new(&bytes);
        assert_eq!(a.as_array(), &bytes);

        let b = a.clone();
        assert_eq!(b.as_array(), &bytes);
        assert!(bool::from(a.ct_eq(&b)));

        // The clone owns a distinct allocation.
        assert_ne!(a.as_array().as_ptr(), b.as_array().as_ptr());
    }

    #[test]
    fn ct_eq_distinguishes_values() {
        let a = SecretBytes::new(&[1u8; KEY_LEN]);
        let b = SecretBytes::new(&[2u8; KEY_LEN]);
        assert!(!bool::from(a.ct_eq(&b)));
    }

    #[test]
    fn locked_page_lies_fully_inside_allocation() {
        let s = SecretBytes::new(&[0u8; KEY_LEN]);
        let page = region::page::size();
        let base = s.buf.as_ptr() as usize;
        let locked_start = base + s.offset;
        assert_eq!(locked_start % page, 0, "locked region is page-aligned");
        assert!(
            s.offset + page <= s.buf.len(),
            "the locked page is fully within the 2-page allocation"
        );
    }
}

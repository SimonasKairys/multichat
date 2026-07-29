//! Process and memory hardening.
//!
//! This is the **only** module in the crate permitted to contain `unsafe`. The crate
//! root sets `#![deny(unsafe_code)]`; the `allow` below is the single audited
//! exception, and CI fails the build if `allow(unsafe_code)` appears in any other file.
//! (`forbid` cannot be used at the crate root because it is, by design, not
//! overridable — so FFI would require splitting this into a separate crate. The
//! `deny` + CI-grep combination gives the same enforcement without that split.)
#![allow(unsafe_code)]

use anyhow::{Result, anyhow};
use zeroize::Zeroize;

/// Outcome of a hardening step: applied, or unavailable with a reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hardening {
    Applied,
    Unavailable(String),
}

impl Hardening {
    pub fn is_applied(&self) -> bool {
        matches!(self, Hardening::Applied)
    }
}

/// Locks the process's pages into RAM so secrets cannot be written to swap.
///
/// This is **best effort by default**. Unprivileged Linux processes typically have a
/// very small `RLIMIT_MEMLOCK`, so `mlockall` fails; treating that as fatal would make
/// the binary refuse to start (including `--help`) on an ordinary machine. When
/// `strict` is set the failure is escalated to an error, so `--classified` sessions
/// still refuse to run unprotected.
#[cfg(unix)]
pub fn enforce_memory_protection(strict: bool) -> Result<Hardening> {
    // SAFETY: `mlockall` takes only an integer flag set and touches no user memory.
    // It reports failure through its return value, which is checked below.
    let ret = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
    if ret == 0 {
        return Ok(Hardening::Applied);
    }

    let err = std::io::Error::last_os_error();
    let reason = format!(
        "mlockall failed: {err}. Raise `ulimit -l` or grant CAP_IPC_LOCK to keep \
         secrets out of swap. (macOS does not implement mlockall at all.)"
    );
    if strict {
        return Err(anyhow!(
            "refusing to start in classified mode without memory locking: {reason}"
        ));
    }
    Ok(Hardening::Unavailable(reason))
}

/// Windows has no process-wide equivalent of `mlockall`. Individual allocations are
/// locked instead — see [`LockedBuffer`], which the vault uses for derived key material.
#[cfg(windows)]
pub fn enforce_memory_protection(strict: bool) -> Result<Hardening> {
    let reason = "Windows provides no process-wide memory lock; key material is locked \
                  per-allocation with VirtualLock instead."
        .to_string();
    if strict {
        return Err(anyhow!(
            "refusing to start in classified mode: {reason} Process-wide locking is \
             only available on Linux."
        ));
    }
    Ok(Hardening::Unavailable(reason))
}

/// Seccomp syscall filtering.
///
/// **NOT IMPLEMENTED.** A useful filter has to permit `socket`/`connect` (cloud
/// providers) while denying `execve`, which requires a hand-built BPF program;
/// `SECCOMP_MODE_STRICT` kills the process on the first socket call. This function
/// deliberately does nothing and reports that, rather than logging a message that
/// implies a sandbox exists. See `docs/progress/22_status.md`.
pub fn enforce_seccomp_sandbox() -> Hardening {
    Hardening::Unavailable("seccomp sandboxing is not implemented".to_string())
}

/// A heap buffer whose pages are locked into RAM and zeroed when dropped.
///
/// Used for derived encryption keys so they are neither swapped to disk nor left in
/// freed memory. Locking is best effort: if the OS refuses, the buffer still works and
/// is still zeroized, it is simply swappable.
pub struct LockedBuffer {
    bytes: Vec<u8>,
    locked: bool,
}

impl LockedBuffer {
    pub fn new(bytes: Vec<u8>) -> Self {
        let locked = lock_region(bytes.as_ptr(), bytes.len());
        Self { bytes, locked }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Whether the pages were successfully pinned to RAM.
    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

impl Drop for LockedBuffer {
    fn drop(&mut self) {
        self.bytes.zeroize();
        if self.locked {
            unlock_region(self.bytes.as_ptr(), self.bytes.len());
        }
    }
}

#[cfg(unix)]
fn lock_region(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return false;
    }
    // SAFETY: `ptr`/`len` describe a live allocation owned by the caller (a `Vec` that
    // outlives this call). `mlock` only pins pages; it never reads or writes them.
    unsafe { libc::mlock(ptr as *const libc::c_void, len) == 0 }
}

#[cfg(unix)]
fn unlock_region(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    // SAFETY: same allocation that was passed to `mlock`, still live at drop time.
    unsafe {
        libc::munlock(ptr as *const libc::c_void, len);
    }
}

#[cfg(windows)]
fn lock_region(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return false;
    }
    // SAFETY: `ptr`/`len` describe a live allocation owned by the caller. `VirtualLock`
    // pins the containing pages and does not read or write the buffer.
    unsafe { windows_sys::Win32::System::Memory::VirtualLock(ptr as *mut _, len) != 0 }
}

#[cfg(windows)]
fn unlock_region(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    // SAFETY: same allocation that was passed to `VirtualLock`, still live at drop time.
    unsafe {
        windows_sys::Win32::System::Memory::VirtualUnlock(ptr as *mut _, len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_buffer_exposes_contents() {
        let buf = LockedBuffer::new(vec![1, 2, 3, 4]);
        assert_eq!(buf.as_slice(), &[1, 2, 3, 4]);
    }

    #[test]
    fn seccomp_reports_unavailable_rather_than_pretending() {
        assert!(!enforce_seccomp_sandbox().is_applied());
    }

    #[test]
    fn non_strict_memory_protection_never_fails_startup() {
        // The whole point of the fail-soft path: an unprivileged process must still boot.
        assert!(enforce_memory_protection(false).is_ok());
    }
}

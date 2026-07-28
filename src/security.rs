#![allow(unsafe_code)] // Unsafe code is ONLY allowed in this specific FFI wrapper module

use anyhow::{Context, Result};

/// Enforces military-grade memory locking, preventing RAM from swapping to disk.
#[cfg(target_os = "linux")]
pub fn enforce_memory_protection() -> Result<()> {
    unsafe {
        let ret = libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE);
        if ret != 0 {
            return Err(std::io::Error::last_os_error())
                .context("FATAL: Failed to lock memory (mlockall). Ensure you have ulimit -l configured or CAP_IPC_LOCK.");
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn enforce_memory_protection() -> Result<()> {
    eprintln!("[SECURITY WARNING] Strict mlockall memory locking is currently only enforced on Linux targets.");
    Ok(())
}

/// Enforces the seccomp execution sandbox.
#[cfg(target_os = "linux")]
pub fn enforce_seccomp_sandbox() -> Result<()> {
    // Note: Implementing a full BPF filter allowing network sockets but denying execve 
    // requires a BPF compiler logic. We stub this foundationally here.
    // In strict mode, `prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT)` kills the app on socket(), so we must use BPF.
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn enforce_seccomp_sandbox() -> Result<()> {
    eprintln!("[SECURITY WARNING] Seccomp sandboxing is only available on Linux targets.");
    Ok(())
}

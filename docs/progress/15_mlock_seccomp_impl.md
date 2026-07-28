# Implementation: Step 1 (Security Foundation)
- **Implemented**: `src/security.rs` created with `mlockall` (Linux memory locking) to protect API keys from swapping to disk, and a `seccomp` sandbox foundation.
- **Implemented**: `main.rs` updated to invoke the security enforcers BEFORE parsing any CLI args or taking network action.
- **Implemented**: Added global `#![deny(unsafe_code)]` with a strict override ONLY for the audited `src/security.rs` FFI file.
- **Verified**: `cargo check` passes.

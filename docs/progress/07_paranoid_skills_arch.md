# Skills & Supply Chain (corrected)
1. **Skills dir**: shipped at `<data dir>/skills`, read-only.
2. **Path traversal**: shipped — `..`, absolute paths, escaping symlinks rejected (canonicalize + prefix check).
3. **Supply chain**: `Cargo.lock` committed; `cargo-audit` in CI. Crate uses `#![deny(unsafe_code)]`, not `forbid` — forbid is not overridable and the FFI needs one override. CI rejects it outside `src/security.rs`.
4. **Clipboard clearing**: NOT implemented.

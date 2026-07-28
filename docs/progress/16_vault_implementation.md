# Implementation: Step 2 (Encrypted Vault)
- **Implemented**: `src/vault.rs` uses AES-256-GCM for encryption.
- **Implemented**: `Argon2` handles secure Key Derivation from a Master Password.
- **Implemented**: Appends 12-byte cryptographically secure nonce to the vault payload.
- **Verified**: Fixed compiler error with `SaltString`, now `cargo check` fully passes.

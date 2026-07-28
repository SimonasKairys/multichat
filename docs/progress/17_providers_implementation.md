# Implementation: Step 3 (Providers)
- **Implemented**: `src/providers/mod.rs` defining the universal async `Provider` trait.
- **Implemented**: `src/providers/ollama.rs` using `reqwest` to hit local HTTP API.
- **Implemented**: `src/providers/cloud.rs` using `reqwest` with Bearer auth wrapped securely in `secrecy::SecretString`.
- **Implemented**: `src/providers/local_binary.rs` using `std::process::Command` to trigger subprocess execution.
- **Verified**: Dependencies deduped, `cargo check` fully passes.

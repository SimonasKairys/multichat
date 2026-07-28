# Final Plan Overview
Goal: `multichat`, zero-trust Rust terminal chat (TUI) for local/cloud models.
Architecture: Modular providers (Ollama, Cloud, Subprocess).
Security (Military Grade):
- `mlock` swap protection.
- Encrypted vault (master password).
- TLS Certificate Pinning.
- `seccomp` sandbox.
- Air-gap routing for `[TOP SECRET]` chats.
Ref: plan.md in artifacts.

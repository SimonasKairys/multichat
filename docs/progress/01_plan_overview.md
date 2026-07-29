# Plan Overview (goals; `22_status.md` = what shipped)
Goal: zero-trust Rust TUI chat for local/cloud models.
Providers: Ollama, Cloud, Subprocess.
Security goals:
- `mlock` swap protection — shipped (Linux process-wide, per-alloc elsewhere).
- Encrypted vault — shipped.
- TLS cert pinning — NOT implemented (breaks on cert rotation).
- `seccomp` sandbox — NOT implemented.
- Air-gap via `--classified` — shipped.

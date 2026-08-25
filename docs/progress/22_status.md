# Authoritative Status

`01`–`14` are plans, not specs. Where they disagree with this file or the README's
"Security posture", those are correct.

**Shipped**: provider routing, keyring keys (never argv), vault salt + wipe policy,
anchored keyed-MAC audit chain, bounded system prompt, `--classified`, Linux
`mlockall` + per-alloc locking, skills traversal guard, SOCKS5, Ollama discovery,
delegation, CI.

**Not implemented**: seccomp, TLS pinning, process-wide locking off Linux, clipboard clear.

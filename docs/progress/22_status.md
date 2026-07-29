# Authoritative Status

`01`–`14` are plans, not specs. Where they disagree with this file or the README's
"Security posture", those are correct.

**Shipped**: per-provider routing, keyring keys (never argv), vault with stored salt and
wipe policy, keyed-MAC audit chain, `--classified`, Linux `mlockall` plus per-allocation
locking, skills traversal guard, SOCKS5, Ollama discovery, delegation, CI.

**Not implemented**: seccomp, TLS pinning, process-wide locking off Linux, clipboard clear.

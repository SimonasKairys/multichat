# Authoritative Status

`01`–`14` are plans, not specs. Where they disagree with this file or the README's
"Security posture", those are correct.

**Shipped**: provider routing, keyring keys (never argv), vault salt + wipe policy,
capped transcript, locked + anchored MAC audit chain, capped system prompt,
`--classified`, Linux `mlockall`, skills guard, SOCKS5, Ollama discovery, delegation,
CI + mutants.

**Not implemented**: seccomp, TLS pinning, process-wide lock off Linux, clipboard.

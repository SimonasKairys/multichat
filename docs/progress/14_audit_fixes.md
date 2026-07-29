# Audit Fixes (corrected)
1. **Proxy**: shipped. reqwest `socks` feature enabled, so `ALL_PROXY=socks5://…` works alongside `HTTP(S)_PROXY`.
2. **Vault**: wipe after 5 failed unlocks or 24h idle — shipped. Caveat: the counter is in the protected file, so a copy resets it.
3. **Audit log**: keyed Blake2s **MAC** chain, not a signature — the keyring holder can forge, so it proves local integrity only.
4. **Stream interceptor**: NOT implemented; responses are non-streaming.

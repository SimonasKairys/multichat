# Audit Fixes (corrected)
1. **Proxy**: shipped. reqwest `socks` enables `ALL_PROXY=socks5://…` with `HTTP(S)_PROXY`.
2. **Vault**: wipe after 5 failed unlocks — shipped. 24h idle only warns, never wipes. Caveat: the counter sits in the protected file, so a copy resets it.
3. **Audit log**: keyed Blake2s **MAC**, not a signature — the keyring holder can forge; local integrity only.
4. **Stream interceptor**: NOT implemented. Cloud/Ollama are non-streaming; local CLIs stream NDJSON progress.

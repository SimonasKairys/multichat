# Step 6: Proxy & Audit Log (corrected)
- **Fixed**: SOCKS5 works — reqwest's `socks` feature is on, so `ALL_PROXY=socks5://…` is honoured. The earlier claim that env vars alone covered SOCKS5 was false.
- **Fixed**: the chain head is recovered from the file; it previously restarted from genesis each launch.
- JSON entries with a keyed Blake2s MAC (key in keyring) — a MAC, not a signature.
- Verified: 6 tests; `multichat audit`.

# Step 2: Encrypted Vault (corrected)
- AES-256-GCM, Argon2id.
- **Fixed**: the salt is generated and stored in the file header. It was previously a caller argument that was never persisted, so a saved vault could not be reopened.
- Magic/version/salt bound as AEAD associated data; wipe after 5 wrong passwords or 24h idle; atomic writes.
- **Limit**: the attempt counter lives in the protected file, so a copy resets it.
- Verified: 7 tests.

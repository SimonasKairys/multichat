# Final Architectural Decisions
1. **History Storage**: Encrypted Vault (AES-256-GCM) unlocked via Master Password.
2. **Data Firewall**: Activated via startup flag (e.g., `multichat --classified`). Strictly disables outbound network access.
3. **Cross-Platform**: OS security abstraction (Linux/macOS `mlock`, Windows `VirtualLock`).
4. **Updates**: Manual updates only via verified cryptographic hashes to prevent supply-chain attacks.

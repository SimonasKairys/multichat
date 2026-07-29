# Architecture Decisions (corrected)
1. **History**: encrypted vault (AES-256-GCM + Argon2id) — shipped.
2. **Data firewall**: `--classified` shipped; refuses remote providers rather than filtering sockets.
3. **Cross-platform**: Linux gets process-wide `mlockall`. macOS returns ENOSYS, Windows has no equivalent, so both lock key material per allocation. `--classified` refuses to start without the process-wide guarantee.
4. **Updates**: manual only; no updater exists.

# Step 1: Security Foundation (corrected)
- `mlockall` process-wide on Linux only. Windows/macOS lack an equivalent, so key material is locked per allocation (`mlock`/`VirtualLock`) and zeroized on drop.
- **Fixed**: args parse *before* hardening, and lock failure warns instead of aborting — it hard-fails only under `--classified`. Previously `--help` aborted on any unprivileged Linux box.
- **NOT implemented**: seccomp; it reports itself unavailable.
- Verified: 65 tests.

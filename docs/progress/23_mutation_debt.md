# Mutation Coverage Debt

CI gates changed lines. Full crate: ~953 mutants / ~3.5h, not recently re-measured.

2026-08-26 accumulated audit diff: 107 tested, 97 caught, 9 unviable, 1 equivalent
survivor. This is diff evidence, not full-module coverage.

Remaining debt includes untouched provider/orchestrator/security paths and historical
vault branches. `Credentials::*` is skipped where runners lack a keyring.

Unset `RUSTFLAGS`: `-D warnings` can hide stub mutants as unviable.

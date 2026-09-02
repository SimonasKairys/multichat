# Mutation Coverage Debt

CI gates changed lines. `mutation-audit.yml` re-measures the crate weekly and files
the score in an issue: measured, not remembered.

Full crate: ~953 mutants / ~3.5h (2026-08); awaiting the first scheduled run.

2026-08-26 audit diff: 107 tested, 97 caught, 9 unviable, 1 survivor.

Debt: untouched provider/orchestrator/security paths, old vault branches.
`restrict_to_owner` left it (see `config.rs`).

Unset `RUSTFLAGS`: `-D warnings` hides stubs as unviable.

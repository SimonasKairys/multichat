# Mutation Coverage Debt

CI gates changed lines. `mutation-audit.yml` re-measures the crate weekly and
files the score in an issue: measured, not remembered.

Full crate: ~953 mutants / ~3.5h (2026-08); awaiting the first scheduled run.

2026-09-02: `usage_ledger.rs` 96/96, from 88. The 8: error paths, the
real-clock wrapper, a pre-epoch branch no date after 1970 reaches.

Debt: untouched provider/orchestrator/security paths, old vault branches.

Unset `RUSTFLAGS`: it hides stubs as unviable.

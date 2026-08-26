# Mutation Coverage Debt

CI gates changed lines only. Full crate: 953 mutants, ~3.5h.

**Measured, 0 missed**: `workspace.rs`, `config.rs`.
**Unmeasured**: everything else — `audit.rs`, `swarm.rs`, `orchestrator.rs`,
`providers/*`, `security.rs`, `skills.rs`, `picker.rs`, `app.rs`, `ui/`.
**Known debt**: ~13 in old `vault.rs` (`aad`, `parse_header`, `destroy`).
**Skipped**: `Credentials::*` — OS keyring, absent on runners.

RUSTFLAGS must be unset: `-D warnings` hides stub mutants as unviable.

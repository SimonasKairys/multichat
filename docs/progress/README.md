# Progress Logging Instructions

**Location:** `docs/progress/`

> **`22_status.md` is authoritative.** Files `01`–`14` are plans written before the code
> existed; several describe features that were never built. Where a plan and `22` (or the
> README's "Security posture" section) disagree, `22` is correct. Do not read a numbered
> file as a statement of what the code does today.

## Rules
1. **Size Limit**: Each file MUST be NO MORE than 500 characters (symbols).
2. **Structure**: Split logs logically by topic (e.g., plan, steps, implemented features, errors).
3. **Format**: Markdown. Can contain references to code, schemas, and file links.
4. **Maintenance**: Create new files sequentially rather than appending to old ones.
5. **Verification**: Every change must be verified (`cargo test`, `cargo clippy`, or a
   manual run) *before* it is recorded here. Record what was actually verified — "cargo
   check passes" is not evidence that a feature works, only that it type-checks.
6. **No completion claims without a caller.** A module that compiles but is never called
   is scaffolding, not a feature. Say so.

## Current Files
- `01`–`02`: plan and roadmap.
- `03`–`04`: early implementation notes and error log.
- `05`–`14`: architecture and security decisions (aspirational; see the note above).
- `15`–`21`: per-step implementation records, corrected after the audit.
- `23_mutation_debt.md`: what mutation testing has and has not measured.
- `22_status.md`: **authoritative** implemented / not-implemented status.
- `../AUDIT-2026-08-26.md`: latest full-tree audit plus current follow-up fixes.
- `../AUDIT-2026-07-30.md` and `../AUDIT-2026-07-31.md`: historical split-tree
  snapshots. Two earlier audits were removed as superseded; recoverable at `2e7984e`.

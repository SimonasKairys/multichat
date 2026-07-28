# Progress Logging Instructions

**Location:** `docs/progress/`

## Rules
1. **Size Limit**: Each file MUST be NO MORE than 500 characters (symbols).
2. **Structure**: Split logs logically by topic (e.g., plan, steps, implemented features, errors).
3. **Format**: Markdown. Can contain references to code, schemas, and file links.
4. **Maintenance**: Create new files sequentially (e.g., `05_ui_update.md`) rather than appending to old ones to avoid exceeding the character limit.
5. **Verification**: Every single change or step must be explicitly verified (e.g., via `cargo check`, `cargo test`, or manual verification) before proceeding to the next step.

## Current Files
- `01_plan_overview.md`: High-level architecture and zero-trust goals.
- `02_plan_steps.md`: Step-by-step development roadmap.
- `03_implemented.md`: Record of successfully completed work.
- `04_mistakes_errors.md`: Debugging logs, encountered issues, and their fixes.

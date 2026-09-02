# Monthly Token Ledger

Status line shows a persisted "this month N tok" total, global across models.
`src/usage_ledger.rs`: `usage_history.json` under the data dir, keyed by UTC
`YYYY-MM`, rolls to zero on month change. `record_month_usage` writes on every
completed call; failures are audit-logged, not propagated. `Event::UsageUpdated
.month_tokens` carries it to `App`; hidden until first usage event. Verified:
`cargo test` (659 passed), fmt, clippy clean.

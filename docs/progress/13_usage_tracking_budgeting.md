# Usage Tracking & Token Budgeting
1. **Rate Limit Tracking**: The Rust backend intercepts `x-ratelimit` HTTP headers from Cloud APIs and tracks estimated usage for CLI tools.
2. **Budget Injection**: The Swarm Ledger includes a "Resource Budget" block (e.g., `claude-opus: 5% limit remaining`).
3. **Smart Routing**: Models are explicitly instructed to check budgets before delegating. If a model is exhausted, tasks are intelligently routed to unrestricted local models or cheaper APIs.

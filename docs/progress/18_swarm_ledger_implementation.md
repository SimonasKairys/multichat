# Step 4: Swarm Ledger (corrected)
- Renders roster, observed rate-limit budgets and task state into a Markdown block.
- **Fixed**: the generator is now called. It previously had zero call sites, so no model ever saw a ledger.
- `parse_delegations` reads `ACTION: delegate_task(target, prompt)`, splitting on the first comma and last `)`.
- Bounded: 3 delegations per turn, no recursion into sub-agent replies.
- Verified: 8 tests.

# Shared Swarm Ledger (Blackboard)
1. **State Synchronization**: A central "Ledger" tracks tasks: `[DONE]`, `[IN_PROGRESS]`, `[TODO]`.
2. **Context Injection**: The Rust backend automatically compiles this Ledger into a tight Markdown summary and injects it into the system prompt of *every* active model.
3. **Updates**: When a model finishes a delegated task, it can return a state-update payload along with the answer, allowing the orchestrator to update the Ledger in real-time.

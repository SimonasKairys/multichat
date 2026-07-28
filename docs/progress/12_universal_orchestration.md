# Universal Orchestration
1. **Universal Sub-Agents**: Any model (API, local, CLI) can be a sub-agent because the Swarm Ledger is injected purely as text in the system prompt.
2. **Commander Models**: To orchestrate, models use native Tool Calling (Claude, OpenAI, Gemini).
3. **ReAct Fallback**: For CLI tools (e.g., `copilot`) without tool APIs, the Rust backend parses their stdout for specific text commands (e.g., `ACTION: delegate_task`), allowing ANY model to command the swarm.

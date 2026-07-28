# Multi-Agent Protocol
1. **Model Awareness**: The primary model is injected with system prompts detailing all other available models on the network.
2. **Delegation Protocol**: The app exposes a `delegate_task` Tool/Function to the LLMs.
3. **Orchestration Engine**: When Claude (for example) calls `delegate_task(target="ollama:llama3", prompt="...")`, the Rust backend intercepts, queries the target model asynchronously, and returns the result to Claude.

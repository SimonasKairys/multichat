# Dynamic Discovery & Auth
1. **Dynamic Model Discovery**: No hardcoded models. APIs and CLI tools are dynamically queried (e.g., `ollama list`, `/v1/models` endpoint) to list available models at runtime.
2. **Unified Auth Layer**: Both CLI tool authentication (e.g., sub-process specific auth) and Cloud API authentication (Bearer tokens) are managed under the same encrypted vault architecture.

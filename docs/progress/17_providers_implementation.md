# Step 3: Providers (corrected)
- **Fixed**: routing is per provider. `provider_name` was stored, never read, and every request went to `api.openai.com` — an Anthropic key was sent to OpenAI as a bearer token.
- Anthropic (`/v1/messages`, `x-api-key`, no sampling params) and OpenAI-compatible (`/chat/completions`, Bearer). Unknown provider errors, never defaults.
- **Fixed**: `local_binary` uses `tokio::process`.
- Verified: 11 tests.

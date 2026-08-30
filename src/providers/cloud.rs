//! Cloud provider transport.
//!
//! Routing is explicit per provider. An earlier version stored `provider_name`, never
//! read it, and posted every request to `api.openai.com` — which meant an Anthropic or
//! Gemini key was transmitted to OpenAI as a bearer token. The [`Api`] discriminant is
//! now the only thing that decides the URL, the auth header, and the response shape.

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};

use crate::config::{Api, CloudEndpoint};
use crate::providers::{
    Provider, ProviderFailure, RateLimit, Reply, TokenUsage, json_u64, truncate_error_detail,
};

/// Anthropic requires this header on every request; it is an API-version pin, not a
/// model version.
const ANTHROPIC_VERSION: &str = "2023-06-01";
const DEFAULT_MAX_TOKENS: u32 = 4096;

pub struct CloudProvider {
    provider: String,
    endpoint: CloudEndpoint,
    model: String,
    api_key: SecretString,
    client: reqwest::Client,
}

impl CloudProvider {
    pub fn new(
        provider: impl Into<String>,
        endpoint: CloudEndpoint,
        model: Option<String>,
        api_key: SecretString,
        client: reqwest::Client,
    ) -> Self {
        let model = model.unwrap_or_else(|| endpoint.default_model.clone());
        Self {
            provider: provider.into(),
            endpoint,
            model,
            api_key,
            client,
        }
    }

    fn url(&self) -> String {
        let base = self.endpoint.base_url.trim_end_matches('/');
        match self.endpoint.api {
            Api::Anthropic => format!("{base}/v1/messages"),
            Api::OpenAiCompatible => format!("{base}/chat/completions"),
        }
    }

    fn body(&self, system: Option<&str>, prompt: &str) -> Value {
        match self.endpoint.api {
            Api::Anthropic => {
                let mut body = json!({
                    "model": self.model,
                    "max_tokens": DEFAULT_MAX_TOKENS,
                    "messages": [{ "role": "user", "content": prompt }],
                });
                if let Some(system) = system {
                    body["system"] = json!(system);
                }
                // Deliberately no `temperature`: current Claude models reject sampling
                // parameters with a 400.
                body
            }
            Api::OpenAiCompatible => {
                let mut messages = Vec::new();
                if let Some(system) = system {
                    messages.push(json!({ "role": "system", "content": system }));
                }
                messages.push(json!({ "role": "user", "content": prompt }));
                json!({ "model": self.model, "messages": messages })
            }
        }
    }

    fn request(&self, body: &Value) -> reqwest::RequestBuilder {
        let req = self.client.post(self.url()).json(body);
        match self.endpoint.api {
            Api::Anthropic => req
                .header("x-api-key", self.api_key.expose_secret())
                .header("anthropic-version", ANTHROPIC_VERSION),
            Api::OpenAiCompatible => req.bearer_auth(self.api_key.expose_secret()),
        }
    }

    /// Pulls the assistant text out of a provider-specific response body.
    fn extract_text(&self, body: &Value) -> Result<String> {
        match self.endpoint.api {
            Api::Anthropic => {
                // Safety classifiers can decline with HTTP 200 and an empty content
                // array; surface that rather than returning "".
                if body.get("stop_reason").and_then(Value::as_str) == Some("refusal") {
                    let category = body
                        .pointer("/stop_details/category")
                        .and_then(Value::as_str)
                        .unwrap_or("unspecified");
                    return Err(anyhow!(
                        "{} declined this request (category: {category})",
                        self.model
                    ));
                }
                let text: String = body
                    .get("content")
                    .and_then(Value::as_array)
                    .map(|blocks| {
                        blocks
                            .iter()
                            .filter(|b| b.get("type").and_then(Value::as_str) == Some("text"))
                            .filter_map(|b| b.get("text").and_then(Value::as_str))
                            .collect::<Vec<_>>()
                            .join("")
                    })
                    .unwrap_or_default();
                // `trim` before the check, not just `is_empty`: a content block of
                // nothing but whitespace is the same nothing as an absent one, and
                // returning it as a reply hands the orchestrator a blank delegation
                // result that looks successful. The OpenAI arm below has always
                // trimmed first; this arm only looked untrimmed-empty.
                if text.trim().is_empty() {
                    return Err(anyhow!(
                        "{} returned no text content (response: {})",
                        self.model,
                        truncate_error_detail(&body.to_string())
                    ));
                }
                Ok(text)
            }
            Api::OpenAiCompatible => {
                let refusal_field = body
                    .pointer("/choices/0/message/refusal")
                    .and_then(Value::as_str);
                if body
                    .pointer("/choices/0/finish_reason")
                    .and_then(Value::as_str)
                    == Some("refusal")
                    || refusal_field.is_some()
                {
                    let reason = refusal_field.unwrap_or("unspecified");
                    return Err(anyhow!("{} declined this request: {reason}", self.model));
                }
                let text = match body.pointer("/choices/0/message/content") {
                    Some(Value::String(s)) => s.clone(),
                    Some(Value::Array(parts)) => parts
                        .iter()
                        .filter_map(|p| {
                            if p.get("type").and_then(Value::as_str) == Some("text") {
                                p.get("text").and_then(Value::as_str)
                            } else {
                                p.as_str()
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(""),
                    _ => String::new(),
                };
                let text = text.trim().to_string();
                if text.is_empty() {
                    return Err(anyhow!(
                        "{} returned no message content (response: {})",
                        self.model,
                        truncate_error_detail(&body.to_string())
                    ));
                }
                Ok(text)
            }
        }
    }

    fn extract_usage(&self, body: &Value) -> TokenUsage {
        match self.endpoint.api {
            Api::Anthropic => TokenUsage {
                input_tokens: json_u64(body.pointer("/usage/input_tokens")),
                output_tokens: json_u64(body.pointer("/usage/output_tokens")),
                total_tokens: None,
            },
            Api::OpenAiCompatible => TokenUsage {
                input_tokens: json_u64(body.pointer("/usage/prompt_tokens")),
                output_tokens: json_u64(body.pointer("/usage/completion_tokens")),
                total_tokens: json_u64(body.pointer("/usage/total_tokens")),
            },
        }
    }
}

#[async_trait]
impl Provider for CloudProvider {
    async fn send(&self, system: Option<&str>, prompt: &str) -> Result<Reply> {
        let body = self.body(system, prompt);
        let response = self
            .request(&body)
            .send()
            .await
            .with_context(|| format!("request to {} failed", self.url()))?;

        let status = response.status();
        let rate_limit = RateLimit::from_headers(response.headers());

        if !status.is_success() {
            // Include the provider's message — a bare status code makes auth failures
            // indistinguishable from bad model names.
            let detail = response.text().await.unwrap_or_default();
            return Err(
                anyhow::Error::new(ProviderFailure::HttpStatus(status.as_u16())).context(format!(
                    "{} returned {}: {}",
                    self.provider,
                    status,
                    truncate_error_detail(detail.trim())
                )),
            );
        }

        let parsed: Value = response
            .json()
            .await
            .with_context(|| format!("{} returned a non-JSON body", self.provider))?;

        Ok(Reply {
            text: self.extract_text(&parsed)?,
            rate_limit,
            usage: self.extract_usage(&parsed),
        })
    }

    fn model_name(&self) -> &str {
        &self.model
    }

    fn provider_name(&self) -> &str {
        &self.provider
    }

    fn is_remote(&self) -> bool {
        true
    }

    fn requires_subagent_tool_guardrails(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::builtin_endpoint;

    fn provider(name: &str) -> CloudProvider {
        CloudProvider::new(
            name,
            builtin_endpoint(name).unwrap(),
            None,
            SecretString::from("test-key".to_string()),
            reqwest::Client::new(),
        )
    }

    #[test]
    fn cloud_completion_providers_skip_agentic_cli_guardrails() {
        assert!(!provider("openai").requires_subagent_tool_guardrails());
    }

    #[test]
    fn anthropic_and_openai_hit_different_urls() {
        // Regression guard for the "every provider posts to OpenAI" bug.
        assert_eq!(
            provider("anthropic").url(),
            "https://api.anthropic.com/v1/messages"
        );
        assert_eq!(
            provider("openai").url(),
            "https://api.openai.com/v1/chat/completions"
        );
    }

    #[test]
    fn anthropic_body_omits_sampling_parameters() {
        // Current Claude models 400 on `temperature`.
        let body = provider("anthropic").body(Some("be terse"), "hi");
        assert!(body.get("temperature").is_none());
        assert_eq!(body["system"], json!("be terse"));
        assert_eq!(body["messages"][0]["role"], json!("user"));
        assert!(body.get("max_tokens").is_some());
    }

    #[test]
    fn openai_body_puts_system_in_the_message_list() {
        let body = provider("openai").body(Some("be terse"), "hi");
        assert_eq!(body["messages"][0]["role"], json!("system"));
        assert_eq!(body["messages"][1]["content"], json!("hi"));
    }

    #[test]
    fn extracts_provider_specific_token_usage() {
        let anthropic = json!({
            "usage": {"input_tokens": 120, "output_tokens": 30}
        });
        assert_eq!(
            provider("anthropic").extract_usage(&anthropic),
            TokenUsage {
                input_tokens: Some(120),
                output_tokens: Some(30),
                total_tokens: None,
            }
        );

        let openai = json!({
            "usage": {"prompt_tokens": 80, "completion_tokens": 20, "total_tokens": 100}
        });
        assert_eq!(
            provider("openai").extract_usage(&openai),
            TokenUsage {
                input_tokens: Some(80),
                output_tokens: Some(20),
                total_tokens: Some(100),
            }
        );
    }

    #[test]
    fn extracts_anthropic_text_blocks() {
        let body = json!({
            "content": [
                {"type": "thinking", "thinking": ""},
                {"type": "text", "text": "hello "},
                {"type": "text", "text": "world"}
            ],
            "stop_reason": "end_turn"
        });
        assert_eq!(
            provider("anthropic").extract_text(&body).unwrap(),
            "hello world"
        );
    }

    #[test]
    fn anthropic_refusal_becomes_an_error_not_an_empty_string() {
        let body = json!({
            "content": [],
            "stop_reason": "refusal",
            "stop_details": {"category": "cyber"}
        });
        let err = provider("anthropic")
            .extract_text(&body)
            .unwrap_err()
            .to_string();
        assert!(err.contains("declined"), "unexpected error: {err}");
        assert!(err.contains("cyber"));
    }

    #[test]
    fn extracts_openai_content() {
        let body = json!({"choices": [{"message": {"content": "hi there"}}]});
        assert_eq!(provider("openai").extract_text(&body).unwrap(), "hi there");
    }

    #[test]
    fn empty_response_is_an_error_rather_than_a_silent_blank() {
        let body = json!({"choices": []});
        assert!(provider("openai").extract_text(&body).is_err());
    }

    #[test]
    fn extracts_openai_content_array() {
        let body = json!({
            "choices": [{
                "message": {
                    "content": [
                        {"type": "text", "text": "hello "},
                        {"type": "text", "text": "world"}
                    ]
                }
            }]
        });
        assert_eq!(
            provider("openai").extract_text(&body).unwrap(),
            "hello world"
        );
    }

    #[test]
    fn openai_finish_reason_alone_triggers_the_decline_error() {
        // `finish_reason == "refusal"` must be enough on its own — `||` swapped for
        // `&&` would additionally require the `refusal` field, which is absent here,
        // and fall through to the "no message content" error instead.
        let body = json!({
            "choices": [{
                "message": { "role": "assistant", "content": null },
                "finish_reason": "refusal"
            }]
        });
        let err = provider("openai")
            .extract_text(&body)
            .unwrap_err()
            .to_string();
        assert!(err.contains("declined"), "unexpected error: {err}");
    }

    #[test]
    fn openai_refusal_field_alone_triggers_the_decline_error() {
        // The `refusal` field must be enough on its own too — `&&` would additionally
        // require `finish_reason == "refusal"`, which isn't the case here.
        let body = json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": null,
                    "refusal": "blocked by policy"
                },
                "finish_reason": "stop"
            }]
        });
        let err = provider("openai")
            .extract_text(&body)
            .unwrap_err()
            .to_string();
        assert!(err.contains("declined"), "unexpected error: {err}");
        assert!(err.contains("blocked by policy"));
    }

    #[test]
    fn openai_refusal_becomes_an_error_not_empty_content_error() {
        let body = json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": null,
                    "refusal": "safety policy violation"
                },
                "finish_reason": "refusal"
            }]
        });
        let err = provider("openai")
            .extract_text(&body)
            .unwrap_err()
            .to_string();
        assert!(err.contains("declined"), "unexpected error: {err}");
        assert!(err.contains("safety policy violation"));
    }

    #[test]
    fn cloud_providers_are_always_remote() {
        assert!(provider("anthropic").is_remote());
        assert_eq!(provider("anthropic").label(), "anthropic:claude-opus-5");
    }

    #[test]
    fn an_anthropic_reply_of_nothing_but_whitespace_is_an_error_not_a_blank_success() {
        // The Anthropic arm promises, four lines above its own `is_empty` check, to
        // "surface that rather than returning \"\"". It only checks `is_empty`, so a
        // content block of nothing but whitespace slips through as a successful reply.
        // The OpenAI arm right below it trims first and does reject this.
        let body = json!({
            "content": [{"type": "text", "text": "   \n  "}],
            "stop_reason": "end_turn"
        });
        let err = provider("anthropic")
            .extract_text(&body)
            .unwrap_err()
            .to_string();
        assert!(err.contains("no text content"), "unexpected error: {err}");
    }

    #[test]
    fn test_reproduction_openai_null_refusal_is_not_treated_as_decline() {
        let body = json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "hello world",
                    "refusal": null
                },
                "finish_reason": "stop"
            }]
        });
        assert_eq!(
            provider("openai").extract_text(&body).unwrap(),
            "hello world"
        );
    }
}

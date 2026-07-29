//! Local Ollama daemon transport. Never leaves the machine, so it stays available in
//! `--classified` mode.

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use serde_json::{Value, json};

use crate::providers::{Provider, RateLimit, Reply};

pub struct OllamaProvider {
    host: String,
    model: String,
    client: reqwest::Client,
}

impl OllamaProvider {
    pub fn new(host: impl Into<String>, model: impl Into<String>, client: reqwest::Client) -> Self {
        Self {
            host: host.into(),
            model: model.into(),
            client,
        }
    }

    fn base(&self) -> &str {
        self.host.trim_end_matches('/')
    }

    /// Lists locally installed models via `GET /api/tags`.
    pub async fn list_models(host: &str, client: &reqwest::Client) -> Result<Vec<String>> {
        let url = format!("{}/api/tags", host.trim_end_matches('/'));
        let response = client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("could not reach the Ollama daemon at {url}"))?;

        if !response.status().is_success() {
            return Err(anyhow!("Ollama returned {} for {url}", response.status()));
        }

        let body: Value = response
            .json()
            .await
            .context("Ollama sent a non-JSON tag list")?;
        Ok(body
            .get("models")
            .and_then(Value::as_array)
            .map(|models| {
                models
                    .iter()
                    .filter_map(|m| m.get("name").and_then(Value::as_str))
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default())
    }
}

#[async_trait]
impl Provider for OllamaProvider {
    async fn send(&self, system: Option<&str>, prompt: &str) -> Result<Reply> {
        let url = format!("{}/api/generate", self.base());
        let mut body = json!({
            "model": self.model,
            "prompt": prompt,
            "stream": false,
        });
        if let Some(system) = system {
            body["system"] = json!(system);
        }

        let response = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("could not reach the Ollama daemon at {url}"))?;

        let status = response.status();
        if !status.is_success() {
            let detail = response.text().await.unwrap_or_default();
            return Err(anyhow!("Ollama returned {status}: {}", detail.trim()));
        }

        let parsed: Value = response
            .json()
            .await
            .context("Ollama sent a non-JSON reply")?;
        let text = parsed
            .get("response")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();

        if text.is_empty() {
            return Err(anyhow!(
                "Ollama model {} returned an empty response; is it pulled?",
                self.model
            ));
        }

        Ok(Reply {
            text,
            // Local models have no quota to report.
            rate_limit: RateLimit::default(),
        })
    }

    fn model_name(&self) -> &str {
        &self.model
    }

    fn provider_name(&self) -> &str {
        "ollama"
    }

    fn is_remote(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ollama_is_local_and_survives_classified_mode() {
        let p = OllamaProvider::new("http://127.0.0.1:11434", "llama3", reqwest::Client::new());
        assert!(!p.is_remote());
        assert_eq!(p.label(), "ollama:llama3");
    }

    #[test]
    fn trailing_slashes_do_not_double_up_in_urls() {
        let p = OllamaProvider::new("http://127.0.0.1:11434/", "llama3", reqwest::Client::new());
        assert_eq!(p.base(), "http://127.0.0.1:11434");
    }
}

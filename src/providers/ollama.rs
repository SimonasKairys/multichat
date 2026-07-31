//! Local Ollama daemon transport. Never leaves the machine, so it stays available in
//! `--classified` mode.

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use serde_json::{Value, json};

use crate::providers::{Provider, RateLimit, Reply, truncate_error_detail};

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
            // Bounded like the cloud transport's error path: the body is
            // daemon-controlled text of arbitrary size, not something to embed whole.
            let detail = response.text().await.unwrap_or_default();
            return Err(anyhow!(
                "Ollama returned {status}: {}",
                truncate_error_detail(detail.trim())
            ));
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
        !is_loopback_host(&self.host)
    }
}

/// True only when `host` is a URL whose host component resolves to loopback:
/// `127.0.0.0/8`, `::1`, or the literal name `localhost`. `ollama_host` is
/// user-writable and unvalidated, so anything this cannot positively identify as
/// loopback — including a host that fails to parse — is treated as remote. Failing
/// open here is exactly the bug finding 1.2 of the 2026-07-29 audit describes
/// (doc removed as superseded; recoverable at commit `2e7984e`):
/// a garbage or non-loopback host must never pass `--classified` as "local".
pub(crate) fn is_loopback_host(host: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(host) else {
        return false;
    };
    match url.host_str() {
        Some(h) if h.eq_ignore_ascii_case("localhost") => true,
        Some(h) => h
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false),
        None => false,
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

    #[test]
    fn loopback_hosts_are_not_remote() {
        assert!(is_loopback_host("http://127.0.0.1:11434"));
        assert!(is_loopback_host("http://127.5.5.5:11434"));
        assert!(is_loopback_host("http://localhost:11434"));
        assert!(is_loopback_host("http://LOCALHOST:11434"));
        assert!(is_loopback_host("http://[::1]:11434"));
    }

    #[test]
    fn a_non_loopback_ollama_host_reports_remote_and_is_refused_under_classified() {
        let p = OllamaProvider::new(
            "http://192.168.1.192:11434",
            "llama3",
            reqwest::Client::new(),
        );
        assert!(p.is_remote(), "a LAN host must never be treated as local");
        assert!(!is_loopback_host("http://192.168.1.192:11434"));
        assert!(!is_loopback_host("http://example.com:11434"));
    }

    #[test]
    fn an_unparseable_host_fails_closed_as_remote() {
        // Garbage config must never read as "local" and slip past --classified.
        assert!(!is_loopback_host("not a url at all"));
        assert!(!is_loopback_host(""));
    }
}

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::json;
use crate::providers::Provider;

pub struct OllamaProvider {
    host: String,
    model: String,
    client: reqwest::Client,
}

impl OllamaProvider {
    pub fn new(host: &str, model: &str) -> Self {
        Self {
            host: host.to_string(),
            model: model.to_string(),
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl Provider for OllamaProvider {
    async fn send_message(&self, prompt: &str) -> Result<String> {
        let url = format!("{}/api/generate", self.host);
        
        let payload = json!({
            "model": self.model,
            "prompt": prompt,
            "stream": false
        });

        let response = self.client.post(&url)
            .json(&payload)
            .send()
            .await
            .context("Failed to send request to Ollama API")?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Ollama API error: {}", response.status()));
        }

        let resp_json: serde_json::Value = response.json().await?;
        let reply = resp_json["response"].as_str().unwrap_or("").to_string();

        Ok(reply)
    }

    fn model_name(&self) -> &str {
        &self.model
    }
}

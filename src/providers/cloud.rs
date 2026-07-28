use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::json;
use secrecy::{ExposeSecret, SecretString};
use crate::providers::Provider;

pub struct CloudProvider {
    provider_name: String,
    model: String,
    api_key: SecretString,
    client: reqwest::Client,
}

impl CloudProvider {
    pub fn new(provider: &str, model: &str, api_key: SecretString) -> Self {
        Self {
            provider_name: provider.to_string(),
            model: model.to_string(),
            api_key,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl Provider for CloudProvider {
    async fn send_message(&self, prompt: &str) -> Result<String> {
        // Example: generic OpenAI compatible endpoint for simplicity.
        // In production, this would route to different API endpoints based on `provider_name` (e.g. Anthropic/Gemini)
        let url = "https://api.openai.com/v1/chat/completions";

        let payload = json!({
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.7
        });

        let response = self.client.post(url)
            .bearer_auth(self.api_key.expose_secret())
            .json(&payload)
            .send()
            .await
            .context("Failed to send request to Cloud API")?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Cloud API error: {}", response.status()));
        }

        let resp_json: serde_json::Value = response.json().await?;
        let reply = resp_json["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("")
            .to_string();

        Ok(reply)
    }

    fn model_name(&self) -> &str {
        &self.model
    }
}

use anyhow::{Context, Result};
use async_trait::async_trait;
use std::process::Command;
use crate::providers::Provider;

pub struct LocalBinaryProvider {
    binary_path: String,
    model: String,
}

impl LocalBinaryProvider {
    pub fn new(binary_path: &str, model: &str) -> Self {
        Self {
            binary_path: binary_path.to_string(),
            model: model.to_string(),
        }
    }
}

#[async_trait]
impl Provider for LocalBinaryProvider {
    async fn send_message(&self, prompt: &str) -> Result<String> {
        // Execute the local binary as a subprocess.
        // e.g. `gh copilot suggest "prompt"`
        let output = Command::new(&self.binary_path)
            .arg(&self.model)
            .arg(prompt)
            .output()
            .context("Failed to execute local binary")?;

        if !output.status.success() {
            let err_str = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("Local binary error: {}", err_str));
        }

        let reply = String::from_utf8_lossy(&output.stdout).to_string();
        Ok(reply)
    }

    fn model_name(&self) -> &str {
        &self.model
    }
}

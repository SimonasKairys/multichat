use anyhow::Result;
use async_trait::async_trait;

pub mod cloud;
pub mod local_binary;
pub mod ollama;

#[async_trait]
pub trait Provider {
    /// Send a message to the AI model and return the text response
    async fn send_message(&self, prompt: &str) -> Result<String>;
    
    /// Get the name/ID of the active model
    fn model_name(&self) -> &str;
}

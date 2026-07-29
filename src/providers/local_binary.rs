//! Subprocess transport for CLI tools that act as models (`gh copilot`, `llm`, …).
//!
//! Uses `tokio::process` rather than `std::process`. The previous implementation called
//! the blocking `std::process::Command::output()` from inside an `async fn`, which
//! parks a Tokio worker thread until the child exits and freezes the TUI for the whole
//! call.

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use std::path::Path;
use tokio::process::Command;

use crate::providers::{Provider, RateLimit, Reply};

/// Ceiling on captured output, so a runaway child cannot exhaust memory.
const MAX_OUTPUT_BYTES: usize = 1 << 20;

#[derive(Debug)]
pub struct LocalBinaryProvider {
    name: String,
    binary_path: String,
    args: Vec<String>,
    model: String,
}

impl LocalBinaryProvider {
    pub fn new(
        name: impl Into<String>,
        binary_path: impl Into<String>,
        args: Vec<String>,
        model: impl Into<String>,
    ) -> Result<Self> {
        let binary_path = binary_path.into();
        let name = name.into();

        // The path comes from the user's own config file, not from model output, but
        // validating it turns a confusing runtime failure into a clear startup error.
        if binary_path.trim().is_empty() {
            return Err(anyhow!("local binary `{name}` has an empty path"));
        }
        let looks_like_path = Path::new(&binary_path).components().count() > 1;
        if looks_like_path && !Path::new(&binary_path).exists() {
            return Err(anyhow!(
                "local binary `{name}` points at {binary_path}, which does not exist"
            ));
        }

        Ok(Self {
            name,
            binary_path,
            args,
            model: model.into(),
        })
    }
}

#[async_trait]
impl Provider for LocalBinaryProvider {
    async fn send(&self, system: Option<&str>, prompt: &str) -> Result<Reply> {
        // Arguments are passed as an argv vector, never through a shell, so prompt
        // content cannot inject additional commands.
        let mut command = Command::new(&self.binary_path);
        command.args(&self.args);
        if let Some(system) = system {
            command.arg("--system").arg(system);
        }
        command.arg(prompt);
        command.kill_on_drop(true);

        let output = command
            .output()
            .await
            .with_context(|| format!("failed to run {}", self.binary_path))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!(
                "{} exited with {}: {}",
                self.binary_path,
                output.status,
                stderr.trim()
            ));
        }

        let mut stdout = output.stdout;
        stdout.truncate(MAX_OUTPUT_BYTES);
        let text = String::from_utf8_lossy(&stdout).trim().to_string();

        if text.is_empty() {
            return Err(anyhow!("{} produced no output", self.binary_path));
        }

        Ok(Reply {
            text,
            rate_limit: RateLimit::default(),
        })
    }

    fn model_name(&self) -> &str {
        &self.model
    }

    fn provider_name(&self) -> &str {
        &self.name
    }

    /// A CLI tool may well call a cloud API internally, and we cannot see whether it
    /// does. Treating it as remote keeps `--classified` conservative: an air-gapped
    /// session must not shell out to something that might phone home.
    fn is_remote(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_a_nonexistent_path() {
        let err = LocalBinaryProvider::new("fake", "./definitely/not/here/binary", vec![], "m")
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not exist"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_an_empty_path() {
        assert!(LocalBinaryProvider::new("fake", "  ", vec![], "m").is_err());
    }

    #[test]
    fn bare_command_names_are_allowed_and_resolved_by_path() {
        // `gh` may not be installed in CI, but a bare name is a legitimate config.
        assert!(LocalBinaryProvider::new("gh", "gh", vec!["copilot".into()], "m").is_ok());
    }

    #[test]
    fn cli_tools_count_as_remote_for_classified_mode() {
        let p = LocalBinaryProvider::new("gh", "gh", vec![], "copilot").unwrap();
        assert!(p.is_remote());
    }
}

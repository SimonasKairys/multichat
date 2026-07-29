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
    /// The flag this CLI accepts for a system prompt (e.g. `--system-prompt`), or
    /// `None` when it has no such flag and the system text must be folded into the
    /// prompt instead.
    system_arg: Option<String>,
}

impl LocalBinaryProvider {
    pub fn new(
        name: impl Into<String>,
        binary_path: impl Into<String>,
        args: Vec<String>,
        model: impl Into<String>,
        system_arg: Option<String>,
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
            system_arg,
        })
    }
}

/// Decides how the system prompt reaches the child process: as a dedicated
/// `--flag <text>` pair when the CLI supports one, or folded into the prompt text
/// (separated by a blank line) when it does not — the only channel a CLI with no
/// system flag offers. Kept pure so both branches are unit-testable without spawning
/// a process.
fn compose_call(
    system_arg: Option<&str>,
    system: Option<&str>,
    prompt: &str,
) -> (Option<(String, String)>, String) {
    match (system_arg, system) {
        (_, None) => (None, prompt.to_string()),
        (Some(flag), Some(system)) => (
            Some((flag.to_string(), system.to_string())),
            prompt.to_string(),
        ),
        (None, Some(system)) => (None, format!("{system}\n\n{prompt}")),
    }
}

#[async_trait]
impl Provider for LocalBinaryProvider {
    async fn send(&self, system: Option<&str>, prompt: &str) -> Result<Reply> {
        let (system_flag, effective_prompt) =
            compose_call(self.system_arg.as_deref(), system, prompt);

        // Arguments are passed as an argv vector, never through a shell, so prompt
        // content (and the folded system text above) cannot inject additional
        // commands.
        let mut command = Command::new(&self.binary_path);
        command.args(&self.args);
        if let Some((flag, value)) = &system_flag {
            command.arg(flag).arg(value);
        }
        command.arg(effective_prompt);
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
        let err =
            LocalBinaryProvider::new("fake", "./definitely/not/here/binary", vec![], "m", None)
                .unwrap_err()
                .to_string();
        assert!(err.contains("does not exist"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_an_empty_path() {
        assert!(LocalBinaryProvider::new("fake", "  ", vec![], "m", None).is_err());
    }

    #[test]
    fn bare_command_names_are_allowed_and_resolved_by_path() {
        // `gh` may not be installed in CI, but a bare name is a legitimate config.
        assert!(LocalBinaryProvider::new("gh", "gh", vec!["copilot".into()], "m", None).is_ok());
    }

    #[test]
    fn cli_tools_count_as_remote_for_classified_mode() {
        let p = LocalBinaryProvider::new("gh", "gh", vec![], "copilot", None).unwrap();
        assert!(p.is_remote());
    }

    #[test]
    fn a_cli_with_a_system_flag_gets_a_dedicated_argument_pair() {
        // This is the `claude` shape: `--system-prompt <text>` plus the prompt.
        let (flag, prompt) = compose_call(Some("--system-prompt"), Some("be terse"), "hi");
        assert_eq!(
            flag,
            Some(("--system-prompt".to_string(), "be terse".to_string()))
        );
        assert_eq!(prompt, "hi");
    }

    #[test]
    fn a_cli_with_no_system_flag_folds_the_system_text_into_the_prompt() {
        // This is the `gemini` shape: no system channel at all, so the swarm ledger
        // and delegation protocol end up in the user message.
        let (flag, prompt) = compose_call(None, Some("be terse"), "hi");
        assert!(flag.is_none());
        assert_eq!(prompt, "be terse\n\nhi");
    }

    #[test]
    fn no_system_text_leaves_the_prompt_untouched_regardless_of_flag_support() {
        let (flag, prompt) = compose_call(Some("--system-prompt"), None, "hi");
        assert!(flag.is_none());
        assert_eq!(prompt, "hi");
    }
}

//! Subprocess transport for CLI tools that act as models (`gh copilot`, `llm`, …).
//!
//! Uses `tokio::process` rather than `std::process`. The previous implementation called
//! the blocking `std::process::Command::output()` from inside an `async fn`, which
//! parks a Tokio worker thread until the child exits and freezes the TUI for the whole
//! call.

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::process::Command;

use crate::providers::{Provider, RateLimit, Reply};

/// Ceiling on captured output, so a runaway child cannot exhaust memory.
const MAX_OUTPUT_BYTES: usize = 1 << 20;

/// Ceiling on how long a subprocess call may run. Matches the 300s HTTP timeout in
/// `providers::http_client` (`src/providers/mod.rs`) so both transports fail on the
/// same clock — a CLI tool should not be allowed to hang the session indefinitely
/// just because it has no network timeout of its own.
const CLI_TIMEOUT: Duration = Duration::from_secs(300);

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
    /// Where the child process is spawned. See `send_with_timeout`'s use of
    /// `Command::current_dir` for what this does and, importantly, does not do.
    project_root: PathBuf,
}

impl LocalBinaryProvider {
    pub fn new(
        name: impl Into<String>,
        binary_path: impl Into<String>,
        args: Vec<String>,
        model: impl Into<String>,
        system_arg: Option<String>,
        project_root: PathBuf,
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
            project_root,
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

/// Condenses a failed child's stderr into something that fits in a chat transcript.
///
/// A Node-based CLI answers a routine auth failure with a multi-line stack trace; the
/// whole thing used to be pasted into the transcript verbatim, burying the one line
/// that says what went wrong. Keeps the leading message lines, drops stack frames
/// (`at ...` / `file:///...`), and caps the result.
fn summarize_stderr(stderr: &str) -> String {
    const MAX_LINES: usize = 3;
    const MAX_CHARS: usize = 300;

    let kept: Vec<&str> = stderr
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with("at ") && !line.starts_with("file:///"))
        .take(MAX_LINES)
        .collect();

    let joined = if kept.is_empty() {
        stderr.trim().to_string()
    } else {
        kept.join(" ")
    };

    match joined.char_indices().nth(MAX_CHARS) {
        Some((cut, _)) => format!("{}…", &joined[..cut]),
        None => joined,
    }
}

impl LocalBinaryProvider {
    /// Does the actual work of `Provider::send`, parameterised on the timeout so a
    /// test can use a short one instead of waiting out `CLI_TIMEOUT` for real —
    /// mirrors why `compose_call` and `summarize_stderr` above are free functions
    /// rather than inlined into `send`.
    async fn send_with_timeout(
        &self,
        system: Option<&str>,
        prompt: &str,
        timeout: Duration,
    ) -> Result<Reply> {
        let (system_flag, effective_prompt) =
            compose_call(self.system_arg.as_deref(), system, prompt);

        // Arguments are passed as an argv vector, never through a shell, so prompt
        // content (and the folded system text above) cannot inject additional
        // commands.
        let mut command = Command::new(&self.binary_path);
        // Sets where the agent CLI *starts* — the project folder, rather than
        // whatever directory happened to be `simon`'s own working directory (its own
        // install location, the user's shell prompt at launch, etc). This is what
        // stops a CLI agent from casually reading whatever was lying around in the
        // launch directory unprompted, which is exactly what was observed with the
        // `claude` CLI reading `Cargo.toml` out of simon's own repo before this fix.
        // It is NOT a sandbox: a CLI agent with shell or filesystem tool access can
        // still `cd` anywhere it can reach and read or write outside `project_root`
        // — this only sets the starting point, nothing more.
        command.current_dir(&self.project_root);
        command.args(&self.args);
        if let Some((flag, value)) = &system_flag {
            command.arg(flag).arg(value);
        }
        command.arg(effective_prompt);
        command.kill_on_drop(true);

        // `kill_on_drop(true)` only reaps the child when *something* drops the future
        // that owns it. Without a timeout, nothing ever did — `command.output().await`
        // would sit forever on a wedged CLI, permanently freezing the session. Wrapping
        // it in `tokio::time::timeout` gives the future a reason to drop: on elapse,
        // `timeout` drops the inner `output()` future, which drops the child handle,
        // which is what actually kills the process.
        let output = match tokio::time::timeout(timeout, command.output()).await {
            Ok(result) => result.with_context(|| format!("failed to run {}", self.binary_path))?,
            Err(_) => {
                return Err(anyhow!(
                    "{} timed out after {}s",
                    self.binary_path,
                    timeout.as_secs()
                ));
            }
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!(
                "{} exited with {}: {}",
                self.binary_path,
                output.status,
                summarize_stderr(&stderr)
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
}

#[async_trait]
impl Provider for LocalBinaryProvider {
    async fn send(&self, system: Option<&str>, prompt: &str) -> Result<Reply> {
        self.send_with_timeout(system, prompt, CLI_TIMEOUT).await
    }

    fn model_name(&self) -> &str {
        &self.model
    }

    fn provider_name(&self) -> &str {
        &self.name
    }

    /// The default `Provider::label` renders `provider:model`, but for a CLI harness
    /// `provider_name()` is the binary name and `model_name()` defaults to that same
    /// binary name (see `LocalBinaryProvider::new` callers), so the default would
    /// render `claude:claude`, `agy:agy`, `codex:codex` — a harness name is not a
    /// model name. When the user configured a real model (`agy` with `gemini-3-pro`),
    /// keep the `binary:model` form so the model is still visible.
    ///
    /// IMPORTANT: `orchestrator::candidate_label` computes this same string
    /// independently, for the picker and for `resolve_commander`, before any provider
    /// exists to call this method on. The two MUST stay in sync — see the comment
    /// there — or a saved commander for a CLI connection silently stops resolving.
    fn label(&self) -> String {
        if self.name == self.model {
            self.name.clone()
        } else {
            format!("{}:{}", self.name, self.model)
        }
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
        let err = LocalBinaryProvider::new(
            "fake",
            "./definitely/not/here/binary",
            vec![],
            "m",
            None,
            PathBuf::from("."),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("does not exist"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_an_empty_path() {
        assert!(
            LocalBinaryProvider::new("fake", "  ", vec![], "m", None, PathBuf::from(".")).is_err()
        );
    }

    #[test]
    fn bare_command_names_are_allowed_and_resolved_by_path() {
        // `gh` may not be installed in CI, but a bare name is a legitimate config.
        assert!(
            LocalBinaryProvider::new(
                "gh",
                "gh",
                vec!["copilot".into()],
                "m",
                None,
                PathBuf::from("."),
            )
            .is_ok()
        );
    }

    #[test]
    fn cli_tools_count_as_remote_for_classified_mode() {
        let p = LocalBinaryProvider::new("gh", "gh", vec![], "copilot", None, PathBuf::from("."))
            .unwrap();
        assert!(p.is_remote());
    }

    #[test]
    fn a_harness_whose_model_defaults_to_the_binary_name_labels_as_just_the_binary() {
        // `claude`, `agy`, `codex` with no configured model all end up with
        // model == name (see `construct_provider`'s CLI branch), which used to render
        // as the meaningless `claude:claude`. A harness name is not a model name.
        let p = LocalBinaryProvider::new(
            "claude",
            "claude",
            vec![],
            "claude",
            None,
            PathBuf::from("."),
        )
        .unwrap();
        assert_eq!(p.label(), "claude");
    }

    #[test]
    fn a_configured_model_keeps_the_binary_colon_model_form() {
        // `agy` is a multi-vendor gateway: the binary name alone doesn't say which
        // model is behind it, so once the user configures one, keep showing both.
        let p = LocalBinaryProvider::new(
            "agy",
            "agy",
            vec![],
            "gemini-3-pro",
            None,
            PathBuf::from("."),
        )
        .unwrap();
        assert_eq!(p.label(), "agy:gemini-3-pro");
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

    #[test]
    fn stderr_summary_keeps_the_message_and_drops_the_stack_trace() {
        // Verbatim shape of a real `gemini` auth failure, which used to be pasted
        // into the transcript in full.
        let stderr = "Error authenticating: IneligibleTierError: This client is no \
                      longer supported.\n\
                      \x20   at throwIneligibleOrProjectIdError \
                      (file:///home/u/.nvm/node_modules/@google/gemini-cli/chunk.js:273372:11)\n\
                      \x20   at _doSetupUser (file:///home/u/.nvm/chunk.js:273361:5)\n\
                      \x20   at process.processTicksAndRejections (node:internal/process:95:5)";

        let summary = summarize_stderr(stderr);
        assert!(summary.starts_with("Error authenticating: IneligibleTierError"));
        assert!(!summary.contains("at throwIneligibleOrProjectIdError"));
        assert!(!summary.contains("file:///"));
        assert!(summary.chars().count() <= 301);
    }

    #[test]
    fn stderr_summary_falls_back_when_everything_looks_like_a_frame() {
        // All lines filtered out must not yield an empty, useless error.
        let summary = summarize_stderr("at one\nat two");
        assert!(!summary.is_empty());
    }

    #[test]
    fn stderr_summary_caps_a_single_enormous_line() {
        let summary = summarize_stderr(&"x".repeat(5000));
        assert!(summary.chars().count() <= 301);
        assert!(summary.ends_with('…'));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_wedged_child_times_out_instead_of_hanging_forever() {
        // Regression guard for Fix 3: `command.output().await` had no timeout, so a
        // CLI that never exits (an interactive auth prompt, a genuinely wedged
        // process) froze the session permanently. `/bin/sleep 5` stands in for that;
        // a 50ms timeout is used instead of the real `CLI_TIMEOUT` so the test itself
        // doesn't hang.
        //
        // Unix-only: `/bin/sleep` does not exist on Windows, and
        // `LocalBinaryProvider::new` rejects a path that does not exist on disk
        // (see `rejects_a_nonexistent_path`), so this would fail construction, not
        // just the assertions, on the `windows-latest` CI runner.
        let p = LocalBinaryProvider::new(
            "slow",
            "/bin/sleep",
            vec![],
            "slow",
            None,
            PathBuf::from("."),
        )
        .unwrap();
        let err = p
            .send_with_timeout(None, "5", Duration::from_millis(50))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("/bin/sleep"), "unexpected error: {err}");
        assert!(err.contains("timed out"), "unexpected error: {err}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_child_that_finishes_within_the_timeout_still_succeeds() {
        // Unix-only: depends on `/bin/echo`, a Unix path that `LocalBinaryProvider::new`
        // would reject as nonexistent on Windows.
        let p = LocalBinaryProvider::new(
            "echoer",
            "/bin/echo",
            vec![],
            "echoer",
            None,
            PathBuf::from("."),
        )
        .unwrap();
        let reply = p
            .send_with_timeout(None, "hello", Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(reply.text, "hello");
    }

    // Unix-only: depends on `pwd` and `/bin/echo`-style bare-argv spawning; the
    // reasoning is the same as the sibling tests above.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_child_is_spawned_inside_the_configured_project_root() {
        // Regression guard for the fix this test is named after: before it, the child
        // inherited whatever directory `simon` itself happened to be running in,
        // which is how a `claude` CLI provider was observed reading `Cargo.toml` out
        // of simon's own repo unprompted. `pwd` printing the directory it was
        // actually spawned in is a direct behavioral check, not just a check that a
        // field got set.
        let project = tempfile::tempdir().unwrap();
        // Canonicalize so the comparison isn't defeated by `/tmp` vs `/private/tmp`
        // (macOS) or similar symlink-resolution differences between what `tempdir()`
        // returns and what the child's own `pwd` reports back.
        let expected = std::fs::canonicalize(project.path()).unwrap();
        // `/bin/sh -c pwd` rather than `/bin/pwd` directly: `send_with_timeout` always
        // appends the prompt as one more argv entry, and `pwd` itself would reject
        // that as an unexpected operand. Under `sh -c`, an argument after the command
        // string becomes `$0` inside the script instead, which `pwd` never sees.
        let p = LocalBinaryProvider::new(
            "sh",
            "/bin/sh",
            vec!["-c".into(), "pwd".into()],
            "sh",
            None,
            project.path().to_path_buf(),
        )
        .unwrap();
        let reply = p
            .send_with_timeout(None, "ignored", Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(reply.text.trim(), expected.to_string_lossy());
    }
}

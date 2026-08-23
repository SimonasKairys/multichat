//! Subprocess transport for CLI tools that act as models (`gh copilot`, `llm`, …).
//!
//! Uses `tokio::process` rather than `std::process`. The previous implementation called
//! the blocking `std::process::Command::output()` from inside an `async fn`, which
//! parks a Tokio worker thread until the child exits and freezes the TUI for the whole
//! call.

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use tokio::process::Command;

use crate::providers::{ProgressSink, Provider, RateLimit, Reply};

/// Ceiling on captured output, so a runaway child cannot exhaust memory.
const MAX_OUTPUT_BYTES: usize = 1 << 20;

/// Ceiling on how long a *non-streaming* CLI call may run. There is nothing to reset
/// this clock on — a plain `claude -p` (no `--output-format stream-json`) buffers all
/// output until exit, so simon sees nothing until the child is already done — so this
/// stays a flat wall-clock timeout, unlike the streaming path below. Raised from the
/// original 300s (which matched `providers::http_client`'s HTTP timeout) to 900s:
/// that 300s figure was calibrated for a single network round trip, not for a CLI
/// that may be doing real agentic work under the hood with no way to show progress.
const CLI_TIMEOUT_NONSTREAMING: Duration = Duration::from_secs(900);

/// For a *streaming* CLI, idle timeout: the clock resets on every line received on
/// stdout. An agent that is genuinely working — long tool calls, a slow model behind
/// it — never trips this as long as it keeps emitting NDJSON progress; a wedged one
/// (hung on an interactive prompt, deadlocked) still gets killed within this long of
/// going silent.
const CLI_IDLE_TIMEOUT: Duration = Duration::from_secs(180);

/// Absolute backstop for a streaming CLI, independent of the idle timer above: caps
/// total wall-clock time even if the child never goes quiet for `CLI_IDLE_TIMEOUT` at
/// a stretch, so a CLI that streams *something* every couple of minutes forever still
/// cannot hold the session hostage indefinitely.
const CLI_TOTAL_TIMEOUT: Duration = Duration::from_secs(3600);

/// Which NDJSON dialect a streaming CLI speaks. `None` (i.e. `Option<StreamDialect>`
/// on `LocalBinaryProvider`, not a variant here) means the original plain-text path:
/// buffer the child's stdout to completion and treat it as the whole reply, unchanged
/// from before this feature existed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamDialect {
    /// `claude -p --output-format stream-json --verbose`.
    ClaudeJson,
    /// `agy --output-format stream-json -p` (flags must precede `-p` for this CLI).
    AgyJson,
}

impl StreamDialect {
    /// Parses a `stream_format` config value (or `known_cli_default`'s hardcoded
    /// choice). Rejects anything unrecognised with a clear error instead of silently
    /// falling back to the non-streaming path — a typo in a hand-written config
    /// should never quietly downgrade a CLI's behaviour.
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "claude" => Ok(StreamDialect::ClaudeJson),
            "agy" => Ok(StreamDialect::AgyJson),
            other => Err(anyhow!(
                "unknown stream_format `{other}`; expected \"claude\" or \"agy\""
            )),
        }
    }
}

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
    /// `Some` when this CLI's stdout is NDJSON progress that can be parsed and
    /// streamed to a `ProgressSink` as it arrives; `None` keeps the original
    /// buffered-until-exit behaviour.
    dialect: Option<StreamDialect>,
}

impl LocalBinaryProvider {
    pub fn new(
        name: impl Into<String>,
        binary_path: impl Into<String>,
        args: Vec<String>,
        model: impl Into<String>,
        system_arg: Option<String>,
        project_root: PathBuf,
        dialect: Option<StreamDialect>,
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
            dialect,
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

    /// Runs a streaming CLI: spawns with piped stdout/stderr, parses each stdout line
    /// as one NDJSON event via `dialect`, forwards progress details to `progress`, and
    /// accumulates the reply text. Mirrors `send_with_timeout`'s shape (compose the
    /// call, spawn with `kill_on_drop`, honour `MAX_OUTPUT_BYTES`, summarize stderr on
    /// failure) but with the timeout model described on `CLI_IDLE_TIMEOUT` and
    /// `CLI_TOTAL_TIMEOUT` instead of a single wall clock.
    async fn send_streaming(
        &self,
        dialect: StreamDialect,
        system: Option<&str>,
        prompt: &str,
        progress: &ProgressSink,
    ) -> Result<Reply> {
        let (system_flag, effective_prompt) =
            compose_call(self.system_arg.as_deref(), system, prompt);

        let mut command = Command::new(&self.binary_path);
        // See `send_with_timeout`'s identical line for why `current_dir` is set and,
        // importantly, what it does not guarantee.
        command.current_dir(&self.project_root);
        command.args(&self.args);
        if let Some((flag, value)) = &system_flag {
            command.arg(flag).arg(value);
        }
        command.arg(effective_prompt);
        command.kill_on_drop(true);
        // The prompt is passed as an argv entry (above), not over stdin, so the child
        // needs none — and must not inherit simon's own stdin, which in the TUI is the
        // terminal in raw mode. `send_with_timeout`'s non-streaming path leaves stdin
        // inherited (unchanged, pre-existing behaviour); this only affects the new
        // streaming path.
        command.stdin(Stdio::null());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        let mut child = command
            .spawn()
            .with_context(|| format!("failed to run {}", self.binary_path))?;
        // `.expect` is safe: both were just set to `Stdio::piped()` above, so tokio
        // always populates these handles on a successful spawn.
        let stdout = child.stdout.take().expect("stdout was piped");
        let stderr = child.stderr.take().expect("stderr was piped");

        // Drained concurrently with stdout so a chatty stderr can never fill its pipe
        // buffer and deadlock the child against a `send_streaming` that is only
        // reading stdout. Best-effort: a read error here just yields an empty
        // summary, which is no worse than today's non-streaming stderr handling on a
        // process that dies mid-write.
        let stderr_task: tokio::task::JoinHandle<String> = tokio::spawn(async move {
            let mut buf = String::new();
            let _ = BufReader::new(stderr).read_to_string(&mut buf).await;
            buf
        });

        let mut lines = BufReader::new(stdout).lines();
        let mut result_text: Option<String> = None;
        let mut stream_error: Option<String> = None;
        let mut assistant_text = String::new();
        let mut accumulated_bytes = 0usize;

        // Not reset on each loop iteration — deliberately: `CLI_TOTAL_TIMEOUT` is a
        // single absolute backstop across the whole call, unlike the idle timeout
        // below, which is a fresh `tokio::time::timeout` every iteration so it
        // resets on every line received.
        let total_deadline = tokio::time::sleep(CLI_TOTAL_TIMEOUT);
        tokio::pin!(total_deadline);

        loop {
            tokio::select! {
                biased;
                _ = &mut total_deadline => {
                    // Dropping `child` here is what actually kills it — see the
                    // `kill_on_drop` comment on `send_with_timeout`; the same
                    // property holds here, just triggered by `select!` dropping the
                    // losing branches instead of `tokio::time::timeout` doing it.
                    drop(child);
                    return Err(anyhow!(
                        "{} timed out after {}s (total time limit for a streaming call)",
                        self.binary_path,
                        CLI_TOTAL_TIMEOUT.as_secs()
                    ));
                }
                next = tokio::time::timeout(CLI_IDLE_TIMEOUT, lines.next_line()) => {
                    match next {
                        Err(_) => {
                            drop(child);
                            return Err(anyhow!(
                                "{} timed out after {}s of no output",
                                self.binary_path,
                                CLI_IDLE_TIMEOUT.as_secs()
                            ));
                        }
                        Ok(Err(e)) => {
                            return Err(e).with_context(|| {
                                format!("failed reading {} output", self.binary_path)
                            });
                        }
                        Ok(Ok(None)) => break, // stdout closed: child is finishing up
                        Ok(Ok(Some(line))) => {
                            accumulated_bytes += line.len();
                            match parse_stream_line(dialect, &line) {
                                StreamLineEffect::Progress(detail) => progress.send(detail),
                                StreamLineEffect::AssistantText(text) => {
                                    if accumulated_bytes <= MAX_OUTPUT_BYTES {
                                        assistant_text.push_str(&text);
                                    }
                                }
                                StreamLineEffect::Result(text) => result_text = Some(text),
                                // Recorded rather than returned immediately: the
                                // child is still running, and letting it exit on its
                                // own keeps the `wait()` below meaningful.
                                StreamLineEffect::Failure(reason) => {
                                    stream_error = Some(reason);
                                }
                                // A line that isn't valid JSON, or is JSON of a shape
                                // this dialect doesn't recognise, is skipped silently
                                // — this is a third-party CLI's own output format and
                                // may change under us; it must never fail the call.
                                StreamLineEffect::Ignore => {}
                            }
                        }
                    }
                }
            }
        }

        let status = tokio::select! {
            biased;
            _ = &mut total_deadline => {
                drop(child);
                return Err(anyhow!(
                    "{} timed out after {}s (total time limit for a streaming call)",
                    self.binary_path,
                    CLI_TOTAL_TIMEOUT.as_secs()
                ));
            }
            status = child.wait() => {
                status.with_context(|| format!("failed to run {}", self.binary_path))?
            }
        };

        let stderr_text = stderr_task.await.unwrap_or_default();

        // A reason reported in the stream beats both the exit status and stderr: an
        // agentic CLI that fails a tool permission check exits non-zero with empty
        // stderr, which on its own produces "exited with exit status: 1: " and tells
        // the user nothing about what actually went wrong.
        if let Some(reason) = stream_error {
            return Err(anyhow!("{} failed: {}", self.binary_path, reason));
        }

        if !status.success() {
            return Err(anyhow!(
                "{} exited with {}: {}",
                self.binary_path,
                status,
                summarize_stderr(&stderr_text)
            ));
        }

        // Prefer the dialect's terminal result event; fall back to whatever
        // assistant-text events arrived if the stream ended without one (the child
        // exited cleanly but the CLI's own output never sent a `result`/`result`
        // event — treat partial progress as better than nothing).
        let mut text = result_text.unwrap_or(assistant_text);
        if text.len() > MAX_OUTPUT_BYTES {
            let mut bytes = text.into_bytes();
            bytes.truncate(MAX_OUTPUT_BYTES);
            text = String::from_utf8_lossy(&bytes).into_owned();
        }
        let text = text.trim().to_string();

        if text.is_empty() {
            return Err(anyhow!("{} produced no output", self.binary_path));
        }

        Ok(Reply {
            text,
            rate_limit: RateLimit::default(),
        })
    }
}

/// What one parsed NDJSON progress line means to `send_streaming`. Kept separate from
/// the parsing itself (`parse_stream_line` and its per-dialect helpers below) so those
/// stay pure functions of a `&str` line, testable without spawning a process — the
/// same reasoning `compose_call` and `summarize_stderr` are free functions for.
#[derive(Debug, Clone, PartialEq, Eq)]
enum StreamLineEffect {
    /// A tool call or step in progress; forwarded to the `ProgressSink` verbatim.
    Progress(String),
    /// A chunk of assistant-authored reply text, accumulated as a fallback for when
    /// the stream ends without a terminal result event.
    AssistantText(String),
    /// The dialect's terminal event: this is the final reply text, replacing whatever
    /// `AssistantText` had accumulated so far.
    Result(String),
    /// The dialect's terminal event reporting that the run FAILED, carrying whatever
    /// reason it gave. Distinct from `Result` because a failed run often still carries
    /// partial reply text: agy answers a denied tool permission with `status: ERROR`,
    /// an `error` string, and a `response` that reads like a normal (but useless)
    /// answer — "I have dispatched a subagent and will report shortly". Treating that
    /// `response` as the reply would report a confident non-answer as success, so the
    /// reason wins over the text.
    Failure(String),
    /// Not JSON, or JSON this dialect doesn't recognise the shape of. Never an error.
    Ignore,
}

/// Dispatches one stdout line to the parser for `dialect`.
fn parse_stream_line(dialect: StreamDialect, line: &str) -> StreamLineEffect {
    match dialect {
        StreamDialect::ClaudeJson => parse_claude_line(line),
        StreamDialect::AgyJson => parse_agy_line(line),
    }
}

/// Parses one line of `claude -p --output-format stream-json --verbose`'s NDJSON.
/// See the module-level ground truth this was built against: `assistant` events carry
/// either a `tool_use` (progress) or `text` (fallback reply) content item; `result` is
/// the terminal event; `system`/`rate_limit_event`/`user` (tool results) and anything
/// unrecognised are ignored.
fn parse_claude_line(line: &str) -> StreamLineEffect {
    let Ok(value) = serde_json::from_str::<Value>(line) else {
        return StreamLineEffect::Ignore;
    };
    match value.get("type").and_then(Value::as_str) {
        Some("assistant") => claude_assistant_effect(&value),
        Some("result") => {
            let text = value
                .get("result")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            // On a failed run this dialect puts the reason in the same `result`
            // field the reply text normally occupies, so the flag is the only thing
            // distinguishing "here is your answer" from "here is why there isn't one".
            if value.get("is_error").and_then(Value::as_bool) == Some(true) {
                return StreamLineEffect::Failure(text);
            }
            StreamLineEffect::Result(text)
        }
        _ => StreamLineEffect::Ignore,
    }
}

/// A tool call takes priority over any text in the same content array: an `assistant`
/// event with a `tool_use` item is progress, not a partial reply.
fn claude_assistant_effect(value: &Value) -> StreamLineEffect {
    let Some(content) = value.pointer("/message/content").and_then(Value::as_array) else {
        return StreamLineEffect::Ignore;
    };
    for item in content {
        if item.get("type").and_then(Value::as_str) == Some("tool_use") {
            let tool_name = item.get("name").and_then(Value::as_str).unwrap_or("tool");
            // `input.description` is often present and more legible than the raw
            // command; fall back to `input.command`, then to just the tool name.
            let detail = item
                .pointer("/input/description")
                .and_then(Value::as_str)
                .or_else(|| item.pointer("/input/command").and_then(Value::as_str));
            return StreamLineEffect::Progress(match detail {
                Some(d) => format!("{tool_name}: {d}"),
                None => tool_name.to_string(),
            });
        }
    }
    for item in content {
        if item.get("type").and_then(Value::as_str) == Some("text")
            && let Some(text) = item.get("text").and_then(Value::as_str)
        {
            return StreamLineEffect::AssistantText(text.to_string());
        }
    }
    StreamLineEffect::Ignore
}

/// Parses one line of `agy --output-format stream-json -p`'s NDJSON. `step_update` is
/// progress; `result` is the terminal event carrying `result.response`; any other
/// `event` value is ignored.
fn parse_agy_line(line: &str) -> StreamLineEffect {
    let Ok(value) = serde_json::from_str::<Value>(line) else {
        return StreamLineEffect::Ignore;
    };
    match value.get("event").and_then(Value::as_str) {
        Some("step_update") => agy_step_update_effect(&value),
        Some("result") => {
            let status = value
                .pointer("/result/status")
                .and_then(Value::as_str)
                .unwrap_or("SUCCESS");
            if status != "SUCCESS" {
                // The `error` field is the actionable half — a denied tool
                // permission, a quota refusal — so prefer it, falling back to the
                // bare status when the CLI gave no detail.
                let reason = value
                    .pointer("/result/error")
                    .and_then(Value::as_str)
                    .unwrap_or(status);
                return StreamLineEffect::Failure(reason.to_string());
            }
            StreamLineEffect::Result(
                value
                    .pointer("/result/response")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
            )
        }
        _ => StreamLineEffect::Ignore,
    }
}

fn agy_step_update_effect(value: &Value) -> StreamLineEffect {
    let Some(step) = value.get("step_update") else {
        return StreamLineEffect::Ignore;
    };
    let step_type = step
        .get("step_type")
        .and_then(Value::as_str)
        .unwrap_or("step");
    let detail = match step.get("tool_name").and_then(Value::as_str) {
        Some(tool_name) => format!("{step_type}: {tool_name}"),
        None => step_type.to_string(),
    };
    StreamLineEffect::Progress(detail)
}

#[async_trait]
impl Provider for LocalBinaryProvider {
    async fn send(&self, system: Option<&str>, prompt: &str) -> Result<Reply> {
        self.send_with_progress(system, prompt, &ProgressSink::disconnected())
            .await
    }

    async fn send_with_progress(
        &self,
        system: Option<&str>,
        prompt: &str,
        progress: &ProgressSink,
    ) -> Result<Reply> {
        match self.dialect {
            Some(dialect) => self.send_streaming(dialect, system, prompt, progress).await,
            // No dialect configured: the original buffered-until-exit path, on the
            // longer non-streaming wall clock — see `CLI_TIMEOUT_NONSTREAMING`.
            None => {
                self.send_with_timeout(system, prompt, CLI_TIMEOUT_NONSTREAMING)
                    .await
            }
        }
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
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("does not exist"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_an_empty_path() {
        assert!(
            LocalBinaryProvider::new("fake", "  ", vec![], "m", None, PathBuf::from("."), None)
                .is_err()
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
                None,
            )
            .is_ok()
        );
    }

    #[test]
    fn cli_tools_count_as_remote_for_classified_mode() {
        let p = LocalBinaryProvider::new(
            "gh",
            "gh",
            vec![],
            "copilot",
            None,
            PathBuf::from("."),
            None,
        )
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
            None,
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
            None,
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
            None,
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
            None,
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
            None,
        )
        .unwrap();
        let reply = p
            .send_with_timeout(None, "ignored", Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(reply.text.trim(), expected.to_string_lossy());
    }

    // --- streaming dialect parsing -----------------------------------------------
    //
    // Kept as pure-function tests against `parse_stream_line`/`parse_claude_line`/
    // `parse_agy_line` directly — no process spawning — mirroring why `compose_call`
    // and `summarize_stderr` are tested the same way above.

    #[test]
    fn claude_dialect_extracts_a_tool_use_detail() {
        let line = r#"{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash","input":{"command":"cat README.md","description":"Read the readme"}}]}}"#;
        assert_eq!(
            parse_claude_line(line),
            StreamLineEffect::Progress("Bash: Read the readme".to_string())
        );
    }

    #[test]
    fn claude_dialect_falls_back_to_the_command_when_no_description_is_present() {
        let line = r#"{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash","input":{"command":"cat README.md"}}]}}"#;
        assert_eq!(
            parse_claude_line(line),
            StreamLineEffect::Progress("Bash: cat README.md".to_string())
        );
    }

    #[test]
    fn claude_dialect_extracts_the_final_result_text() {
        let line = r#"{"type":"result","subtype":"success","is_error":false,"result":"OK.","duration_ms":9312}"#;
        assert_eq!(
            parse_claude_line(line),
            StreamLineEffect::Result("OK.".to_string())
        );
    }

    #[test]
    fn claude_dialect_ignores_system_and_rate_limit_lines() {
        assert_eq!(
            parse_claude_line(r#"{"type":"system","subtype":"init"}"#),
            StreamLineEffect::Ignore
        );
        assert_eq!(
            parse_claude_line(r#"{"type":"rate_limit_event","tier":"standard"}"#),
            StreamLineEffect::Ignore
        );
    }

    #[test]
    fn claude_dialect_ignores_a_malformed_non_json_line() {
        // Regression guard for the requirement that a third-party CLI's output
        // changing shape under us must never fail the call — see `send_streaming`.
        assert_eq!(
            parse_claude_line("not json at all { broken"),
            StreamLineEffect::Ignore
        );
    }

    #[test]
    fn agy_dialect_extracts_a_step_update_detail_with_a_tool_name() {
        let line = r#"{"event":"step_update","step_update":{"step_index":3,"state":"ACTIVE","step_type":"subagent","tool_name":"invoke_subagent","duration_seconds":0.02}}"#;
        assert_eq!(
            parse_agy_line(line),
            StreamLineEffect::Progress("subagent: invoke_subagent".to_string())
        );
    }

    #[test]
    fn agy_dialect_reports_a_failed_run_as_a_failure_not_as_its_partial_text() {
        // Captured from a real run: agy denied its own `run_command` tool, then
        // answered with a confident-sounding `response` that contains no answer. The
        // reason must win, or a denied-permission failure reads as a successful reply.
        let line = r#"{"event":"result","result":{"status":"ERROR","response":"I have dispatched a research subagent and will report shortly.\n","error":"permission check failed for command \"pwd\": user denied permission to run command:\npwd"}}"#;
        match parse_agy_line(line) {
            StreamLineEffect::Failure(reason) => {
                assert!(reason.contains("user denied permission"), "got: {reason}");
            }
            other => panic!("expected a Failure, got {other:?}"),
        }
    }

    #[test]
    fn agy_dialect_falls_back_to_the_bare_status_when_no_error_detail_is_given() {
        let line = r#"{"event":"result","result":{"status":"CANCELLED","response":""}}"#;
        match parse_agy_line(line) {
            StreamLineEffect::Failure(reason) => assert_eq!(reason, "CANCELLED"),
            other => panic!("expected a Failure, got {other:?}"),
        }
    }

    #[test]
    fn claude_dialect_reports_an_is_error_result_as_a_failure() {
        // This dialect reuses the `result` field for the failure reason, so the flag
        // is the only thing separating an answer from an explanation of its absence.
        let line = r#"{"type":"result","subtype":"error_during_execution","is_error":true,"result":"Credit balance is too low"}"#;
        match parse_claude_line(line) {
            StreamLineEffect::Failure(reason) => assert_eq!(reason, "Credit balance is too low"),
            other => panic!("expected a Failure, got {other:?}"),
        }
    }

    #[test]
    fn agy_dialect_extracts_result_response_as_the_final_text() {
        let line = r#"{"event":"result","result":{"status":"SUCCESS","response":"OK.\n","duration_seconds":2.58,"num_turns":1}}"#;
        assert_eq!(
            parse_agy_line(line),
            StreamLineEffect::Result("OK.\n".to_string())
        );
    }

    #[test]
    fn agy_dialect_ignores_unknown_event_values() {
        assert_eq!(
            parse_agy_line(r#"{"event":"something_else","payload":{}}"#),
            StreamLineEffect::Ignore
        );
    }

    #[test]
    fn agy_dialect_ignores_a_malformed_non_json_line() {
        assert_eq!(parse_agy_line("{not valid"), StreamLineEffect::Ignore);
    }

    #[test]
    fn stream_dialect_parses_known_names_and_rejects_unknown_ones() {
        assert_eq!(
            StreamDialect::parse("claude").unwrap(),
            StreamDialect::ClaudeJson
        );
        assert_eq!(StreamDialect::parse("agy").unwrap(), StreamDialect::AgyJson);
        let err = StreamDialect::parse("bogus").unwrap_err().to_string();
        assert!(err.contains("bogus"), "unexpected error: {err}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_streaming_call_forwards_progress_and_returns_the_result_text() {
        // A tiny shell script stands in for a real `claude`/`agy` binary: it prints
        // one progress line, then one result line, so this exercises the real
        // `send_streaming` spawn/parse/forward path end to end without depending on
        // either real CLI being installed.
        let p = LocalBinaryProvider::new(
            "sh",
            "/bin/sh",
            vec![
                "-c".into(),
                r#"printf '%s\n' '{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash","input":{"description":"Read the readme"}}]}}' '{"type":"result","subtype":"success","is_error":false,"result":"all good"}'"#
                    .into(),
            ],
            "sh",
            None,
            PathBuf::from("."),
            Some(StreamDialect::ClaudeJson),
        )
        .unwrap();

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let progress = ProgressSink::new(tx);
        let reply = p
            .send_with_progress(None, "ignored", &progress)
            .await
            .unwrap();
        assert_eq!(reply.text, "all good");
        drop(progress);

        let detail = rx.recv().await.expect("a progress detail was sent");
        assert_eq!(detail, "Bash: Read the readme");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_streaming_call_with_no_result_event_falls_back_to_assistant_text() {
        let p = LocalBinaryProvider::new(
            "sh",
            "/bin/sh",
            vec![
                "-c".into(),
                r#"printf '%s\n' '{"type":"assistant","message":{"content":[{"type":"text","text":"partial reply"}]}}'"#
                    .into(),
            ],
            "sh",
            None,
            PathBuf::from("."),
            Some(StreamDialect::ClaudeJson),
        )
        .unwrap();

        let reply = p
            .send_with_progress(None, "ignored", &ProgressSink::disconnected())
            .await
            .unwrap();
        assert_eq!(reply.text, "partial reply");
    }
}

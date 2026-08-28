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

use crate::providers::{
    ProgressSink, Provider, ProviderFailure, RateLimit, Reply, TokenUsage, json_u64,
};

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
    /// `copilot --output-format json --prompt`.
    CopilotJson,
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
            "copilot" => Ok(StreamDialect::CopilotJson),
            other => Err(anyhow!(
                "unknown stream_format `{other}`; expected \"claude\", \"agy\", or \"copilot\""
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
    /// The flag this CLI uses to declare an additional allowed working directory
    /// (`--add-dir` for both known agentic CLIs), or `None`. When set, it is passed
    /// with `project_root` — see `apply_workspace_arg`.
    workspace_arg: Option<String>,
    /// `Some` when this CLI's stdout is NDJSON progress that can be parsed and
    /// streamed to a `ProgressSink` as it arrives; `None` keeps the original
    /// buffered-until-exit behaviour.
    dialect: Option<StreamDialect>,
}

/// Adds the CLI's "additional allowed directory" flag, pointing at the project root.
///
/// Called BEFORE the CLI's own configured args, which matters: agy's `-p` takes the
/// next argument as its prompt, so a flag appended after the arg list would be
/// swallowed as the prompt text instead of parsed. Placing workspace flags first is
/// safe for both known CLIs.
fn apply_workspace_arg(command: &mut Command, workspace_arg: Option<&str>, project_root: &Path) {
    if let Some(flag) = workspace_arg {
        command.arg(flag).arg(project_root);
    }
}

/// How to build a CLI's command line, grouped into one value.
///
/// These four travel together — they come from the same `CliSpec`, and they are all
/// about the shape of the argv this CLI expects. Passing them as four positional
/// parameters meant a constructor call ending in three bare `None`s whose meaning
/// depended entirely on counting commas.
#[derive(Debug, Clone, Default)]
pub struct CliInvocation {
    /// Fixed arguments this CLI needs before the prompt (`-p`, `--output-format`, …).
    pub args: Vec<String>,
    /// The flag carrying a system prompt, or `None` when the CLI has none and the
    /// system text must be folded into the prompt instead.
    pub system_arg: Option<String>,
    /// The NDJSON progress dialect this CLI's stdout speaks, if any.
    pub dialect: Option<StreamDialect>,
    /// The flag declaring an additional allowed working directory, if any.
    pub workspace_arg: Option<String>,
}

impl LocalBinaryProvider {
    pub fn new(
        name: impl Into<String>,
        binary_path: impl Into<String>,
        model: impl Into<String>,
        project_root: PathBuf,
        invocation: CliInvocation,
    ) -> Result<Self> {
        let CliInvocation {
            args,
            system_arg,
            dialect,
            workspace_arg,
        } = invocation;
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
            workspace_arg,
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

/// Reads one child output stream up to `cap` bytes, then drains whatever is left to a
/// sink instead of returning as soon as the cap is hit.
///
/// The drain is not dead weight — deleting it reintroduces a regression already fixed
/// once, in `94b5c1d`. Stopping at the cap and dropping the reader closes the pipe out
/// from under a child that is still writing to it; the child then takes SIGPIPE and
/// dies, and simon reports "exited with signal: 13 (SIGPIPE)" instead of whatever the
/// child was actually about to exit with — measured exactly that way there, with a
/// stub whose last statement (`exit 1`) never ran. Draining to `tokio::io::sink()`
/// keeps the pipe open (and memory bounded, since nothing past `cap` is retained)
/// until the child closes it on its own or the caller's own timeout kills the child.
///
/// Returns the bytes kept and whether the stream held more than `cap` of them.
async fn read_capped<R: tokio::io::AsyncRead + Unpin>(reader: R, cap: usize) -> (Vec<u8>, bool) {
    let mut buf = Vec::new();
    // `.take(cap)` makes the limited reader report EOF once `cap` bytes have been
    // read, whether or not the underlying stream actually ended there — so
    // `read_to_end` can never over-retain, but on its own can't say *why* it stopped.
    let mut limited = reader.take(cap as u64);
    let _ = limited.read_to_end(&mut buf).await;
    let mut reader = limited.into_inner();
    let drained = tokio::io::copy(&mut reader, &mut tokio::io::sink())
        .await
        .unwrap_or(0);
    (buf, drained > 0)
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
        apply_workspace_arg(
            &mut command,
            self.workspace_arg.as_deref(),
            &self.project_root,
        );
        command.args(&self.args);
        if let Some((flag, value)) = &system_flag {
            command.arg(flag).arg(value);
        }
        command.arg(effective_prompt);
        command.kill_on_drop(true);
        command.stdin(Stdio::null());
        // `command.output()` used to do this call in one shot: spawn, then buffer
        // BOTH streams to completion, and only afterwards was `MAX_OUTPUT_BYTES`
        // applied to what came back. A child that emits a gigabyte put a gigabyte in
        // `simon`'s address space — physically pinned there by `mlockall` (see
        // `main.rs`), unable even to page out — before a single byte was discarded.
        // Piping explicitly lets `read_capped` below stop retaining bytes past the
        // cap *as they arrive*, per stream.
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        // `kill_on_drop(true)` only reaps the child when *something* drops the future
        // that owns it. Without a timeout, nothing ever did — sitting on a wedged CLI
        // would permanently freeze the session. Wrapping the whole spawn/read/wait
        // sequence in `tokio::time::timeout` gives it a reason to drop: on elapse,
        // `timeout` drops `run`, which drops `child` inside it, which is what
        // actually kills the process — the same mechanism as before `output()` was
        // inlined here, just now wrapped around more work.
        let run = async move {
            let mut child = command.spawn()?;
            // `.expect` is safe: both were just set to `Stdio::piped()` above, so
            // tokio always populates these handles on a successful spawn.
            let stdout = child.stdout.take().expect("stdout was piped");
            let stderr = child.stderr.take().expect("stderr was piped");

            // Read both streams concurrently, not one after the other: a child that
            // fills its stderr pipe buffer while stdout is being drained first (or
            // the reverse) blocks on its next write to the full pipe, and nothing
            // here would ever get back around to draining it — a self-inflicted
            // deadlock. `tokio::join!` polls both futures on this task instead.
            let ((stdout_bytes, stdout_truncated), (stderr_bytes, stderr_truncated)) = tokio::join!(
                read_capped(stdout, MAX_OUTPUT_BYTES),
                read_capped(stderr, MAX_OUTPUT_BYTES),
            );

            let status = child.wait().await?;
            Ok::<_, std::io::Error>((
                status,
                stdout_bytes,
                stdout_truncated,
                stderr_bytes,
                stderr_truncated,
            ))
        };

        // `stderr_truncated` is intentionally unused past this point: on failure,
        // `summarize_stderr` below already caps and marks its own summary for
        // display, independent of whether `read_capped`'s memory cap also cut the
        // raw bytes it was given — a second truncation marker on top would be noise.
        let (status, stdout_bytes, stdout_truncated, stderr_bytes, _stderr_truncated) =
            match tokio::time::timeout(timeout, run).await {
                Ok(result) => {
                    result.with_context(|| format!("failed to run {}", self.binary_path))?
                }
                Err(_) => {
                    return Err(
                        anyhow::Error::new(ProviderFailure::Timeout).context(format!(
                            "{} timed out after {}s",
                            self.binary_path,
                            timeout.as_secs()
                        )),
                    );
                }
            };

        if !status.success() {
            let stderr = String::from_utf8_lossy(&stderr_bytes);
            return Err(anyhow!(
                "{} exited with {}: {}",
                self.binary_path,
                status,
                summarize_stderr(&stderr)
            ));
        }

        // `from_utf8_lossy` runs on bytes `read_capped` already cut to
        // `MAX_OUTPUT_BYTES` — never a raw byte-index slice taken here — so a
        // multi-byte codepoint straddling the cap becomes a replacement character
        // instead of panicking (the failure mode fixed in `923b934`).
        let text = String::from_utf8_lossy(&stdout_bytes).trim().to_string();

        if text.is_empty() {
            return Err(anyhow!("{} produced no output", self.binary_path));
        }

        // Report a cut reply rather than silently handing back a partial one as if
        // it were complete — mirrors `send_streaming`'s truncation handling below.
        let text = if stdout_truncated {
            format!("{text}\n\n… output truncated at {MAX_OUTPUT_BYTES} bytes")
        } else {
            text
        };

        Ok(Reply {
            text,
            rate_limit: RateLimit::default(),
            usage: TokenUsage::default(),
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
        self.send_streaming_with_timeouts(
            dialect,
            system,
            prompt,
            progress,
            CLI_IDLE_TIMEOUT,
            CLI_TOTAL_TIMEOUT,
        )
        .await
    }

    async fn send_streaming_with_timeouts(
        &self,
        dialect: StreamDialect,
        system: Option<&str>,
        prompt: &str,
        progress: &ProgressSink,
        idle_timeout: Duration,
        total_timeout: Duration,
    ) -> Result<Reply> {
        let (system_flag, effective_prompt) =
            compose_call(self.system_arg.as_deref(), system, prompt);

        let mut command = Command::new(&self.binary_path);
        // See `send_with_timeout`'s identical line for why `current_dir` is set and,
        // importantly, what it does not guarantee.
        command.current_dir(&self.project_root);
        apply_workspace_arg(
            &mut command,
            self.workspace_arg.as_deref(),
            &self.project_root,
        );
        command.args(&self.args);
        if let Some((flag, value)) = &system_flag {
            command.arg(flag).arg(value);
        }
        command.arg(effective_prompt);
        command.kill_on_drop(true);
        // The prompt is passed as an argv entry (above), not over stdin, so the child
        // needs none — and must not inherit simon's own stdin, which in the TUI is the
        // terminal in raw mode.
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

        let stderr_task: tokio::task::JoinHandle<String> = tokio::spawn(async move {
            let mut reader = BufReader::new(stderr);
            let mut buf = Vec::new();
            let _ = (&mut reader)
                .take(MAX_OUTPUT_BYTES as u64)
                .read_to_end(&mut buf)
                .await;
            let _ = tokio::io::copy(&mut reader, &mut tokio::io::sink()).await;
            String::from_utf8_lossy(&buf).into_owned()
        });

        let mut stdout_reader = BufReader::new(stdout);
        let mut line_bytes = Vec::new();
        let mut result_text: Option<String> = None;
        let mut stream_error: Option<String> = None;
        let mut assistant_text = String::new();
        let mut assistant_text_truncated = false;
        let mut usage = TokenUsage::default();

        // Not reset on each loop iteration — deliberately: `total_timeout` is a
        // single absolute backstop across the whole call, unlike the idle timeout
        // below, which is a fresh `tokio::time::timeout` every iteration so it
        // resets on every line received.
        let total_deadline = tokio::time::sleep(total_timeout);
        tokio::pin!(total_deadline);

        loop {
            line_bytes.clear();
            // `read_until` is NOT cancellation-safe (unlike the `lines().next_line()`
            // this replaced): if another `select!` branch wins, whatever it had already
            // read into `line_bytes` is lost. That is sound only because every other
            // branch below returns immediately instead of looping again. Anyone adding
            // a branch that *continues* the loop has to move the read out of `select!`
            // first, or it will silently drop a partially-read line of model output.
            tokio::select! {
                biased;
                _ = &mut total_deadline => {
                    // Dropping `child` here is what actually kills it — see the
                    // `kill_on_drop` comment on `send_with_timeout`; the same
                    // property holds here, just triggered by `select!` dropping the
                    // losing branches instead of `tokio::time::timeout` doing it.
                    drop(child);
                    return Err(anyhow::Error::new(ProviderFailure::Timeout).context(format!(
                        "{} timed out after {}s (total time limit for a streaming call)",
                        self.binary_path,
                        total_timeout.as_secs()
                    )));
                }
                next = tokio::time::timeout(idle_timeout, stdout_reader.read_until(b'\n', &mut line_bytes)) => {
                    match next {
                        Err(_) => {
                            drop(child);
                            return Err(anyhow::Error::new(ProviderFailure::Timeout).context(
                                format!(
                                    "{} timed out after {}s of no output",
                                    self.binary_path,
                                    idle_timeout.as_secs()
                                ),
                            ));
                        }
                        Ok(Err(e)) => {
                            return Err(e).with_context(|| {
                                format!("failed reading {} output", self.binary_path)
                            });
                        }
                        Ok(Ok(0)) => break, // stdout closed: child is finishing up
                        Ok(Ok(_)) => {
                            let line = String::from_utf8_lossy(&line_bytes);
                            let line = line.trim_end_matches(['\r', '\n']);
                            usage.merge(parse_stream_usage(dialect, line));
                            match parse_stream_line(dialect, line) {
                                StreamLineEffect::Progress(detail) => progress.send(detail),
                                StreamLineEffect::AssistantText(text) => {
                                    if assistant_text.len() + text.len() <= MAX_OUTPUT_BYTES {
                                        assistant_text.push_str(&text);
                                    } else {
                                        let remaining = MAX_OUTPUT_BYTES.saturating_sub(assistant_text.len());
                                        if remaining > 0 {
                                            let mut bytes = text.into_bytes();
                                            bytes.truncate(remaining);
                                            assistant_text.push_str(&String::from_utf8_lossy(&bytes));
                                        }
                                        assistant_text_truncated = true;
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
                return Err(anyhow::Error::new(ProviderFailure::Timeout).context(format!(
                    "{} timed out after {}s (total time limit for a streaming call)",
                    self.binary_path,
                    total_timeout.as_secs()
                )));
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
        // assistant-text events arrived if the stream ended without one, or if it
        // arrived but carried no text — see `select_stream_reply` for why an empty
        // result must not beat real accumulated text.
        let (mut text, mut truncated) =
            select_stream_reply(result_text, assistant_text, assistant_text_truncated);
        if text.len() > MAX_OUTPUT_BYTES {
            let mut bytes = text.into_bytes();
            bytes.truncate(MAX_OUTPUT_BYTES);
            text = String::from_utf8_lossy(&bytes).into_owned();
            truncated = true;
        }
        let text = text.trim().to_string();

        if text.is_empty() {
            return Err(anyhow!("{} produced no output", self.binary_path));
        }

        // Report a cut reply rather than silently handing back a partial one as if
        // it were complete — see the identical marker on the non-streaming path in
        // `send_with_timeout`, which this mirrors for consistency between the two.
        let text = if truncated {
            format!("{text}\n\n… output truncated at {MAX_OUTPUT_BYTES} bytes")
        } else {
            text
        };

        Ok(Reply {
            text,
            rate_limit: RateLimit::default(),
            usage,
        })
    }
}

/// Chooses `send_streaming`'s final reply text from the dialect's terminal result
/// event (if any) and the assistant-text accumulated as a fallback, plus whether that
/// fallback dropped text on the floor (see `assistant_text_truncated` at its call
/// site). Returns the chosen text and whether it should carry a truncation marker.
///
/// Precedence: a non-empty result wins outright; failing that, non-empty accumulated
/// assistant text; failing that, whatever is left (letting the caller's own "produced
/// no output" error fire honestly for a genuinely empty run). An empty terminal
/// result must NOT beat non-empty assistant text — a stream that already delivered a
/// full answer as `AssistantText` events and then closes with a blank `result`/
/// `response` field (observed from `agy` on a denied tool call, but not dialect-
/// specific) used to have that blank value win via `unwrap_or`, silently discarding a
/// complete answer and reporting "produced no output" instead. Kept as a free
/// function, pure of the process-spawning code around it, for the same reason
/// `compose_call` and `summarize_stderr` above are: it's the part worth unit-testing
/// directly.
fn select_stream_reply(
    result_text: Option<String>,
    assistant_text: String,
    assistant_text_truncated: bool,
) -> (String, bool) {
    match result_text {
        Some(text) if !text.trim().is_empty() => (text, false),
        _ if !assistant_text.trim().is_empty() => (assistant_text, assistant_text_truncated),
        Some(text) => (text, false),
        None => (assistant_text, assistant_text_truncated),
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
        StreamDialect::CopilotJson => parse_copilot_line(line),
    }
}

fn parse_stream_usage(dialect: StreamDialect, line: &str) -> TokenUsage {
    let Ok(value) = serde_json::from_str::<Value>(line) else {
        return TokenUsage::default();
    };
    let usage = match dialect {
        StreamDialect::ClaudeJson => value
            .get("usage")
            .or_else(|| value.pointer("/message/usage")),
        StreamDialect::AgyJson => value
            .pointer("/result/usage")
            .or_else(|| value.get("usage")),
        // Copilot's JSONL stream currently exposes billing checkpoints rather than
        // per-call input/output token counts, so reporting those as this call's usage
        // would be misleading.
        StreamDialect::CopilotJson => None,
    };
    let Some(usage) = usage else {
        return TokenUsage::default();
    };

    TokenUsage {
        input_tokens: json_u64(
            usage
                .get("input_tokens")
                .or_else(|| usage.get("prompt_tokens")),
        ),
        output_tokens: json_u64(
            usage
                .get("output_tokens")
                .or_else(|| usage.get("completion_tokens")),
        ),
        total_tokens: json_u64(usage.get("total_tokens")),
    }
}

/// Parses one line of `claude -p --output-format stream-json --verbose`'s NDJSON.
/// See the module-level ground truth this was built against: `assistant` events carry
/// either a `tool_use` (progress) or `text` (fallback reply) content item; `result` is
/// the terminal event; `system`/`rate_limit_event`/`user` (tool results) and anything
/// unrecognised are ignored.
fn extract_error_message(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => {
            let s = s.trim();
            if s.is_empty() {
                None
            } else {
                Some(s.to_string())
            }
        }
        Value::Object(_) => v
            .get("message")
            .and_then(Value::as_str)
            .or_else(|| v.get("error").and_then(Value::as_str))
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().to_string()),
        _ => None,
    }
}

fn parse_claude_line(line: &str) -> StreamLineEffect {
    let Ok(value) = serde_json::from_str::<Value>(line) else {
        return StreamLineEffect::Ignore;
    };
    match value.get("type").and_then(Value::as_str) {
        Some("assistant") => claude_assistant_effect(&value),
        Some("error") => {
            let reason = value
                .get("error")
                .and_then(extract_error_message)
                .or_else(|| {
                    value
                        .get("message")
                        .and_then(Value::as_str)
                        .filter(|s| !s.trim().is_empty())
                        .map(str::to_string)
                })
                .unwrap_or_else(|| "error".to_string());
            StreamLineEffect::Failure(reason)
        }
        Some("result") => {
            let text = value
                .get("result")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            // On a failed run this dialect puts the reason in the same `result`
            // field the reply text normally occupies, so the flag is the only thing
            // distinguishing "here is your answer" from "here is why there isn't one".
            let is_error = value.get("is_error").and_then(Value::as_bool) == Some(true)
                || value
                    .get("subtype")
                    .and_then(Value::as_str)
                    .map(|s| s.starts_with("error"))
                    == Some(true);
            if is_error {
                let reason = if !text.trim().is_empty() {
                    text
                } else if let Some(err) = value.get("error").and_then(extract_error_message) {
                    err
                } else if let Some(subtype) = value
                    .get("subtype")
                    .and_then(Value::as_str)
                    .filter(|s| !s.trim().is_empty())
                {
                    subtype.to_string()
                } else {
                    "error".to_string()
                };
                return StreamLineEffect::Failure(reason);
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
                .filter(|s| !s.trim().is_empty())
                .or_else(|| {
                    item.pointer("/input/command")
                        .and_then(Value::as_str)
                        .filter(|s| !s.trim().is_empty())
                });
            return StreamLineEffect::Progress(match detail {
                Some(d) => format!("{tool_name}: {d}"),
                None => tool_name.to_string(),
            });
        }
    }
    let texts: Vec<&str> = content
        .iter()
        .filter(|item| item.get("type").and_then(Value::as_str) == Some("text"))
        .filter_map(|item| item.get("text").and_then(Value::as_str))
        .collect();
    if !texts.is_empty() {
        return StreamLineEffect::AssistantText(texts.join(""));
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
        Some("error") => {
            let reason = value
                .get("error")
                .and_then(extract_error_message)
                .or_else(|| {
                    value
                        .get("message")
                        .and_then(Value::as_str)
                        .filter(|s| !s.trim().is_empty())
                        .map(str::to_string)
                })
                .unwrap_or_else(|| "error".to_string());
            StreamLineEffect::Failure(reason)
        }
        Some("result") => {
            let status = value
                .pointer("/result/status")
                .and_then(Value::as_str)
                .unwrap_or("SUCCESS");
            if !status.eq_ignore_ascii_case("success") && !status.eq_ignore_ascii_case("ok") {
                // The `error` field is the actionable half — a denied tool
                // permission, a quota refusal — so prefer it, falling back to the
                // bare status when the CLI gave no detail.
                let reason = value
                    .pointer("/result/error")
                    .and_then(extract_error_message)
                    .or_else(|| {
                        value
                            .pointer("/result/message")
                            .and_then(Value::as_str)
                            .filter(|s| !s.trim().is_empty())
                            .map(str::to_string)
                    })
                    .unwrap_or_else(|| status.to_string());
                return StreamLineEffect::Failure(reason);
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
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("step");
    let detail = match step
        .get("tool_name")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
    {
        Some(tool_name) => format!("{step_type}: {tool_name}"),
        None => step_type.to_string(),
    };
    StreamLineEffect::Progress(detail)
}

/// Parses `copilot --output-format json` JSONL. The complete `assistant.message`
/// event is used as the terminal reply, while deltas remain a fallback if a future
/// CLI version omits that event. Tool starts provide lightweight live progress.
fn parse_copilot_line(line: &str) -> StreamLineEffect {
    let Ok(value) = serde_json::from_str::<Value>(line) else {
        return StreamLineEffect::Ignore;
    };
    match value.get("type").and_then(Value::as_str) {
        Some("assistant.message_delta") => StreamLineEffect::AssistantText(
            value
                .pointer("/data/deltaContent")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        ),
        Some("assistant.message") => StreamLineEffect::Result(
            value
                .pointer("/data/content")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        ),
        Some("tool.execution_start") => {
            let tool = value
                .pointer("/data/toolName")
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty())
                .unwrap_or("tool");
            StreamLineEffect::Progress(tool.to_string())
        }
        _ => StreamLineEffect::Ignore,
    }
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
            "m",
            PathBuf::from("."),
            CliInvocation {
                args: vec![],
                system_arg: None,
                dialect: None,
                workspace_arg: None,
            },
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("does not exist"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_an_empty_path() {
        assert!(
            LocalBinaryProvider::new(
                "fake",
                "  ",
                "m",
                PathBuf::from("."),
                CliInvocation {
                    args: vec![],
                    system_arg: None,
                    dialect: None,
                    workspace_arg: None,
                },
            )
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
                "m",
                PathBuf::from("."),
                CliInvocation {
                    args: vec!["copilot".into()],
                    system_arg: None,
                    dialect: None,
                    workspace_arg: None,
                },
            )
            .is_ok()
        );
    }

    #[test]
    fn cli_tools_count_as_remote_for_classified_mode() {
        let p = LocalBinaryProvider::new(
            "gh",
            "gh",
            "copilot",
            PathBuf::from("."),
            CliInvocation {
                args: vec![],
                system_arg: None,
                dialect: None,
                workspace_arg: None,
            },
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
            "claude",
            PathBuf::from("."),
            CliInvocation {
                args: vec![],
                system_arg: None,
                dialect: None,
                workspace_arg: None,
            },
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
            "gemini-3-pro",
            PathBuf::from("."),
            CliInvocation {
                args: vec![],
                system_arg: None,
                dialect: None,
                workspace_arg: None,
            },
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
            "slow",
            PathBuf::from("."),
            CliInvocation {
                args: vec![],
                system_arg: None,
                dialect: None,
                workspace_arg: None,
            },
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

    /// Builds a provider that runs `script` under `/bin/sh`. Unix-only, like the
    /// `/bin/echo` test above: `LocalBinaryProvider::new` rejects a nonexistent binary,
    /// and there is no `/bin/sh` on Windows.
    #[cfg(unix)]
    fn shell_provider(script: &str) -> LocalBinaryProvider {
        LocalBinaryProvider::new(
            "sh",
            "/bin/sh",
            "sh",
            PathBuf::from("."),
            CliInvocation {
                args: vec!["-c".to_string(), script.to_string()],
                system_arg: None,
                dialect: None,
                workspace_arg: None,
            },
        )
        .unwrap()
    }

    /// ~3 MiB down the given fd — comfortably past `MAX_OUTPUT_BYTES` (1 MiB), so the
    /// cap is genuinely exercised rather than just approached.
    #[cfg(unix)]
    const FLOOD: &str = "dd if=/dev/zero bs=1024 count=3072 2>/dev/null | tr '\\0' 'x'";

    #[tokio::test]
    #[cfg(unix)]
    async fn a_chatty_child_is_capped_without_being_killed_by_sigpipe() {
        // The regression, fixed once in 94b5c1d: capping a stream by dropping the reader
        // closes the pipe under a child still writing to it, the child dies of SIGPIPE,
        // and simon reports "signal: 13" instead of the child's real exit.
        //
        // The flood must come from the shell's own builtin `printf`, not from a
        // `dd | tr` pipeline. In a pipeline it is the *subprocess* that takes SIGPIPE
        // while the shell survives to run `exit`, so the test would pass whether or not
        // the drain existed — which is exactly what an earlier version of this test did.
        let chunk = "y".repeat(4096);
        let p = shell_provider(&format!(
            "i=0; while [ $i -lt 1024 ]; do printf '%s' '{chunk}' >&2; i=$((i+1)); done; exit 7"
        ));
        let err = p
            .send_with_timeout(None, "ignored", Duration::from_secs(60))
            .await
            .expect_err("a child exiting non-zero must surface as an error");
        let msg = err.to_string();
        assert!(
            !msg.contains("signal"),
            "the child was killed by a signal instead of exiting on its own: {msg}"
        );
        assert!(
            msg.contains('7'),
            "the child's own exit status 7 did not survive: {msg}"
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn an_enormous_stdout_is_capped_rather_than_retained_whole() {
        let p = shell_provider(FLOOD);
        let reply = p
            .send_with_timeout(None, "ignored", Duration::from_secs(60))
            .await
            .unwrap();
        // Fixture guard: if the flood produced nothing, a "is bounded" assertion below
        // would pass for entirely the wrong reason.
        assert!(
            !reply.text.is_empty(),
            "fixture produced no output at all, so the cap was never exercised"
        );
        assert!(
            reply.text.len() <= MAX_OUTPUT_BYTES + 1024,
            "kept {} bytes, which is not bounded by MAX_OUTPUT_BYTES ({MAX_OUTPUT_BYTES})",
            reply.text.len()
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn a_child_flooding_both_streams_at_once_does_not_deadlock() {
        // Reading the streams one after the other deadlocks here: the child blocks
        // writing to whichever pipe buffer fills first, and a sequential reader never
        // gets back to drain it. The outer `tokio::time::timeout` is the assertion —
        // it turns a hang into a failure instead of a CI job that never ends.
        let p = shell_provider(&format!("{FLOOD} & {FLOOD} >&2; wait"));
        let result = tokio::time::timeout(
            Duration::from_secs(90),
            p.send_with_timeout(None, "ignored", Duration::from_secs(60)),
        )
        .await;
        assert!(
            result.is_ok(),
            "reading both streams deadlocked instead of completing"
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn output_cut_at_the_cap_mid_codepoint_does_not_panic() {
        // Every character here is multi-byte, so a 1 MiB cut is overwhelmingly likely
        // to land inside one. Byte-index slicing panicked on exactly this shape before
        // (923b934).
        let p =
            shell_provider("i=0; while [ $i -lt 40000 ]; do printf 'ąčęėįšųūž'; i=$((i+1)); done");
        let reply = p
            .send_with_timeout(None, "ignored", Duration::from_secs(60))
            .await
            .unwrap();
        assert!(!reply.text.is_empty(), "fixture produced no output");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_child_that_finishes_within_the_timeout_still_succeeds() {
        // Unix-only: depends on `/bin/echo`, a Unix path that `LocalBinaryProvider::new`
        // would reject as nonexistent on Windows.
        let p = LocalBinaryProvider::new(
            "echoer",
            "/bin/echo",
            "echoer",
            PathBuf::from("."),
            CliInvocation {
                args: vec![],
                system_arg: None,
                dialect: None,
                workspace_arg: None,
            },
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
    async fn the_workspace_flag_reaches_the_command_line_before_the_cli_own_args() {
        // Order is the point, not just presence: `agy`'s `-p` takes the NEXT argument
        // as its prompt, so a workspace flag appended after the configured args would
        // be swallowed as prompt text. `echo` reports argv back, so this checks the
        // real command line rather than a struct field.
        let project = tempfile::tempdir().unwrap();
        // Canonicalize BEFORE constructing, and assert against the same value: the
        // flag carries `project_root` verbatim, so a test that hands over a raw
        // tempdir path but expects a canonical one only passes where the two happen
        // to be equal. They are not on macOS, where `tempdir()` returns a path under
        // `/var/folders/...` that is a symlink to `/private/var/folders/...` — which
        // is exactly how this test passed on Linux and Windows while failing CI on
        // macOS. Canonicalizing here also mirrors production: `resolve_project_root`
        // in `main.rs` canonicalizes once at startup, so a real `project_root` is
        // already canonical by the time a provider sees it.
        let root = std::fs::canonicalize(project.path()).unwrap();
        let expected = root.clone();
        let p = LocalBinaryProvider::new(
            "echo",
            "/bin/echo",
            "echo",
            root,
            CliInvocation {
                args: vec!["--configured-arg".into()],
                system_arg: None,
                dialect: None,
                workspace_arg: Some("--add-dir".into()),
            },
        )
        .unwrap();
        let reply = p
            .send_with_timeout(None, "the-prompt", Duration::from_secs(5))
            .await
            .unwrap();
        let expected_line = format!(
            "--add-dir {} --configured-arg the-prompt",
            expected.to_string_lossy()
        );
        assert_eq!(reply.text.trim(), expected_line);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_workspace_flag_carries_its_root_verbatim_even_through_a_symlink() {
        // Exercises the macOS condition on every platform. `/tmp` is a real directory
        // on Linux, so a plain `tempdir()` can never catch a raw-vs-canonical path
        // mismatch there; macOS CI could, and did. Building the symlink by hand makes
        // the contract explicit and platform-independent: the flag passes on exactly
        // the root the provider was constructed with, resolving nothing.
        let base = tempfile::tempdir().unwrap();
        let real = base.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_ne!(
            link,
            std::fs::canonicalize(&link).unwrap(),
            "the symlink must actually differ from its target, or this proves nothing"
        );

        let p = LocalBinaryProvider::new(
            "echo",
            "/bin/echo",
            "echo",
            link.clone(),
            CliInvocation {
                args: vec![],
                system_arg: None,
                dialect: None,
                workspace_arg: Some("--add-dir".into()),
            },
        )
        .unwrap();
        let reply = p
            .send_with_timeout(None, "p", Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(
            reply.text.trim(),
            format!("--add-dir {} p", link.to_string_lossy())
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn no_workspace_flag_leaves_the_command_line_untouched() {
        let project = tempfile::tempdir().unwrap();
        let p = LocalBinaryProvider::new(
            "echo",
            "/bin/echo",
            "echo",
            project.path().to_path_buf(),
            CliInvocation {
                args: vec!["--configured-arg".into()],
                system_arg: None,
                dialect: None,
                workspace_arg: None,
            },
        )
        .unwrap();
        let reply = p
            .send_with_timeout(None, "the-prompt", Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(reply.text.trim(), "--configured-arg the-prompt");
    }

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
            "sh",
            project.path().to_path_buf(),
            CliInvocation {
                args: vec!["-c".into(), "pwd".into()],
                system_arg: None,
                dialect: None,
                workspace_arg: None,
            },
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
    fn streaming_dialects_extract_token_usage() {
        assert_eq!(
            parse_stream_usage(
                StreamDialect::ClaudeJson,
                r#"{"type":"result","usage":{"input_tokens":120,"output_tokens":30}}"#
            ),
            TokenUsage {
                input_tokens: Some(120),
                output_tokens: Some(30),
                total_tokens: None,
            }
        );
        assert_eq!(
            parse_stream_usage(
                StreamDialect::AgyJson,
                r#"{"event":"result","result":{"usage":{"prompt_tokens":"80","completion_tokens":20,"total_tokens":100}}}"#
            ),
            TokenUsage {
                input_tokens: Some(80),
                output_tokens: Some(20),
                total_tokens: Some(100),
            }
        );
        assert_eq!(
            parse_stream_usage(
                StreamDialect::CopilotJson,
                r#"{"type":"session.usage_checkpoint","data":{"prompt_tokens":999}}"#
            ),
            TokenUsage::default()
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
    fn copilot_dialect_extracts_reply_deltas_final_text_and_tool_progress() {
        assert_eq!(
            parse_copilot_line(
                r#"{"type":"assistant.message_delta","data":{"deltaContent":"hel"}}"#
            ),
            StreamLineEffect::AssistantText("hel".to_string())
        );
        assert_eq!(
            parse_copilot_line(
                r#"{"type":"tool.execution_start","data":{"toolName":"view","arguments":{"path":"Cargo.toml"}}}"#
            ),
            StreamLineEffect::Progress("view".to_string())
        );
        assert_eq!(
            parse_copilot_line(
                r#"{"type":"assistant.message","data":{"content":"hello","toolRequests":[]}}"#
            ),
            StreamLineEffect::Result("hello".to_string())
        );
    }

    #[test]
    fn stream_dialect_parses_known_names_and_rejects_unknown_ones() {
        assert_eq!(
            StreamDialect::parse("claude").unwrap(),
            StreamDialect::ClaudeJson
        );
        assert_eq!(StreamDialect::parse("agy").unwrap(), StreamDialect::AgyJson);
        assert_eq!(
            StreamDialect::parse("copilot").unwrap(),
            StreamDialect::CopilotJson
        );
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
            "sh",
            PathBuf::from("."),
            CliInvocation {
                args: vec![
                "-c".into(),
                r#"printf '%s\n' '{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash","input":{"description":"Read the readme"}}]}}' '{"type":"result","subtype":"success","is_error":false,"result":"all good"}'"#
                    .into(),
            ],
                system_arg: None,
                dialect: Some(StreamDialect::ClaudeJson),
                workspace_arg: None,
            },
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
            "sh",
            PathBuf::from("."),
            CliInvocation {
                args: vec![
                "-c".into(),
                r#"printf '%s\n' '{"type":"assistant","message":{"content":[{"type":"text","text":"partial reply"}]}}'"#
                    .into(),
            ],
                system_arg: None,
                dialect: Some(StreamDialect::ClaudeJson),
                workspace_arg: None,
            },
        )
        .unwrap();

        let reply = p
            .send_with_progress(None, "ignored", &ProgressSink::disconnected())
            .await
            .unwrap();
        assert_eq!(reply.text, "partial reply");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn streaming_assistant_text_fallback_carries_its_truncation_marker() {
        // Regression guard: an NDJSON stream with no terminal result event produces
        // accumulated lines exceeding MAX_OUTPUT_BYTES, so `AssistantText` stops being
        // appended (see `accumulated_bytes` in `send_streaming`). Because that counter
        // includes each line's full JSON envelope, not just the text pushed onto
        // `assistant_text`, the resulting string can sit under MAX_OUTPUT_BYTES even
        // though real content was dropped — `text.len() > MAX_OUTPUT_BYTES` alone
        // would miss it. `assistant_text_truncated` (fed into `select_stream_reply`)
        // is what catches this and keeps the marker attached, matching the
        // non-streaming path's `send_with_timeout`.
        let chunk = "A".repeat(1024);
        let p = LocalBinaryProvider::new(
            "sh",
            "/bin/sh",
            "sh",
            PathBuf::from("."),
            CliInvocation {
                args: vec![
                    "-c".into(),
                    format!(
                        "i=0; while [ $i -lt 1100 ]; do printf '%s\\n' '{{\"type\":\"assistant\",\"message\":{{\"content\":[{{\"type\":\"text\",\"text\":\"{chunk}\"}}]}}}}'; i=$((i+1)); done"
                    ),
                ],
                system_arg: None,
                dialect: Some(StreamDialect::ClaudeJson),
                workspace_arg: None,
            },
        )
        .unwrap();

        let reply = p
            .send_with_progress(None, "ignored", &ProgressSink::disconnected())
            .await
            .unwrap();

        // Total emitted was 1100 * 1024 = 1,126,400 bytes (> 1,048,576 MAX_OUTPUT_BYTES).
        // Fixture guard: the fallback must have actually been cut, or the marker
        // assertion below would pass even with the fix removed and the accumulation
        // never having reached the cap in the first place.
        assert!(
            reply.text.len() < 1100 * 1024,
            "fixture didn't actually exceed MAX_OUTPUT_BYTES, so this proves nothing: len={}",
            reply.text.len()
        );
        assert!(
            reply.text.contains("output truncated"),
            "a cut fallback reply must say so: len={}",
            reply.text.len()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn streaming_empty_terminal_result_keeps_accumulated_assistant_text() {
        // Regression guard: a stream that already delivered a full answer via
        // `AssistantText` events, then closes with a terminal result carrying an
        // empty `result`/`response` field, must not have that empty value win. See
        // `select_stream_reply` for the precedence and why (an empty terminal result
        // is far more likely to mean "the CLI didn't populate this field" than "throw
        // away the real answer").
        let p = LocalBinaryProvider::new(
            "sh",
            "/bin/sh",
            "sh",
            PathBuf::from("."),
            CliInvocation {
                args: vec![
                    "-c".into(),
                    r#"printf '%s\n' '{"type":"assistant","message":{"content":[{"type":"text","text":"Here is the full and complete answer."}]}}' '{"type":"result","subtype":"success","is_error":false,"result":""}'"#
                        .into(),
                ],
                system_arg: None,
                dialect: Some(StreamDialect::ClaudeJson),
                workspace_arg: None,
            },
        )
        .unwrap();

        let reply = p
            .send_with_progress(None, "ignored", &ProgressSink::disconnected())
            .await
            .unwrap();

        // The accumulated assistant text must survive, not be discarded in favour of
        // the terminal event's empty `result` field.
        assert_eq!(reply.text, "Here is the full and complete answer.");
    }

    // --- select_stream_reply --------------------------------------------------
    //
    // Pure-function tests for the precedence rules behind Fix 1 (a truncated
    // fallback reply must carry its marker) and Fix 2 (an empty terminal result must
    // not discard real accumulated text) — mirrors why `compose_call` and
    // `summarize_stderr` above are tested the same way, independent of process
    // spawning.

    #[test]
    fn select_stream_reply_prefers_a_nonempty_result_over_assistant_text() {
        let (text, truncated) = select_stream_reply(Some("final".into()), "partial".into(), false);
        assert_eq!(text, "final");
        assert!(!truncated);
    }

    #[test]
    fn select_stream_reply_falls_back_to_assistant_text_when_no_result_arrived() {
        let (text, truncated) = select_stream_reply(None, "partial".into(), true);
        assert_eq!(text, "partial");
        assert!(truncated, "the fallback's own truncation flag must survive");
    }

    #[test]
    fn select_stream_reply_prefers_nonempty_assistant_text_over_an_empty_result() {
        // Fix 2: an empty terminal result must not beat a real accumulated answer.
        let (text, truncated) =
            select_stream_reply(Some(String::new()), "the real answer".into(), false);
        assert_eq!(text, "the real answer");
        assert!(!truncated);
    }

    #[test]
    fn select_stream_reply_a_whitespace_only_result_also_counts_as_empty() {
        let (text, _truncated) =
            select_stream_reply(Some("   \n".into()), "the real answer".into(), false);
        assert_eq!(text, "the real answer");
    }

    #[test]
    fn select_stream_reply_keeps_the_truncated_flag_when_falling_back_on_an_empty_result() {
        // Fix 1: falling back to assistant text (here, because the result was empty)
        // must still carry whatever truncation the fallback accumulation itself hit.
        let (text, truncated) = select_stream_reply(Some("  ".into()), "cut off".into(), true);
        assert_eq!(text, "cut off");
        assert!(truncated);
    }

    #[test]
    fn select_stream_reply_returns_the_empty_result_when_everything_is_empty() {
        // Both sides empty: let the caller's own "produced no output" error fire
        // honestly for a genuinely empty run, rather than inventing content here.
        let (text, truncated) = select_stream_reply(Some(String::new()), String::new(), false);
        assert_eq!(text, "");
        assert!(!truncated);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn streaming_stderr_survives_invalid_utf8_instead_of_vanishing() {
        // Regression guard for Fix 3: `read_to_string` rejects the WHOLE buffer on a
        // single invalid byte, so one non-UTF-8 byte anywhere in stderr used to wipe
        // out the entire diagnostic, leaving the user with a bare
        // "sh exited with exit status: 3: " and no explanation. `\301` (octal) is
        // 0xC1, never a valid UTF-8 lead byte, standing in for the stray byte a real
        // CLI's stack trace or mangled-locale output could contain.
        let p = LocalBinaryProvider::new(
            "sh",
            "/bin/sh",
            "sh",
            PathBuf::from("."),
            CliInvocation {
                args: vec![
                    "-c".into(),
                    "printf 'boom \\301 explanation of the failure' >&2; exit 3".into(),
                ],
                system_arg: None,
                dialect: Some(StreamDialect::ClaudeJson),
                workspace_arg: None,
            },
        )
        .unwrap();

        let err = p
            .send_with_progress(None, "ignored", &ProgressSink::disconnected())
            .await
            .unwrap_err()
            .to_string();

        assert!(
            err.contains('3'),
            "the child's own exit status did not survive: {err}"
        );
        // Fixture + fix guard: with `read_to_string`, the single invalid byte drops
        // the ENTIRE buffer, so text on BOTH sides of it would be lost — checking
        // just one side could pass by accident if only a prefix or suffix survived.
        assert!(
            err.contains("boom"),
            "diagnostic text before the bad byte was lost: {err}"
        );
        assert!(
            err.contains("explanation of the failure"),
            "diagnostic text after the bad byte was lost: {err}"
        );
    }

    #[test]
    fn claude_dialect_concatenates_multiple_text_blocks_in_assistant_message() {
        let line = r#"{"type":"assistant","message":{"content":[{"type":"text","text":"Part 1. "},{"type":"text","text":"Part 2."}]}}"#;
        assert_eq!(
            parse_claude_line(line),
            StreamLineEffect::AssistantText("Part 1. Part 2.".to_string())
        );
    }

    #[test]
    fn claude_dialect_falls_back_to_command_when_description_is_empty_string() {
        let line = r#"{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash","input":{"command":"cat README.md","description":""}}]}}"#;
        assert_eq!(
            parse_claude_line(line),
            StreamLineEffect::Progress("Bash: cat README.md".to_string())
        );
    }

    #[test]
    fn claude_dialect_error_result_uses_the_error_field_when_result_is_empty() {
        // Pins the `.filter(|s| !s.trim().is_empty())` guard on the `error` field:
        // with the `!` dropped, the filter would keep only a blank `error` value and
        // discard a genuine one, falling through past it to the `subtype`/default
        // fallback instead of surfacing the real message.
        let line = r#"{"type":"result","is_error":true,"result":"","error":"rate limited"}"#;
        match parse_claude_line(line) {
            StreamLineEffect::Failure(reason) => assert_eq!(reason, "rate limited"),
            other => panic!("expected a Failure, got {other:?}"),
        }
    }

    #[test]
    fn claude_dialect_error_result_falls_back_when_result_field_is_empty() {
        let line =
            r#"{"type":"result","subtype":"error_during_execution","is_error":true,"result":""}"#;
        match parse_claude_line(line) {
            StreamLineEffect::Failure(reason) => {
                assert!(!reason.is_empty(), "reason must not be empty");
                assert_eq!(reason, "error_during_execution");
            }
            other => panic!("expected Failure, got {other:?}"),
        }
    }

    #[test]
    fn agy_dialect_falls_back_to_status_when_error_field_is_empty_string() {
        let line = r#"{"event":"result","result":{"status":"PERMISSION_DENIED","error":""}}"#;
        match parse_agy_line(line) {
            StreamLineEffect::Failure(reason) => assert_eq!(reason, "PERMISSION_DENIED"),
            other => panic!("expected Failure, got {other:?}"),
        }
    }

    #[test]
    fn agy_dialect_omits_colon_when_tool_name_is_empty_string() {
        let line =
            r#"{"event":"step_update","step_update":{"step_type":"thinking","tool_name":""}}"#;
        assert_eq!(
            parse_agy_line(line),
            StreamLineEffect::Progress("thinking".to_string())
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn streaming_progress_flood_does_not_starve_subsequent_assistant_text() {
        let chunk = "x".repeat(1024);
        let script = format!(
            r#"i=0; while [ $i -lt 1100 ]; do printf '%s\n' '{{"type":"assistant","message":{{"content":[{{"type":"tool_use","name":"Bash","input":{{"command":"{chunk}"}}}}]}}}}'; i=$((i+1)); done; printf '%s\n' '{{"type":"assistant","message":{{"content":[{{"type":"text","text":"final valid reply"}}]}}}}'; exit 0"#
        );
        let p = LocalBinaryProvider::new(
            "sh",
            "/bin/sh",
            "sh",
            PathBuf::from("."),
            CliInvocation {
                args: vec!["-c".into(), script],
                system_arg: None,
                dialect: Some(StreamDialect::ClaudeJson),
                workspace_arg: None,
            },
        )
        .unwrap();

        let reply = p
            .send_with_progress(None, "ignored", &ProgressSink::disconnected())
            .await
            .expect("should not fail with produced no output");
        assert_eq!(reply.text, "final valid reply");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn nonstreaming_child_does_not_inherit_stdin_and_blocks() {
        let p = LocalBinaryProvider::new(
            "sh",
            "/bin/sh",
            "sh",
            PathBuf::from("."),
            CliInvocation {
                args: vec!["-c".into(), "cat; echo done".into()],
                system_arg: None,
                dialect: None,
                workspace_arg: None,
            },
        )
        .unwrap();
        let reply = p
            .send_with_timeout(None, "ignored", Duration::from_millis(200))
            .await
            .expect("cat on null stdin should exit immediately");
        assert_eq!(reply.text, "done");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn streaming_post_stream_wait_timeout_carries_typed_timeout_failure() {
        let p = LocalBinaryProvider::new(
            "sh",
            "/bin/sh",
            "sh",
            PathBuf::from("."),
            CliInvocation {
                args: vec!["-c".into(), "exec 1>&-; sleep 5".into()],
                system_arg: None,
                dialect: Some(StreamDialect::ClaudeJson),
                workspace_arg: None,
            },
        )
        .unwrap();

        let err = p
            .send_streaming_with_timeouts(
                StreamDialect::ClaudeJson,
                None,
                "ignored",
                &ProgressSink::disconnected(),
                Duration::from_secs(5),
                Duration::from_millis(50),
            )
            .await
            .unwrap_err();
        let timeout = err
            .chain()
            .find_map(|c| c.downcast_ref::<crate::providers::ProviderFailure>());
        assert!(
            matches!(timeout, Some(crate::providers::ProviderFailure::Timeout)),
            "expected Timeout, got {timeout:?}"
        );
    }

    #[test]
    fn test_reproduction_agy_dialect_accepts_lowercase_success_status() {
        let line = r#"{"event":"result","result":{"status":"success","response":"All good.\n"}}"#;
        assert_eq!(
            parse_agy_line(line),
            StreamLineEffect::Result("All good.\n".to_string()),
            "lowercase 'success' status must be treated as successful Result, not Failure"
        );
    }

    #[test]
    fn test_reproduction_agy_dialect_extracts_error_object_message() {
        let line = r#"{"event":"result","result":{"status":"ERROR","error":{"message":"Permission check failed"}}}"#;
        match parse_agy_line(line) {
            StreamLineEffect::Failure(reason) => {
                assert_eq!(reason, "Permission check failed");
            }
            other => panic!("expected Failure, got {other:?}"),
        }
    }

    #[test]
    fn test_reproduction_agy_dialect_handles_top_level_error_event() {
        let line = r#"{"event":"error","error":"Authentication failed"}"#;
        match parse_agy_line(line) {
            StreamLineEffect::Failure(reason) => {
                assert_eq!(reason, "Authentication failed");
            }
            other => panic!("expected Failure, got {other:?}"),
        }
    }

    #[test]
    fn test_reproduction_claude_dialect_handles_top_level_error_event() {
        let line = r#"{"type":"error","error":{"message":"Invalid API key"}}"#;
        match parse_claude_line(line) {
            StreamLineEffect::Failure(reason) => {
                assert_eq!(reason, "Invalid API key");
            }
            other => panic!("expected Failure, got {other:?}"),
        }
    }

    #[test]
    fn test_claude_dialect_top_level_whitespace_only_message_falls_through_to_default_reason() {
        // No `error` field, and `message` is whitespace-only -- the `or_else` fallback
        // must reject it (not accept it as the failure reason), so this falls all the
        // way through to the generic "error" default.
        let line = r#"{"type":"error","message":"   "}"#;
        match parse_claude_line(line) {
            StreamLineEffect::Failure(reason) => {
                assert_eq!(reason, "error");
            }
            other => panic!("expected Failure, got {other:?}"),
        }
    }

    #[test]
    fn test_claude_dialect_top_level_message_is_used_as_failure_reason() {
        // No `error` field, but `message` carries real text -- the `or_else` fallback
        // must accept and surface it verbatim.
        let line = r#"{"type":"error","message":"real text"}"#;
        match parse_claude_line(line) {
            StreamLineEffect::Failure(reason) => {
                assert_eq!(reason, "real text");
            }
            other => panic!("expected Failure, got {other:?}"),
        }
    }

    #[test]
    fn test_reproduction_claude_dialect_extracts_error_object_message_on_result() {
        let line = r#"{"type":"result","is_error":true,"result":"","error":{"message":"Credit balance is too low"}}"#;
        match parse_claude_line(line) {
            StreamLineEffect::Failure(reason) => {
                assert_eq!(reason, "Credit balance is too low");
            }
            other => panic!("expected Failure, got {other:?}"),
        }
    }

    #[test]
    fn test_reproduction_claude_dialect_detects_error_subtype_when_is_error_omitted() {
        let line = r#"{"type":"result","subtype":"error_during_execution","result":"Credit balance is too low"}"#;
        match parse_claude_line(line) {
            StreamLineEffect::Failure(reason) => {
                assert_eq!(reason, "Credit balance is too low");
            }
            other => panic!("expected Failure, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_reproduction_streaming_stdout_survives_invalid_utf8_in_progress_event() {
        let p = LocalBinaryProvider::new(
            "sh",
            "/bin/sh",
            "sh",
            PathBuf::from("."),
            CliInvocation {
                args: vec![
                    "-c".into(),
                    "printf '{\"type\":\"assistant\",\"message\":{\"content\":[{\"type\":\"tool_use\",\"name\":\"Bash\",\"input\":{\"description\":\"bad \\301 byte\"}}]}}\n{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":false,\"result\":\"final answer\"}\n'".into(),
                ],
                system_arg: None,
                dialect: Some(StreamDialect::ClaudeJson),
                workspace_arg: None,
            },
        )
        .unwrap();

        let reply = p
            .send_with_progress(None, "ignored", &ProgressSink::disconnected())
            .await
            .expect(
                "streaming stdout with non-utf8 progress bytes must decode lossily and succeed",
            );
        assert_eq!(reply.text, "final answer");
    }

    #[test]
    fn test_reproduction_agy_dialect_extracts_error_from_message_fields() {
        let line1 = r#"{"event": "error", "message": "Failed to launch subagent"}"#;
        assert_eq!(
            parse_agy_line(line1),
            StreamLineEffect::Failure("Failed to launch subagent".to_string())
        );

        let line2 = r#"{"event": "result", "result": {"status": "ERROR", "message": "Quota limit reached"}}"#;
        assert_eq!(
            parse_agy_line(line2),
            StreamLineEffect::Failure("Quota limit reached".to_string())
        );
    }
}

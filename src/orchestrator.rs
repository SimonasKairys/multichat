//! The engine that ties the TUI, the providers, the ledger, and the audit log together.
//!
//! This is the module the previous version was missing entirely: every provider,
//! the vault, the ledger, and the audit logger existed but had no caller, so user input
//! never reached a model.

use anyhow::{Result, anyhow};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

use crate::app::ActivityKind;
use crate::audit::AuditLogger;
use crate::config::{ConnectionSpec, Credentials, Paths, Settings, Transport};
use crate::providers::{
    ProgressSink, Provider,
    cloud::CloudProvider,
    http_client,
    local_binary::{CliInvocation, LocalBinaryProvider, StreamDialect},
    ollama::OllamaProvider,
};
use crate::skills::SkillsDir;
use crate::swarm::SwarmLedger;
use crate::workspace::Workspace;

/// Delegations honoured per user turn, so a model cannot spin the swarm forever.
const MAX_DELEGATIONS_PER_TURN: usize = 3;

/// How many files one model may write in a single turn.
///
/// Higher than `MAX_DELEGATIONS_PER_TURN`, which it used to borrow, because the two
/// bound different things. A delegation costs a model call; a write costs a disk write
/// the user has already been shown and has approved one at a time. Creating a project
/// from nothing is the case that needs the headroom — a README, a module, a test and a
/// manifest is already four — and the user, not this number, is the real limit on how
/// much lands.
const MAX_WRITES_PER_TURN: usize = 10;

/// The commander directive prepended to the user's own prompt, or `None` when the
/// commander is the only model connected and there is therefore nobody to delegate to.
///
/// The delegation protocol already lives in the system prompt (see
/// `SwarmLedger::system_prompt`), and for a plain API or Ollama model that is enough —
/// emitting `ACTION:` lines is the only way such a model can act at all. It is NOT
/// enough for an agentic CLI provider. `claude` and `agy` ship their own system prompt
/// and their own tool loop; handed simon's protocol via `--system-prompt`, they
/// ignore it and do the work with their own `Bash`/`Read` tools instead. That was
/// measured, not assumed: with the delegation mandate in the system prompt alone, a
/// `claude` commander asked to audit a project ran six of its own tool calls and
/// delegated nothing. With the same mandate in the user turn, it delegated three
/// well-formed tasks to the cheap model instead.
///
/// So the directive rides in the user turn, where an agentic CLI weights it against
/// its own instructions rather than under them. It is deliberately short and
/// conditional — prepending a heavy "you must delegate" block to every message would
/// make a commander delegate the word "hi" — and it defers to the model's judgement on
/// whether the question actually needs any work doing.
fn commander_preamble(primary: &str, roster: &[String]) -> Option<String> {
    let others: Vec<&str> = roster
        .iter()
        .map(String::as_str)
        .filter(|label| *label != primary)
        .collect();
    if others.is_empty() {
        return None;
    }

    Some(format!(
        "[swarm] You are the commander. Connected and available to you: {}.\n\
         If this needs no more than a direct answer, give it and ignore the rest.\n\
         Otherwise work in three steps and do not jump to the third.\n\
         1. ORIENT. Look before you decide anything. List the directories that \
         matter and read the few files that actually determine the answer, using \
         your own list-files and read-file requests — their results reach you on \
         your NEXT turn. Do not delegate this part: a sub-agent sees only the prompt \
         you write for it, so a task written before you looked is a task written \
         from guesswork. Read only what you need in order to plan; bulk reading is \
         still work to hand off.\n\
         2. PROPOSE, and stop. Say what you found, what you intend to do, any real \
         alternative worth weighing and why you prefer yours, and exactly which \
         tasks you would give to which model and why that model. Then stop and let \
         the user answer. They know things the files do not, and a plan is far \
         cheaper to correct than finished files are.\n\
         3. DELEGATE, once the plan has been agreed. Hand each piece to the cheapest \
         capable model with `ACTION: delegate_task(<label>, <self-contained \
         prompt>)`, then stop and say what you delegated; results reach you on your \
         NEXT turn. A sub-agent can create and edit project files, so \"build X\" is \
         delegated like anything else: tell it exactly which files to write and what \
         each must contain. Give one file, or one coherent group of files, per \
         delegation. Keep only judgement and synthesis for yourself.\n\
         If the user has already told you what to do, or already approved a plan, \
         treat step 2 as done and get on with it — do not re-propose what has been \
         settled.\n\
         --- the user's message follows ---\n",
        others.join(", ")
    ))
}

/// Sent from the UI to the orchestrator.
pub enum Command {
    Prompt(String),
    Shutdown,
    /// A new connection set was applied (from the picker, reopened with Ctrl+O/F2
    /// inside chat). The orchestrator rebuilds its registry from this and resets the
    /// swarm roster so the system prompt matches reality.
    Reconfigure(Settings),
    /// `/commander <name>` typed in chat: switch the primary, live, to whatever
    /// `name` resolves to against the current registry (exact label, bare model
    /// name, or provider name — the same rule `Registry::get` uses).
    SetCommander(String),
}

impl std::fmt::Debug for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Command::Prompt(p) => f.debug_tuple("Prompt").field(p).finish(),
            Command::Shutdown => write!(f, "Shutdown"),
            // `Settings` can carry API-shaped strings the user typed as endpoint
            // overrides; never derive Debug through it into a log line.
            Command::Reconfigure(_) => write!(f, "Reconfigure(..)"),
            // User-typed but not secret (it is a model name/label the user chose),
            // unlike `Settings` above — fine to print verbatim.
            Command::SetCommander(name) => f.debug_tuple("SetCommander").field(name).finish(),
        }
    }
}

/// Sent from the orchestrator back to the UI.
#[derive(Debug, Clone)]
pub enum Event {
    /// A model produced a reply.
    Reply { label: String, text: String },
    /// A delegation was dispatched. `task` is the sub-agent's prompt, truncated to
    /// `MAX_TASK_DISPLAY_CHARS` for display — the audit log already records the
    /// delegation by size and label only (see `run_delegations`'s `task.delegated`
    /// call), and that must stay true; this field exists for the TUI transcript
    /// only, never for a `self.audit.log(...)` detail string.
    Delegated {
        from: String,
        to: String,
        task: String,
    },
    /// A delegation finished, successfully or not. Emitted from both the `Ok` and
    /// `Err` arms of `run_delegations`'s provider call, so the status line's activity
    /// indicator always has a terminal event to clear on (see `App::apply`) — a
    /// delegation that only reported success would leave a failed one spinning
    /// forever.
    DelegationFinished {
        to: String,
        ok: bool,
        chars: usize,
        millis: u64,
    },
    /// A delegation failed transiently and is about to be attempted again. Carries
    /// the reason so the user can see WHY it is retrying rather than watching the
    /// same task silently restart — a retry that hides its cause is indistinguishable
    /// from a hang.
    DelegationRetry {
        to: String,
        attempt: usize,
        max: usize,
        reason: String,
    },
    /// A model wants to write a file and is waiting for the user to allow it. The
    /// orchestrator blocks on a `WriteDecision` until the UI answers, so nothing
    /// reaches disk before the user has seen this.
    WriteRequested {
        /// Which model is asking. A sub-agent can propose writes too, and "agy wants
        /// to overwrite this" is a materially different question from "your commander
        /// does".
        author: String,
        path: String,
        bytes: usize,
        /// Size of the file this would overwrite, or `None` when creating a new one.
        /// The single most important thing to know before answering.
        overwrites: Option<u64>,
        preview: String,
    },
    /// The user refused a write. Distinct from `Error`: nothing went wrong.
    WriteDenied { author: String, path: String },
    /// A skill was read successfully. A failed read still goes through `Event::Error`
    /// (unchanged), which is enough on its own to clear the activity indicator.
    SkillLoaded { name: String, chars: usize },
    /// The session started waiting on `label` for the reason in `kind`. There is no
    /// matching "activity stopped" event — every other `Event` variant clears it (see
    /// `App::apply`), so a `TurnComplete`, `Reply`, `Error`, `DelegationFinished`, or
    /// `SkillLoaded` that follows is what ends it, not a paired stop event here.
    ActivityStarted { label: String, kind: ActivityKind },
    /// A streaming CLI provider reported progress (a tool call, a step) while its
    /// call is still in flight. `label` matches the `ActivityStarted` this updates —
    /// see `App::apply`, which folds this into the existing activity in place rather
    /// than treating it as a new one. Never logged to the audit trail: this is
    /// high-volume, third-party CLI output, not something simon itself decided to
    /// do — see the audit log's existing rule against putting tool output or file
    /// contents into the log.
    ActivityProgress { label: String, detail: String },
    /// A model wrote a file into the sandboxed workspace via `ACTION: write_file`.
    /// Carries only the path — never content, same reasoning as `WrittenFile` in
    /// `swarm.rs` — so the user can see that a write happened without this event
    /// itself becoming a way to smuggle file content through the TUI.
    FileWritten { author: String, path: String },
    /// A project file was read successfully via `ACTION: read_file(...)`. Carries
    /// only the path and a size, never content — same reasoning as `FileWritten`. A
    /// failed read still goes through `Event::Error` (unchanged), which is enough on
    /// its own to clear the activity indicator.
    FileRead { path: String, chars: usize },
    /// A project directory was listed successfully via `ACTION: list_files(...)`.
    /// `path` is the requested directory, empty for the project root; `entries` is
    /// the entry count, never the entries themselves — same reasoning as
    /// `FileWritten`. Same failure handling as `FileRead`.
    FilesListed { path: String, entries: usize },
    /// Something went wrong; the session continues.
    Error(String),
    /// The orchestrator has finished handling a turn.
    TurnComplete,
    /// A new connection set was applied successfully.
    Reconfigured {
        primary: String,
        roster: Vec<String>,
    },
    /// `/commander <name>` resolved and switched the primary. `connection_id` is
    /// `settings.commander`'s key (see `Registry::connection_id`'s doc comment for
    /// why that differs from `label`) — `None` only if the label somehow has no
    /// backing connection id, in which case the UI still switches for the session
    /// but has nothing to persist.
    CommanderChanged {
        label: String,
        connection_id: Option<String>,
    },
}

/// Ceiling on how much of a delegated task's prompt is shown in the TUI transcript —
/// mirrors `MAX_DELEGATIONS_PER_TURN`'s bound-the-noise reasoning, just for one line's
/// length instead of a turn's total effort.
const MAX_TASK_DISPLAY_CHARS: usize = 120;

/// Ceiling on how much of a single streaming-CLI progress detail is kept before it
/// reaches an `Event::ActivityProgress`. Mirrors `MAX_TASK_DISPLAY_CHARS`'s reasoning,
/// just for a status-line detail instead of a transcript line — short enough that it
/// never wraps the status line on its own.
/// The directive prepended to a delegated task's prompt before it is sent.
///
/// Symmetric with `commander_preamble` and for the same underlying reason: an
/// agentic CLI has its own ideas about how to work, and the only lever simon has over
/// them is the text of the turn.
///
/// A sub-agent's reply is the ENTIRE result that reaches simon — there is no second
/// round trip in which to collect anything it deferred. Left to itself, `agy` will
/// dispatch a subagent of its own and return immediately with
/// "I have delegated running `ls -1` to a subagent and am waiting for the results",
/// which its stream reports as `status: SUCCESS`. That is the worst possible shape of
/// failure: simon records a completed task whose content is a promise, and the
/// commander then synthesises an answer out of nothing.
///
/// The second half addresses a separate failure with the same root: `agy`'s permission
/// system does not function in non-interactive print mode at all — there is nobody
/// present to approve anything. Captured from the real audit log: `permission check
/// failed for command "python3 -c ..."` (agy shelling out to check its own work),
/// `permission check failed for command "git log -p -n 5"` (agy shelling out to read
/// history), and — the same failure hitting agy's own tools, not just ours —
/// `declaring permissions: cortex tool write_to_file: convert tool call for
/// permissions: model output error: invalid tool call error (invalid_args) <path>`.
/// Reading files needs no permission and was measured to work reliably, so that is all
/// that is left on offer: shell commands and agy's own writer/editor tools are refused
/// outright, not merely discouraged, because "prefer not to" still leaves the
/// tempting cases — run the code to check it, `git log` to see what changed — as live
/// options that fail the task. simon cannot grant the missing permission itself; the
/// only switch on offer is agy's blanket `--dangerously-skip-permissions`, which was
/// deliberately rejected: it would auto-approve every tool call agy makes, and agy's
/// own file writes already bypass simon's write-approval gate and audit log when
/// permission checking is out of the way — four such files were observed appearing
/// during delegations simon had recorded as *failed*. Skipping permissions would make
/// that worse, not better. Keeping the sub-agent to permission-free tools and routing
/// every file it produces back through simon's own write protocol closes that hole:
/// the write is plain text in the reply, so it lands on simon's side of the gate.
fn subagent_preamble() -> &'static str {
    "[sub-agent] Complete this task fully in THIS reply. Do not dispatch, launch, or \
     delegate to a subagent of your own, and do not answer that you are waiting on \
     one: your reply is the entire result that reaches the requester, so anything you \
     defer is lost. If you genuinely cannot finish, say what you found and what \
     blocked you.\n\
     Do not run any shell, terminal, or command-line tool for any reason. This \
     includes running or executing code to check that it works, and inspecting git \
     history or git log. You are running non-interactively with nobody present to \
     approve a command, so any attempt to run one is refused and fails this task — \
     do not try, even once, even to verify something you already wrote.\n\
     Do not use your own file-writing or file-editing tools either, for the same \
     reason: a file written that way is invisible to this system and to the user, is \
     not recorded anywhere, and does not count as this task being done, even if the \
     tool call itself appears to succeed.\n\
     Reading files and listing directories needs no permission and is fine to use \
     freely.\n\
     If this task is to CREATE or EDIT a file, the only way that file actually \
     reaches the project is to emit it as plain text in your reply, using the marker \
     that opens a write block followed by the path in parentheses, then the file's \
     complete final content, then the matching end-of-file marker — one such block \
     per file. Describing a file, or quoting it in prose outside such a block, writes \
     nothing.\n\
     --- the task follows ---\n"
}

/// The user's answer to a pending write request.
///
/// `ApproveAll` is per-session, not persisted: a user who trusts one turn's writes has
/// not necessarily agreed to be asked nothing for the rest of time, and a persisted
/// "yes to everything" is exactly the setting people forget they enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteDecision {
    Approve,
    ApproveAll,
    Deny,
}

/// How much of a pending file's content is shown before the user decides.
///
/// A write is unreviewable if the user cannot see what it says, but a 256KB file
/// (`workspace::MAX_FILE_BYTES`) would bury the question itself off-screen. The size
/// and path are always exact; this only bounds the body.
const WRITE_PREVIEW_LINES: usize = 20;
const WRITE_PREVIEW_CHARS: usize = 1200;

/// Renders the head of a pending write's content for the confirmation prompt, marking
/// it when truncated so a preview is never mistaken for the whole file.
fn write_preview(content: &str) -> String {
    let mut out = String::new();
    let total_lines = content.lines().count();
    for line in content.lines().take(WRITE_PREVIEW_LINES) {
        out.push_str(line);
        out.push('\n');
    }
    if let Some((cut, _)) = out.char_indices().nth(WRITE_PREVIEW_CHARS) {
        out.truncate(cut);
        out.push_str("…\n");
    }
    if total_lines > WRITE_PREVIEW_LINES {
        out.push_str(&format!(
            "… {} more line(s) not shown\n",
            total_lines - WRITE_PREVIEW_LINES
        ));
    }
    out
}

/// How many times a delegated task is attempted before it is reported as failed.
///
/// Not defensive padding — measured. An agentic CLI sub-agent fails transiently in
/// several unrelated ways, all observed from `agy` on this machine while running the
/// identical command twice in a row: `another active schedule task "<id>"` (it keeps
/// session state alive briefly after its process exits, so a delegation that starts
/// promptly after the previous one is refused), `invalid arguments: missing
/// properties 'toolSummary', 'toolAction'` (an internal error of its own), and
/// `CANCELED`. A failed delegation is expensive in a way a failed HTTP call is not:
/// the commander does not learn of it until its NEXT turn, so one transient blip
/// costs the user a full round trip.
const MAX_DELEGATION_ATTEMPTS: usize = 3;

/// How long to wait before each retry. Indexed by attempts already made, so the
/// first retry waits `[0]` and the second `[1]`; must therefore hold
/// `MAX_DELEGATION_ATTEMPTS - 1` entries. Deliberately several seconds rather than
/// milliseconds: the failure this most often clears is a sub-agent's own session
/// state not having been released yet, which no amount of immediate hammering fixes.
const DELEGATION_RETRY_BACKOFF: [Duration; MAX_DELEGATION_ATTEMPTS - 1] =
    [Duration::from_secs(3), Duration::from_secs(8)];

/// Whether a failed delegation is worth another attempt.
///
/// The default is to retry: sub-agent failures are dominated by the transient CLI
/// errors described on `MAX_DELEGATION_ATTEMPTS`, and a wrongly-retried permanent
/// failure costs a few seconds while a wrongly-abandoned transient one costs the user
/// a whole turn. The exceptions are the cases where retrying is either useless or
/// actively harmful:
///
/// - a timeout has already spent the caller's patience (up to an hour for a streaming
///   CLI, see `local_binary`); doing that twice more is not a recovery strategy;
/// - a misconfigured binary (missing path, empty path) fails identically forever;
/// - a `--classified` refusal is a policy decision, not a blip.
fn is_retryable_delegation_error(error: &str) -> bool {
    const PERMANENT: &[&str] = &[
        "timed out",
        "does not exist",
        "has an empty path",
        "classified",
    ];
    let lowered = error.to_ascii_lowercase();
    !PERMANENT.iter().any(|marker| lowered.contains(marker))
}

const MAX_PROGRESS_DETAIL_CHARS: usize = 80;

/// Truncates `s` to at most `max_chars` characters, appending `…` when cut. Same
/// char-boundary-safe approach as `swarm::record_result`/`providers::truncate_error_detail`
/// (and the panic class commit `923b934` fixed in `cloud.rs`): `s` here is a
/// delegated task's prompt, which is free-form model output and may contain
/// multi-byte UTF-8, so slicing on a raw byte index can land mid-character and panic.
fn truncate_chars(s: &str, max_chars: usize) -> String {
    match s.char_indices().nth(max_chars) {
        Some((cut, _)) => format!("{}…", &s[..cut]),
        None => s.to_string(),
    }
}

/// Sanitises one streaming-CLI progress detail before it reaches an
/// `Event::ActivityProgress`. This is third-party process output — a `tool_use`
/// description, a step's `text_delta` — not text simon itself produced, so it is
/// treated the same as any other untrusted model/tool output reaching the TUI:
/// control characters (which includes `\n`/`\r`) are stripped so a detail line can
/// never smuggle a terminal escape sequence or turn one status line into several, and
/// the result is truncated with `truncate_chars`, never a raw byte index — the same
/// panic class commit `923b934` fixed in `cloud.rs`.
fn sanitize_progress_detail(raw: &str) -> String {
    let cleaned: String = raw.chars().filter(|c| !c.is_control()).collect();
    truncate_chars(cleaned.trim(), MAX_PROGRESS_DETAIL_CHARS)
}

/// Whether a candidate connection can actually be constructed right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Availability {
    Available,
    /// Carries the reason shown in the picker's hint line, e.g. "no key stored".
    Unavailable(String),
}

impl Availability {
    pub fn is_available(&self) -> bool {
        matches!(self, Availability::Available)
    }
}

/// Enough to construct a `LocalBinaryProvider` for a CLI transport option, captured
/// at discovery time so construction never has to re-probe `PATH`.
#[derive(Debug, Clone)]
pub struct CliSpec {
    pub binary_name: String,
    pub path: String,
    pub args: Vec<String>,
    pub system_arg: Option<String>,
    /// `Some` when this CLI's stdout is a recognised NDJSON progress dialect;
    /// resolved once here (from `known_cli_default` or a validated
    /// `LocalBinarySpec::stream_format`) so `construct_provider` never has to
    /// re-parse or re-validate it.
    pub dialect: Option<StreamDialect>,
    /// The flag this CLI uses to declare an extra allowed working directory, or
    /// `None` when it has none. Set to `--add-dir` for both known agentic CLIs — see
    /// `CliDefaults::workspace_arg` for why it matters.
    pub workspace_arg: Option<String>,
}

/// One way to reach a [`Candidate`]: a specific transport, its availability, and
/// (for `Cli`) enough to construct it.
#[derive(Debug, Clone)]
pub struct TransportOption {
    /// `None` for Ollama, which has exactly one transport and no choice to make.
    pub transport: Option<Transport>,
    /// Display label for the picker row, e.g. `"via CLI"` — empty for Ollama.
    pub label: String,
    /// Shown alongside the label: a resolved path, an endpoint host, or `"(no key
    /// stored)"`.
    pub detail: String,
    pub availability: Availability,
    /// Present only when `transport == Some(Transport::Cli)`.
    pub cli: Option<CliSpec>,
    /// `true` only for the "no key stored" API row: the one case the picker can fix
    /// on its own, by prompting for a key and writing it to the keyring. Every other
    /// unavailable reason (a classified-mode refusal, a keyring read error) needs
    /// something outside the picker to resolve, so this must never be set from the
    /// reason string — only from the specific `Credentials::get` outcome below.
    pub needs_key: bool,
}

/// A connectable model the picker can show the user, whether or not it can actually
/// be reached right now. Unavailable candidates are included deliberately: the
/// picker renders them dimmed with a reason instead of omitting them, so a row is
/// never shown as selectable and then silently dropped during construction.
#[derive(Debug, Clone)]
pub struct Candidate {
    /// Storage key into `Settings::connections`. Shared by every transport option of
    /// the same connection — this is what makes ticking "via API" and ticking "via
    /// CLI" for the same vendor mutually exclusive rather than two unrelated
    /// bookkeeping entries.
    pub id: String,
    /// Display heading in the picker, e.g. `"ANTHROPIC"`.
    pub group: String,
    /// The model or binary name shown next to the checkbox.
    pub model: String,
    /// One entry per selectable transport; more than one only for a connection like
    /// Anthropic that is reachable via CLI or API.
    pub transports: Vec<TransportOption>,
}

/// Maps a CLI binary name to the vendor connection id it shares with a cloud
/// endpoint, so "via CLI" and "via API" rows for the same vendor read and write the
/// same `ConnectionSpec`. Anything not in this list is its own id (e.g. `codex`,
/// `llm`, or a user's custom `local_binaries` entry).
fn cli_vendor_id(binary_name: &str) -> String {
    match binary_name {
        "claude" => "anthropic".to_string(),
        "gemini" => "google".to_string(),
        // `agy` (Antigravity) deliberately gets its own id rather than sharing
        // `google`: it is a gateway that serves Gemini, Claude and gpt-oss models
        // alike, so pairing it with the Gemini API row would misrepresent it.
        other => other.to_string(),
    }
}

/// Args, system-prompt flag, and NDJSON dialect for a CLI this build knows how to
/// auto-detect. Verified live on this machine (see the ground truth captured on the
/// task this streaming support was built from):
///
/// - `claude`: flags before the prompt — `-p --output-format stream-json --verbose`
///   — plus `--system-prompt <text>`, streaming the `ClaudeJson` dialect.
/// - `agy` (Antigravity): flags must precede `-p` — `--output-format stream-json -p`
///   — with `-p` anywhere after them breaks nothing, but `-p --output-format ...`
///   does: `agy` takes `--output-format` itself as the prompt in that order. No
///   system-prompt flag at all, so its system text is folded into the prompt (see
///   `LocalBinaryProvider::send`). Streams the `AgyJson` dialect.
///
/// `codex` and `llm` are unverified best guesses, treated the same as before: no
/// args, no system flag, and no streaming dialect until someone confirms their real
/// shape.
/// What a known agentic CLI needs on its command line, resolved in one place.
///
/// A struct rather than a tuple because there are now four of these and a
/// `(Vec<String>, Option<String>, Option<StreamDialect>, Option<String>)` at every
/// call site says nothing about which `Option<String>` is which.
struct CliDefaults {
    args: Vec<String>,
    system_arg: Option<String>,
    dialect: Option<StreamDialect>,
    /// The flag that declares an additional directory the CLI may work in.
    ///
    /// Not cosmetic. An agentic CLI that does not know where its project is will go
    /// looking: asked to read `src/` and `data.csv`, `agy` ran
    /// `find /home/main -name "data.csv" -o -name "src"` — a scan of the user's entire
    /// home directory — and only its own permission check stopped it. Passing
    /// `--add-dir <project root>` tells it where the work actually is, which both
    /// makes it succeed and keeps it from wandering. `Command::current_dir` alone was
    /// not enough to convey this.
    workspace_arg: Option<String>,
}

fn known_cli_default(binary_name: &str) -> CliDefaults {
    match binary_name {
        "claude" => CliDefaults {
            args: vec![
                "-p".into(),
                "--output-format".into(),
                "stream-json".into(),
                "--verbose".into(),
            ],
            system_arg: Some("--system-prompt".into()),
            dialect: Some(StreamDialect::ClaudeJson),
            workspace_arg: Some("--add-dir".into()),
        },
        // `--sandbox` runs agy under its own terminal restrictions, which is what
        // lets it work without prompting for permission on every command. Its
        // `--print-timeout` defaults to 5m, short enough to clip a real delegated
        // task; raised well past that so simon's own idle/total limits (see
        // `local_binary`) are the ones that actually govern. Note the flag order:
        // agy's `-p` takes the NEXT argument as its prompt, so every flag must
        // precede it.
        "agy" => CliDefaults {
            args: vec![
                "--sandbox".into(),
                "--print-timeout".into(),
                "30m".into(),
                "--output-format".into(),
                "stream-json".into(),
                "-p".into(),
            ],
            system_arg: None,
            dialect: Some(StreamDialect::AgyJson),
            workspace_arg: Some("--add-dir".into()),
        },
        _ => CliDefaults {
            args: Vec::new(),
            system_arg: None,
            dialect: None,
            workspace_arg: None,
        },
    }
}

/// Every CLI tool this build can act as a provider for: whatever the user configured
/// explicitly in `local_binaries` (which always wins), plus anything from the known
/// list found on `PATH`.
fn detect_cli_tools(settings: &Settings) -> Vec<CliSpec> {
    // `gemini` is deliberately absent: Google retired free Code Assist for
    // individuals on that CLI's OAuth login, so auto-detecting it only ever produced
    // a row that failed on first use. `agy` is its replacement. A user who still has
    // a working `gemini` can add it under `local_binaries`, which always wins.
    const KNOWN: &[&str] = &["claude", "agy", "codex", "llm"];
    let mut found = Vec::new();
    let mut configured = std::collections::BTreeSet::new();

    for (name, spec) in &settings.local_binaries {
        configured.insert(name.clone());
        // A hand-configured CLI keeps dialect `None` (the plain-text path) unless the
        // user opts in via `stream_format`. An unrecognised value is a clear
        // discovery-time error, not a silent fallback to non-streaming — the whole
        // point of validating here rather than swallowing it into `None` — so the
        // entry is skipped entirely and explained on stderr, the same visibility
        // `Registry::build`'s `eprintln!("[discovery] skipping ...")` gives a bad
        // path or a missing key.
        let dialect = match &spec.stream_format {
            None => None,
            Some(fmt) => match StreamDialect::parse(fmt) {
                Ok(d) => Some(d),
                Err(e) => {
                    eprintln!("[discovery] local binary `{name}`: {e}");
                    continue;
                }
            },
        };
        found.push(CliSpec {
            binary_name: name.clone(),
            path: spec.path.clone(),
            args: spec.args.clone(),
            system_arg: spec.system_arg.clone(),
            dialect,
            // Tied to the declared dialect rather than the entry's name: declaring
            // `stream_format = "claude"` or `"agy"` is a statement that this binary
            // IS that CLI, and both of them spell the flag `--add-dir`. A custom CLI
            // with no dialect gets nothing, since an unknown binary handed an
            // unknown flag would just fail to start.
            workspace_arg: dialect.map(|_| "--add-dir".to_string()),
        });
    }

    for name in KNOWN {
        if configured.contains(*name) {
            continue;
        }
        if let Some(path) = which_on_path(name) {
            let defaults = known_cli_default(name);
            found.push(CliSpec {
                binary_name: name.to_string(),
                path,
                args: defaults.args,
                system_arg: defaults.system_arg,
                dialect: defaults.dialect,
                workspace_arg: defaults.workspace_arg,
            });
        }
    }

    found
}

/// Minimal `which`: scans `PATH` for an executable regular file named `name`. The
/// project has no `which` dependency; this is the only place that needs one.
fn which_on_path(name: &str) -> Option<String> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(name);
        if is_executable_file(&candidate) {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

#[cfg(unix)]
fn is_executable_file(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable_file(path: &std::path::Path) -> bool {
    path.is_file()
}

/// Discovers every candidate connection, available or not, without constructing any
/// providers. Split out of construction so the picker can show — and explain — rows
/// the user cannot currently select.
pub async fn discover_candidates(settings: &Settings, classified: bool) -> Vec<Candidate> {
    let mut candidates = discover_ollama(settings, classified).await;
    candidates.extend(discover_vendors(settings, classified));
    candidates
}

async fn discover_ollama(settings: &Settings, classified: bool) -> Vec<Candidate> {
    let remote = !crate::providers::ollama::is_loopback_host(&settings.ollama_host);

    if classified && remote {
        // Never even query a remote daemon under --classified: a garbage or
        // non-loopback `ollama_host` must not get to make an outbound request just
        // to be told no. This is finding 1.2 of the 2026-07-29 audit (doc removed
        // as superseded; recoverable at commit `2e7984e`).
        return vec![Candidate {
            id: "ollama".into(),
            group: "OLLAMA".into(),
            // No model list was fetched, so name the daemon itself rather than
            // rendering a row that begins with a blank column.
            model: "daemon".into(),
            transports: vec![TransportOption {
                transport: None,
                label: String::new(),
                detail: settings.ollama_host.clone(),
                availability: Availability::Unavailable(
                    "remote Ollama hosts are refused under --classified".into(),
                ),
                cli: None,
                needs_key: false,
            }],
        }];
    }

    let Ok(client) = http_client() else {
        return Vec::new();
    };
    match OllamaProvider::list_models(&settings.ollama_host, &client).await {
        Ok(models) => models
            .into_iter()
            .map(|model| Candidate {
                id: format!("ollama:{model}"),
                group: "OLLAMA".into(),
                model,
                transports: vec![TransportOption {
                    transport: None,
                    label: String::new(),
                    detail: settings.ollama_host.clone(),
                    availability: Availability::Available,
                    cli: None,
                    needs_key: false,
                }],
            })
            .collect(),
        Err(e) => vec![Candidate {
            id: "ollama".into(),
            group: "OLLAMA".into(),
            model: "daemon".into(),
            transports: vec![TransportOption {
                transport: None,
                label: String::new(),
                detail: settings.ollama_host.clone(),
                availability: Availability::Unavailable(format!("unreachable: {e}")),
                cli: None,
                needs_key: false,
            }],
        }],
    }
}

fn discover_vendors(settings: &Settings, classified: bool) -> Vec<Candidate> {
    let cli_tools = detect_cli_tools(settings);

    let mut ids: Vec<String> = ["anthropic", "openai", "google", "openrouter", "groq"]
        .iter()
        .map(|s| s.to_string())
        .chain(settings.custom_endpoints.keys().cloned())
        .collect();
    for cli in &cli_tools {
        let vid = cli_vendor_id(&cli.binary_name);
        if !ids.contains(&vid) {
            ids.push(vid);
        }
    }
    ids.sort();
    ids.dedup();

    ids.iter()
        .filter_map(|id| build_vendor_candidate(id, settings, classified, &cli_tools))
        .collect()
}

fn build_vendor_candidate(
    id: &str,
    settings: &Settings,
    classified: bool,
    cli_tools: &[CliSpec],
) -> Option<Candidate> {
    let mut transports = Vec::new();

    if let Some(endpoint) = settings.endpoint(id) {
        let (availability, detail, needs_key) = if classified {
            (
                Availability::Unavailable("cloud APIs are refused under --classified".into()),
                endpoint.base_url.clone(),
                false,
            )
        } else {
            match Credentials::get(id) {
                Ok(Some(_)) => (Availability::Available, endpoint.base_url.clone(), false),
                // The reason is rendered separately from the detail column, so the
                // detail stays the endpoint URL — repeating it here printed it twice.
                // This is the only branch the picker can resolve by itself (prompt
                // for a key, write it to the keyring), so it is the only one that
                // sets `needs_key`.
                Ok(None) => (
                    Availability::Unavailable("no key stored".into()),
                    endpoint.base_url.clone(),
                    true,
                ),
                Err(e) => (
                    Availability::Unavailable(format!("keyring error: {e}")),
                    endpoint.base_url.clone(),
                    false,
                ),
            }
        };
        transports.push(TransportOption {
            transport: Some(Transport::Api),
            label: "via API".into(),
            detail,
            availability,
            cli: None,
            needs_key,
        });
    }

    let cli = cli_tools
        .iter()
        .find(|c| cli_vendor_id(&c.binary_name) == id);
    if let Some(cli) = cli {
        // `local_binary` is already `is_remote() -> true`, so under --classified this
        // must render unavailable with a reason rather than being silently dropped
        // (or, worse, constructed and only excluded via the primary check).
        let availability = if classified {
            Availability::Unavailable(
                "CLI tools may reach the network and are refused under --classified".into(),
            )
        } else {
            Availability::Available
        };
        transports.push(TransportOption {
            transport: Some(Transport::Cli),
            label: "via CLI".into(),
            detail: cli.path.clone(),
            availability,
            cli: Some(cli.clone()),
            needs_key: false,
        });
    }

    if transports.is_empty() {
        return None;
    }

    let model = cli
        .map(|c| c.binary_name.clone())
        .or_else(|| settings.endpoint(id).map(|e| e.default_model))
        .unwrap_or_else(|| id.to_string());

    Some(Candidate {
        id: id.to_string(),
        group: id.to_uppercase(),
        model,
        transports,
    })
}

/// The label a candidate would register under if connected via the given transport
/// option, computed without constructing anything — used by `simon models` to show
/// available-but-not-connected rows.
pub fn candidate_label(
    candidate: &Candidate,
    option: &TransportOption,
    settings: &Settings,
) -> String {
    match option.transport {
        None => format!("ollama:{}", candidate.model),
        Some(Transport::Api) => {
            let model = settings
                .connections
                .get(&candidate.id)
                .and_then(|c| c.model.clone())
                .or_else(|| settings.endpoint(&candidate.id).map(|e| e.default_model))
                .unwrap_or_else(|| candidate.id.clone());
            format!("{}:{model}", candidate.id)
        }
        Some(Transport::Cli) => {
            let binary = option
                .cli
                .as_ref()
                .map(|c| c.binary_name.clone())
                .unwrap_or_else(|| candidate.id.clone());
            let model = settings
                .connections
                .get(&candidate.id)
                .and_then(|c| c.model.clone())
                .unwrap_or_else(|| binary.clone());
            // Mirrors `LocalBinaryProvider::label` exactly: when no model was
            // configured, `model` defaults to `binary` a few lines up, so this is the
            // same "harness name is not a model name" collapse. IMPORTANT: these two
            // implementations must stay in sync — `resolve_commander` recomputes this
            // string with `candidate_label` and looks it up against labels that real
            // providers registered via `label()`; if the two rules ever diverge, a
            // saved commander for a CLI connection silently stops resolving.
            if binary == model {
                binary
            } else {
                format!("{binary}:{model}")
            }
        }
    }
}

fn transport_tag(transport: Option<Transport>) -> &'static str {
    match transport {
        None => "ollama",
        Some(Transport::Cli) => "cli",
        Some(Transport::Api) => "api",
    }
}

/// Builds one provider from a chosen candidate, transport, and any per-connection
/// overrides. The only place that turns a `Candidate` into something that can
/// actually send a prompt.
fn construct_provider(
    candidate: &Candidate,
    transport: Option<Transport>,
    conn: &ConnectionSpec,
    client: &reqwest::Client,
    settings: &Settings,
    project_root: &Path,
) -> Result<Arc<dyn Provider>> {
    match transport {
        None => Ok(Arc::new(OllamaProvider::new(
            &settings.ollama_host,
            &candidate.model,
            client.clone(),
        ))),
        Some(Transport::Api) => {
            let endpoint = settings
                .endpoint(&candidate.id)
                .ok_or_else(|| anyhow!("`{}` has no known cloud endpoint", candidate.id))?;
            let key = Credentials::get(&candidate.id)?
                .ok_or_else(|| anyhow!("no API key stored for `{}`", candidate.id))?;
            Ok(Arc::new(CloudProvider::new(
                candidate.id.clone(),
                endpoint,
                conn.model.clone(),
                key,
                client.clone(),
            )))
        }
        Some(Transport::Cli) => {
            let cli = candidate
                .transports
                .iter()
                .find_map(|t| {
                    if t.transport == Some(Transport::Cli) {
                        t.cli.as_ref()
                    } else {
                        None
                    }
                })
                .ok_or_else(|| anyhow!("`{}` has no detected CLI transport", candidate.id))?;
            let path = conn.path.clone().unwrap_or_else(|| cli.path.clone());
            let model = conn
                .model
                .clone()
                .unwrap_or_else(|| cli.binary_name.clone());
            let p = LocalBinaryProvider::new(
                &cli.binary_name,
                &path,
                &model,
                project_root.to_path_buf(),
                CliInvocation {
                    args: cli.args.clone(),
                    system_arg: cli.system_arg.clone(),
                    dialect: cli.dialect,
                    workspace_arg: cli.workspace_arg.clone(),
                },
            )?;
            Ok(Arc::new(p))
        }
    }
}

/// Every reachable model, keyed by `provider:model`.
pub struct Registry {
    providers: BTreeMap<String, Arc<dyn Provider>>,
    primary: String,
    /// The connection set actually applied, keyed by connection id. Logged verbatim
    /// to the audit trail so an entry carries real config identity (addresses part
    /// of audit finding 2.3).
    applied: BTreeMap<String, ConnectionSpec>,
    /// Maps a provider's label back to the connection id it was built from. Needed
    /// because a live commander switch (`/commander <name>`) must persist
    /// `settings.commander`, which is a connection id, not a label — see
    /// `resolve_commander`'s doc comment for why the two are not interchangeable.
    connection_ids: BTreeMap<String, String>,
}

impl Registry {
    /// Builds the registry from settings.
    ///
    /// When `classified` is set, any provider whose traffic leaves the machine is
    /// refused — this is what makes `--classified` an actual air gap rather than a flag
    /// that is parsed and ignored.
    ///
    /// When `settings.connections` is empty (no picker choice has ever been saved),
    /// this connects everything available — today's behaviour — so a first run
    /// doesn't require the picker to have run first. Otherwise only entries marked
    /// `enabled` are connected, each via its recorded transport.
    pub async fn build(
        settings: &Settings,
        requested: Option<&str>,
        classified: bool,
        project_root: &Path,
    ) -> Result<Self> {
        let candidates = discover_candidates(settings, classified).await;
        let client = http_client()?;
        let mut providers: BTreeMap<String, Arc<dyn Provider>> = BTreeMap::new();
        let mut applied: BTreeMap<String, ConnectionSpec> = BTreeMap::new();
        let mut connection_ids: BTreeMap<String, String> = BTreeMap::new();

        if settings.connections.is_empty() {
            for candidate in &candidates {
                let Some(option) = candidate
                    .transports
                    .iter()
                    .find(|t| t.availability.is_available())
                else {
                    continue;
                };
                let conn = ConnectionSpec {
                    enabled: true,
                    transport: option.transport,
                    path: option.cli.as_ref().map(|c| c.path.clone()),
                    model: None,
                };
                match construct_provider(
                    candidate,
                    option.transport,
                    &conn,
                    &client,
                    settings,
                    project_root,
                ) {
                    Ok(p) => {
                        let label = p.label();
                        connection_ids.insert(label.clone(), candidate.id.clone());
                        providers.insert(label, p);
                        applied.insert(candidate.id.clone(), conn);
                    }
                    Err(e) => eprintln!("[discovery] skipping {}: {e}", candidate.id),
                }
            }
        } else {
            for (id, conn) in &settings.connections {
                if !conn.enabled {
                    continue;
                }
                let Some(candidate) = candidates.iter().find(|c| &c.id == id) else {
                    eprintln!(
                        "[discovery] connection `{id}` is enabled but no longer discoverable; skipping"
                    );
                    continue;
                };
                let transport = conn
                    .transport
                    .or_else(|| candidate.transports.first().and_then(|t| t.transport));
                let Some(option) = candidate
                    .transports
                    .iter()
                    .find(|t| t.transport == transport)
                else {
                    eprintln!("[discovery] connection `{id}` has no matching transport; skipping");
                    continue;
                };
                // Re-check availability here too, not just at discovery time: this is
                // what stops a connection saved as enabled under normal operation
                // from being constructed anyway under --classified. Without this, a
                // remote provider could reach the registry (and the swarm) through
                // any saved config, with only the primary re-checked below.
                if let Availability::Unavailable(reason) = &option.availability {
                    eprintln!("[discovery] skipping {id}: {reason}");
                    continue;
                }
                match construct_provider(
                    candidate,
                    transport,
                    conn,
                    &client,
                    settings,
                    project_root,
                ) {
                    Ok(p) => {
                        let label = p.label();
                        connection_ids.insert(label.clone(), id.clone());
                        providers.insert(label, p);
                        applied.insert(id.clone(), conn.clone());
                    }
                    Err(e) => eprintln!("[discovery] skipping {id}: {e}"),
                }
            }
        }

        if providers.is_empty() {
            return Err(anyhow!(
                "no models are reachable.{} Start Ollama, or run `simon auth anthropic` \
                 to store a cloud key.",
                if classified {
                    " Classified mode permits local models only."
                } else {
                    ""
                }
            ));
        }

        let primary = match requested {
            Some(want) => Self::match_label(&providers, want).ok_or_else(|| {
                anyhow!(
                    "no model matches `{want}`. Available: {}",
                    providers.keys().cloned().collect::<Vec<_>>().join(", ")
                )
            })?,
            None => Self::resolve_commander(settings, &candidates, &providers)
                .or_else(|| providers.keys().next().cloned())
                .expect("registry is non-empty"),
        };

        if classified
            && let Some(p) = providers.get(&primary)
            && p.is_remote()
        {
            return Err(anyhow!(
                "`{primary}` sends traffic off this machine and cannot be used in \
                 classified mode"
            ));
        }

        Ok(Self {
            providers,
            primary,
            applied,
            connection_ids,
        })
    }

    /// Resolves `settings.commander` — a connection id such as `"anthropic"`, the
    /// same key the picker writes — to an actual provider label.
    ///
    /// A connection id is not always a usable label on its own: an Anthropic
    /// connection reached via the `claude` CLI registers as `claude:claude`
    /// (`provider_name` is the binary name), not `anthropic:...`, so `match_label`
    /// alone would silently fail to find it and fall back to whatever sorts first.
    /// Recomputing the label with `candidate_label` — using the same transport the
    /// connection was actually built with — is what makes the saved commander round-
    /// trip for every transport, not just Ollama and pure-API vendors.
    fn resolve_commander(
        settings: &Settings,
        candidates: &[Candidate],
        providers: &BTreeMap<String, Arc<dyn Provider>>,
    ) -> Option<String> {
        let id = settings.commander.as_deref()?;
        let candidate = candidates.iter().find(|c| c.id == id)?;
        let transport = settings
            .connections
            .get(id)
            .and_then(|c| c.transport)
            .or_else(|| candidate.transports.first().and_then(|t| t.transport));
        let option = candidate
            .transports
            .iter()
            .find(|t| t.transport == transport)?;
        let label = candidate_label(candidate, option, settings);
        Self::match_label(providers, &label)
    }

    /// Accepts an exact label, a bare model name, or a provider name.
    fn match_label(providers: &BTreeMap<String, Arc<dyn Provider>>, want: &str) -> Option<String> {
        if providers.contains_key(want) {
            return Some(want.to_string());
        }
        providers
            .iter()
            .find(|(label, p)| {
                p.model_name() == want
                    || p.provider_name() == want
                    || label.starts_with(&format!("{want}:"))
            })
            .map(|(label, _)| label.clone())
    }

    pub fn labels(&self) -> Vec<String> {
        self.providers.keys().cloned().collect()
    }

    pub fn primary(&self) -> &str {
        &self.primary
    }

    pub fn get(&self, label: &str) -> Option<Arc<dyn Provider>> {
        self.providers.get(label).cloned().or_else(|| {
            Self::match_label(&self.providers, label).and_then(|l| self.providers.get(&l).cloned())
        })
    }

    pub fn applied_connections(&self) -> &BTreeMap<String, ConnectionSpec> {
        &self.applied
    }

    /// The connection id a label was built from, for persisting `settings.commander`
    /// after a live switch. See the field doc comment on `connection_ids`.
    pub fn connection_id(&self, label: &str) -> Option<&str> {
        self.connection_ids.get(label).map(String::as_str)
    }

    /// Switches the primary to whatever `want` resolves to, using the same flexible
    /// matching as `get` (exact label, bare model name, or provider name). Returns
    /// the resolved label on success; leaves `primary` untouched on no match, so a
    /// bad `/commander` argument never leaves the session without a commander.
    pub fn set_primary(&mut self, want: &str) -> Option<String> {
        let label = Self::match_label(&self.providers, want)?;
        self.primary = label.clone();
        Some(label)
    }
}

pub struct Orchestrator {
    registry: Registry,
    ledger: SwarmLedger,
    audit: AuditLogger,
    skills: SkillsDir,
    /// The only place models may read, list, or write project files. Rooted at
    /// `project_root` below — see `workspace.rs`'s module doc.
    workspace: Workspace,
    events: mpsc::Sender<Event>,
    /// Carried so a picker reopened mid-chat (`Command::Reconfigure`) rebuilds the
    /// registry under the same air-gap policy the session started with.
    classified: bool,
    /// The project folder resolved at startup (`main::resolve_project_root`). Carried
    /// so `reconfigure` can rebuild the registry — and, through it, any CLI providers
    /// — with the same project root the session started with, without re-reading it
    /// from anywhere else.
    project_root: PathBuf,
    /// Answers to `Event::WriteRequested`, from the UI. `None` when the session was
    /// started with writes pre-approved (`--auto-write`), which is also what test and
    /// non-interactive callers pass.
    decisions: Option<mpsc::Receiver<WriteDecision>>,
    /// Set by a `WriteDecision::ApproveAll`; skips the prompt for the rest of the
    /// session. Never persisted — see `WriteDecision`.
    approve_all: bool,
}

impl Orchestrator {
    pub fn new(
        registry: Registry,
        paths: &Paths,
        project_root: PathBuf,
        classified: bool,
        events: mpsc::Sender<Event>,
        decisions: Option<mpsc::Receiver<WriteDecision>>,
    ) -> Result<Self> {
        let mut ledger = SwarmLedger::new();
        ledger.set_roster(registry.labels());

        Ok(Self {
            registry,
            ledger,
            audit: AuditLogger::open(paths.audit_log.clone())?,
            skills: SkillsDir::new(paths.skills_dir.clone())?,
            workspace: Workspace::new(project_root.clone())?,
            events,
            classified,
            project_root,
            decisions,
            approve_all: false,
        })
    }

    async fn emit(&self, event: Event) {
        // A closed channel means the UI already exited; dropping the event is correct.
        let _ = self.events.send(event).await;
    }

    /// Sets up progress reporting for one provider call: a `ProgressSink` to hand to
    /// `send_with_progress`, and a background task that forwards whatever it
    /// receives into `Event::ActivityProgress { label, .. }`, sanitising each detail
    /// first (see `sanitize_progress_detail`).
    ///
    /// The forwarding task ends on its own once the call is over: the returned
    /// `ProgressSink` is the only sender for its channel, so once the caller drops it
    /// (falling out of scope at the end of the `send_with_progress` call is enough —
    /// see both call sites), `rx.recv()` returns `None` and the task's loop exits.
    /// Nothing here needs to be joined or cancelled explicitly.
    fn spawn_progress_forwarder(&self, label: String) -> ProgressSink {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let events = self.events.clone();
        tokio::spawn(async move {
            while let Some(detail) = rx.recv().await {
                // A closed UI channel here just means the session is shutting down;
                // dropping the rest of the progress stream is correct, same as `emit`.
                let _ = events
                    .send(Event::ActivityProgress {
                        label: label.clone(),
                        detail: sanitize_progress_detail(&detail),
                    })
                    .await;
            }
        });
        ProgressSink::new(tx)
    }

    /// Assembles the system prompt: ledger blackboard plus any skills on disk.
    fn system_prompt(&self) -> String {
        let mut prompt = self.ledger.system_prompt();
        if let Ok(metas) = self.skills.list_with_descriptions()
            && !metas.is_empty()
        {
            prompt.push_str("\n### Available skills (read-only)\n");
            for meta in metas {
                // Bare filenames give a model no basis to judge relevance; the
                // description (when the file has frontmatter for one) is what makes
                // this list actionable. Fall back to just the name rather than
                // printing "None" or an empty trailing dash.
                match meta.description {
                    Some(description) => {
                        prompt.push_str(&format!("- {} — {}\n", meta.name, description));
                    }
                    None => prompt.push_str(&format!("- {}\n", meta.name)),
                }
            }
        }
        prompt
    }

    /// Renders the applied connection set as `id:transport` pairs for the audit log.
    fn connections_summary(&self) -> String {
        self.registry
            .applied_connections()
            .iter()
            .map(|(id, spec)| format!("{id}:{}", transport_tag(spec.transport)))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Consumes commands until the channel closes or a shutdown arrives.
    pub async fn run(mut self, mut commands: mpsc::Receiver<Command>) {
        if let Err(e) = self.audit.log(
            "session.start",
            &format!(
                "primary={} connections={}",
                self.registry.primary(),
                self.connections_summary()
            ),
        ) {
            self.emit(Event::Error(format!("audit log unavailable: {e}")))
                .await;
        }

        while let Some(command) = commands.recv().await {
            match command {
                Command::Shutdown => break,
                Command::Prompt(prompt) => {
                    self.handle_prompt(&prompt).await;
                    self.emit(Event::TurnComplete).await;
                }
                Command::Reconfigure(settings) => {
                    self.reconfigure(settings).await;
                }
                Command::SetCommander(name) => {
                    self.set_commander(&name).await;
                    // Mirrors `Command::Prompt`: `submit()` set `busy` optimistically
                    // for every command typed in chat, so this must always clear it,
                    // success or failure, the same way a prompt's `TurnComplete`
                    // always follows regardless of whether the reply was an error.
                    self.emit(Event::TurnComplete).await;
                }
            }
        }

        let _ = self.audit.log("session.end", "clean shutdown");
    }

    /// Rebuilds the registry from a freshly-applied connection set (the picker,
    /// reopened mid-chat) and resets the swarm roster so the system prompt matches
    /// reality.
    async fn reconfigure(&mut self, settings: Settings) {
        match Registry::build(&settings, None, self.classified, &self.project_root).await {
            Ok(registry) => {
                self.registry = registry;
                self.ledger.set_roster(self.registry.labels());
                let _ = self.audit.log(
                    "connections.updated",
                    &format!(
                        "primary={} connections={}",
                        self.registry.primary(),
                        self.connections_summary()
                    ),
                );
                self.emit(Event::Reconfigured {
                    primary: self.registry.primary().to_string(),
                    roster: self.registry.labels(),
                })
                .await;
            }
            Err(e) => {
                let _ = self.audit.log("connections.failed", &format!("error={e}"));
                self.emit(Event::Error(format!(
                    "failed to apply new connections: {e}"
                )))
                .await;
            }
        }
    }

    /// Handles `/commander <name>` typed in chat: resolves `name` against the live
    /// registry and, on success, switches the primary for the rest of the session and
    /// tells the UI what to persist. On no match, the registry (and the session's
    /// commander) are left exactly as they were — the same "leave it alone on
    /// failure" rule `reconfigure` follows.
    async fn set_commander(&mut self, name: &str) {
        match self.registry.set_primary(name) {
            Some(label) => {
                let connection_id = self.registry.connection_id(&label).map(str::to_string);
                let _ = self.audit.log("commander.changed", &format!("to={label}"));
                self.emit(Event::CommanderChanged {
                    label,
                    connection_id,
                })
                .await;
            }
            None => {
                self.emit(Event::Error(format!(
                    "no model matches `{name}`. Available: {}",
                    self.registry.labels().join(", ")
                )))
                .await;
            }
        }
    }

    async fn handle_prompt(&mut self, prompt: &str) {
        let primary_label = self.registry.primary().to_string();
        let _ = self.audit.log(
            "prompt.sent",
            &format!("model={primary_label} chars={}", prompt.len()),
        );

        let Some(provider) = self.registry.get(&primary_label) else {
            self.emit(Event::Error(format!("model `{primary_label}` disappeared")))
                .await;
            return;
        };

        self.emit(Event::ActivityStarted {
            label: primary_label.clone(),
            kind: ActivityKind::Primary,
        })
        .await;

        let system = self.system_prompt();
        // The user's own text is what the transcript and the audit log record; only
        // what reaches the model is augmented. See `commander_preamble` for why the
        // directive cannot just live in the system prompt.
        let effective_prompt = match commander_preamble(&primary_label, &self.registry.labels()) {
            Some(preamble) => format!("{preamble}\n{prompt}"),
            None => prompt.to_string(),
        };
        let progress = self.spawn_progress_forwarder(primary_label.clone());
        let reply = match provider
            .send_with_progress(Some(&system), &effective_prompt, &progress)
            .await
        {
            Ok(reply) => reply,
            Err(e) => {
                let _ = self
                    .audit
                    .log("prompt.failed", &format!("model={primary_label} error={e}"));
                self.emit(Event::Error(format!("{primary_label}: {e}")))
                    .await;
                return;
            }
        };
        // Drops the sink, closing the forwarding task's channel — see
        // `spawn_progress_forwarder`'s doc comment for why that's all the cleanup it
        // needs.
        drop(progress);

        if let Some(budget) = reply.rate_limit.summary() {
            self.ledger.update_budget(&primary_label, &budget);
        }
        let _ = self.audit.log(
            "reply.received",
            &format!("model={primary_label} chars={}", reply.text.len()),
        );

        // The TUI sees the RAW reply, unmodified — the user must see exactly what the
        // model said, including any write_file/end_file block markers, not a version
        // silently edited by the write-block parser below.
        self.emit(Event::Reply {
            label: primary_label.clone(),
            text: reply.text.clone(),
        })
        .await;

        // `parse_file_writes` strips write blocks out of the reply before anything
        // else sees it, so an `ACTION: delegate_task(...)`/`ACTION: read_skill(...)`
        // line inside a file a model is writing (documentation about this very
        // protocol, say) is never mistaken for a real request. Delegation and skill
        // reads run on the stripped text; writes run last, keeping the existing
        // execution order (delegations, then skill reads) unchanged for the two
        // actions that already existed.
        let (writes, stripped) = SwarmLedger::parse_file_writes(&reply.text);

        // Recorded before the actions run, so a plan the commander just proposed is in
        // the ledger regardless of what any of them do.
        self.ledger.record_commander_reply(&stripped);

        self.run_delegations(&primary_label, &stripped).await;
        self.run_skill_reads(&primary_label, &stripped).await;
        self.run_file_reads(&primary_label, &stripped).await;
        self.run_file_lists(&primary_label, &stripped).await;
        self.run_file_writes(&primary_label, writes).await;
    }

    /// Executes any `delegate_task` lines the primary emitted.
    ///
    /// Sub-agent replies are not themselves scanned for delegations, so the swarm
    /// cannot recurse indefinitely.
    async fn run_delegations(&mut self, from: &str, reply_text: &str) {
        let delegations = SwarmLedger::parse_delegations(reply_text);
        if delegations.is_empty() {
            return;
        }

        for delegation in delegations.into_iter().take(MAX_DELEGATIONS_PER_TURN) {
            let Some(target) = self.registry.get(&delegation.target) else {
                self.emit(Event::Error(format!(
                    "cannot delegate to unknown model `{}`",
                    delegation.target
                )))
                .await;
                continue;
            };
            let target_label = target.label();

            let task_id = self.ledger.add_task(&delegation.prompt);
            self.ledger.assign_task(task_id, &target_label);
            let _ = self.audit.log(
                "task.delegated",
                &format!("from={from} to={target_label} task={task_id}"),
            );

            self.emit(Event::Delegated {
                from: from.to_string(),
                to: target_label.clone(),
                task: truncate_chars(&delegation.prompt, MAX_TASK_DISPLAY_CHARS),
            })
            .await;
            self.emit(Event::ActivityStarted {
                label: target_label.clone(),
                kind: ActivityKind::Delegating,
            })
            .await;

            let system = self.system_prompt();
            // Only what is sent is augmented; the ledger and the TUI keep the
            // commander's own wording, the same split `commander_preamble` uses.
            let effective_task = format!("{}{}", subagent_preamble(), delegation.prompt);
            let started = Instant::now();
            let mut attempts = 1;
            let outcome = loop {
                let progress = self.spawn_progress_forwarder(target_label.clone());
                let result = target
                    .send_with_progress(Some(&system), &effective_task, &progress)
                    .await;
                // Drops the sink, closing the forwarding task's channel — see
                // `spawn_progress_forwarder`'s doc comment. Inside the loop because a
                // retry needs a fresh sink; the old one's task has already ended.
                drop(progress);

                let Err(error) = result else {
                    break result;
                };
                let reason = error.to_string();
                if attempts >= MAX_DELEGATION_ATTEMPTS || !is_retryable_delegation_error(&reason) {
                    break Err(error);
                }

                let _ = self.audit.log(
                    "task.retrying",
                    &format!("task={task_id} attempt={attempts} error={reason}"),
                );
                self.emit(Event::DelegationRetry {
                    to: target_label.clone(),
                    attempt: attempts + 1,
                    max: MAX_DELEGATION_ATTEMPTS,
                    reason: sanitize_progress_detail(&reason),
                })
                .await;
                tokio::time::sleep(DELEGATION_RETRY_BACKOFF[attempts - 1]).await;
                attempts += 1;
                // The activity line was cleared by the retry event above, so the next
                // attempt has to re-announce itself or the status line stays blank
                // for the whole of it.
                self.emit(Event::ActivityStarted {
                    label: target_label.clone(),
                    kind: ActivityKind::Delegating,
                })
                .await;
            };
            match outcome {
                Ok(reply) => {
                    let millis = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                    if let Some(budget) = reply.rate_limit.summary() {
                        self.ledger.update_budget(&target_label, &budget);
                    }
                    // A sub-agent's reply IS scanned for write blocks — and for
                    // nothing else. That asymmetry is the whole design: the bound on
                    // the swarm is that a sub-agent cannot *delegate*, read a skill,
                    // or read/list files, so no reply can spawn more work. A write
                    // spawns nothing. Without this a swarm could only ever describe a
                    // project it had been asked to build, because the commander is the
                    // one told to hand authoring off and the author could not write.
                    //
                    // Safe to allow only because every write still passes the same two
                    // gates a commander's does: `Workspace`'s path hardening, and the
                    // user's explicit approval, which now names the sub-agent as the
                    // one asking.
                    let (sub_writes, sub_text) = SwarmLedger::parse_file_writes(&reply.text);
                    self.run_file_writes(&target_label, sub_writes).await;

                    // Record the reply on the task before flipping it to Done, so the
                    // ledger shown to the delegating model on its next turn carries
                    // the answer, not just a status tag. The *stripped* text: file
                    // content is already on disk, and echoing it back into every
                    // future prompt is exactly the ledger growth `MAX_RESULT_CHARS`
                    // exists to prevent.
                    self.ledger.record_result(task_id, &sub_text);
                    self.ledger
                        .update_status(task_id, crate::swarm::TaskStatus::Done);
                    let _ = self.audit.log(
                        "task.completed",
                        &format!("task={task_id} model={target_label}"),
                    );
                    self.emit(Event::DelegationFinished {
                        to: target_label.clone(),
                        ok: true,
                        chars: sub_text.len(),
                        millis,
                    })
                    .await;
                    self.emit(Event::Reply {
                        label: target_label,
                        text: sub_text,
                    })
                    .await;
                }
                Err(e) => {
                    let millis = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                    let _ = self
                        .audit
                        .log("task.failed", &format!("task={task_id} error={e}"));
                    // Record the error as the task's result and mark it Failed, not
                    // just logged-and-dropped: without this a failed delegation sat at
                    // [IN_PROGRESS] forever, indistinguishable from one still running,
                    // on a blackboard every other model reads as fact. Recording the
                    // error text (not just the status) lets the delegating model see
                    // WHY it failed and decide whether to retry — a failure with no
                    // explanation is useless to whoever has to act on it.
                    self.ledger.record_result(task_id, &e.to_string());
                    self.ledger
                        .update_status(task_id, crate::swarm::TaskStatus::Failed);
                    self.emit(Event::DelegationFinished {
                        to: target_label.clone(),
                        ok: false,
                        chars: 0,
                        millis,
                    })
                    .await;
                    self.emit(Event::Error(format!("{target_label}: {e}")))
                        .await;
                }
            }
        }
    }

    /// Executes any `read_skill` lines the primary emitted, mirroring
    /// `run_delegations` in structure: parse every request out of the reply, resolve
    /// each one, and never let a bad request take down the turn.
    ///
    /// Like sub-agent replies not being re-scanned for delegations, this is only
    /// called on the primary's own reply — not on delegation replies — so the same
    /// non-recursion guarantee holds here too. `primary_label` is who the read is on
    /// behalf of; it is what `Event::ActivityStarted` names, since a skill read is
    /// not a provider call and so has no sub-agent label of its own to report.
    async fn run_skill_reads(&mut self, primary_label: &str, reply_text: &str) {
        let requests = SwarmLedger::parse_read_skill(reply_text);

        // Mirrors `run_delegations` capping to `MAX_DELEGATIONS_PER_TURN`: the
        // ledger already caps how many skills stay loaded (`MAX_LOADED_SKILLS`), but
        // that caps storage, not effort per turn — without this, a reply with
        // hundreds of `read_skill` lines would still trigger hundreds of filesystem
        // reads, just to have all but the last few evicted immediately after.
        for name in requests.into_iter().take(MAX_DELEGATIONS_PER_TURN) {
            self.emit(Event::ActivityStarted {
                label: primary_label.to_string(),
                kind: ActivityKind::ReadingSkill,
            })
            .await;
            // `SkillsDir::read` already rejects `..`, absolute paths, and symlinks
            // that escape the skills root (see `skills.rs`). Until now every caller
            // passed it a name the application itself constructed. This is the first
            // caller where `name` comes straight from model output — exactly the
            // threat that hardening exists to stop, since a model's reply is
            // effectively untrusted input (it may be echoing text from a delegated
            // sub-agent, a fetched document, anything). Calling `resolve`/`read`
            // rather than reimplementing the check here is what keeps that guarantee
            // intact.
            match self.skills.read(&name) {
                Ok(content) => {
                    // Skill files are user-authored local files, not model output —
                    // the model only supplied the *name* being resolved above. So
                    // injecting `content` into the system prompt is equivalent to
                    // the user having written that text into a system prompt
                    // themselves, which is why it is acceptable to do so at all;
                    // this would be a very different call if a model could write a
                    // skill file too.
                    self.ledger.record_skill(&name, &content);
                    let _ = self.audit.log(
                        "skill.read",
                        &format!("name={name} chars={}", content.len()),
                    );
                    self.emit(Event::SkillLoaded {
                        name: name.clone(),
                        chars: content.len(),
                    })
                    .await;
                }
                Err(e) => {
                    let _ = self
                        .audit
                        .log("skill.read_failed", &format!("name={name} error={e}"));
                    self.emit(Event::Error(format!("skill `{name}`: {e}")))
                        .await;
                }
            }
        }
    }

    /// Executes any `write_file` blocks the primary emitted, mirroring
    /// `run_skill_reads` in structure: resolve each request and never let one bad
    /// write take down the turn.
    ///
    /// Only the primary's own reply is ever scanned for write blocks — `writes` here
    /// comes from `parse_file_writes(&reply.text)` in `handle_prompt`, never from a
    /// sub-agent's delegation reply — so the same non-recursion guarantee that holds
    /// for delegations and skill reads holds here too.
    /// Asks the user to allow one write, returning whether it may proceed.
    ///
    /// Returns `true` without asking when the session pre-approved writes
    /// (`--auto-write`, and every non-interactive caller) or the user has already
    /// answered "all" this session.
    ///
    /// A closed channel means the UI is gone, and that denies the write. Failing
    /// closed is the only defensible choice for a gate whose entire purpose is that
    /// nothing reaches disk unseen: if there is nobody left to ask, there is nobody to
    /// have consented.
    async fn confirm_write(&mut self, author: &str, write: &crate::swarm::FileWrite) -> bool {
        if self.approve_all {
            return true;
        }
        if self.decisions.is_none() {
            return true;
        }

        // Read the existing file's size before asking, not after: "overwrites 4KB" and
        // "creates a new file" are different questions, and the user is being asked to
        // answer one of them.
        let overwrites = self
            .workspace
            .metadata(&write.path)
            .ok()
            .filter(|m| m.is_file())
            .map(|m| m.len());

        self.emit(Event::WriteRequested {
            author: author.to_string(),
            path: write.path.clone(),
            bytes: write.content.len(),
            overwrites,
            preview: write_preview(&write.content),
        })
        .await;

        // Borrowed only now: `emit` needs `&self`, so holding a `&mut` on the receiver
        // across it would not compile.
        let Some(decisions) = self.decisions.as_mut() else {
            return true;
        };
        match decisions.recv().await {
            Some(WriteDecision::Approve) => true,
            Some(WriteDecision::ApproveAll) => {
                self.approve_all = true;
                true
            }
            Some(WriteDecision::Deny) | None => false,
        }
    }

    async fn run_file_writes(&mut self, author: &str, writes: Vec<crate::swarm::FileWrite>) {
        for write in writes.into_iter().take(MAX_WRITES_PER_TURN) {
            // Before the user is asked anything: a write that `Workspace` will refuse
            // regardless must not be put to them for approval. Asking about a doomed
            // write teaches that the answer does not matter, and makes the refusal
            // that follows a "yes" look like a consequence of approving it.
            if let Err(e) = self.workspace.precheck(&write.path, write.content.len()) {
                let outcome = format!("failed: {e}");
                let _ = self.audit.log(
                    "file.write_failed",
                    &format!("path={} error={e}", write.path),
                );
                self.ledger.record_file_write(&write.path, &outcome);
                self.emit(Event::Error(format!("write `{}`: {e}", write.path)))
                    .await;
                continue;
            }
            if !self.confirm_write(author, &write).await {
                let _ = self
                    .audit
                    .log("file.write_denied", &format!("path={}", write.path));
                // Recorded in the ledger like any other outcome, so the model learns on
                // its next turn that the file was NOT written. Without this it would
                // carry on as though the write had succeeded and build on a file that
                // does not exist.
                self.ledger
                    .record_file_write(&write.path, "denied by the user");
                self.emit(Event::WriteDenied {
                    author: author.to_string(),
                    path: write.path.clone(),
                })
                .await;
                continue;
            }
            match self.workspace.write(&write.path, &write.content) {
                Ok(_) => {
                    let outcome = format!("ok ({} bytes)", write.content.len());
                    let _ = self.audit.log(
                        "file.written",
                        &format!("path={} chars={}", write.path, write.content.len()),
                    );
                    self.ledger.record_file_write(&write.path, &outcome);
                    self.emit(Event::FileWritten {
                        author: author.to_string(),
                        path: write.path.clone(),
                    })
                    .await;
                }
                Err(e) => {
                    let _ = self.audit.log(
                        "file.write_failed",
                        &format!("path={} error={e}", write.path),
                    );
                    self.ledger.record_file_write(&write.path, &e.to_string());
                    self.emit(Event::Error(format!("write `{}`: {e}", write.path)))
                        .await;
                }
            }
        }
    }

    /// Executes any `read_file` lines the primary emitted, mirroring
    /// `run_skill_reads` in structure: resolve each request through `Workspace::read`
    /// and never let one bad read take down the turn.
    ///
    /// `reply_text` comes from `parse_file_writes(&reply.text)`'s stripped output in
    /// `handle_prompt`, never the raw reply, so an `ACTION: read_file(...)` line that
    /// only appears inside a `write_file` block's content is never executed — same
    /// non-recursion/non-injection guarantee as `run_skill_reads` and
    /// `run_file_writes`. Only the primary's own reply is ever scanned; a sub-agent's
    /// delegation reply is not.
    async fn run_file_reads(&mut self, primary_label: &str, reply_text: &str) {
        let requests = SwarmLedger::parse_read_files(reply_text);

        // Mirrors `run_skill_reads` capping to `MAX_DELEGATIONS_PER_TURN`: bounds how
        // much filesystem effort a single turn can trigger, independent of how many
        // of the results the ledger ends up keeping (`MAX_LOADED_READS`).
        for path in requests.into_iter().take(MAX_DELEGATIONS_PER_TURN) {
            self.emit(Event::ActivityStarted {
                label: primary_label.to_string(),
                kind: ActivityKind::ReadingProject,
            })
            .await;
            // `Workspace::read` already rejects `..`, absolute paths, and symlinks
            // that escape the project root (see `workspace.rs`) — `path` here comes
            // straight from model output, the same untrusted-input case that
            // hardening exists for.
            match self.workspace.read(&path) {
                Ok(content) => {
                    self.ledger.record_file_read(&path, &content);
                    // Sizes and counts only, never content — a hard invariant of the
                    // audit log (see `docs/AUDIT-2026-07-30.md` §3.5).
                    let _ = self.audit.log(
                        "project.read",
                        &format!("path={path} chars={}", content.len()),
                    );
                    self.emit(Event::FileRead {
                        path: path.clone(),
                        chars: content.len(),
                    })
                    .await;
                }
                Err(e) => {
                    let _ = self
                        .audit
                        .log("project.read_failed", &format!("path={path} error={e}"));
                    self.emit(Event::Error(format!("read `{path}`: {e}"))).await;
                }
            }
        }
    }

    /// Executes any `list_files` lines the primary emitted, mirroring
    /// `run_file_reads` in structure and sharing the same stripped-text and
    /// non-recursion guarantees.
    async fn run_file_lists(&mut self, primary_label: &str, reply_text: &str) {
        let requests = SwarmLedger::parse_list_files(reply_text);

        for path in requests.into_iter().take(MAX_DELEGATIONS_PER_TURN) {
            self.emit(Event::ActivityStarted {
                label: primary_label.to_string(),
                kind: ActivityKind::ReadingProject,
            })
            .await;
            match self.workspace.list(&path) {
                Ok(entries) => {
                    let outcome = format!("ok ({} entries)\n{}", entries.len(), entries.join("\n"));
                    self.ledger.record_file_list(&path, &outcome);
                    // Path and entry count only, never the entries themselves — same
                    // audit-log invariant as `run_file_reads`.
                    let _ = self.audit.log(
                        "project.list",
                        &format!("path={path} entries={}", entries.len()),
                    );
                    self.emit(Event::FilesListed {
                        path: path.clone(),
                        entries: entries.len(),
                    })
                    .await;
                }
                Err(e) => {
                    let _ = self
                        .audit
                        .log("project.list_failed", &format!("path={path} error={e}"));
                    self.emit(Event::Error(format!("list `{path}`: {e}"))).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::{RateLimit, Reply};
    use async_trait::async_trait;

    struct StubProvider {
        provider: String,
        model: String,
        remote: bool,
    }

    #[async_trait]
    impl Provider for StubProvider {
        async fn send(&self, _system: Option<&str>, prompt: &str) -> Result<Reply> {
            Ok(Reply {
                text: format!("echo: {prompt}"),
                rate_limit: RateLimit::default(),
            })
        }
        fn model_name(&self) -> &str {
            &self.model
        }
        fn provider_name(&self) -> &str {
            &self.provider
        }
        fn is_remote(&self) -> bool {
            self.remote
        }
    }

    /// A provider that returns fixed text regardless of the prompt, for exercising
    /// what a *reply's* shape causes. `StubProvider` echoes its prompt, which cannot
    /// carry a multi-line write block: `parse_delegations` is a per-line parser, so a
    /// delegated prompt is always one line.
    struct ScriptedProvider {
        provider: String,
        model: String,
        reply: String,
    }

    #[async_trait]
    impl Provider for ScriptedProvider {
        async fn send(&self, _system: Option<&str>, _prompt: &str) -> Result<Reply> {
            Ok(Reply {
                text: self.reply.clone(),
                rate_limit: RateLimit::default(),
            })
        }
        fn model_name(&self) -> &str {
            &self.model
        }
        fn provider_name(&self) -> &str {
            &self.provider
        }
        fn is_remote(&self) -> bool {
            false
        }
    }

    /// A provider that fails its first `fail_times` calls and then succeeds, for
    /// exercising the retry path without waiting on a real flaky CLI.
    struct FlakyProvider {
        provider: String,
        model: String,
        remaining_failures: std::sync::Mutex<usize>,
        error: String,
    }

    #[async_trait]
    impl Provider for FlakyProvider {
        async fn send(&self, _system: Option<&str>, _prompt: &str) -> Result<Reply> {
            let mut remaining = self.remaining_failures.lock().unwrap();
            if *remaining > 0 {
                *remaining -= 1;
                return Err(anyhow!("{}", self.error));
            }
            Ok(Reply {
                text: "recovered".into(),
                rate_limit: RateLimit::default(),
            })
        }
        fn model_name(&self) -> &str {
            &self.model
        }
        fn provider_name(&self) -> &str {
            &self.provider
        }
        fn is_remote(&self) -> bool {
            false
        }
    }

    /// A provider that always errors, used to exercise the failed-delegation path
    /// (Fix 2) without spawning a real subprocess or making a real request.
    struct FailingProvider {
        provider: String,
        model: String,
    }

    #[async_trait]
    impl Provider for FailingProvider {
        async fn send(&self, _system: Option<&str>, _prompt: &str) -> Result<Reply> {
            Err(anyhow!("simulated transport failure"))
        }
        fn model_name(&self) -> &str {
            &self.model
        }
        fn provider_name(&self) -> &str {
            &self.provider
        }
        fn is_remote(&self) -> bool {
            false
        }
    }

    /// A registry whose delegation target fails `failures` times before succeeding.
    /// Separate from `registry_with` because that one only builds `StubProvider`s.
    fn registry_with_flaky(failures: usize) -> Registry {
        let mut providers: BTreeMap<String, Arc<dyn Provider>> = BTreeMap::new();
        providers.insert(
            "ollama:llama3".into(),
            Arc::new(StubProvider {
                provider: "ollama".into(),
                model: "llama3".into(),
                remote: false,
            }),
        );
        providers.insert(
            "ollama:flaky".into(),
            Arc::new(FlakyProvider {
                provider: "ollama".into(),
                model: "flaky".into(),
                remaining_failures: std::sync::Mutex::new(failures),
                error: "another active schedule task".into(),
            }),
        );
        Registry {
            providers,
            primary: "ollama:llama3".into(),
            applied: BTreeMap::new(),
            connection_ids: BTreeMap::new(),
        }
    }

    fn registry_with(entries: Vec<(&str, &str, bool)>, primary: &str) -> Registry {
        let mut providers: BTreeMap<String, Arc<dyn Provider>> = BTreeMap::new();
        for (provider, model, remote) in entries {
            let p = StubProvider {
                provider: provider.into(),
                model: model.into(),
                remote,
            };
            providers.insert(p.label(), Arc::new(p));
        }
        Registry {
            providers,
            primary: primary.to_string(),
            applied: BTreeMap::new(),
            connection_ids: BTreeMap::new(),
        }
    }

    #[test]
    fn resolves_labels_by_exact_match_model_or_provider() {
        let reg = registry_with(
            vec![
                ("ollama", "llama3", false),
                ("anthropic", "claude-opus-5", true),
            ],
            "ollama:llama3",
        );
        assert!(reg.get("ollama:llama3").is_some());
        assert!(reg.get("llama3").is_some());
        assert!(reg.get("anthropic").is_some());
        assert!(reg.get("nonexistent").is_none());
    }

    #[test]
    fn roster_lists_every_model() {
        let reg = registry_with(
            vec![
                ("ollama", "llama3", false),
                ("anthropic", "claude-opus-5", true),
            ],
            "ollama:llama3",
        );
        let labels = reg.labels();
        assert!(labels.contains(&"ollama:llama3".to_string()));
        assert!(labels.contains(&"anthropic:claude-opus-5".to_string()));
    }

    #[test]
    fn set_primary_accepts_a_bare_model_name_or_provider_name() {
        let mut reg = registry_with(
            vec![
                ("ollama", "llama3", false),
                ("anthropic", "claude-opus-5", true),
            ],
            "ollama:llama3",
        );

        assert_eq!(
            reg.set_primary("claude-opus-5").as_deref(),
            Some("anthropic:claude-opus-5"),
            "a bare model name must resolve"
        );
        assert_eq!(reg.primary(), "anthropic:claude-opus-5");

        assert_eq!(
            reg.set_primary("ollama").as_deref(),
            Some("ollama:llama3"),
            "a bare provider name must resolve"
        );
        assert_eq!(reg.primary(), "ollama:llama3");
    }

    #[test]
    fn set_primary_rejects_an_unknown_model_and_leaves_the_primary_alone() {
        let mut reg = registry_with(vec![("ollama", "llama3", false)], "ollama:llama3");
        assert_eq!(reg.set_primary("ghost"), None);
        assert_eq!(reg.primary(), "ollama:llama3");
    }

    #[test]
    fn a_labels_connection_id_round_trips() {
        let p = StubProvider {
            provider: "anthropic".into(),
            model: "claude-opus-5".into(),
            remote: true,
        };
        let label = p.label();
        let mut providers: BTreeMap<String, Arc<dyn Provider>> = BTreeMap::new();
        providers.insert(label.clone(), Arc::new(p));
        let mut connection_ids = BTreeMap::new();
        connection_ids.insert(label.clone(), "anthropic".to_string());

        let reg = Registry {
            providers,
            primary: label.clone(),
            applied: BTreeMap::new(),
            connection_ids,
        };

        assert_eq!(reg.connection_id(&label), Some("anthropic"));
        assert_eq!(reg.connection_id("nonexistent"), None);
    }

    #[test]
    fn cli_vendor_id_groups_known_binaries_under_their_vendor() {
        assert_eq!(cli_vendor_id("claude"), "anthropic");
        assert_eq!(cli_vendor_id("gemini"), "google");
        assert_eq!(cli_vendor_id("codex"), "codex");
        // `agy` is a multi-vendor gateway, so it stands alone rather than folding
        // into `google` the way the old `gemini` CLI did.
        assert_eq!(cli_vendor_id("agy"), "agy");
    }

    #[test]
    fn agy_is_auto_detected_with_streaming_flags_before_p_and_no_system_flag() {
        let defaults = known_cli_default("agy");
        // Flags must precede `-p` for `agy`: `agy -p --output-format ...` is broken
        // (it takes `--output-format` as the prompt), so `-p` has to be last.
        assert_eq!(defaults.args.last().unwrap(), "-p");
        assert!(defaults.args.contains(&"stream-json".to_string()));
        // `--sandbox` is what lets agy run its own tools without prompting for a
        // permission it cannot ask for in print mode.
        assert!(defaults.args.contains(&"--sandbox".to_string()));
        // agy's own print timeout defaults to 5m, short enough to clip a real task.
        assert!(defaults.args.contains(&"--print-timeout".to_string()));
        // Verified against `agy --help` on this machine: there is no system-prompt
        // flag, so the system text has to be folded into the prompt.
        assert!(defaults.system_arg.is_none());
        assert_eq!(defaults.dialect, Some(StreamDialect::AgyJson));
        assert_eq!(defaults.workspace_arg, Some("--add-dir".to_string()));
    }

    #[test]
    fn claude_is_auto_detected_with_streaming_flags_and_a_system_flag() {
        let defaults = known_cli_default("claude");
        assert_eq!(
            defaults.args,
            vec![
                "-p".to_string(),
                "--output-format".to_string(),
                "stream-json".to_string(),
                "--verbose".to_string()
            ]
        );
        assert_eq!(defaults.system_arg, Some("--system-prompt".to_string()));
        assert_eq!(defaults.dialect, Some(StreamDialect::ClaudeJson));
        assert_eq!(defaults.workspace_arg, Some("--add-dir".to_string()));
    }

    #[test]
    fn an_unrecognised_binary_gets_no_streaming_dialect() {
        let defaults = known_cli_default("some-random-cli");
        assert!(defaults.args.is_empty());
        assert!(defaults.system_arg.is_none());
        assert!(defaults.dialect.is_none());
        // An unknown binary handed an unknown flag would just fail to start.
        assert!(defaults.workspace_arg.is_none());
    }

    // Unix-only: both this test and its sibling below hardcode `/bin/echo`, which
    // does not exist on Windows. `LocalBinaryProvider::new` rejects a path-like
    // string that does not exist on disk (see `rejects_a_nonexistent_path` in
    // `providers::local_binary`), so `Registry::build` would fail construction on
    // `windows-latest` rather than exercising the label-resolution logic under test.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_saved_commander_resolves_even_when_the_connection_id_is_not_the_provider_label() {
        // `settings.commander` holds a connection id ("anthropic"), the same key the
        // picker writes. When that connection is backed by a CLI (the `claude`
        // binary) with no model configured, the constructed provider's label is
        // `claude` — `provider_name()` is the binary name, not the vendor id, and
        // `LocalBinaryProvider::label` collapses `claude:claude` down to just `claude`
        // since a harness name is not a model name (Fix 4) — so a naive
        // `match_label(&providers, "anthropic")` finds nothing and the commander
        // silently falls back to whatever label sorts first. This is the regression
        // `resolve_commander` exists to prevent.
        let mut local_binaries = BTreeMap::new();
        local_binaries.insert(
            "claude".to_string(),
            crate::config::LocalBinarySpec {
                path: "/bin/echo".into(),
                args: vec![],
                system_arg: None,
                stream_format: None,
            },
        );
        let mut connections = BTreeMap::new();
        connections.insert(
            "anthropic".to_string(),
            ConnectionSpec {
                enabled: true,
                transport: Some(Transport::Cli),
                path: Some("/bin/echo".into()),
                model: None,
            },
        );
        let settings = Settings {
            ollama_host: "http://127.0.0.1:1".into(), // unreachable; keeps this Ollama-free
            local_binaries,
            connections,
            commander: Some("anthropic".to_string()),
            ..Default::default()
        };

        let registry = Registry::build(&settings, None, false, Path::new("."))
            .await
            .expect("the claude CLI connection must construct");
        assert_eq!(registry.primary(), "claude");
    }

    // Unix-only: hardcodes `/bin/echo`, which `LocalBinaryProvider::new` would reject
    // as a nonexistent path on Windows — see the comment on the sibling test above.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_saved_commander_with_a_configured_model_keeps_the_binary_colon_model_label() {
        // Sibling of the test above, covering the branch it doesn't: when the user
        // *did* configure a model (the `agy` multi-vendor gateway pointed at
        // `gemini-3-pro`), the label must keep the `binary:model` form so the model
        // stays visible. `candidate_label` and `LocalBinaryProvider::label` compute
        // this independently and must agree, or this diverges from `resolve_commander`
        // silently — see the comment on both.
        let mut local_binaries = BTreeMap::new();
        local_binaries.insert(
            "agy".to_string(),
            crate::config::LocalBinarySpec {
                path: "/bin/echo".into(),
                args: vec![],
                system_arg: None,
                stream_format: None,
            },
        );
        let mut connections = BTreeMap::new();
        connections.insert(
            "agy".to_string(),
            ConnectionSpec {
                enabled: true,
                transport: Some(Transport::Cli),
                path: Some("/bin/echo".into()),
                model: Some("gemini-3-pro".to_string()),
            },
        );
        let settings = Settings {
            ollama_host: "http://127.0.0.1:1".into(),
            local_binaries,
            connections,
            commander: Some("agy".to_string()),
            ..Default::default()
        };

        let registry = Registry::build(&settings, None, false, Path::new("."))
            .await
            .expect("the agy CLI connection must construct");
        assert_eq!(registry.primary(), "agy:gemini-3-pro");
    }

    #[tokio::test]
    async fn an_old_config_with_no_connections_still_discovers_and_connects_everything() {
        // Regression guard: a settings value with an empty `connections` map (an old
        // config file, or a fresh install) must behave like today — connect
        // everything available — rather than connecting nothing.
        let settings = Settings {
            ollama_host: "http://127.0.0.1:1".into(), // nothing listens here
            ..Default::default()
        };
        let candidates = discover_candidates(&settings, false).await;
        // Ollama unreachable at that port, so only cloud/CLI candidates (if any on
        // this machine) would show up; either way discovery must not panic and must
        // not require any saved connections.
        assert!(settings.connections.is_empty());
        let _ = candidates; // presence/absence depends on the machine; just must not panic
    }

    #[tokio::test]
    async fn a_non_loopback_ollama_host_is_unavailable_under_classified_without_a_network_call() {
        let settings = Settings {
            ollama_host: "http://192.0.2.1:11434".into(), // TEST-NET-1, guaranteed unreachable
            ..Default::default()
        };
        let candidates = discover_candidates(&settings, true).await;
        let ollama = candidates
            .iter()
            .find(|c| c.group == "OLLAMA")
            .expect("a classified run must still show an OLLAMA row to explain why");
        assert_eq!(ollama.transports.len(), 1);
        assert!(!ollama.transports[0].availability.is_available());
    }

    /// End-to-end: a prompt reaches a provider and its reply comes back as an event.
    /// This is the wiring whose absence was the headline audit finding.
    #[tokio::test]
    async fn a_prompt_reaches_a_provider_and_the_reply_comes_back() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        let reg = registry_with(vec![("ollama", "llama3", false)], "ollama:llama3");

        let (event_tx, mut event_rx) = mpsc::channel(16);

        let mut orch = Orchestrator {
            registry: reg,
            ledger: SwarmLedger::new(),
            audit: AuditLogger::with_key(paths.audit_log.clone(), vec![3u8; 32]).unwrap(),
            skills: SkillsDir::new(paths.skills_dir.clone()).unwrap(),
            workspace: Workspace::new(project_dir.path().to_path_buf()).unwrap(),
            events: event_tx,
            classified: false,
            project_root: project_dir.path().to_path_buf(),
            decisions: None,
            approve_all: false,
        };
        orch.ledger.set_roster(orch.registry.labels());

        let handle = tokio::spawn(async move {
            orch.handle_prompt("hello there").await;
        });

        // `handle_prompt` now also emits `ActivityStarted` before the provider call;
        // skip past it to the reply, which is what this test is actually about.
        let reply = loop {
            match event_rx.recv().await.expect("expected a reply event") {
                Event::Reply { label, text } => break (label, text),
                _ => continue,
            }
        };
        assert_eq!(reply.0, "ollama:llama3");
        assert_eq!(reply.1, "echo: hello there");

        handle.await.unwrap();
    }

    #[tokio::test]
    async fn delegation_dispatches_to_the_named_model() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        let reg = registry_with(
            vec![("ollama", "llama3", false), ("ollama", "mistral", false)],
            "ollama:llama3",
        );

        let (event_tx, mut event_rx) = mpsc::channel(16);
        let mut orch = Orchestrator {
            registry: reg,
            ledger: SwarmLedger::new(),
            audit: AuditLogger::with_key(paths.audit_log.clone(), vec![3u8; 32]).unwrap(),
            skills: SkillsDir::new(paths.skills_dir.clone()).unwrap(),
            workspace: Workspace::new(project_dir.path().to_path_buf()).unwrap(),
            events: event_tx,
            classified: false,
            project_root: project_dir.path().to_path_buf(),
            decisions: None,
            approve_all: false,
        };

        orch.run_delegations(
            "ollama:llama3",
            "ACTION: delegate_task(ollama:mistral, do the thing)",
        )
        .await;

        let mut saw_delegation = false;
        let mut saw_reply = false;
        while let Ok(event) = event_rx.try_recv() {
            match event {
                Event::Delegated { to, .. } => {
                    assert_eq!(to, "ollama:mistral");
                    saw_delegation = true;
                }
                Event::Reply { label, text } => {
                    assert_eq!(label, "ollama:mistral");
                    assert!(text.contains("do the thing"));
                    saw_reply = true;
                }
                _ => {}
            }
        }
        assert!(saw_delegation && saw_reply);
        assert_eq!(orch.ledger.tasks().len(), 1);
    }

    #[tokio::test]
    async fn delegating_to_an_unknown_model_is_reported_not_ignored() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        let reg = registry_with(vec![("ollama", "llama3", false)], "ollama:llama3");

        let (event_tx, mut event_rx) = mpsc::channel(16);
        let mut orch = Orchestrator {
            registry: reg,
            ledger: SwarmLedger::new(),
            audit: AuditLogger::with_key(paths.audit_log.clone(), vec![3u8; 32]).unwrap(),
            skills: SkillsDir::new(paths.skills_dir.clone()).unwrap(),
            workspace: Workspace::new(project_dir.path().to_path_buf()).unwrap(),
            events: event_tx,
            classified: false,
            project_root: project_dir.path().to_path_buf(),
            decisions: None,
            approve_all: false,
        };

        orch.run_delegations("ollama:llama3", "ACTION: delegate_task(ghost:model, hi)")
            .await;

        assert!(matches!(event_rx.try_recv(), Ok(Event::Error(_))));
    }

    #[tokio::test]
    async fn a_failed_delegation_is_tagged_failed_not_left_in_progress_forever() {
        // Regression guard for Fix 2: before this fix, the Err arm of run_delegations
        // logged and emitted an Event::Error but never called update_status, so a
        // failed task sat at [IN_PROGRESS] forever — indistinguishable from one still
        // running, on a blackboard other models read as fact.
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let mut providers: BTreeMap<String, Arc<dyn Provider>> = BTreeMap::new();
        let ok = StubProvider {
            provider: "ollama".into(),
            model: "llama3".into(),
            remote: false,
        };
        providers.insert(ok.label(), Arc::new(ok));
        let failing = FailingProvider {
            provider: "ollama".into(),
            model: "mistral".into(),
        };
        providers.insert(failing.label(), Arc::new(failing));
        let reg = Registry {
            providers,
            primary: "ollama:llama3".to_string(),
            applied: BTreeMap::new(),
            connection_ids: BTreeMap::new(),
        };

        let (event_tx, mut event_rx) = mpsc::channel(16);
        let mut orch = Orchestrator {
            registry: reg,
            ledger: SwarmLedger::new(),
            audit: AuditLogger::with_key(paths.audit_log.clone(), vec![3u8; 32]).unwrap(),
            skills: SkillsDir::new(paths.skills_dir.clone()).unwrap(),
            workspace: Workspace::new(project_dir.path().to_path_buf()).unwrap(),
            events: event_tx,
            classified: false,
            project_root: project_dir.path().to_path_buf(),
            decisions: None,
            approve_all: false,
        };

        orch.run_delegations(
            "ollama:llama3",
            "ACTION: delegate_task(ollama:mistral, do the thing)",
        )
        .await;

        let mut events = Vec::new();
        while let Ok(event) = event_rx.try_recv() {
            events.push(event);
        }
        assert!(matches!(events[0], Event::Delegated { .. }));
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::DelegationFinished { ok: false, .. }))
        );
        assert!(events.iter().any(|e| matches!(e, Event::Error(_))));

        let task = &orch.ledger.tasks()[0];
        assert_eq!(task.status, crate::swarm::TaskStatus::Failed);
        // The error text is recorded as the result, so the delegating model can see
        // WHY the task failed on its next turn.
        assert!(
            task.result
                .as_deref()
                .unwrap()
                .contains("simulated transport failure")
        );
    }

    #[tokio::test]
    async fn a_delegation_emits_the_task_and_a_finish_event() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        let reg = registry_with(
            vec![("ollama", "llama3", false), ("ollama", "mistral", false)],
            "ollama:llama3",
        );

        let (event_tx, mut event_rx) = mpsc::channel(16);
        let mut orch = Orchestrator {
            registry: reg,
            ledger: SwarmLedger::new(),
            audit: AuditLogger::with_key(paths.audit_log.clone(), vec![3u8; 32]).unwrap(),
            skills: SkillsDir::new(paths.skills_dir.clone()).unwrap(),
            workspace: Workspace::new(project_dir.path().to_path_buf()).unwrap(),
            events: event_tx,
            classified: false,
            project_root: project_dir.path().to_path_buf(),
            decisions: None,
            approve_all: false,
        };

        orch.run_delegations(
            "ollama:llama3",
            "ACTION: delegate_task(ollama:mistral, summarise the attached diff)",
        )
        .await;

        let mut events = Vec::new();
        while let Ok(event) = event_rx.try_recv() {
            events.push(event);
        }

        let delegated = events
            .iter()
            .find_map(|e| match e {
                Event::Delegated { to, task, .. } => Some((to.clone(), task.clone())),
                _ => None,
            })
            .expect("expected an Event::Delegated");
        assert_eq!(delegated.0, "ollama:mistral");
        assert_eq!(delegated.1, "summarise the attached diff");

        let finished = events
            .iter()
            .find_map(|e| match e {
                Event::DelegationFinished { to, ok, chars, .. } => Some((to.clone(), *ok, *chars)),
                _ => None,
            })
            .expect("expected an Event::DelegationFinished");
        assert_eq!(finished.0, "ollama:mistral");
        assert!(finished.1, "the stub provider always succeeds");
        assert!(finished.2 > 0, "a successful reply must report its size");
    }

    #[tokio::test]
    async fn a_failed_delegation_still_emits_a_finish_event() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let mut providers: BTreeMap<String, Arc<dyn Provider>> = BTreeMap::new();
        let ok = StubProvider {
            provider: "ollama".into(),
            model: "llama3".into(),
            remote: false,
        };
        providers.insert(ok.label(), Arc::new(ok));
        let failing = FailingProvider {
            provider: "ollama".into(),
            model: "mistral".into(),
        };
        providers.insert(failing.label(), Arc::new(failing));
        let reg = Registry {
            providers,
            primary: "ollama:llama3".to_string(),
            applied: BTreeMap::new(),
            connection_ids: BTreeMap::new(),
        };

        let (event_tx, mut event_rx) = mpsc::channel(16);
        let mut orch = Orchestrator {
            registry: reg,
            ledger: SwarmLedger::new(),
            audit: AuditLogger::with_key(paths.audit_log.clone(), vec![3u8; 32]).unwrap(),
            skills: SkillsDir::new(paths.skills_dir.clone()).unwrap(),
            workspace: Workspace::new(project_dir.path().to_path_buf()).unwrap(),
            events: event_tx,
            classified: false,
            project_root: project_dir.path().to_path_buf(),
            decisions: None,
            approve_all: false,
        };

        orch.run_delegations(
            "ollama:llama3",
            "ACTION: delegate_task(ollama:mistral, do the thing)",
        )
        .await;

        let mut events = Vec::new();
        while let Ok(event) = event_rx.try_recv() {
            events.push(event);
        }
        // A failed delegation must still produce a finish event — the whole point is
        // that the activity indicator (and, in the ledger, the task's status) always
        // has a terminal event to clear on, success or failure alike.
        assert!(events.iter().any(|e| matches!(
            e,
            Event::DelegationFinished {
                to,
                ok: false,
                chars: 0,
                ..
            } if to == "ollama:mistral"
        )));
    }

    #[tokio::test]
    async fn a_long_task_is_truncated_on_a_char_boundary_not_a_byte_index() {
        // Same trick as
        // `providers::mod::error_detail_is_truncated_on_a_char_boundary_not_a_byte_index`:
        // one ASCII byte followed by enough 3-byte `€` characters that a naive
        // `&s[..MAX_TASK_DISPLAY_CHARS]` byte slice lands mid-character and panics.
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        let reg = registry_with(
            vec![("ollama", "llama3", false), ("ollama", "mistral", false)],
            "ollama:llama3",
        );

        let (event_tx, mut event_rx) = mpsc::channel(16);
        let mut orch = Orchestrator {
            registry: reg,
            ledger: SwarmLedger::new(),
            audit: AuditLogger::with_key(paths.audit_log.clone(), vec![3u8; 32]).unwrap(),
            skills: SkillsDir::new(paths.skills_dir.clone()).unwrap(),
            workspace: Workspace::new(project_dir.path().to_path_buf()).unwrap(),
            events: event_tx,
            classified: false,
            project_root: project_dir.path().to_path_buf(),
            decisions: None,
            approve_all: false,
        };

        let long_task = format!("a{}", "€".repeat(130));
        orch.run_delegations(
            "ollama:llama3",
            &format!("ACTION: delegate_task(ollama:mistral, {long_task})"),
        )
        .await;

        let task = loop {
            match event_rx.try_recv() {
                Ok(Event::Delegated { task, .. }) => break task,
                Ok(_) => continue,
                Err(_) => panic!("expected an Event::Delegated"),
            }
        };
        assert!(task.ends_with('…'));
        // MAX_TASK_DISPLAY_CHARS kept chars, plus the ellipsis marker.
        assert_eq!(task.chars().count(), MAX_TASK_DISPLAY_CHARS + 1);
    }

    #[tokio::test]
    async fn a_successful_skill_read_emits_a_skill_loaded_event() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        std::fs::write(paths.skills_dir.join("notes.md"), "be terse").unwrap();

        let reg = registry_with(vec![("ollama", "llama3", false)], "ollama:llama3");
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let mut orch = Orchestrator {
            registry: reg,
            ledger: SwarmLedger::new(),
            audit: AuditLogger::with_key(paths.audit_log.clone(), vec![3u8; 32]).unwrap(),
            skills: SkillsDir::new(paths.skills_dir.clone()).unwrap(),
            workspace: Workspace::new(project_dir.path().to_path_buf()).unwrap(),
            events: event_tx,
            classified: false,
            project_root: project_dir.path().to_path_buf(),
            decisions: None,
            approve_all: false,
        };

        orch.run_skill_reads("ollama:llama3", "ACTION: read_skill(notes.md)")
            .await;

        let loaded = loop {
            match event_rx.try_recv() {
                Ok(Event::SkillLoaded { name, chars }) => break (name, chars),
                Ok(_) => continue,
                Err(_) => panic!("expected an Event::SkillLoaded"),
            }
        };
        assert_eq!(loaded.0, "notes.md");
        assert_eq!(loaded.1, "be terse".len());
    }

    #[tokio::test]
    async fn a_read_skill_request_loads_the_named_skill_into_the_ledger() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        std::fs::write(
            paths.skills_dir.join("notes.md"),
            "be terse and cite sources",
        )
        .unwrap();

        let reg = registry_with(vec![("ollama", "llama3", false)], "ollama:llama3");
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let mut orch = Orchestrator {
            registry: reg,
            ledger: SwarmLedger::new(),
            audit: AuditLogger::with_key(paths.audit_log.clone(), vec![3u8; 32]).unwrap(),
            skills: SkillsDir::new(paths.skills_dir.clone()).unwrap(),
            workspace: Workspace::new(project_dir.path().to_path_buf()).unwrap(),
            events: event_tx,
            classified: false,
            project_root: project_dir.path().to_path_buf(),
            decisions: None,
            approve_all: false,
        };

        orch.run_skill_reads("ollama:llama3", "ACTION: read_skill(notes.md)")
            .await;

        let mut events = Vec::new();
        while let Ok(event) = event_rx.try_recv() {
            events.push(event);
        }
        assert!(
            !events.iter().any(|e| matches!(e, Event::Error(_))),
            "a successful read must not emit Event::Error"
        );
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::SkillLoaded { name, .. } if name == "notes.md"))
        );
        let loaded = orch.ledger.loaded_skills();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "notes.md");
        assert_eq!(loaded[0].content, "be terse and cite sources");
    }

    #[tokio::test]
    async fn a_read_skill_traversal_attempt_surfaces_as_an_error_not_a_crash() {
        // This is the whole point of routing `read_skill` through the existing
        // `SkillsDir::read`: the skill name here comes straight from model output,
        // which is exactly the untrusted-input case `resolve`'s hardening (rejecting
        // `..`, absolute paths, and escaping symlinks) was written for. A malicious
        // or confused model must get an Event::Error, not a path outside the skills
        // root and not a panic that takes down the turn.
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let reg = registry_with(vec![("ollama", "llama3", false)], "ollama:llama3");
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let mut orch = Orchestrator {
            registry: reg,
            ledger: SwarmLedger::new(),
            audit: AuditLogger::with_key(paths.audit_log.clone(), vec![3u8; 32]).unwrap(),
            skills: SkillsDir::new(paths.skills_dir.clone()).unwrap(),
            workspace: Workspace::new(project_dir.path().to_path_buf()).unwrap(),
            events: event_tx,
            classified: false,
            project_root: project_dir.path().to_path_buf(),
            decisions: None,
            approve_all: false,
        };

        orch.run_skill_reads(
            "ollama:llama3",
            "ACTION: read_skill(../../../../etc/passwd)",
        )
        .await;

        // `ActivityStarted` now interleaves with the failure, so this can no longer
        // assert the error was the *only* event. Asserting no `SkillLoaded` keeps the
        // part that mattered: a failed read must never also report success.
        let mut saw_error = false;
        let mut saw_loaded = false;
        while let Ok(event) = event_rx.try_recv() {
            match event {
                Event::Error(_) => saw_error = true,
                Event::SkillLoaded { .. } => saw_loaded = true,
                _ => {}
            }
        }
        assert!(saw_error);
        assert!(!saw_loaded, "a failed skill read must not report success");
        assert!(orch.ledger.loaded_skills().is_empty());
    }

    #[tokio::test]
    async fn a_missing_skill_request_surfaces_as_an_error_not_a_crash() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let reg = registry_with(vec![("ollama", "llama3", false)], "ollama:llama3");
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let mut orch = Orchestrator {
            registry: reg,
            ledger: SwarmLedger::new(),
            audit: AuditLogger::with_key(paths.audit_log.clone(), vec![3u8; 32]).unwrap(),
            skills: SkillsDir::new(paths.skills_dir.clone()).unwrap(),
            workspace: Workspace::new(project_dir.path().to_path_buf()).unwrap(),
            events: event_tx,
            classified: false,
            project_root: project_dir.path().to_path_buf(),
            decisions: None,
            approve_all: false,
        };

        orch.run_skill_reads("ollama:llama3", "ACTION: read_skill(nope.md)")
            .await;

        // `ActivityStarted` now interleaves with the failure, so this can no longer
        // assert the error was the *only* event. Asserting no `SkillLoaded` keeps the
        // part that mattered: a failed read must never also report success.
        let mut saw_error = false;
        let mut saw_loaded = false;
        while let Ok(event) = event_rx.try_recv() {
            match event {
                Event::Error(_) => saw_error = true,
                Event::SkillLoaded { .. } => saw_loaded = true,
                _ => {}
            }
        }
        assert!(saw_error);
        assert!(!saw_loaded, "a failed skill read must not report success");
        assert!(orch.ledger.loaded_skills().is_empty());
    }

    #[tokio::test]
    async fn the_system_prompt_renders_a_skills_description_when_present() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        std::fs::write(
            paths.skills_dir.join("notes.md"),
            "---\ndescription: Summarise long documents.\n---\nbody\n",
        )
        .unwrap();
        std::fs::write(paths.skills_dir.join("plain.md"), "no frontmatter here").unwrap();

        let reg = registry_with(vec![("ollama", "llama3", false)], "ollama:llama3");
        let (event_tx, _event_rx) = mpsc::channel(16);
        let orch = Orchestrator {
            registry: reg,
            ledger: SwarmLedger::new(),
            audit: AuditLogger::with_key(paths.audit_log.clone(), vec![3u8; 32]).unwrap(),
            skills: SkillsDir::new(paths.skills_dir.clone()).unwrap(),
            workspace: Workspace::new(project_dir.path().to_path_buf()).unwrap(),
            events: event_tx,
            classified: false,
            project_root: project_dir.path().to_path_buf(),
            decisions: None,
            approve_all: false,
        };

        let prompt = orch.system_prompt();
        assert!(prompt.contains("- notes.md — Summarise long documents."));
        assert!(prompt.contains("- plain.md\n"));
    }

    #[tokio::test]
    async fn reconfigure_rebuilds_the_registry_and_resets_the_roster() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        let reg = registry_with(vec![("ollama", "llama3", false)], "ollama:llama3");

        let (event_tx, mut event_rx) = mpsc::channel(16);
        let mut orch = Orchestrator {
            registry: reg,
            ledger: SwarmLedger::new(),
            audit: AuditLogger::with_key(paths.audit_log.clone(), vec![3u8; 32]).unwrap(),
            skills: SkillsDir::new(paths.skills_dir.clone()).unwrap(),
            workspace: Workspace::new(project_dir.path().to_path_buf()).unwrap(),
            events: event_tx,
            classified: false,
            project_root: project_dir.path().to_path_buf(),
            decisions: None,
            approve_all: false,
        };
        orch.ledger.set_roster(orch.registry.labels());

        // Reconfigure to a settings value with no reachable connection at all: this
        // must surface as Event::Error, not a panic, and must leave the previous
        // registry in place.
        let empty_settings = Settings {
            ollama_host: "http://127.0.0.1:1".into(),
            connections: {
                let mut m = BTreeMap::new();
                m.insert(
                    "ollama:llama3".to_string(),
                    ConnectionSpec {
                        enabled: true,
                        transport: None,
                        path: None,
                        model: None,
                    },
                );
                m
            },
            ..Default::default()
        };
        orch.reconfigure(empty_settings).await;
        assert!(matches!(event_rx.try_recv(), Ok(Event::Error(_))));
        // The old registry is untouched: still has the original primary.
        assert_eq!(orch.registry.primary(), "ollama:llama3");
    }

    #[tokio::test]
    async fn set_commander_switches_the_primary_and_emits_the_resolved_label() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        let reg = registry_with(
            vec![("ollama", "llama3", false), ("ollama", "mistral", false)],
            "ollama:llama3",
        );

        let (event_tx, mut event_rx) = mpsc::channel(16);
        let mut orch = Orchestrator {
            registry: reg,
            ledger: SwarmLedger::new(),
            audit: AuditLogger::with_key(paths.audit_log.clone(), vec![3u8; 32]).unwrap(),
            skills: SkillsDir::new(paths.skills_dir.clone()).unwrap(),
            workspace: Workspace::new(project_dir.path().to_path_buf()).unwrap(),
            events: event_tx,
            classified: false,
            project_root: project_dir.path().to_path_buf(),
            decisions: None,
            approve_all: false,
        };

        // Bare model name, not the full label — exercises `set_primary`'s flexible
        // matching through the command path, not just directly on `Registry`.
        orch.set_commander("mistral").await;

        assert_eq!(orch.registry.primary(), "ollama:mistral");
        match event_rx.try_recv() {
            Ok(Event::CommanderChanged {
                label,
                connection_id,
            }) => {
                assert_eq!(label, "ollama:mistral");
                // `registry_with` never populates `connection_ids`, mirroring a
                // provider with no backing connection — the switch must still
                // succeed, just with nothing to persist.
                assert_eq!(connection_id, None);
            }
            other => panic!("expected CommanderChanged, got {other:?}"),
        }
        let audit_text = std::fs::read_to_string(&paths.audit_log).unwrap();
        assert!(audit_text.contains("commander.changed"));
        assert!(audit_text.contains("to=ollama:mistral"));
    }

    #[tokio::test]
    async fn set_commander_with_an_unknown_name_emits_an_error_and_leaves_primary_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        let reg = registry_with(vec![("ollama", "llama3", false)], "ollama:llama3");

        let (event_tx, mut event_rx) = mpsc::channel(16);
        let mut orch = Orchestrator {
            registry: reg,
            ledger: SwarmLedger::new(),
            audit: AuditLogger::with_key(paths.audit_log.clone(), vec![3u8; 32]).unwrap(),
            skills: SkillsDir::new(paths.skills_dir.clone()).unwrap(),
            workspace: Workspace::new(project_dir.path().to_path_buf()).unwrap(),
            events: event_tx,
            classified: false,
            project_root: project_dir.path().to_path_buf(),
            decisions: None,
            approve_all: false,
        };

        orch.set_commander("ghost").await;

        assert_eq!(orch.registry.primary(), "ollama:llama3");
        assert!(matches!(event_rx.try_recv(), Ok(Event::Error(_))));
    }

    #[tokio::test]
    async fn a_write_file_reply_creates_the_file_and_audits_it() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        let reg = registry_with(vec![("ollama", "llama3", false)], "ollama:llama3");

        let (event_tx, mut event_rx) = mpsc::channel(16);
        let mut orch = Orchestrator {
            registry: reg,
            ledger: SwarmLedger::new(),
            audit: AuditLogger::with_key(paths.audit_log.clone(), vec![3u8; 32]).unwrap(),
            skills: SkillsDir::new(paths.skills_dir.clone()).unwrap(),
            workspace: Workspace::new(project_dir.path().to_path_buf()).unwrap(),
            events: event_tx,
            classified: false,
            project_root: project_dir.path().to_path_buf(),
            decisions: None,
            approve_all: false,
        };

        // `StubProvider::send` echoes `"echo: {prompt}"`, prefixing only the first
        // line — the write block markers on later lines reach the reply intact.
        orch.handle_prompt(
            "please write it\nACTION: write_file(hello.txt)\nHello, world!\nACTION: end_file",
        )
        .await;

        let mut saw_write = false;
        while let Ok(event) = event_rx.try_recv() {
            if let Event::FileWritten { path, .. } = event {
                assert_eq!(path, "hello.txt");
                saw_write = true;
            }
        }
        assert!(saw_write, "expected an Event::FileWritten");

        let written = std::fs::read_to_string(project_dir.path().join("hello.txt")).unwrap();
        assert_eq!(written, "Hello, world!");

        let audit_text = std::fs::read_to_string(&paths.audit_log).unwrap();
        assert!(audit_text.contains("file.written"));
        assert!(audit_text.contains("hello.txt"));
    }

    #[tokio::test]
    async fn a_write_traversal_attempt_surfaces_as_an_error_not_a_crash() {
        // Mirrors `a_read_skill_traversal_attempt_surfaces_as_an_error_not_a_crash`:
        // the path here comes straight from model output, so it must go through
        // `Workspace::write`'s hardening and surface as `Event::Error`, not a path
        // outside the workspace root and not a panic that takes down the turn.
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        let reg = registry_with(vec![("ollama", "llama3", false)], "ollama:llama3");

        let (event_tx, mut event_rx) = mpsc::channel(16);
        let mut orch = Orchestrator {
            registry: reg,
            ledger: SwarmLedger::new(),
            audit: AuditLogger::with_key(paths.audit_log.clone(), vec![3u8; 32]).unwrap(),
            skills: SkillsDir::new(paths.skills_dir.clone()).unwrap(),
            workspace: Workspace::new(project_dir.path().to_path_buf()).unwrap(),
            events: event_tx,
            classified: false,
            project_root: project_dir.path().to_path_buf(),
            decisions: None,
            approve_all: false,
        };

        orch.run_file_writes(
            "ollama:llama3",
            vec![crate::swarm::FileWrite {
                path: "../escape.txt".into(),
                content: "malicious".into(),
            }],
        )
        .await;

        assert!(matches!(event_rx.try_recv(), Ok(Event::Error(_))));
        // "../escape.txt" would land one directory above the project root if the
        // traversal check failed to catch it.
        assert!(
            !project_dir
                .path()
                .parent()
                .unwrap()
                .join("escape.txt")
                .exists()
        );
        let written = orch.ledger.written_files();
        assert_eq!(written.len(), 1);
        assert!(written[0].outcome.contains("escapes"));
    }

    #[tokio::test]
    async fn a_written_file_is_listed_in_the_next_system_prompt() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        let reg = registry_with(vec![("ollama", "llama3", false)], "ollama:llama3");

        let (event_tx, _event_rx) = mpsc::channel(16);
        let mut orch = Orchestrator {
            registry: reg,
            ledger: SwarmLedger::new(),
            audit: AuditLogger::with_key(paths.audit_log.clone(), vec![3u8; 32]).unwrap(),
            skills: SkillsDir::new(paths.skills_dir.clone()).unwrap(),
            workspace: Workspace::new(project_dir.path().to_path_buf()).unwrap(),
            events: event_tx,
            classified: false,
            project_root: project_dir.path().to_path_buf(),
            decisions: None,
            approve_all: false,
        };

        orch.run_file_writes(
            "ollama:llama3",
            vec![crate::swarm::FileWrite {
                path: "notes.txt".into(),
                content: "hello".into(),
            }],
        )
        .await;

        let prompt = orch.system_prompt();
        assert!(prompt.contains("### Files you have written"));
        assert!(prompt.contains("notes.txt: ok (5 bytes)"));
        // The write's content ("hello") must never itself be echoed into the ledger —
        // only the path and byte-count outcome (see `WrittenFile`'s doc comment).
        assert!(!prompt.contains("hello"));
    }

    #[tokio::test]
    async fn a_delegated_task_is_told_to_finish_in_turn_but_the_ledger_keeps_the_original() {
        // `StubProvider` echoes the prompt it received, so the reply proves what was
        // actually sent; the ledger and the transcript must still show the
        // commander's own wording, not simon's augmentation.
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        let reg = registry_with(
            vec![("ollama", "llama3", false), ("ollama", "helper", false)],
            "ollama:llama3",
        );

        let (event_tx, mut event_rx) = mpsc::channel(64);
        let mut orch = Orchestrator {
            registry: reg,
            ledger: SwarmLedger::new(),
            audit: AuditLogger::with_key(paths.audit_log.clone(), vec![4u8; 32]).unwrap(),
            skills: SkillsDir::new(paths.skills_dir.clone()).unwrap(),
            workspace: Workspace::new(project_dir.path().to_path_buf()).unwrap(),
            events: event_tx,
            classified: false,
            project_root: project_dir.path().to_path_buf(),
            decisions: None,
            approve_all: false,
        };

        orch.run_delegations(
            "ollama:llama3",
            "ACTION: delegate_task(ollama:helper, summarise the diff)",
        )
        .await;

        let mut sent = String::new();
        let mut announced = String::new();
        while let Ok(event) = event_rx.try_recv() {
            match event {
                Event::Reply { text, .. } => sent = text,
                Event::Delegated { task, .. } => announced = task,
                _ => {}
            }
        }
        assert!(
            sent.contains("Do not dispatch, launch, or delegate to a subagent of your own"),
            "the sub-agent should have been told to finish in-turn: {sent}"
        );
        assert!(
            sent.contains("Do not run any shell, terminal, or command-line tool"),
            "the sub-agent should be told shell commands are refused outright, not \
             merely discouraged: {sent}"
        );
        assert!(sent.contains("summarise the diff"));
        // What the user and the commander see stays unaugmented.
        assert_eq!(announced, "summarise the diff");
        let tasks = orch.ledger.tasks();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].description, "summarise the diff");
    }

    /// Builds an orchestrator whose writes must be approved through `decisions`.
    fn orch_with_write_gate(
        project: &std::path::Path,
        paths: &Paths,
        events: mpsc::Sender<Event>,
        decisions: mpsc::Receiver<WriteDecision>,
    ) -> Orchestrator {
        Orchestrator {
            registry: registry_with(vec![("ollama", "llama3", false)], "ollama:llama3"),
            ledger: SwarmLedger::new(),
            audit: AuditLogger::with_key(paths.audit_log.clone(), vec![5u8; 32]).unwrap(),
            skills: SkillsDir::new(paths.skills_dir.clone()).unwrap(),
            workspace: Workspace::new(project.to_path_buf()).unwrap(),
            events,
            classified: false,
            project_root: project.to_path_buf(),
            decisions: Some(decisions),
            approve_all: false,
        }
    }

    fn one_write() -> Vec<crate::swarm::FileWrite> {
        vec![crate::swarm::FileWrite {
            path: "notes.txt".into(),
            content: "hello".into(),
        }]
    }

    #[tokio::test]
    async fn a_denied_write_never_reaches_disk_and_is_recorded_as_denied() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project = tempfile::tempdir().unwrap();
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let (dec_tx, dec_rx) = mpsc::channel(1);
        let mut orch = orch_with_write_gate(project.path(), &paths, event_tx, dec_rx);

        dec_tx.send(WriteDecision::Deny).await.unwrap();
        orch.run_file_writes("ollama:llama3", one_write()).await;

        assert!(
            !project.path().join("notes.txt").exists(),
            "a denied write must not create the file"
        );
        let mut asked = false;
        let mut denied = false;
        let mut written = false;
        while let Ok(e) = event_rx.try_recv() {
            match e {
                Event::WriteRequested { .. } => asked = true,
                Event::WriteDenied { .. } => denied = true,
                Event::FileWritten { .. } => written = true,
                _ => {}
            }
        }
        assert!(asked && denied && !written);
        // The model must learn the write did not happen, or it builds on a file that
        // does not exist.
        let recorded = orch.ledger.written_files();
        assert_eq!(recorded.len(), 1);
        assert!(recorded[0].outcome.contains("denied"));
    }

    #[tokio::test]
    async fn an_approved_write_lands_and_reports_what_it_would_overwrite() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("notes.txt"), "0123456789").unwrap();
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let (dec_tx, dec_rx) = mpsc::channel(1);
        let mut orch = orch_with_write_gate(project.path(), &paths, event_tx, dec_rx);

        dec_tx.send(WriteDecision::Approve).await.unwrap();
        orch.run_file_writes("ollama:llama3", one_write()).await;

        assert_eq!(
            std::fs::read_to_string(project.path().join("notes.txt")).unwrap(),
            "hello"
        );
        let mut overwrites = None;
        while let Ok(e) = event_rx.try_recv() {
            if let Event::WriteRequested { overwrites: o, .. } = e {
                overwrites = o;
            }
        }
        // Knowing 10 bytes are about to be destroyed is the point of the prompt.
        assert_eq!(overwrites, Some(10));
    }

    #[tokio::test]
    async fn approve_all_stops_asking_for_the_rest_of_the_session() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project = tempfile::tempdir().unwrap();
        let (event_tx, mut event_rx) = mpsc::channel(32);
        // Capacity 1 and only ONE decision sent: if the second write asked again this
        // would deadlock rather than pass, which is the assertion.
        let (dec_tx, dec_rx) = mpsc::channel(1);
        let mut orch = orch_with_write_gate(project.path(), &paths, event_tx, dec_rx);

        dec_tx.send(WriteDecision::ApproveAll).await.unwrap();
        orch.run_file_writes("ollama:llama3", one_write()).await;
        orch.run_file_writes(
            "ollama:llama3",
            vec![crate::swarm::FileWrite {
                path: "second.txt".into(),
                content: "two".into(),
            }],
        )
        .await;

        assert!(project.path().join("notes.txt").exists());
        assert!(project.path().join("second.txt").exists());
        let asked = std::iter::from_fn(|| event_rx.try_recv().ok())
            .filter(|e| matches!(e, Event::WriteRequested { .. }))
            .count();
        assert_eq!(asked, 1, "the second write must not ask again");
    }

    #[tokio::test]
    async fn a_closed_decision_channel_denies_rather_than_writes() {
        // Fail closed: if the UI is gone there is nobody to have consented, and the
        // entire purpose of the gate is that nothing reaches disk unseen.
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project = tempfile::tempdir().unwrap();
        let (event_tx, _event_rx) = mpsc::channel(16);
        let (dec_tx, dec_rx) = mpsc::channel(1);
        drop(dec_tx);
        let mut orch = orch_with_write_gate(project.path(), &paths, event_tx, dec_rx);

        orch.run_file_writes("ollama:llama3", one_write()).await;
        assert!(!project.path().join("notes.txt").exists());
    }

    #[tokio::test]
    async fn a_doomed_write_is_refused_without_asking_the_user() {
        // `.git/HEAD` is refused by `Workspace` no matter what the user answers, so
        // putting it to them would teach that their answer does not matter — and a
        // refusal after a "yes" reads as approval having failed.
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project = tempfile::tempdir().unwrap();
        std::fs::create_dir(project.path().join(".git")).unwrap();
        std::fs::write(project.path().join(".git/HEAD"), "ref: refs/heads/main").unwrap();
        let (event_tx, mut event_rx) = mpsc::channel(16);
        // Nothing is ever sent on this channel: if the code asked, it would block
        // forever rather than pass.
        let (_dec_tx, dec_rx) = mpsc::channel(1);
        let mut orch = orch_with_write_gate(project.path(), &paths, event_tx, dec_rx);

        orch.run_file_writes(
            "ollama:llama3",
            vec![crate::swarm::FileWrite {
                path: ".git/HEAD".into(),
                content: "ref: refs/heads/pwned".into(),
            }],
        )
        .await;

        assert_eq!(
            std::fs::read_to_string(project.path().join(".git/HEAD")).unwrap(),
            "ref: refs/heads/main"
        );
        let mut asked = false;
        let mut errored = false;
        while let Ok(e) = event_rx.try_recv() {
            match e {
                Event::WriteRequested { .. } => asked = true,
                Event::Error(_) => errored = true,
                _ => {}
            }
        }
        assert!(!asked, "a doomed write must not be put to the user");
        assert!(errored, "but it must still be reported");
    }

    #[test]
    fn a_write_preview_marks_itself_when_truncated() {
        let short = write_preview("one\ntwo\n");
        assert!(short.contains("one") && short.contains("two"));
        assert!(!short.contains("not shown"));

        let long: String = (0..100).map(|i| format!("line {i}\n")).collect();
        let preview = write_preview(&long);
        assert!(
            preview.contains("more line(s) not shown"),
            "a truncated preview must say so, or it reads as the whole file"
        );
    }

    #[tokio::test]
    async fn a_sub_agent_can_write_files_but_still_cannot_delegate_or_read() {
        // The asymmetry that makes a swarm able to build a project without becoming
        // unbounded: a sub-agent's reply produces writes, and nothing else. A write
        // spawns no further work, so the recursion bound is untouched.
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("secret.txt"), "top secret").unwrap();

        let mut providers: BTreeMap<String, Arc<dyn Provider>> = BTreeMap::new();
        providers.insert(
            "ollama:llama3".into(),
            Arc::new(StubProvider {
                provider: "ollama".into(),
                model: "llama3".into(),
                remote: false,
            }),
        );
        // Its reply is a write block plus two actions that must stay inert.
        providers.insert(
            "ollama:builder".into(),
            Arc::new(ScriptedProvider {
                provider: "ollama".into(),
                model: "builder".into(),
                reply: "Done.\n\
                        ACTION: write_file(made.txt)\n\
                        from the sub-agent\n\
                        ACTION: end_file\n\
                        ACTION: read_file(secret.txt)\n\
                        ACTION: delegate_task(ollama:llama3, recurse)"
                    .into(),
            }),
        );
        let (event_tx, mut event_rx) = mpsc::channel(64);
        let mut orch = Orchestrator {
            registry: Registry {
                providers,
                primary: "ollama:llama3".into(),
                applied: BTreeMap::new(),
                connection_ids: BTreeMap::new(),
            },
            ledger: SwarmLedger::new(),
            audit: AuditLogger::with_key(paths.audit_log.clone(), vec![6u8; 32]).unwrap(),
            skills: SkillsDir::new(paths.skills_dir.clone()).unwrap(),
            workspace: Workspace::new(project.path().to_path_buf()).unwrap(),
            events: event_tx,
            classified: false,
            project_root: project.path().to_path_buf(),
            // Pre-approved: the gate is exercised by its own tests, and this one is
            // about what a sub-agent's reply is allowed to cause.
            decisions: None,
            approve_all: false,
        };

        orch.run_delegations(
            "ollama:llama3",
            "ACTION: delegate_task(ollama:builder, build it)",
        )
        .await;

        // The write landed, attributed to the sub-agent.
        assert_eq!(
            std::fs::read_to_string(project.path().join("made.txt")).unwrap(),
            "from the sub-agent"
        );
        let mut author = None;
        let mut saw_read = false;
        let mut delegated_to = Vec::new();
        while let Ok(e) = event_rx.try_recv() {
            match e {
                Event::FileWritten { author: a, .. } => author = Some(a),
                Event::FileRead { .. } => saw_read = true,
                Event::Delegated { to, .. } => delegated_to.push(to),
                _ => {}
            }
        }
        assert_eq!(author.as_deref(), Some("ollama:builder"));
        // ...but its other actions are inert: no read, and no second delegation.
        assert!(
            !saw_read,
            "a sub-agent must not be able to read project files"
        );
        assert_eq!(
            delegated_to.len(),
            1,
            "a sub-agent reply must not spawn another delegation"
        );
        // The file content must not be echoed back into the ledger either.
        let tasks = orch.ledger.tasks();
        assert!(
            !tasks[0]
                .result
                .as_deref()
                .unwrap_or("")
                .contains("from the sub-agent")
        );
    }

    #[test]
    fn a_transient_sub_agent_error_is_worth_retrying() {
        // All four observed live from `agy` running the identical command twice.
        assert!(is_retryable_delegation_error(
            r#"agy failed: another active schedule task "3c32f6d6-0315""#
        ));
        assert!(is_retryable_delegation_error(
            "agy failed: invalid arguments:\n- missing properties 'toolSummary'"
        ));
        assert!(is_retryable_delegation_error("agy failed: CANCELED"));
        assert!(is_retryable_delegation_error("agy produced no output"));
    }

    #[test]
    fn a_permanent_failure_is_not_retried() {
        // A timeout has already spent the caller's patience — up to an hour for a
        // streaming CLI — so doing it twice more is not a recovery strategy.
        assert!(!is_retryable_delegation_error(
            "/usr/bin/agy timed out after 3600s (total time limit for a streaming call)"
        ));
        assert!(!is_retryable_delegation_error(
            "local binary `agy` points at /nope, which does not exist"
        ));
        assert!(!is_retryable_delegation_error(
            "local binary `agy` has an empty path"
        ));
    }

    #[test]
    fn there_is_a_backoff_for_every_retry() {
        // A mismatch here would panic on the last retry via an out-of-bounds index.
        assert_eq!(DELEGATION_RETRY_BACKOFF.len(), MAX_DELEGATION_ATTEMPTS - 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_delegation_that_fails_transiently_is_retried_and_then_succeeds() {
        // `start_paused` makes tokio auto-advance its clock over the backoff sleeps,
        // so this covers the real retry loop without spending 11 real seconds.
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let (event_tx, mut event_rx) = mpsc::channel(64);
        let mut orch = Orchestrator {
            registry: registry_with_flaky(2),
            ledger: SwarmLedger::new(),
            audit: AuditLogger::with_key(paths.audit_log.clone(), vec![9u8; 32]).unwrap(),
            skills: SkillsDir::new(paths.skills_dir.clone()).unwrap(),
            workspace: Workspace::new(project_dir.path().to_path_buf()).unwrap(),
            events: event_tx,
            classified: false,
            project_root: project_dir.path().to_path_buf(),
            decisions: None,
            approve_all: false,
        };

        orch.run_delegations(
            "ollama:llama3",
            "ACTION: delegate_task(ollama:flaky, do the thing)",
        )
        .await;

        let mut retries = 0;
        let mut finished_ok = None;
        while let Ok(event) = event_rx.try_recv() {
            match event {
                Event::DelegationRetry { attempt, max, .. } => {
                    retries += 1;
                    assert_eq!(max, MAX_DELEGATION_ATTEMPTS);
                    assert!(attempt > 1);
                }
                Event::DelegationFinished { ok, .. } => finished_ok = Some(ok),
                _ => {}
            }
        }
        assert_eq!(retries, 2, "two failures should produce two retry events");
        assert_eq!(finished_ok, Some(true), "the third attempt should succeed");
    }

    #[tokio::test(start_paused = true)]
    async fn a_delegation_that_keeps_failing_gives_up_after_the_attempt_cap() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let (event_tx, mut event_rx) = mpsc::channel(64);
        let mut orch = Orchestrator {
            registry: registry_with_flaky(usize::MAX),
            ledger: SwarmLedger::new(),
            audit: AuditLogger::with_key(paths.audit_log.clone(), vec![9u8; 32]).unwrap(),
            skills: SkillsDir::new(paths.skills_dir.clone()).unwrap(),
            workspace: Workspace::new(project_dir.path().to_path_buf()).unwrap(),
            events: event_tx,
            classified: false,
            project_root: project_dir.path().to_path_buf(),
            decisions: None,
            approve_all: false,
        };

        orch.run_delegations(
            "ollama:llama3",
            "ACTION: delegate_task(ollama:flaky, do the thing)",
        )
        .await;

        let mut retries = 0;
        let mut finished_ok = None;
        while let Ok(event) = event_rx.try_recv() {
            match event {
                Event::DelegationRetry { .. } => retries += 1,
                Event::DelegationFinished { ok, .. } => finished_ok = Some(ok),
                _ => {}
            }
        }
        // Three attempts means two retries, then a reported failure — not silence.
        assert_eq!(retries, MAX_DELEGATION_ATTEMPTS - 1);
        assert_eq!(finished_ok, Some(false));
    }

    #[test]
    fn the_commander_must_orient_and_propose_before_it_delegates() {
        // Without this the commander delegated on its very first turn having read
        // nothing — one real delegated prompt began "You are inspecting a software
        // project... produce a complete inventory", i.e. it was outsourcing the
        // discovery it needed in order to write that prompt in the first place. The
        // user also never saw a plan until files were already landing.
        let preamble = commander_preamble("claude", &["claude".into(), "agy".into()])
            .expect("a swarm roster must produce a preamble");
        assert!(preamble.contains("1. ORIENT"));
        assert!(preamble.contains("2. PROPOSE, and stop"));
        assert!(preamble.contains("3. DELEGATE"));
        assert!(preamble.contains("do not jump to the third"));
        // Orienting is the commander's own job: a sub-agent sees only its prompt, so
        // delegating discovery is what produces guesswork prompts.
        assert!(preamble.contains("Do not delegate this part"));
        // ...but bulk reading is still handed off, or the expensive model does the
        // very work delegation exists to avoid.
        assert!(preamble.contains("bulk reading is still work to hand off"));
    }

    #[test]
    fn an_already_settled_plan_is_not_re_proposed() {
        // The failure mode of a mandatory propose step: the user says "yes, do it"
        // and the commander proposes the same plan again instead of acting.
        let preamble = commander_preamble("claude", &["claude".into(), "agy".into()]).unwrap();
        assert!(preamble.contains("already approved a plan"));
        assert!(preamble.contains("do not re-propose what has been settled"));
    }

    #[test]
    fn a_lone_commander_gets_no_delegation_preamble() {
        // Nobody to delegate to: telling the model to hand work off would be advice it
        // cannot follow, and would waste tokens on every single turn.
        assert!(commander_preamble("claude", &["claude".to_string()]).is_none());
        assert!(commander_preamble("claude", &[]).is_none());
    }

    #[test]
    fn a_commander_with_a_swarm_is_told_who_it_can_delegate_to() {
        let preamble = commander_preamble(
            "claude",
            &[
                "claude".to_string(),
                "agy".to_string(),
                "ollama:l3".to_string(),
            ],
        )
        .expect("a roster with other models must produce a preamble");
        assert!(preamble.contains("ACTION: delegate_task"));
        // The commander itself must not be listed as a delegation target.
        assert!(!preamble.contains("claude."));
        assert!(preamble.contains("agy, ollama:l3"));
        // A trivial question must still be answerable directly, or the commander will
        // orient, plan and delegate its way through a greeting.
        assert!(preamble.contains("needs no more than a direct answer"));
    }

    #[test]
    fn subagent_preamble_forbids_shell_commands_outright() {
        // "Prefer not to" still leaves running the code to check it, or `git log` to
        // read history, as live options — both are real failures pulled from the
        // audit log, so the wording must refuse the tool, not just discourage it.
        let preamble = subagent_preamble();
        assert!(preamble.contains("Do not run any shell, terminal, or command-line tool"));
        assert!(preamble.contains("running or executing code to check that it works"));
        assert!(preamble.contains("git history or git log"));
    }

    #[test]
    fn subagent_preamble_forbids_its_own_file_writing_tools() {
        // agy's own writer already errors while declaring permissions non-interactively,
        // and separately was observed writing files simon never saw or approved. Both
        // are closed by refusing the tool outright rather than merely preferring simon's.
        let preamble = subagent_preamble();
        assert!(preamble.contains("Do not use your own file-writing or file-editing tools"));
        assert!(preamble.contains("does not count as this task being done"));
    }

    #[test]
    fn subagent_preamble_still_tells_it_to_finish_in_turn_and_not_dispatch_a_subagent() {
        let preamble = subagent_preamble();
        assert!(preamble.contains("Complete this task fully in THIS reply"));
        assert!(
            preamble.contains("Do not dispatch, launch, or delegate to a subagent of your own")
        );
        assert!(preamble.contains("do not answer that you are waiting on"));
        assert!(preamble.contains("say what you found and what blocked you"));
    }

    #[test]
    fn subagent_preamble_never_opens_a_write_block_at_line_start() {
        // Guards against reintroducing the bug `parse_file_writes` is sensitive to:
        // a line that STARTS with the write-block marker opens a real block, so this
        // instructional text must never contain that marker at the start of a line
        // (mid-sentence is fine — the parser only checks a line's start).
        for line in subagent_preamble().lines() {
            assert!(
                !line.trim().starts_with("ACTION: write_file("),
                "preamble line would be parsed as a real write block: {line:?}"
            );
        }
    }

    #[tokio::test]
    async fn the_preamble_reaches_the_model_but_not_the_transcript_or_the_audit_log() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        let reg = registry_with(
            vec![("ollama", "llama3", false), ("ollama", "helper", false)],
            "ollama:llama3",
        );

        let (event_tx, mut event_rx) = mpsc::channel(16);
        let mut orch = Orchestrator {
            registry: reg,
            ledger: SwarmLedger::new(),
            audit: AuditLogger::with_key(paths.audit_log.clone(), vec![7u8; 32]).unwrap(),
            skills: SkillsDir::new(paths.skills_dir.clone()).unwrap(),
            workspace: Workspace::new(project_dir.path().to_path_buf()).unwrap(),
            events: event_tx,
            classified: false,
            project_root: project_dir.path().to_path_buf(),
            decisions: None,
            approve_all: false,
        };

        orch.handle_prompt("hello").await;

        // `StubProvider` echoes whatever prompt it received, so the reply is proof of
        // what actually reached the model.
        let mut reply_text = String::new();
        while let Ok(event) = event_rx.try_recv() {
            if let Event::Reply { text, .. } = event {
                reply_text = text;
            }
        }
        assert!(
            reply_text.contains("ACTION: delegate_task"),
            "the model should have received the commander directive: {reply_text}"
        );
        assert!(reply_text.contains("hello"));

        // The audit log records what the *user* typed, not the augmented prompt —
        // otherwise every turn's recorded size is inflated by a constant simon added.
        let log = std::fs::read_to_string(&paths.audit_log).unwrap();
        assert!(
            log.contains("chars=5"),
            "audit log should record `hello`: {log}"
        );
    }

    #[tokio::test]
    async fn a_successful_read_emits_file_read_and_records_in_the_ledger() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        std::fs::write(project_dir.path().join("notes.txt"), "hello there").unwrap();
        let reg = registry_with(vec![("ollama", "llama3", false)], "ollama:llama3");

        let (event_tx, mut event_rx) = mpsc::channel(16);
        let mut orch = Orchestrator {
            registry: reg,
            ledger: SwarmLedger::new(),
            audit: AuditLogger::with_key(paths.audit_log.clone(), vec![3u8; 32]).unwrap(),
            skills: SkillsDir::new(paths.skills_dir.clone()).unwrap(),
            workspace: Workspace::new(project_dir.path().to_path_buf()).unwrap(),
            events: event_tx,
            classified: false,
            project_root: project_dir.path().to_path_buf(),
            decisions: None,
            approve_all: false,
        };

        orch.run_file_reads("ollama:llama3", "ACTION: read_file(notes.txt)")
            .await;

        let mut saw_read = false;
        while let Ok(event) = event_rx.try_recv() {
            if let Event::FileRead { path, chars } = event {
                assert_eq!(path, "notes.txt");
                assert_eq!(chars, "hello there".len());
                saw_read = true;
            }
        }
        assert!(saw_read, "expected an Event::FileRead");

        let loaded = orch.ledger.loaded_reads();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].path, "notes.txt");
        assert_eq!(loaded[0].content, "hello there");
    }

    #[tokio::test]
    async fn a_read_traversal_attempt_surfaces_as_an_error_not_a_crash() {
        // Mirrors `a_read_skill_traversal_attempt_surfaces_as_an_error_not_a_crash`
        // and `a_write_traversal_attempt_surfaces_as_an_error_not_a_crash`: the path
        // comes straight from model output, so it must go through `Workspace::read`'s
        // hardening and surface as `Event::Error`, never a path outside the project
        // root and never a panic that takes down the turn.
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        std::fs::write(
            project_dir.path().parent().unwrap().join("secret.txt"),
            "top secret",
        )
        .unwrap();
        let reg = registry_with(vec![("ollama", "llama3", false)], "ollama:llama3");

        let (event_tx, mut event_rx) = mpsc::channel(16);
        let mut orch = Orchestrator {
            registry: reg,
            ledger: SwarmLedger::new(),
            audit: AuditLogger::with_key(paths.audit_log.clone(), vec![3u8; 32]).unwrap(),
            skills: SkillsDir::new(paths.skills_dir.clone()).unwrap(),
            workspace: Workspace::new(project_dir.path().to_path_buf()).unwrap(),
            events: event_tx,
            classified: false,
            project_root: project_dir.path().to_path_buf(),
            decisions: None,
            approve_all: false,
        };

        orch.run_file_reads("ollama:llama3", "ACTION: read_file(../secret.txt)")
            .await;

        let mut saw_error = false;
        let mut saw_read = false;
        while let Ok(event) = event_rx.try_recv() {
            match event {
                Event::Error(_) => saw_error = true,
                Event::FileRead { .. } => saw_read = true,
                _ => {}
            }
        }
        assert!(saw_error);
        assert!(!saw_read, "a failed read must not emit Event::FileRead");
        assert!(
            orch.ledger.loaded_reads().is_empty(),
            "a failed read must not also record success in the ledger"
        );
    }

    #[tokio::test]
    async fn a_read_file_line_inside_a_write_block_is_not_executed() {
        // Security-critical: an `ACTION: read_file(...)` line that only appears
        // inside a `write_file` block's content (a model documenting this very
        // protocol, say) must be treated as file content, not a real request. This
        // is only true because `handle_prompt` feeds `run_file_reads` the *stripped*
        // text `parse_file_writes` returns, never the raw reply — see
        // `parse_read_files`'s doc comment for why that ordering matters.
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        std::fs::write(project_dir.path().join("secret.txt"), "top secret").unwrap();
        let reg = registry_with(vec![("ollama", "llama3", false)], "ollama:llama3");

        let (event_tx, mut event_rx) = mpsc::channel(16);
        let mut orch = Orchestrator {
            registry: reg,
            ledger: SwarmLedger::new(),
            audit: AuditLogger::with_key(paths.audit_log.clone(), vec![3u8; 32]).unwrap(),
            skills: SkillsDir::new(paths.skills_dir.clone()).unwrap(),
            workspace: Workspace::new(project_dir.path().to_path_buf()).unwrap(),
            events: event_tx,
            classified: false,
            project_root: project_dir.path().to_path_buf(),
            decisions: None,
            approve_all: false,
        };

        // Leading newline so the marker lands at the start of a line in the stub's
        // echoed reply (`echo: <prompt>`), which is what a real model emits and what
        // `parse_file_writes` now requires — see its `strip_prefix` comment.
        orch.handle_prompt(
            "\nACTION: write_file(README.md)\n\
             Here is how to read a file:\n\
             ACTION: read_file(secret.txt)\n\
             ACTION: end_file",
        )
        .await;

        let mut saw_read = false;
        let mut saw_error = false;
        while let Ok(event) = event_rx.try_recv() {
            match event {
                Event::FileRead { .. } => saw_read = true,
                Event::Error(_) => saw_error = true,
                _ => {}
            }
        }
        assert!(
            !saw_read,
            "a read_file line inside write_file content must not execute"
        );
        assert!(
            !saw_error,
            "an unexecuted read_file line must not surface as an error either"
        );
        assert!(orch.ledger.loaded_reads().is_empty());
    }

    #[tokio::test]
    async fn a_list_of_the_root_returns_the_projects_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        std::fs::write(project_dir.path().join("a.txt"), "a").unwrap();
        std::fs::write(project_dir.path().join("b.txt"), "b").unwrap();
        let reg = registry_with(vec![("ollama", "llama3", false)], "ollama:llama3");

        let (event_tx, mut event_rx) = mpsc::channel(16);
        let mut orch = Orchestrator {
            registry: reg,
            ledger: SwarmLedger::new(),
            audit: AuditLogger::with_key(paths.audit_log.clone(), vec![3u8; 32]).unwrap(),
            skills: SkillsDir::new(paths.skills_dir.clone()).unwrap(),
            workspace: Workspace::new(project_dir.path().to_path_buf()).unwrap(),
            events: event_tx,
            classified: false,
            project_root: project_dir.path().to_path_buf(),
            decisions: None,
            approve_all: false,
        };

        orch.run_file_lists("ollama:llama3", "ACTION: list_files()")
            .await;

        let mut saw_list = false;
        while let Ok(event) = event_rx.try_recv() {
            if let Event::FilesListed { path, entries } = event {
                assert_eq!(path, "");
                assert_eq!(entries, 2);
                saw_list = true;
            }
        }
        assert!(saw_list, "expected an Event::FilesListed");

        let listings = orch.ledger.file_listings();
        assert_eq!(listings.len(), 1);
        assert!(listings[0].outcome.contains("a.txt"));
        assert!(listings[0].outcome.contains("b.txt"));
    }
}

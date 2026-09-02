//! The engine that ties the TUI, the providers, the ledger, and the audit log together.
//!
//! This is the module the previous version was missing entirely: every provider,
//! the vault, the ledger, and the audit logger existed but had no caller, so user input
//! never reached a model.

use anyhow::{Result, anyhow};
use secrecy::ExposeSecret;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt as _;
use tokio::process::Command as TokioCommand;
use tokio::sync::mpsc;

use crate::app::ActivityKind;
use crate::audit::AuditLogger;
use crate::command_runner::{COMMAND_TIMEOUT, execute_command, validate_command};
use crate::config::{ConnectionSpec, Credentials, Paths, Settings, Transport};
use crate::providers::{
    ProgressSink, Provider, RateLimit, TokenUsage,
    cloud::CloudProvider,
    http_client,
    local_binary::{CliInvocation, LocalBinaryProvider, StreamDialect},
    ollama::OllamaProvider,
};
use crate::skills::SkillsDir;
use crate::swarm::{CopyDisposition, Delegation, RunOutcome, RunRequest, SwarmLedger, TaskStatus};
use crate::workspace::Workspace;

/// Delegations honoured per user turn, so a model cannot spin the swarm forever.
///
/// Ten leaves enough room for the common "ask every connected model" request while
/// retaining a hard upper bound against a malformed or hostile commander response.
const MAX_DELEGATIONS_PER_TURN: usize = 10;

/// Skill loads and project reads honoured per turn. These are independent of the
/// model roster: increasing delegation capacity for "ask everyone" must not also
/// multiply filesystem work a model can trigger.
const MAX_READ_ACTIONS_PER_TURN: usize = 3;

/// How many files one model may write in a single turn.
///
/// Separate from `MAX_DELEGATIONS_PER_TURN`, which it used to borrow, because the two
/// bound different things. A delegation costs a model call; a write costs a disk write
/// the user has already been shown and has approved one at a time. Creating a project
/// from nothing is the case that needs the headroom — a README, a module, a test and a
/// manifest is already four — and the user, not this number, is the real limit on how
/// much lands.
const MAX_WRITES_PER_TURN: usize = 10;
const MAX_RUN_ACTIONS_PER_TURN: usize = 2;
const MAX_COPY_ACTIONS_PER_TURN: usize = 5;
const MAX_APPLY_FILES: usize = 500;

/// Automatic commander follow-ups per user message. Together with the initial call,
/// this permits six bounded reasoning/action rounds before the workflow is stopped.
const MAX_AUTO_CONTINUATION_TURNS: u8 = 5;

/// Total protocol actions that one user message may trigger across every automatic
/// round. Per-action-type caps still apply inside each round.
const MAX_ACTIONS_PER_WORKFLOW: usize = 48;

const CONTINUATION_PROMPT: &str = "[automatic continuation] This is not a new user turn. Action results are now recorded in the ledger. Continue the already-authorized workflow without re-proposing it or asking the user to type `continue`; when the work is complete, give the final answer with no ACTION lines.";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum ActionKey {
    Delegation {
        target: String,
        prompt_hash: u64,
        workspace_task: Option<usize>,
    },
    SkillRead(String),
    FileRead(String),
    FileList(String),
    FileWrite {
        path: String,
        content_hash: u64,
    },
    Run {
        task_id: usize,
        argv_hash: u64,
    },
    ApplyCopy(usize),
    DiscardCopy(usize),
}

#[derive(Debug)]
struct TurnOutcome {
    commander_failed: bool,
    action_fingerprint: Vec<ActionKey>,
    state_fingerprint: u64,
    action_limit: Option<ActionLimit>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActionLimit {
    PerTurn,
    Workflow,
}

fn hash_action_str(value: &str) -> u64 {
    const OFFSET: u64 = 14_695_981_039_346_656_037;
    const PRIME: u64 = 1_099_511_628_211;
    value.bytes().fold(OFFSET, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(PRIME)
    })
}

fn take_action_budget<T>(
    requests: Vec<T>,
    per_turn_limit: usize,
    remaining: &mut usize,
) -> (Vec<T>, bool, bool) {
    let total_requested = requests.len();
    let requested = requests.len().min(per_turn_limit);
    let allowed = requested.min(*remaining);
    *remaining -= allowed;
    (
        requests.into_iter().take(allowed).collect(),
        requested < total_requested,
        allowed < requested,
    )
}

fn display_argv(argv: &[String]) -> String {
    argv.iter()
        .map(|arg| format!("{arg:?}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn summarize_paths(paths: &[String]) -> String {
    const SHOWN: usize = 10;
    let mut summary = paths
        .iter()
        .take(SHOWN)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    if paths.len() > SHOWN {
        summary.push_str(&format!(", ... and {} more", paths.len() - SHOWN));
    }
    summary
}

fn continuation_prompt(original_prompt: &str) -> String {
    format!("{CONTINUATION_PROMPT}\n\n--- original user request ---\n{original_prompt}")
}

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
         Reading and inspecting to orient yourself is fine. CREATING OR EDITING A \
         FILE WITH YOUR OWN TOOLS IS NOT — not an edit tool, not a shell redirect, \
         not a heredoc. A file changed that way never reaches the user for approval \
         and is never recorded, so from where they sit it changed by itself. Every \
         file you write goes out as a write block in your reply, exactly like a \
         sub-agent's, and the user approves it before it lands. Do not run the \
         project's code with your own shell or tools. Proof commands are available \
         only through Simon's explicit `ACTION: run_command(...)` protocol and only \
         inside an isolated delegated-task copy, where the user approves each run.\n\
         2. PROPOSE, and stop. Say what you found, what you intend to do, any real \
         alternative worth weighing and why you prefer yours, and exactly which \
         tasks you would give to which model and why that model. Then stop and let \
         the user answer. They know things the files do not, and a plan is far \
         cheaper to correct than finished files are.\n\
         3. DELEGATE, once the plan has been agreed. Hand each piece to the cheapest \
         capable model with `ACTION: delegate_task(<label>, <self-contained \
         prompt>)`, then stop and say what you delegated; results reach you on your \
         NEXT turn. Use `ACTION: delegate_file_task(<label>, <self-contained prompt>)` \
         instead when the task must create or edit project files; that creates a \
         bounded isolated copy and only that explicit form gives the worker the \
         file-write protocol. Its writes stay in the copy, never the user's project. \
         Use `ACTION: delegate_in_copy(<task id>, <label>, <prompt>)` to continue the \
         same RED → fix → GREEN investigation. Tell it exactly what evidence or files \
         to produce. Keep judgement, proof review, and synthesis for yourself.\n\
         If the user asks to hear from every connected model, emit every required \
         delegation in this reply (up to the 10-delegation safety cap). After any \
         ACTION requests finish, their results are fed back to you automatically on \
         a bounded continuation turn; do not ask the user to type `continue`.\n\
         For defect work, do not accept an agent's claim as proof. Have it name an \
         exact argv-only proof, run that command yourself in its task copy, inspect \
         that RED failed for the claimed reason rather than a malformed test, then \
         continue the same copy for the fix and rerun GREEN plus relevant regressions. \
         Apply or discard the copy explicitly; there is no automatic merge.\n\
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
    /// `/forget` typed in chat: clear the ledger's accumulated content. This is
    /// `docs/AUDIT-2026-07-30.md` §3.2's other half — the whole-prompt budget in
    /// `SwarmLedger::system_prompt` bounds any single turn, but a session that has run
    /// long enough has no way back to a small prompt short of restarting. See
    /// `SwarmLedger::clear_content` for exactly what survives and why.
    ClearLedger,
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
            Command::ClearLedger => write!(f, "ClearLedger"),
        }
    }
}

/// Sent from the orchestrator back to the UI.
#[derive(Debug, Clone)]
pub enum Event {
    /// A model produced a reply.
    Reply { label: String, text: String },
    /// Usage and quota metadata observed for one completed provider call.
    ///
    /// Kept separate from `Reply` so transcript rendering stays concerned only with
    /// user-visible text while the global status line can accumulate telemetry.
    UsageUpdated {
        label: String,
        usage: TokenUsage,
        rate_limit: RateLimit,
        /// Running total of tokens spent so far this UTC calendar month, across every
        /// model and session, persisted by `usage_ledger.rs` so it survives restarts.
        /// Set to `0` if persisting this call's tokens failed (see
        /// `Orchestrator::record_month_usage`) rather than silently keeping the
        /// previous, now-inaccurate, total.
        month_tokens: u64,
    },
    /// A delegation was dispatched. `task` is the complete sub-agent prompt for the
    /// scrollable TUI transcript. The audit log still records only its task id and
    /// labels (see `run_delegations`'s `task.delegated` call).
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
    /// A bounded snapshot was created for a file-producing delegated task.
    TaskCopyCreated {
        task_id: usize,
        files: usize,
        bytes: u64,
        excluded: usize,
    },
    /// A task copy was explicitly applied or discarded and then removed.
    TaskCopyReleased { task_id: usize, applied: bool },
    /// A validated task-copy command is waiting for explicit user approval.
    RunRequested {
        author: String,
        task_id: usize,
        argv_display: String,
    },
    /// The user refused a proof command. Nothing was spawned.
    RunDenied { author: String, task_id: usize },
    /// A proof command finished. Nonzero and timeout outcomes are evidence, not
    /// orchestration errors, so both travel through this event.
    RunCompleted {
        author: String,
        task_id: usize,
        outcome: RunOutcome,
        chars: usize,
        millis: u64,
    },
    /// Action results were recorded and the commander is being called again without
    /// requiring the user to type "continue".
    AutoContinuation { turn: u8, max: u8 },
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
        model_statuses: Vec<ModelStatus>,
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
    /// `/forget` (`Command::ClearLedger`) ran. `chars_before`/`chars_after` are the
    /// rendered system prompt's size immediately before and after the clear, so the
    /// user gets concrete evidence the command did something rather than a bare
    /// "cleared" they have to take on faith.
    LedgerCleared {
        chars_before: usize,
        chars_after: usize,
    },
}

/// Ceiling on how much of a single streaming-CLI progress detail is kept before it
/// reaches an `Event::ActivityProgress`. Progress belongs in a one-line status area,
/// unlike delegated task text, which lives in the scrollable transcript and is kept
/// complete.
/// Builds the directive prepended to a delegated task's prompt before it is sent.
///
/// Symmetric with `commander_preamble` and for the same underlying reason: an
/// agentic CLI has its own ideas about how to work, and the only lever simon has over
/// them is the text of the turn. Plain completion providers skip those irrelevant
/// tool warnings; a small local model was observed following the warning instead of
/// its greeting task.
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
/// explicitly requested files back through simon's own write protocol closes that
/// hole: the write is plain text in the reply, so it lands on simon's side of the
/// gate.
fn subagent_preamble(requires_tool_guardrails: bool, allow_writes: bool) -> String {
    let mut out = String::from(
        "[sub-agent] Complete this task fully in THIS reply. Do not dispatch, launch, \
         or delegate to a subagent of your own, and do not answer that you are waiting \
         on one: your reply is the entire result that reaches the requester, so \
         anything you defer is lost. If you genuinely cannot finish, say what you \
         found and what blocked you.\n",
    );

    if requires_tool_guardrails {
        out.push_str(
            "Do not run any shell, terminal, or command-line tool for any reason. This \
             includes running or executing code to check that it works, and inspecting \
             git history or git log. You are running non-interactively with nobody \
             present to approve a command, so any attempt to run one is refused and \
             fails this task — do not try, even once, even to verify something you \
             already wrote.\n\
             Do not use your own file-writing or file-editing tools either, for the \
             same reason: a file written that way is invisible to this system and to \
             the user, is not recorded anywhere, and does not count as this task being \
             done, even if the tool call itself appears to succeed.\n\
             Reading files and listing directories needs no permission and is fine to \
             use freely. Prefer listing a directory to searching across one: a \
             project-wide search is slow enough to time out on its own, and on a task \
             that starts from an empty or nearly empty folder it has nothing to find \
             anyway.\n",
        );
    }

    if allow_writes {
        out.push_str(
            "This task explicitly allows project-file writes. The only way a file \
             reaches the project is to emit it as plain text using the file-write \
             protocol in the system prompt. Do not use your own file-writing tools.\n",
        );
    } else {
        out.push_str(
            "This is a text-only task. Do not create or edit files, emit any ACTION \
             line, or invent a file as a way to answer; reply only with the requested \
             prose.\n",
        );
    }
    out.push_str("--- the task follows ---\n");
    out
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
    let mut lines_shown = 0;
    for line in content.lines().take(WRITE_PREVIEW_LINES) {
        out.push_str(line);
        out.push('\n');
        lines_shown += 1;
    }
    if let Some((cut, _)) = out.char_indices().nth(WRITE_PREVIEW_CHARS) {
        // The char cap can bite mid-way through the lines just counted — a long
        // enough line 12 of 20 means lines 12 through 20 never actually reached
        // `out`. `lines_shown` has to reflect what is really there, not what the
        // loop above attempted, or the "more line(s)" count below understates how
        // much of the file the user has not seen before approving it.
        lines_shown = out[..cut].matches('\n').count();
        out.truncate(cut);
        out.push_str("…\n");
    }
    if total_lines > lines_shown {
        out.push_str(&format!(
            "… {} more line(s) not shown\n",
            total_lines - lines_shown
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
/// - an invalid model or exhausted quota needs user/configuration action;
/// - an authentication failure (HTTP 401/403) means the configured credentials are
///   wrong or lack permission; retrying resends the same header and fails identically;
/// - a `--classified` refusal is a policy decision, not a blip.
fn is_retryable_delegation_error(error: &str) -> bool {
    // "timed out after", not bare "timed out": every timeout simon raises itself is
    // formatted "<binary> timed out after <N>s" (see `local_binary`), and those are
    // the only ones that have already spent the caller's patience. A sub-agent's own
    // internal tool timeout reads differently — "Grep command timed out due to the
    // size of the codebase" was observed being classified permanent and abandoned on
    // its first attempt, when it is exactly the transient blip retrying exists for.
    const PERMANENT: &[&str] = &[
        "timed out after",
        "does not exist",
        "has an empty path",
        "invalid model selection",
        "not recognized as a known model",
        "you've hit your weekly limit",
        "insufficient_quota",
        "quota exceeded",
        "exceeded your current quota",
        // Both `cloud.rs` and `ollama.rs` format a non-2xx response as
        // "<provider> returned <status>: <detail>", where `<status>` is
        // `reqwest::StatusCode`'s `Display` — always the numeric code followed by its
        // fixed canonical reason phrase, never provider- or attacker-controlled text.
        // An OpenRouter 401 ("openrouter returned 401 Unauthorized: {\"error\":...
        // \"User not found.\"...}") was observed retried twice before failing, wasting
        // ~11s: a bad or revoked API key answers every retry identically, so this
        // belongs with the other configuration failures above, not the transient ones.
        "401 unauthorized",
        "403 forbidden",
        // Not bare "classified": every real refusal is worded "refused under
        // --classified" (see `discover_ollama`/`build_vendor_candidate`), and bare
        // "classified" also matches "unclassified", "declassified" and
        // "reclassified" appearing in any unrelated transient error, abandoning a
        // retryable failure after one attempt — the exact bug `"timed out after"`
        // was narrowed for above.
        "--classified",
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
    truncate_chars(&sanitize_transcript_detail(raw), MAX_PROGRESS_DETAIL_CHARS)
}

/// Removes terminal control characters and folds whitespace without shortening the
/// message. Used for retry explanations in the scrollable transcript, where the full
/// reason is useful and wrapping is available.
fn sanitize_transcript_detail(raw: &str) -> String {
    raw.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// The *kind* of a failure — safe to write to the audit log even though the error's
/// own message is not (see `safe_error_detail`). A closed, small set: every variant
/// exists because a reader auditing the log later needs to tell one failure mode from
/// another (a stuck connection is not the same incident as a missing file), not
/// because it captures everything the error could mean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorKind {
    NotFound,
    PermissionDenied,
    Timeout,
    ConnectionRefused,
    ConnectionFailed,
    InvalidResponse,
    /// The provider answered, with a status that was not a success.
    HttpStatus,
    /// Nothing in the error's cause chain matched a known kind above. Still reachable —
    /// plenty of failures here are `anyhow!("...")` with no typed source — but no longer
    /// the common case: the two that dominate in practice, a model CLI that never
    /// answered and a provider returning a non-2xx status, now carry a
    /// `providers::ProviderFailure` cause precisely so they do not land here.
    Unspecified,
}

impl ErrorKind {
    fn as_str(self) -> &'static str {
        match self {
            ErrorKind::NotFound => "not_found",
            ErrorKind::PermissionDenied => "permission_denied",
            ErrorKind::Timeout => "timeout",
            ErrorKind::ConnectionRefused => "connection_refused",
            ErrorKind::ConnectionFailed => "connection_failed",
            ErrorKind::InvalidResponse => "invalid_response",
            ErrorKind::HttpStatus => "http_status",
            ErrorKind::Unspecified => "unspecified",
        }
    }
}

/// Classifies `err` by walking its `anyhow` cause chain for a concrete type whose
/// *kind* — never its `Display` — is safe to name.
///
/// This is the chosen alternative to two weaker options. Bounding-only (what
/// `providers::truncate_error_detail` already does) caps *length*, not *content*: a
/// short string can still be a fragment of a response body. Grepping the message for
/// suspicious substrings is worse still — it is trying to blocklist an open-ended
/// space of attacker- and model-controlled text, and a blocklist over free text is
/// always incomplete. Classifying by type is closed instead of open: `std::io::Error`
/// and `reqwest::Error` expose their kind through a fixed, developer-defined
/// vocabulary (`ErrorKind::NotFound`, `is_timeout()`, …) that a remote server or a
/// model's own output has no way to steer, unlike the prose next to it.
///
/// `serde_json::Error` gets one bucket (`InvalidResponse`) because a malformed-JSON
/// body is the same *kind* of failure however it is malformed — nothing downstream
/// acts differently on "unexpected EOF" versus "expected `,`".
///
/// A plain `anyhow!("...")` with no wrapped source — the common case, per
/// `ErrorKind::Unspecified`'s doc comment — matches nothing here and falls through.
fn classify_error(err: &anyhow::Error) -> ErrorKind {
    for cause in err.chain() {
        if let Some(io_err) = cause.downcast_ref::<std::io::Error>() {
            match io_err.kind() {
                std::io::ErrorKind::NotFound => return ErrorKind::NotFound,
                std::io::ErrorKind::PermissionDenied => return ErrorKind::PermissionDenied,
                std::io::ErrorKind::TimedOut => return ErrorKind::Timeout,
                std::io::ErrorKind::ConnectionRefused => return ErrorKind::ConnectionRefused,
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted => {
                    return ErrorKind::ConnectionFailed;
                }
                _ => {}
            }
        }
        if let Some(req_err) = cause.downcast_ref::<reqwest::Error>() {
            if req_err.is_timeout() {
                return ErrorKind::Timeout;
            }
            if req_err.is_connect() {
                return ErrorKind::ConnectionFailed;
            }
            if req_err.is_status() {
                return ErrorKind::HttpStatus;
            }
            if req_err.is_decode() || req_err.is_body() {
                return ErrorKind::InvalidResponse;
            }
        }
        if cause.downcast_ref::<serde_json::Error>().is_some() {
            return ErrorKind::InvalidResponse;
        }
        // This crate's own failures. Without these the dominant real-world cases —
        // a model CLI that never answered, a provider that returned 429 — fell through
        // to `Unspecified`, which is exactly the information the audit entry exists to
        // carry. See `providers::ProviderFailure`.
        if let Some(failure) = cause.downcast_ref::<crate::providers::ProviderFailure>() {
            return match failure {
                crate::providers::ProviderFailure::Timeout => ErrorKind::Timeout,
                crate::providers::ProviderFailure::HttpStatus(_) => ErrorKind::HttpStatus,
            };
        }
    }
    ErrorKind::Unspecified
}

/// Turns an error into the only representation the audit log's hard invariant
/// allows — sizes, counts, and paths only, never content (see the `Sizes and counts
/// only, never content` comment on `run_file_reads`'s audit call, and
/// `docs/AUDIT-2026-07-30.md` §3.5). Every call site that used to write
/// `format!("... error={e}")` embedded the error's own `Display` straight into the
/// log, which is exactly what the invariant forbids: a provider error can carry a
/// fragment of the response body, an `anyhow` chain concatenates its whole context,
/// and none of that is simon's to disclose in a file designed to be handed to someone
/// else as evidence.
///
/// This never touches `Display`. It records the *kind* alone (`classify_error`), which
/// is safe by construction, plus an explicit `detail=withheld` marker — so a reader
/// can tell "this event has no error text" (a log line with no detail field) apart
/// from "there was error text, and it was deliberately not recorded" (this). Bounded
/// regardless of input for the strongest possible reason: the input's length never
/// factors into the output at all.
fn safe_error_detail(err: &anyhow::Error) -> String {
    format!("kind={} detail=withheld", classify_error(err).as_str())
}

/// Whether a candidate connection can actually be constructed right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Availability {
    /// Live probe succeeded (or Ollama responded): fully ready.
    Available,
    /// Key or binary was found but has not been verified against the real API.
    /// The endpoint is treated as usable but the user should know auth is unchecked.
    AvailableUnverified(String),
    /// Carries the reason shown in the picker's hint line, e.g. "no key stored".
    Unavailable(String),
}

impl Availability {
    pub fn is_available(&self) -> bool {
        matches!(
            self,
            Availability::Available | Availability::AvailableUnverified(_)
        )
    }

    /// The reason for an `Unavailable` state only — `None` for verified or unverified
    /// available states. Used by the picker to decide whether to open the key-entry
    /// prompt vs flash a reason.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Availability::Available | Availability::AvailableUnverified(_) => None,
            Availability::Unavailable(reason) => Some(reason),
        }
    }

    /// The note to display alongside this state: the unverified explanation for
    /// `AvailableUnverified`, the reason for `Unavailable`, and `None` for a
    /// fully-verified `Available`. Used to populate `ModelStatus::reason` so all
    /// three rendering surfaces (chat transcript, `/commander`, `simon models`)
    /// can show honest detail.
    pub fn status_note(&self) -> Option<&str> {
        match self {
            Availability::Available => None,
            Availability::AvailableUnverified(note) => Some(note),
            Availability::Unavailable(reason) => Some(reason),
        }
    }
}

/// User-facing state for one candidate transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Connected,
    /// Key or binary found but authentication has not been probed yet.
    ConnectedUnverified,
    NotConnected,
    ConnectedUnavailable,
}

impl ConnectionState {
    pub fn from_availability(connected: bool, availability: &Availability) -> Self {
        match (connected, availability) {
            (true, Availability::Available) => Self::Connected,
            (true, Availability::AvailableUnverified(_)) => Self::ConnectedUnverified,
            (true, Availability::Unavailable(_)) => Self::ConnectedUnavailable,
            (false, _) => Self::NotConnected,
        }
    }

    pub fn symbol(self) -> &'static str {
        match self {
            Self::Connected => "●",
            Self::ConnectedUnverified => "◐",
            Self::NotConnected => "○",
            Self::ConnectedUnavailable => "×",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::Connected => "connected/verified",
            Self::ConnectedUnverified => "connected; authentication unverified",
            Self::NotConnected => "not connected",
            Self::ConnectedUnavailable => "connected but unavailable",
        }
    }

    pub fn is_connected(self) -> bool {
        matches!(
            self,
            Self::Connected | Self::ConnectedUnverified | Self::ConnectedUnavailable
        )
    }
}

/// Status metadata shared by `simon models`, `/commander`, and reconfiguration
/// events so those surfaces cannot disagree about the same connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelStatus {
    pub connection_id: String,
    pub label: String,
    pub transport: Option<Transport>,
    pub state: ConnectionState,
    pub reason: Option<String>,
}

impl ModelStatus {
    pub fn matches_commander(&self, commander: Option<&str>) -> bool {
        commander.is_some_and(|commander| {
            self.connection_id.eq_ignore_ascii_case(commander)
                || self.label.eq_ignore_ascii_case(commander)
        })
    }
}

/// Enough to construct a `LocalBinaryProvider` for a CLI transport option, captured
/// at discovery time so construction never has to re-probe `PATH`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliModelOption {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct CliSpec {
    pub binary_name: String,
    pub path: String,
    pub args: Vec<String>,
    /// Flag used to select an explicit model, when this CLI supports one.
    pub model_arg: Option<String>,
    pub system_arg: Option<String>,
    /// `Some` when this CLI's stdout is a recognised NDJSON progress dialect;
    /// resolved once here (from `known_cli_default` or a validated
    /// `LocalBinarySpec::stream_format`) so `construct_provider` never has to
    /// re-parse or re-validate it.
    pub dialect: Option<StreamDialect>,
    /// The flag this CLI uses to declare an extra allowed working directory, or
    /// `None` when it has none. Set to `--add-dir` for known agentic CLIs — see
    /// `CliDefaults::workspace_arg` for why it matters.
    pub workspace_arg: Option<String>,
    /// Models reported by the installed CLI itself. Empty when the CLI has no
    /// discovery command or discovery failed, in which case the picker uses its
    /// curated fallback list.
    pub models: Vec<CliModelOption>,
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
/// - `copilot`: restricted to read-only project tools, with the built-in GitHub MCP
///   disabled, and invoked as JSONL via `--output-format json --prompt`. Copilot
///   requires `--allow-all-tools` in non-interactive mode, but `--available-tools`
///   narrows that approval to `view`, `grep`, and `glob`.
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
    model_arg: Option<String>,
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
            model_arg: Some("--model".into()),
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
            model_arg: Some("--model".into()),
            system_arg: None,
            dialect: Some(StreamDialect::AgyJson),
            workspace_arg: Some("--add-dir".into()),
        },
        "copilot" => CliDefaults {
            args: vec![
                "--allow-all-tools".into(),
                "--available-tools=view,grep,glob".into(),
                "--disable-builtin-mcps".into(),
                "--output-format".into(),
                "json".into(),
                "--silent".into(),
                "--prompt".into(),
            ],
            model_arg: Some("--model".into()),
            system_arg: None,
            dialect: Some(StreamDialect::CopilotJson),
            workspace_arg: Some("--add-dir".into()),
        },
        "codex" => CliDefaults {
            args: vec!["exec".into()],
            model_arg: Some("--model".into()),
            system_arg: None,
            dialect: None,
            workspace_arg: None,
        },
        "llm" => CliDefaults {
            args: Vec::new(),
            model_arg: Some("--model".into()),
            system_arg: None,
            dialect: None,
            workspace_arg: None,
        },
        _ => CliDefaults {
            args: Vec::new(),
            model_arg: None,
            system_arg: None,
            dialect: None,
            workspace_arg: None,
        },
    }
}

/// Well-known model identifiers offered as a pick-list when editing a CLI row's
/// model, mirroring `config::known_models` for the API side. Kept next to
/// `known_cli_default` so both stay about the same set of known binaries. `llm` is
/// deliberately absent — it is a plugin-based wrapper with no fixed model set, so a
/// hardcoded list would either be wrong or perpetually stale — and so is any binary
/// not in `known_cli_default`'s match, including hand-configured `local_binaries`
/// entries: the model editor falls back to free-text entry for those, exactly as it
/// did before this list existed.
pub(crate) fn known_cli_models(binary_name: &str) -> &'static [&'static str] {
    match binary_name {
        "claude" => &[
            "claude-opus-5",
            "claude-sonnet-5",
            "claude-opus-4-5",
            "claude-haiku-4-5",
        ],
        "copilot" => &[
            "claude-sonnet-5",
            "claude-opus-4.8",
            "claude-opus-4.7",
            "claude-sonnet-4.6",
            "claude-opus-4.6",
            "claude-sonnet-4.5",
            "claude-opus-4.5",
            "claude-haiku-4.5",
            "gpt-5.6-sol",
            "gpt-5.6-terra",
            "gpt-5.6-luna",
            "gpt-5.5",
            "gpt-5.4",
            "gpt-5.4-mini",
            "gpt-5.3-codex",
            "gpt-5-mini",
            "gemini-3.6-flash",
            "gemini-3.5-flash",
            "gemini-3.1-pro-preview",
        ],
        "codex" => &["gpt-5.4", "gpt-5.4-mini", "gpt-5.3-codex", "gpt-5-mini"],
        _ => &[],
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
    const KNOWN: &[&str] = &["claude", "agy", "copilot", "codex", "llm"];
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
            model_arg: spec
                .model_arg
                .clone()
                .or_else(|| known_cli_default(name).model_arg),
            system_arg: spec.system_arg.clone(),
            dialect,
            // Tied to the declared dialect rather than the entry's name: a recognised
            // `stream_format` is a statement that this binary is that CLI, and all
            // supported streaming CLIs spell the flag `--add-dir`. A custom CLI
            // with no dialect gets nothing, since an unknown binary handed an
            // unknown flag would just fail to start.
            workspace_arg: dialect.map(|_| "--add-dir".to_string()),
            models: Vec::new(),
        });
    }

    for name in KNOWN {
        if configured.contains(*name) {
            continue;
        }
        let id = cli_vendor_id(name);
        let saved_path = settings
            .connections
            .get(&id)
            .filter(|connection| connection.transport == Some(Transport::Cli))
            .and_then(|connection| connection.path.clone());
        if let Some(path) = saved_path.or_else(|| which_on_path(name)) {
            let defaults = known_cli_default(name);
            found.push(CliSpec {
                binary_name: name.to_string(),
                path,
                args: defaults.args,
                model_arg: defaults.model_arg,
                system_arg: defaults.system_arg,
                dialect: defaults.dialect,
                workspace_arg: defaults.workspace_arg,
                models: Vec::new(),
            });
        }
    }

    found
}

const CLI_MODEL_LIST_MAX_BYTES: usize = 64 * 1024;
const CLI_MODEL_LIST_TIMEOUT: Duration = Duration::from_secs(10);

fn parse_agy_models(output: &str) -> Vec<CliModelOption> {
    output
        .lines()
        .filter_map(|line| {
            let (id, name) = line.split_once('\t')?;
            let id = id.trim();
            let name = name.trim();
            (!id.is_empty() && !name.is_empty()).then(|| CliModelOption {
                id: id.to_string(),
                name: name.to_string(),
            })
        })
        .collect()
}

async fn read_model_list(mut stdout: tokio::process::ChildStdout) -> std::io::Result<Vec<u8>> {
    let mut kept = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let read = stdout.read(&mut chunk).await?;
        if read == 0 {
            return Ok(kept);
        }
        let remaining = CLI_MODEL_LIST_MAX_BYTES.saturating_sub(kept.len());
        kept.extend_from_slice(&chunk[..read.min(remaining)]);
    }
}

async fn discover_agy_models(path: &str) -> Vec<CliModelOption> {
    let mut command = TokioCommand::new(path);
    command
        .arg("models")
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    let run = async move {
        let mut child = command.spawn().ok()?;
        let stdout = child.stdout.take()?;
        let (output, status) = tokio::join!(read_model_list(stdout), child.wait());
        let output = output.ok()?;
        if !status.ok()?.success() {
            return None;
        }
        Some(parse_agy_models(&String::from_utf8_lossy(&output)))
    };

    tokio::time::timeout(CLI_MODEL_LIST_TIMEOUT, run)
        .await
        .ok()
        .flatten()
        .unwrap_or_default()
}

/// Enriches picker candidates with model IDs and display names reported by CLIs that
/// expose a model-list command. Kept separate from registry discovery so starting a
/// non-interactive chat never waits on a cosmetic picker query.
pub async fn enrich_cli_model_options(candidates: &mut [Candidate]) {
    for candidate in candidates {
        for option in &mut candidate.transports {
            let Some(cli) = option.cli.as_mut() else {
                continue;
            };
            if option.availability.is_available()
                && cli.binary_name == "agy"
                && cli.models.is_empty()
            {
                cli.models = discover_agy_models(&cli.path).await;
            }
        }
    }
}

fn cli_is_available(path: &str) -> bool {
    let path = Path::new(path);
    if path.components().count() > 1 {
        is_executable_file(path)
    } else {
        which_on_path(path.to_string_lossy().as_ref()).is_some()
    }
}

/// Minimal `which`: scans `PATH` for an executable regular file named `name`, including
/// Windows extensions from `PATHEXT`. The project has no `which` dependency; this is
/// the only place that needs one.
pub(crate) fn which_on_path(name: &str) -> Option<String> {
    let path_var = std::env::var_os("PATH");
    which_on_path_in(name, path_var)
}

pub(crate) fn which_on_path_in(name: &str, path_var: Option<std::ffi::OsString>) -> Option<String> {
    if name.is_empty() {
        return None;
    }
    let path_var = path_var?;
    #[cfg(windows)]
    let extensions: Vec<String> = match std::env::var_os("PATHEXT") {
        Some(ext) => std::env::split_paths(&ext)
            .filter_map(|p| p.to_str().map(|s| s.to_string()))
            .collect(),
        None => vec![".exe".into(), ".cmd".into(), ".bat".into(), ".com".into()],
    };

    for dir in std::env::split_paths(&path_var) {
        // On Windows the `PATHEXT` candidates are tried *before* the bare name. npm's
        // CLI shims — the usual way `claude` and its peers land on a Windows PATH —
        // install an extensionless POSIX `claude` script (for Git Bash) right next to
        // the `claude.cmd` Windows can actually run, and `is_executable_file` on
        // Windows is only an `is_file` check, so the bare name used to win and hand
        // `Command::new` a shell script `CreateProcess` rejects. The bare name stays
        // as a last resort rather than being dropped: `CreateProcess` judges by PE
        // format, not extension, so a genuinely extensionless executable still
        // resolves when nothing with a `PATHEXT` extension shadows it.
        #[cfg(windows)]
        {
            for ext in &extensions {
                let ext_name = if ext.starts_with('.') {
                    format!("{name}{ext}")
                } else {
                    format!("{name}.{ext}")
                };
                let candidate_ext = dir.join(&ext_name);
                if is_executable_file(&candidate_ext) {
                    return Some(candidate_ext.to_string_lossy().into_owned());
                }
            }
        }
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
    // Unit tests exercise the probe protocol against local TcpListeners below.
    // Discovery tests must never turn a developer's real keyring entries into
    // outbound cloud requests merely because `cargo test` was run.
    #[cfg(not(test))]
    if !classified {
        run_cloud_probes(&mut candidates, settings).await;
    }
    candidates
}

/// Returns the URL to probe without making a request. OpenRouter is checked against
/// its actual inference route: its key-management endpoint can accept a credential
/// that chat generation still rejects. Other providers use their models list.
fn probe_url_for(id: &str, endpoint: &crate::config::CloudEndpoint, is_builtin: bool) -> String {
    let base = endpoint.base_url.trim_end_matches('/');
    if is_builtin && id.eq_ignore_ascii_case("openrouter") {
        return format!("{base}/chat/completions");
    }
    match endpoint.api {
        crate::config::Api::Anthropic => format!("{base}/v1/models"),
        crate::config::Api::OpenAiCompatible => format!("{base}/models"),
    }
}

/// Inner probe: accepts a pre-fetched key so tests can exercise the logic without
/// touching the OS keyring. Credential values are never logged or stored.
pub(crate) async fn probe_cloud_endpoint(
    id: &str,
    endpoint: &crate::config::CloudEndpoint,
    is_builtin: bool,
    key: &secrecy::SecretString,
    client: &reqwest::Client,
) -> Availability {
    let url = probe_url_for(id, endpoint, is_builtin);
    let probes_openrouter_chat = is_builtin && id.eq_ignore_ascii_case("openrouter");

    let req = if probes_openrouter_chat {
        // An empty JSON object cannot start a generation because OpenRouter requires
        // either `messages` or `prompt`. Its documented response is 400/422 after
        // successful authentication and 401 when inference credentials are invalid,
        // so this exercises the same auth path as a real turn without spending tokens.
        client
            .post(&url)
            .bearer_auth(key.expose_secret())
            .json(&serde_json::json!({}))
    } else {
        match endpoint.api {
            crate::config::Api::Anthropic => client
                .get(&url)
                .header("x-api-key", key.expose_secret())
                .header(
                    "anthropic-version",
                    crate::providers::cloud::ANTHROPIC_VERSION,
                ),
            crate::config::Api::OpenAiCompatible => {
                client.get(&url).bearer_auth(key.expose_secret())
            }
        }
    };

    match req.send().await {
        Ok(response) => {
            let status = response.status();
            let code = status.as_u16();
            if status.is_success() || (probes_openrouter_chat && matches!(code, 400 | 422)) {
                return Availability::Available;
            }
            if probes_openrouter_chat && code == 401 {
                return Availability::Unavailable(
                    "inference authentication rejected (401; check the key/account; management \
                     keys cannot generate)"
                        .into(),
                );
            }
            if probes_openrouter_chat && code == 403 {
                return Availability::Unavailable("generation access denied (403)".into());
            }
            if probes_openrouter_chat && code == 402 {
                return Availability::Unavailable(
                    "generation unavailable: insufficient credits (402)".into(),
                );
            }
            if code == 401 || code == 403 {
                return Availability::Unavailable(format!("authentication rejected ({code})"));
            }
            if code == 429 {
                Availability::AvailableUnverified(format!(
                    "authentication probe rate limited (HTTP {code})"
                ))
            } else if (500..=599).contains(&code) {
                Availability::AvailableUnverified(format!(
                    "service error during authentication probe (HTTP {code})"
                ))
            } else {
                Availability::AvailableUnverified(format!(
                    "authentication probe inconclusive (HTTP {code})"
                ))
            }
        }
        // `is_connect` is tested before `is_timeout`: a connect timeout satisfies
        // both, and it means the TCP handshake never completed — the endpoint is
        // unreachable, whichever clock noticed first. The distinction is real on
        // Windows, where a refused loopback port is retried by the socket stack
        // long enough to trip the 2-second connect timeout, and the probe used to
        // report "timed out" for an endpoint that was simply not there. "timed
        // out" is reserved for endpoints that accepted the connection and then
        // never answered.
        Err(e) if e.is_connect() => Availability::Unavailable("endpoint unreachable".into()),
        Err(e) if e.is_timeout() => {
            Availability::Unavailable("authentication probe timed out".into())
        }
        Err(_) => Availability::Unavailable("authentication probe request failed".into()),
    }
}

/// Reads credentials from the keyring and probes the endpoint, updating the
/// candidate's availability. Drops the key immediately after the request.
#[cfg(not(test))]
async fn probe_cloud(
    id: &str,
    endpoint: &crate::config::CloudEndpoint,
    is_builtin: bool,
    client: &reqwest::Client,
) -> Availability {
    let key = match Credentials::get(id) {
        Ok(Some(key)) => key,
        Ok(None) => return Availability::Unavailable("no key stored".into()),
        Err(e) => return Availability::Unavailable(format!("keyring error: {e}")),
    };
    let result = probe_cloud_endpoint(id, endpoint, is_builtin, &key, client).await;
    // `key` is dropped here — SecretString zeroizes on drop.
    result
}

/// Runs concurrent live probes against all API transports that are currently
/// `AvailableUnverified` (i.e. a key was found but not yet validated). Updates
/// each transport's `availability` in place. Never called under `--classified`.
#[cfg(not(test))]
async fn run_cloud_probes(candidates: &mut [Candidate], settings: &Settings) {
    struct ProbeTarget {
        candidate_idx: usize,
        transport_idx: usize,
        id: String,
        endpoint: crate::config::CloudEndpoint,
        is_builtin: bool,
    }

    let mut targets: Vec<ProbeTarget> = Vec::new();
    for (c_idx, candidate) in candidates.iter().enumerate() {
        for (t_idx, transport) in candidate.transports.iter().enumerate() {
            if transport.transport == Some(Transport::Api)
                && matches!(transport.availability, Availability::AvailableUnverified(_))
                && let Some(endpoint) = settings.endpoint(&candidate.id)
            {
                let is_builtin = !settings
                    .custom_endpoints
                    .keys()
                    .any(|k| k.eq_ignore_ascii_case(&candidate.id));
                targets.push(ProbeTarget {
                    candidate_idx: c_idx,
                    transport_idx: t_idx,
                    id: candidate.id.clone(),
                    endpoint,
                    is_builtin,
                });
            }
        }
    }

    if targets.is_empty() {
        return;
    }

    let probe_client = match reqwest::Client::builder()
        .use_rustls_tls()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(client) => client,
        Err(_) => {
            for target in targets {
                candidates[target.candidate_idx].transports[target.transport_idx].availability =
                    Availability::AvailableUnverified(
                        "authentication probe could not start".into(),
                    );
            }
            return;
        }
    };

    let results = futures::future::join_all(
        targets
            .iter()
            .map(|t| probe_cloud(&t.id, &t.endpoint, t.is_builtin, &probe_client)),
    )
    .await;

    for (target, result) in targets.iter().zip(results) {
        candidates[target.candidate_idx].transports[target.transport_idx].availability = result;
    }
}

async fn discover_ollama(settings: &Settings, classified: bool) -> Vec<Candidate> {
    let remote = !crate::providers::ollama::is_loopback_host(&settings.ollama_host);

    if classified && remote {
        // Never even query a remote daemon under --classified: a garbage or
        // non-loopback `ollama_host` must not get to make an outbound request just
        // to be told no. This is finding 1.2 of the 2026-07-29 audit (doc removed
        // as superseded; recoverable at commit `2e7984e`).
        return unavailable_ollama_candidates(
            settings,
            "remote Ollama hosts are refused under --classified".into(),
        );
    }

    let Ok(client) = http_client(classified) else {
        return Vec::new();
    };
    match OllamaProvider::list_models(&settings.ollama_host, &client).await {
        Ok(models) => {
            let mut candidates = models
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
                .collect::<Vec<_>>();
            let discovered = candidates
                .iter()
                .map(|candidate| candidate.id.as_str())
                .collect::<std::collections::BTreeSet<_>>();
            let missing = settings
                .connections
                .keys()
                .filter(|id| id.starts_with("ollama:") && !discovered.contains(id.as_str()))
                .cloned()
                .collect::<Vec<_>>();
            for id in missing {
                let model = id
                    .strip_prefix("ollama:")
                    .filter(|model| !model.is_empty())
                    .unwrap_or("unknown")
                    .to_string();
                candidates.push(Candidate {
                    id,
                    group: "OLLAMA".into(),
                    model,
                    transports: vec![TransportOption {
                        transport: None,
                        label: String::new(),
                        detail: settings.ollama_host.clone(),
                        availability: Availability::Unavailable(
                            "model is not installed in Ollama".into(),
                        ),
                        cli: None,
                        needs_key: false,
                    }],
                });
            }
            candidates
        }
        Err(e) => unavailable_ollama_candidates(settings, format!("unreachable: {e}")),
    }
}

fn unavailable_ollama_candidates(settings: &Settings, reason: String) -> Vec<Candidate> {
    let saved = settings
        .connections
        .keys()
        .filter_map(|id| {
            id.strip_prefix("ollama:")
                .filter(|model| !model.is_empty())
                .map(|model| (id.clone(), model.to_string()))
        })
        .collect::<Vec<_>>();

    if saved.is_empty() {
        return vec![Candidate {
            id: "ollama".into(),
            group: "OLLAMA".into(),
            model: "daemon".into(),
            transports: vec![TransportOption {
                transport: None,
                label: String::new(),
                detail: settings.ollama_host.clone(),
                availability: Availability::Unavailable(reason),
                cli: None,
                needs_key: false,
            }],
        }];
    }

    saved
        .into_iter()
        .map(|(id, model)| Candidate {
            id,
            group: "OLLAMA".into(),
            model,
            transports: vec![TransportOption {
                transport: None,
                label: String::new(),
                detail: settings.ollama_host.clone(),
                availability: Availability::Unavailable(reason.clone()),
                cli: None,
                needs_key: false,
            }],
        })
        .collect()
}

fn discover_vendors(settings: &Settings, classified: bool) -> Vec<Candidate> {
    let cli_tools = detect_cli_tools(settings);

    let mut ids: Vec<String> = Vec::new();
    for (id, connection) in &settings.connections {
        if connection.transport.is_some() && !ids.iter().any(|known| known.eq_ignore_ascii_case(id))
        {
            ids.push(id.clone());
        }
    }
    for custom in settings.custom_endpoints.keys() {
        if !ids.iter().any(|id| id.eq_ignore_ascii_case(custom)) {
            ids.push(custom.clone());
        }
    }
    for builtin in ["anthropic", "openai", "google", "openrouter", "groq", "xai"] {
        if !ids.iter().any(|id| id.eq_ignore_ascii_case(builtin)) {
            ids.push(builtin.to_string());
        }
    }
    for cli in &cli_tools {
        let vid = cli_vendor_id(&cli.binary_name);
        if !ids.iter().any(|id| id.eq_ignore_ascii_case(&vid)) {
            ids.push(vid);
        }
    }
    ids.sort_by_key(|id| id.to_ascii_lowercase());
    ids.dedup_by(|a, b| a.eq_ignore_ascii_case(b));

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
                Ok(Some(_)) => (
                    Availability::AvailableUnverified(
                        "key stored; authentication not yet checked".into(),
                    ),
                    endpoint.base_url.clone(),
                    false,
                ),
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
        .find(|c| cli_vendor_id(&c.binary_name).eq_ignore_ascii_case(id))
        .cloned()
        .map(|mut cli| {
            if let Some(saved_path) = settings
                .connections
                .get(id)
                .filter(|connection| connection.transport == Some(Transport::Cli))
                .and_then(|connection| connection.path.as_ref())
            {
                cli.path = saved_path.clone();
            }
            cli
        });
    if let Some(cli) = cli.as_ref() {
        // `local_binary` is already `is_remote() -> true`, so under --classified this
        // must render unavailable with a reason rather than being silently dropped
        // (or, worse, constructed and only excluded via the primary check).
        let availability = if classified {
            Availability::Unavailable(
                "CLI tools may reach the network and are refused under --classified".into(),
            )
        } else if !cli_is_available(&cli.path) {
            Availability::Unavailable(format!(
                "CLI executable is missing or not executable: {}",
                cli.path
            ))
        } else {
            Availability::AvailableUnverified(
                "executable found; authentication is checked on first request".into(),
            )
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

    if let Some(connection) = settings.connections.get(id)
        && connection.transport.is_some()
        && !transports
            .iter()
            .any(|option| option.transport == connection.transport)
    {
        match connection.transport {
            Some(Transport::Api) => transports.push(TransportOption {
                transport: Some(Transport::Api),
                label: "via API".into(),
                detail: "(endpoint no longer configured)".into(),
                availability: Availability::Unavailable(
                    "cloud endpoint is no longer configured".into(),
                ),
                cli: None,
                needs_key: false,
            }),
            Some(Transport::Cli) => {
                let binary_name = match id {
                    "anthropic" => "claude",
                    "google" => "gemini",
                    other => other,
                };
                let defaults = known_cli_default(binary_name);
                let path = connection.path.clone().unwrap_or_default();
                transports.push(TransportOption {
                    transport: Some(Transport::Cli),
                    label: "via CLI".into(),
                    detail: if path.is_empty() {
                        "(saved CLI path missing)".into()
                    } else {
                        path.clone()
                    },
                    availability: Availability::Unavailable(
                        "CLI is no longer configured or detected".into(),
                    ),
                    cli: Some(CliSpec {
                        binary_name: binary_name.to_string(),
                        path,
                        args: defaults.args,
                        model_arg: defaults.model_arg,
                        system_arg: defaults.system_arg,
                        dialect: defaults.dialect,
                        workspace_arg: defaults.workspace_arg,
                        models: Vec::new(),
                    }),
                    needs_key: false,
                });
            }
            None => {}
        }
    }

    if transports.is_empty() {
        return None;
    }

    let model = settings
        .endpoint(id)
        .map(|e| e.default_model)
        .or_else(|| cli.as_ref().map(|c| c.binary_name.clone()))
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

/// Classifies every discovered candidate transport using the same first-run and
/// saved-selection rules as `PickerState` and `Registry`.
pub fn candidate_statuses(candidates: &[Candidate], settings: &Settings) -> Vec<ModelStatus> {
    let first_run = settings.connections.is_empty();
    let mut statuses = Vec::new();

    for candidate in candidates {
        let first_available = candidate
            .transports
            .iter()
            .position(|option| option.availability.is_available());
        for (option_index, option) in candidate.transports.iter().enumerate() {
            let connected = if first_run {
                first_available == Some(option_index)
            } else {
                settings
                    .connections
                    .get(&candidate.id)
                    .is_some_and(|connection| {
                        connection.enabled && connection.transport == option.transport
                    })
            };
            statuses.push(ModelStatus {
                connection_id: candidate.id.clone(),
                label: candidate_label(candidate, option, settings),
                transport: option.transport,
                state: ConnectionState::from_availability(connected, &option.availability),
                reason: option.availability.status_note().map(str::to_string),
            });
        }
    }

    statuses.sort_by(|left, right| {
        left.label
            .cmp(&right.label)
            .then_with(|| left.connection_id.cmp(&right.connection_id))
    });
    statuses
}

fn transport_tag(transport: Option<Transport>) -> &'static str {
    match transport {
        None => "ollama",
        Some(Transport::Cli) => "cli",
        Some(Transport::Api) => "api",
    }
}

/// Builds a CLI's fixed argv prefix, adding an explicit model before any
/// prompt-taking flag such as agy's trailing `-p`.
fn cli_args_with_model(cli: &CliSpec, model: Option<&str>) -> Vec<String> {
    let mut args = cli.args.clone();
    if let (Some(model_arg), Some(model)) = (
        cli.model_arg.as_deref(),
        model.map(str::trim).filter(|model| !model.is_empty()),
    ) {
        // Subcommand-based CLIs (notably `codex exec`) need the subcommand first;
        // flag-first CLIs (`copilot`, `claude`, `agy`, `llm`) insert at zero.
        let insert_at = usize::from(args.first().is_some_and(|arg| !arg.starts_with('-')));
        args.splice(
            insert_at..insert_at,
            [model_arg.to_string(), model.to_string()],
        );
    }
    args
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
            let args = cli_args_with_model(cli, conn.model.as_deref());
            let p = LocalBinaryProvider::new(
                &cli.binary_name,
                &path,
                &model,
                project_root.to_path_buf(),
                CliInvocation {
                    args,
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
        Self::build_discovered(settings, requested, classified, project_root, candidates)
    }

    pub(crate) fn build_discovered(
        settings: &Settings,
        requested: Option<&str>,
        classified: bool,
        project_root: &Path,
        candidates: Vec<Candidate>,
    ) -> Result<Self> {
        let client = http_client(classified)?;
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
            // A saved commander (`settings.commander`) is a prior, explicit user
            // choice — unlike the "connect everything, pick anything" default a
            // fresh install starts from, silently replacing it is never acceptable
            // (Fix 4). So the two cases are handled differently: no saved choice at
            // all falls back to whatever is available, same as always; a saved
            // choice that fails to resolve fails loudly instead of falling back,
            // the same way an explicit `want` above does.
            None => match &settings.commander {
                Some(saved) => Self::resolve_commander(settings, &candidates, &providers)
                    .ok_or_else(|| {
                        anyhow!(
                            // The advice has to be reachable from where the user is
                            // standing: this fires before the TUI exists, so `/commander`
                            // — a command typed inside it — would be useless here.
                            "saved commander `{saved}` is not reachable right now. \
                             Available: {}. Choose one in the connection picker, or \
                             start with `-m <name>`.",
                            providers.keys().cloned().collect::<Vec<_>>().join(", ")
                        )
                    })?,
                None => providers
                    .keys()
                    .next()
                    .cloned()
                    .expect("registry is non-empty"),
            },
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
    ///
    /// Every transport the candidate offers is tried, starting with whichever one
    /// `settings.connections` recorded, before giving up (Fix 4). `/commander`
    /// persists only `settings.commander` — nothing updates it when the RECORDED
    /// transport alone goes stale later (an API key pulled from the keyring, a CLI
    /// uninstalled) while a different transport for the very same vendor still
    /// works. Trying only the recorded transport turned that ordinary drift into a
    /// silent switch to an unrelated model: this function would return `None`, and
    /// the caller used to fall back to `providers.keys().next()` — alphabetically
    /// first — with no warning. The caller no longer does that for a saved
    /// commander; see its doc comment.
    fn resolve_commander(
        settings: &Settings,
        candidates: &[Candidate],
        providers: &BTreeMap<String, Arc<dyn Provider>>,
    ) -> Option<String> {
        let id = settings.commander.as_deref()?;
        let candidate = match candidates.iter().find(|c| c.id == id) {
            Some(c) => c,
            None => return Self::match_label(providers, id),
        };
        let saved_transport = settings.connections.get(id).and_then(|c| c.transport);

        // Stable sort, so ties (including "no saved transport at all") keep the
        // candidate's own declared order — only the recorded transport, if any, is
        // pulled to the front.
        let mut transports: Vec<&TransportOption> = candidate.transports.iter().collect();
        transports.sort_by_key(|t| t.transport != saved_transport);

        transports
            .into_iter()
            .map(|option| candidate_label(candidate, option, settings))
            .find_map(|label| Self::match_label(providers, &label))
            .or_else(|| Self::match_label(providers, id))
    }

    /// Accepts an exact label, a bare model name, or a provider name.
    fn match_label(providers: &BTreeMap<String, Arc<dyn Provider>>, want: &str) -> Option<String> {
        if let Some(exact) = providers.keys().find(|k| k.eq_ignore_ascii_case(want)) {
            return Some(exact.clone());
        }
        let want_prefix = format!("{}:", want.to_ascii_lowercase());
        providers
            .iter()
            .find(|(label, p)| {
                p.model_name().eq_ignore_ascii_case(want)
                    || p.provider_name().eq_ignore_ascii_case(want)
                    || label.to_ascii_lowercase().starts_with(&want_prefix)
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
    /// Answers to write and proof-run approval events from the UI. Production keeps
    /// this connected even under `--auto-write`, because that flag skips file
    /// approvals only; tests and non-interactive callers may pass `None`.
    decisions: Option<mpsc::Receiver<WriteDecision>>,
    /// Set by a `WriteDecision::ApproveAll`; skips the prompt for the rest of the
    /// session. Never persisted — see `WriteDecision`.
    approve_all: bool,
    /// The application data directory, kept so `record_call_usage` can persist the
    /// running this-month token total (`usage_ledger.rs`) without needing the full
    /// `Paths` struct (whose other fields describe files this orchestrator never
    /// touches) threaded through every call site.
    data_dir: PathBuf,
}

impl Orchestrator {
    pub fn new(
        registry: Registry,
        paths: &Paths,
        project_root: PathBuf,
        classified: bool,
        events: mpsc::Sender<Event>,
        decisions: Option<mpsc::Receiver<WriteDecision>>,
        auto_write: bool,
    ) -> Result<Self> {
        let mut ledger = SwarmLedger::new();
        ledger.set_roster(registry.labels());
        let mut workspace = Workspace::new(project_root.clone())?;
        workspace.enable_task_copies(&paths.data_dir)?;

        Ok(Self {
            registry,
            ledger,
            audit: AuditLogger::open(paths.audit_log.clone())?,
            skills: SkillsDir::new(paths.skills_dir.clone())?,
            workspace,
            events,
            classified,
            project_root,
            decisions,
            approve_all: auto_write,
            data_dir: paths.data_dir.clone(),
        })
    }

    async fn emit(&self, event: Event) {
        // A closed channel means the UI already exited; dropping the event is correct.
        let _ = self.events.send(event).await;
    }

    /// Persists `usage`'s observed token count into this-month's running total
    /// (`usage_ledger::record`) and returns the new total, or the previous known
    /// total (via `Err`'s absence — see below) if the write failed.
    ///
    /// A disk error here (permissions, full disk, a concurrent writer) must never
    /// interrupt the turn that is already in flight and must already have its reply
    /// ready to show the user — the whole point of this counter is a status-line
    /// nicety, not something worth failing a prompt over. So this logs to the audit
    /// trail and falls back to `0`, which just means "this call's tokens didn't make
    /// it into this month's total"; the status line stays believable (no phantom
    /// spike, no stale-looking freeze) rather than propagating an error the caller
    /// has no good way to surface anyway.
    fn record_month_usage(&mut self, usage: &TokenUsage) -> u64 {
        let tokens = usage.observed_total().unwrap_or(0);
        match crate::usage_ledger::record(&self.data_dir, tokens) {
            Ok(total) => total,
            Err(e) => {
                let _ = self
                    .audit
                    .log("usage.persist_failed", &safe_error_detail(&e));
                0
            }
        }
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
                    let mut remaining_actions = MAX_ACTIONS_PER_WORKFLOW;
                    let mut continuation_turn = 0u8;
                    let mut previous_progress: Option<(Vec<ActionKey>, u64)> = None;
                    let continuation_prompt = continuation_prompt(&prompt);
                    let mut outcome = self
                        .handle_prompt_round(&prompt, false, &mut remaining_actions)
                        .await;

                    loop {
                        if outcome.commander_failed {
                            break;
                        }
                        if let Some(limit) = outcome.action_limit {
                            let (message, kind) = match limit {
                                ActionLimit::Workflow => (
                                    format!(
                                        "auto-continuation stopped: workflow action limit ({MAX_ACTIONS_PER_WORKFLOW}) reached"
                                    ),
                                    "workflow_actions",
                                ),
                                ActionLimit::PerTurn => (
                                    "auto-continuation stopped: a per-turn action limit was exceeded"
                                        .into(),
                                    "per_turn_actions",
                                ),
                            };
                            let _ = self
                                .audit
                                .log("continuation.capped", &format!("kind={kind}"));
                            self.emit(Event::Error(message)).await;
                            break;
                        }
                        if outcome.action_fingerprint.is_empty() {
                            break;
                        }
                        if previous_progress.as_ref()
                            == Some(&(
                                outcome.action_fingerprint.clone(),
                                outcome.state_fingerprint,
                            ))
                        {
                            let _ = self.audit.log("continuation.stalled", "repeated_actions");
                            self.emit(Event::Error(
                                "auto-continuation stopped: the commander repeated the same actions with the same results"
                                    .into(),
                            ))
                            .await;
                            break;
                        }
                        if continuation_turn >= MAX_AUTO_CONTINUATION_TURNS {
                            let _ = self.audit.log("continuation.capped", "kind=turns");
                            self.emit(Event::Error(format!(
                                "auto-continuation stopped: turn limit ({MAX_AUTO_CONTINUATION_TURNS}) reached"
                            )))
                            .await;
                            break;
                        }

                        previous_progress =
                            Some((outcome.action_fingerprint, outcome.state_fingerprint));
                        continuation_turn += 1;
                        self.emit(Event::AutoContinuation {
                            turn: continuation_turn,
                            max: MAX_AUTO_CONTINUATION_TURNS,
                        })
                        .await;
                        outcome = self
                            .handle_prompt_round(&continuation_prompt, true, &mut remaining_actions)
                            .await;
                    }

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
                Command::ClearLedger => {
                    self.clear_ledger().await;
                    // Same reasoning as `SetCommander` above: this never fails, but
                    // `submit()` still assumed a model turn when the user typed it.
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
        let candidates = discover_candidates(&settings, self.classified).await;
        let model_statuses = candidate_statuses(&candidates, &settings);
        match Registry::build_discovered(
            &settings,
            None,
            self.classified,
            &self.project_root,
            candidates,
        ) {
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
                    model_statuses,
                })
                .await;
            }
            Err(e) => {
                let _ = self.audit.log("connections.failed", &safe_error_detail(&e));
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

    /// Handles `/forget` typed in chat. Measures the rendered prompt before and after
    /// so `Event::LedgerCleared` can show the user real numbers, not just a claim that
    /// something happened; see that variant's doc comment.
    async fn clear_ledger(&mut self) {
        let chars_before = self.ledger.system_prompt().chars().count();
        self.ledger.clear_content();
        let chars_after = self.ledger.system_prompt().chars().count();
        let _ = self.audit.log(
            "ledger.cleared",
            &format!("chars_before={chars_before} chars_after={chars_after}"),
        );
        self.emit(Event::LedgerCleared {
            chars_before,
            chars_after,
        })
        .await;
    }

    #[cfg(test)]
    async fn handle_prompt(&mut self, prompt: &str) -> TurnOutcome {
        let mut remaining_actions = MAX_ACTIONS_PER_WORKFLOW;
        self.handle_prompt_round(prompt, false, &mut remaining_actions)
            .await
    }

    async fn handle_prompt_round(
        &mut self,
        prompt: &str,
        is_continuation: bool,
        remaining_actions: &mut usize,
    ) -> TurnOutcome {
        let primary_label = self.registry.primary().to_string();
        let _ = self.audit.log(
            if is_continuation {
                "prompt.continuation"
            } else {
                "prompt.sent"
            },
            &format!("model={primary_label} chars={}", prompt.chars().count()),
        );

        let Some(provider) = self.registry.get(&primary_label) else {
            self.emit(Event::Error(format!("model `{primary_label}` disappeared")))
                .await;
            return TurnOutcome {
                commander_failed: true,
                action_fingerprint: Vec::new(),
                state_fingerprint: self.ledger.state_fingerprint(),
                action_limit: None,
            };
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
                let _ = self.audit.log(
                    "prompt.failed",
                    &format!("model={primary_label} {}", safe_error_detail(&e)),
                );
                self.emit(Event::Error(format!("{primary_label}: {e}")))
                    .await;
                return TurnOutcome {
                    commander_failed: true,
                    action_fingerprint: Vec::new(),
                    state_fingerprint: self.ledger.state_fingerprint(),
                    action_limit: None,
                };
            }
        };
        // Drops the sink, closing the forwarding task's channel — see
        // `spawn_progress_forwarder`'s doc comment for why that's all the cleanup it
        // needs.
        drop(progress);

        let month_tokens = self.record_month_usage(&reply.usage);
        self.emit(Event::UsageUpdated {
            label: primary_label.clone(),
            usage: reply.usage.clone(),
            rate_limit: reply.rate_limit.clone(),
            month_tokens,
        })
        .await;
        if let Some(budget) = reply.rate_limit.summary() {
            self.ledger.update_budget(&primary_label, &budget);
        }
        let _ = self.audit.log(
            "reply.received",
            &format!("model={primary_label} chars={}", reply.text.chars().count()),
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
        let (raw_writes, stripped) = SwarmLedger::parse_file_writes(&reply.text);

        // Recorded before the actions run, so a plan the commander just proposed is in
        // the ledger regardless of what any of them do.
        self.ledger.record_commander_reply(&stripped);

        let (delegations, delegation_per_turn, delegation_workflow) = take_action_budget(
            SwarmLedger::parse_delegations(&stripped),
            MAX_DELEGATIONS_PER_TURN,
            remaining_actions,
        );
        let (skill_reads, skill_per_turn, skill_workflow) = take_action_budget(
            SwarmLedger::parse_read_skill(&stripped),
            MAX_READ_ACTIONS_PER_TURN,
            remaining_actions,
        );
        let (file_reads, file_read_per_turn, file_read_workflow) = take_action_budget(
            SwarmLedger::parse_read_files(&stripped),
            MAX_READ_ACTIONS_PER_TURN,
            remaining_actions,
        );
        let (file_lists, file_list_per_turn, file_list_workflow) = take_action_budget(
            SwarmLedger::parse_list_files(&stripped),
            MAX_READ_ACTIONS_PER_TURN,
            remaining_actions,
        );
        let (writes, write_per_turn, write_workflow) =
            take_action_budget(raw_writes, MAX_WRITES_PER_TURN, remaining_actions);
        let (run_requests, run_per_turn, run_workflow) = take_action_budget(
            SwarmLedger::parse_run_requests(&stripped),
            MAX_RUN_ACTIONS_PER_TURN,
            remaining_actions,
        );
        let (copy_dispositions, copy_per_turn, copy_workflow) = take_action_budget(
            SwarmLedger::parse_copy_dispositions(&stripped),
            MAX_COPY_ACTIONS_PER_TURN,
            remaining_actions,
        );

        let mut action_fingerprint = Vec::new();
        action_fingerprint.extend(delegations.iter().map(|delegation| ActionKey::Delegation {
            target: delegation.target.clone(),
            prompt_hash: hash_action_str(&delegation.prompt),
            workspace_task: delegation.workspace_task,
        }));
        action_fingerprint.extend(skill_reads.iter().cloned().map(ActionKey::SkillRead));
        action_fingerprint.extend(file_reads.iter().cloned().map(ActionKey::FileRead));
        action_fingerprint.extend(file_lists.iter().cloned().map(ActionKey::FileList));
        action_fingerprint.extend(writes.iter().map(|write| ActionKey::FileWrite {
            path: write.path.clone(),
            content_hash: hash_action_str(&write.content),
        }));
        action_fingerprint.extend(run_requests.iter().map(|request| ActionKey::Run {
            task_id: request.task_id,
            argv_hash: hash_action_str(&request.argv.join("\0")),
        }));
        action_fingerprint.extend(
            copy_dispositions
                .iter()
                .map(|disposition| match disposition {
                    CopyDisposition::Apply(task_id) => ActionKey::ApplyCopy(*task_id),
                    CopyDisposition::Discard(task_id) => ActionKey::DiscardCopy(*task_id),
                }),
        );
        action_fingerprint.sort();
        action_fingerprint.dedup();

        let delegation_execution_limit = self
            .run_delegation_requests(&primary_label, delegations, remaining_actions)
            .await;
        self.run_skill_read_requests(&primary_label, skill_reads)
            .await;
        self.run_file_read_requests(&primary_label, file_reads)
            .await;
        self.run_file_list_requests(&primary_label, file_lists)
            .await;
        self.run_file_writes(&primary_label, writes).await;
        let ran_commands = !run_requests.is_empty();
        self.run_command_requests(&primary_label, run_requests)
            .await;
        self.run_copy_disposition_requests(&primary_label, copy_dispositions, ran_commands)
            .await;

        TurnOutcome {
            commander_failed: false,
            action_fingerprint,
            state_fingerprint: self.ledger.state_fingerprint(),
            action_limit: if delegation_execution_limit == Some(ActionLimit::Workflow)
                || delegation_workflow
                || skill_workflow
                || file_read_workflow
                || file_list_workflow
                || write_workflow
                || run_workflow
                || copy_workflow
            {
                Some(ActionLimit::Workflow)
            } else if delegation_execution_limit == Some(ActionLimit::PerTurn)
                || delegation_per_turn
                || skill_per_turn
                || file_read_per_turn
                || file_list_per_turn
                || write_per_turn
                || run_per_turn
                || copy_per_turn
            {
                Some(ActionLimit::PerTurn)
            } else {
                None
            },
        }
    }

    /// Executes any `delegate_task` or `delegate_file_task` lines the primary emitted.
    ///
    /// Sub-agent replies are not themselves scanned for delegations, so the swarm
    /// cannot recurse indefinitely.
    #[cfg(test)]
    async fn run_delegations(&mut self, from: &str, reply_text: &str) {
        let mut remaining_actions = MAX_ACTIONS_PER_WORKFLOW;
        let (delegations, _, _) = take_action_budget(
            SwarmLedger::parse_delegations(reply_text),
            MAX_DELEGATIONS_PER_TURN,
            &mut remaining_actions,
        );
        self.run_delegation_requests(from, delegations, &mut remaining_actions)
            .await;
    }

    async fn run_delegation_requests(
        &mut self,
        from: &str,
        delegations: Vec<Delegation>,
        remaining_actions: &mut usize,
    ) -> Option<ActionLimit> {
        if delegations.is_empty() {
            return None;
        }

        let mut action_limit = None;
        for delegation in delegations {
            let Some(target) = self.registry.get(&delegation.target) else {
                let err_msg = format!("cannot delegate to unknown model `{}`", delegation.target);
                let task_id = self.ledger.add_task(&delegation.prompt);
                self.ledger.assign_task(task_id, &delegation.target);
                self.ledger.record_result(task_id, &err_msg);
                self.ledger.update_status(task_id, TaskStatus::Failed);
                let _ = self.audit.log(
                    "task.failed",
                    &format!("task={task_id} kind=not_found detail=withheld"),
                );
                self.emit(Event::Error(err_msg)).await;
                self.emit(Event::DelegationFinished {
                    to: delegation.target.clone(),
                    ok: false,
                    chars: 0,
                    millis: 0,
                })
                .await;
                continue;
            };
            let target_label = target.label();

            let task_id = self.ledger.add_task(&delegation.prompt);
            self.ledger.assign_task(task_id, &target_label);
            let mut created_workspace = None;
            let workspace_id = if let Some(source_task_id) = delegation.workspace_task {
                match self.ledger.resolve_live_workspace_id(source_task_id) {
                    Some(workspace_id) if self.workspace.has_task_copy(workspace_id) => {
                        self.ledger.associate_workspace(
                            task_id,
                            workspace_id,
                            Some(&format!("continued from task {source_task_id}")),
                        );
                        Some(workspace_id)
                    }
                    _ => {
                        let error = format!("task {source_task_id} has no live isolated copy");
                        self.ledger.record_result(task_id, &error);
                        self.ledger.update_status(task_id, TaskStatus::Failed);
                        let _ = self.audit.log(
                            "task.failed",
                            &format!("task={task_id} kind=workspace_unavailable detail=withheld"),
                        );
                        self.emit(Event::DelegationFinished {
                            to: target_label.clone(),
                            ok: false,
                            chars: 0,
                            millis: 0,
                        })
                        .await;
                        self.emit(Event::Error(format!(
                            "cannot continue task {source_task_id}: {error}"
                        )))
                        .await;
                        continue;
                    }
                }
            } else if delegation.allow_writes {
                match self.workspace.create_task_copy(task_id) {
                    Ok(summary) => {
                        let workspace_id = task_id;
                        let mut note = format!(
                            "{} files, {} bytes, {} excluded",
                            summary.files, summary.bytes, summary.excluded_total
                        );
                        if !summary.excluded.is_empty() {
                            note.push_str("; sample: ");
                            note.push_str(&truncate_chars(
                                &sanitize_transcript_detail(&summary.excluded.join("; ")),
                                500,
                            ));
                        }
                        self.ledger
                            .associate_workspace(task_id, workspace_id, Some(&note));
                        created_workspace = Some(workspace_id);
                        let _ = self.audit.log(
                            "copy.created",
                            &format!(
                                "task={task_id} workspace={workspace_id} files={} bytes={} excluded={}",
                                summary.files, summary.bytes, summary.excluded_total
                            ),
                        );
                        self.emit(Event::TaskCopyCreated {
                            task_id,
                            files: summary.files,
                            bytes: summary.bytes,
                            excluded: summary.excluded_total,
                        })
                        .await;
                        Some(workspace_id)
                    }
                    Err(error) => {
                        self.ledger.record_result(task_id, &error.to_string());
                        self.ledger.update_status(task_id, TaskStatus::Failed);
                        let _ = self.audit.log(
                            "task.failed",
                            &format!("task={task_id} kind=copy_failed detail=withheld"),
                        );
                        self.emit(Event::DelegationFinished {
                            to: target_label.clone(),
                            ok: false,
                            chars: 0,
                            millis: 0,
                        })
                        .await;
                        self.emit(Event::Error(format!(
                            "could not create isolated copy for task {task_id}: {error}"
                        )))
                        .await;
                        continue;
                    }
                }
            } else {
                None
            };

            let workspace_root = match workspace_id {
                Some(workspace_id) => match self.workspace.task_copy_root(workspace_id) {
                    Some(path) => Some(path),
                    None => {
                        let error = anyhow!("isolated copy {workspace_id} is unavailable");
                        self.ledger.record_result(task_id, &error.to_string());
                        self.ledger.update_status(task_id, TaskStatus::Failed);
                        self.emit(Event::Error(format!(
                            "task {task_id} copy is unavailable: {error}"
                        )))
                        .await;
                        if created_workspace.is_some() {
                            self.release_task_copy(
                                workspace_id,
                                false,
                                format!("task {task_id} setup failed"),
                            )
                            .await;
                        }
                        continue;
                    }
                },
                None => None,
            };
            let rerooted_target = workspace_root
                .as_deref()
                .and_then(|root| target.with_project_root(root));
            let monitor_provider_copy = rerooted_target.is_some();
            let target = rerooted_target.unwrap_or(target);

            let _ = self.audit.log(
                "task.delegated",
                &format!("from={from} to={target_label} task={task_id}"),
            );

            self.emit(Event::Delegated {
                from: from.to_string(),
                to: target_label.clone(),
                task: delegation.prompt.clone(),
            })
            .await;
            self.emit(Event::ActivityStarted {
                label: target_label.clone(),
                kind: ActivityKind::Delegating,
            })
            .await;

            // A delegated task is intentionally isolated from the shared ledger.
            // Besides matching the protocol's documented contract ("its prompt is
            // all it gets"), this prevents a later worker in the same batch from
            // copying an earlier worker's identity or result. Only an explicit
            // `delegate_file_task` receives the file-write protocol.
            let system =
                SwarmLedger::subagent_system_prompt(&target_label, delegation.allow_writes);
            // Only what is sent is augmented; the ledger and the TUI keep the
            // commander's own wording, the same split `commander_preamble` uses.
            let preamble = subagent_preamble(
                target.requires_subagent_tool_guardrails(),
                delegation.allow_writes,
            );
            let effective_task = format!("{preamble}{}", delegation.prompt);
            let started = Instant::now();
            let mut attempts = 1;
            let mut copy_quota_failed = false;
            let outcome = loop {
                let progress = self.spawn_progress_forwarder(target_label.clone());
                let mut provider_result = if monitor_provider_copy
                    && let (Some(workspace_id), Some(root)) =
                        (workspace_id, workspace_root.as_deref())
                {
                    match self.workspace.task_copy_quota(workspace_id) {
                        Ok(quota) => {
                            tokio::select! {
                                result = target.send_with_progress(
                                    Some(&system),
                                    &effective_task,
                                    &progress,
                                ) => result,
                                error = crate::isolation::wait_for_copy_quota_violation(root, quota) => {
                                    copy_quota_failed = true;
                                    Err(error.context("delegated CLI exceeded the task-copy storage quota"))
                                }
                            }
                        }
                        Err(error) => {
                            copy_quota_failed = true;
                            Err(error)
                        }
                    }
                } else {
                    target
                        .send_with_progress(Some(&system), &effective_task, &progress)
                        .await
                };
                if let Some(workspace_id) = workspace_id
                    && let Err(error) = self.workspace.validate_task_copy(workspace_id)
                {
                    copy_quota_failed = true;
                    provider_result =
                        Err(error.context("delegated task exceeded its storage quota"));
                }
                let result = provider_result.and_then(|reply| {
                    if reply.text.trim().is_empty() {
                        Err(anyhow!("{target_label} produced no output"))
                    } else {
                        let (parsed_writes, sub_text) = SwarmLedger::parse_file_writes(&reply.text);
                        let sub_writes = if delegation.allow_writes {
                            parsed_writes
                        } else {
                            Vec::new()
                        };
                        if sub_text.trim().is_empty() && sub_writes.is_empty() {
                            // A malformed unterminated write block is removed by
                            // the parser so its swallowed content cannot execute
                            // as another action. Validate the usable result, not
                            // only the raw response, or that safe removal turns a
                            // non-empty model reply into a blank "success".
                            Err(anyhow!("{target_label} produced no usable output"))
                        } else {
                            Ok((reply, sub_writes, sub_text))
                        }
                    }
                });
                // Drops the sink, closing the forwarding task's channel — see
                // `spawn_progress_forwarder`'s doc comment. Inside the loop because a
                // retry needs a fresh sink; the old one's task has already ended.
                drop(progress);

                let Err(error) = result else {
                    break result;
                };
                let reason = error.to_string();
                if copy_quota_failed
                    || attempts >= MAX_DELEGATION_ATTEMPTS
                    || !is_retryable_delegation_error(&reason)
                {
                    break Err(error);
                }

                let _ = self.audit.log(
                    "task.retrying",
                    &format!(
                        "task={task_id} attempt={attempts} {}",
                        safe_error_detail(&error)
                    ),
                );
                self.emit(Event::DelegationRetry {
                    to: target_label.clone(),
                    attempt: attempts + 1,
                    max: MAX_DELEGATION_ATTEMPTS,
                    reason: sanitize_transcript_detail(&reason),
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
                Ok((reply, sub_writes, sub_text)) => {
                    let millis = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                    let month_tokens = self.record_month_usage(&reply.usage);
                    self.emit(Event::UsageUpdated {
                        label: target_label.clone(),
                        usage: reply.usage.clone(),
                        rate_limit: reply.rate_limit.clone(),
                        month_tokens,
                    })
                    .await;
                    if let Some(budget) = reply.rate_limit.summary() {
                        self.ledger.update_budget(&target_label, &budget);
                    }
                    // A sub-agent's reply IS scanned for write blocks — and for
                    // nothing else. Only `delegate_file_task` keeps and executes
                    // those blocks; a regular text delegation strips them. That
                    // asymmetry bounds the swarm: a sub-agent cannot delegate, read a
                    // skill, or read/list files, so no reply can spawn more work. A
                    // permitted write spawns nothing.
                    //
                    // Safe to allow only because every write still passes the same two
                    // gates a commander's does: `Workspace`'s path hardening, and the
                    // user's explicit approval, which now names the sub-agent as the
                    // one asking.
                    let requested_write_count = sub_writes.len();
                    let (sub_writes, per_turn_capped, workflow_capped) =
                        take_action_budget(sub_writes, MAX_WRITES_PER_TURN, remaining_actions);
                    if workflow_capped {
                        action_limit = Some(ActionLimit::Workflow);
                    } else if per_turn_capped && action_limit.is_none() {
                        action_limit = Some(ActionLimit::PerTurn);
                    }
                    let write_count = sub_writes.len();
                    let (mut writes_ok, write_errors) =
                        if let (Some(workspace_id), Some(workspace_root)) =
                            (workspace_id, workspace_root.as_deref())
                        {
                            self.run_file_writes_in_workspace(
                                &target_label,
                                sub_writes,
                                workspace_root,
                                Some(workspace_id),
                            )
                            .await
                        } else if sub_writes.is_empty() {
                            (true, Vec::new())
                        } else {
                            let message = format!(
                                "{target_label} attempted file writes without an isolated copy"
                            );
                            self.emit(Event::Error(message.clone())).await;
                            (false, vec![message])
                        };
                    let quota_error = workspace_id.and_then(|workspace_id| {
                        self.workspace
                            .validate_task_copy(workspace_id)
                            .err()
                            .map(|error| (workspace_id, error))
                    });
                    let quota_message = if let Some((workspace_id, error)) = quota_error {
                        writes_ok = false;
                        let message =
                            format!("task copy {workspace_id} exceeded its storage quota: {error}");
                        self.emit(Event::Error(message.clone())).await;
                        self.release_task_copy(
                            workspace_id,
                            false,
                            "delegated writes exceeded the task-copy storage quota".into(),
                        )
                        .await;
                        Some(message)
                    } else {
                        None
                    };
                    let mut sub_text = if sub_text.trim().is_empty() {
                        format!(
                            "Submitted {write_count} file write request{}.",
                            if write_count == 1 { "" } else { "s" }
                        )
                    } else {
                        sub_text
                    };
                    if let Some(message) = quota_message {
                        sub_text.push_str("\n\n");
                        sub_text.push_str(&message);
                    }
                    for error in write_errors {
                        sub_text.push_str("\n\n");
                        sub_text.push_str(&error);
                    }
                    let writes_ok = if requested_write_count > write_count {
                        let message = format!(
                            "Only {write_count} of {requested_write_count} worker write actions were accepted before an action limit was reached."
                        );
                        sub_text.push_str("\n\n");
                        sub_text.push_str(&message);
                        self.emit(Event::Error(message)).await;
                        false
                    } else {
                        writes_ok
                    };

                    // Record the reply on the task before flipping it to Done, so the
                    // ledger shown to the delegating model on its next turn carries
                    // the answer, not just a status tag. The *stripped* text: file
                    // content is already on disk, and echoing it back into every
                    // future prompt is exactly the ledger growth `MAX_RESULT_CHARS`
                    // exists to prevent.
                    self.ledger.record_result(task_id, &sub_text);
                    self.ledger.update_status(
                        task_id,
                        if writes_ok {
                            TaskStatus::Done
                        } else {
                            TaskStatus::Failed
                        },
                    );
                    let _ = self.audit.log(
                        if writes_ok {
                            "task.completed"
                        } else {
                            "task.write_failed"
                        },
                        &format!("task={task_id} model={target_label}"),
                    );
                    self.emit(Event::DelegationFinished {
                        to: target_label.clone(),
                        ok: writes_ok,
                        chars: sub_text.chars().count(),
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
                    let _ = self.audit.log(
                        "task.failed",
                        &format!("task={task_id} {}", safe_error_detail(&e)),
                    );
                    // Record the error as the task's result and mark it Failed, not
                    // just logged-and-dropped: without this a failed delegation sat at
                    // [IN_PROGRESS] forever, indistinguishable from one still running,
                    // on a blackboard every other model reads as fact. Recording the
                    // error text (not just the status) lets the delegating model see
                    // WHY it failed and decide whether to retry — a failure with no
                    // explanation is useless to whoever has to act on it.
                    self.ledger.record_result(task_id, &e.to_string());
                    self.ledger.update_status(task_id, TaskStatus::Failed);
                    if let Some(workspace_id) = workspace_id
                        && (created_workspace.is_some() || copy_quota_failed)
                    {
                        self.release_task_copy(
                            workspace_id,
                            false,
                            format!("task {task_id} provider failed"),
                        )
                        .await;
                    }
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
        action_limit
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
    #[cfg(test)]
    async fn run_skill_reads(&mut self, primary_label: &str, reply_text: &str) {
        self.run_skill_read_requests(primary_label, SwarmLedger::parse_read_skill(reply_text))
            .await;
    }

    async fn run_skill_read_requests(&mut self, primary_label: &str, requests: Vec<String>) {
        // Mirrors `run_delegations`' bounded-effort rule, but keeps its own smaller
        // filesystem-action limit: the
        // ledger already caps how many skills stay loaded (`MAX_LOADED_SKILLS`), but
        // that caps storage, not effort per turn — without this, a reply with
        // hundreds of `read_skill` lines would still trigger hundreds of filesystem
        // reads, just to have all but the last few evicted immediately after.
        for name in requests {
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
                        &format!("name={name} chars={}", content.chars().count()),
                    );
                    self.emit(Event::SkillLoaded {
                        name: name.clone(),
                        chars: content.chars().count(),
                    })
                    .await;
                }
                Err(e) => {
                    let _ = self.audit.log(
                        "skill.read_failed",
                        &format!("name={name} {}", safe_error_detail(&e)),
                    );
                    // Record the failure so the commander learns next turn that
                    // the skill could not be loaded — without this the model
                    // would see the request silently vanish from its context and
                    // have no way to know the read failed.
                    self.ledger.record_skill(&name, &format!("failed: {e}"));
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
    /// Worker write blocks reach the same helper only for explicit
    /// `delegate_file_task`/`delegate_in_copy` actions. They cannot recursively
    /// delegate, read, or execute commands.
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
    async fn confirm_write(
        &mut self,
        author: &str,
        write: &crate::swarm::FileWrite,
        target: &Workspace,
    ) -> bool {
        if self.approve_all {
            return true;
        }
        if self.decisions.is_none() {
            return true;
        }

        // Read the existing file's size before asking, not after: "overwrites 4KB" and
        // "creates a new file" are different questions, and the user is being asked to
        // answer one of them.
        let overwrites = target
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

    async fn run_file_writes(
        &mut self,
        author: &str,
        writes: Vec<crate::swarm::FileWrite>,
    ) -> bool {
        let root = self.workspace.root().to_path_buf();
        self.run_file_writes_in_workspace(
            author,
            writes.into_iter().take(MAX_WRITES_PER_TURN).collect(),
            &root,
            None,
        )
        .await
        .0
    }

    async fn run_file_writes_in_workspace(
        &mut self,
        author: &str,
        writes: Vec<crate::swarm::FileWrite>,
        root: &Path,
        workspace_id: Option<usize>,
    ) -> (bool, Vec<String>) {
        let target = match Workspace::new(root.to_path_buf()) {
            Ok(target) => target,
            Err(error) => {
                let _ = self.audit.log(
                    "file.write_failed",
                    &format!("kind=workspace_unavailable {}", safe_error_detail(&error)),
                );
                self.emit(Event::Error(format!(
                    "cannot open write target {}: {error}",
                    root.display()
                )))
                .await;
                return (false, vec![error.to_string()]);
            }
        };
        let mut all_ok = true;
        let mut errors = Vec::new();
        for write in writes {
            // Before the user is asked anything: a write that `Workspace` will refuse
            // regardless must not be put to them for approval. Asking about a doomed
            // write teaches that the answer does not matter, and makes the refusal
            // that follows a "yes" look like a consequence of approving it.
            if let Err(e) = target.precheck(&write.path, write.content.len()) {
                let outcome = format!("failed: {e}");
                let _ = self.audit.log(
                    "file.write_failed",
                    &format!("path={} {}", write.path, safe_error_detail(&e)),
                );
                self.ledger.record_file_write(&write.path, &outcome);
                self.emit(Event::Error(format!("write `{}`: {e}", write.path)))
                    .await;
                errors.push(format!("write `{}` failed: {e}", write.path));
                all_ok = false;
                continue;
            }
            if let Some(workspace_id) = workspace_id
                && let Err(e) = self.workspace.precheck_task_copy_write(
                    workspace_id,
                    &write.path,
                    write.content.len(),
                )
            {
                let outcome = format!("failed: {e}");
                let _ = self.audit.log(
                    "file.write_failed",
                    &format!("path={} kind=copy_quota detail=withheld", write.path),
                );
                self.ledger.record_file_write(&write.path, &outcome);
                self.emit(Event::Error(format!("write `{}`: {e}", write.path)))
                    .await;
                errors.push(format!("write `{}` failed: {e}", write.path));
                all_ok = false;
                continue;
            }
            if !self.confirm_write(author, &write, &target).await {
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
                errors.push(format!("write `{}` was denied by the user", write.path));
                all_ok = false;
                continue;
            }
            match target.write(&write.path, &write.content) {
                Ok(_) => {
                    let outcome = format!("ok ({} bytes)", write.content.len());
                    let _ = self.audit.log(
                        "file.written",
                        &format!(
                            "path={} chars={}",
                            write.path,
                            write.content.chars().count()
                        ),
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
                        &format!("path={} {}", write.path, safe_error_detail(&e)),
                    );
                    self.ledger.record_file_write(&write.path, &e.to_string());
                    self.emit(Event::Error(format!("write `{}`: {e}", write.path)))
                        .await;
                    errors.push(format!("write `{}` failed: {e}", write.path));
                    all_ok = false;
                }
            }
        }
        (all_ok, errors)
    }

    async fn approve_write_batch(
        &mut self,
        author: &str,
        writes: &[crate::swarm::FileWrite],
        root: &Path,
    ) -> bool {
        let target = match Workspace::new(root.to_path_buf()) {
            Ok(target) => target,
            Err(error) => {
                self.emit(Event::Error(format!(
                    "cannot open write target {}: {error}",
                    root.display()
                )))
                .await;
                return false;
            }
        };

        for write in writes {
            if let Err(error) = target.precheck(&write.path, write.content.len()) {
                let _ = self.audit.log(
                    "file.write_failed",
                    &format!("path={} {}", write.path, safe_error_detail(&error)),
                );
                self.ledger
                    .record_file_write(&write.path, &format!("failed: {error}"));
                self.emit(Event::Error(format!("write `{}`: {error}", write.path)))
                    .await;
                return false;
            }
        }
        for write in writes {
            if !self.confirm_write(author, write, &target).await {
                let _ = self
                    .audit
                    .log("file.write_denied", &format!("path={}", write.path));
                self.ledger
                    .record_file_write(&write.path, "denied by the user");
                self.emit(Event::WriteDenied {
                    author: author.to_string(),
                    path: write.path.clone(),
                })
                .await;
                return false;
            }
        }
        true
    }

    async fn write_preapproved_batch(
        &mut self,
        author: &str,
        writes: Vec<crate::swarm::FileWrite>,
        root: &Path,
    ) -> bool {
        let target = match Workspace::new(root.to_path_buf()) {
            Ok(target) => target,
            Err(error) => {
                self.emit(Event::Error(format!(
                    "cannot open write target {}: {error}",
                    root.display()
                )))
                .await;
                return false;
            }
        };
        let mut all_ok = true;
        let mut writes = writes.into_iter();
        while let Some(write) = writes.next() {
            match target.write(&write.path, &write.content) {
                Ok(_) => {
                    let outcome = format!("ok ({} bytes)", write.content.len());
                    let _ = self.audit.log(
                        "file.written",
                        &format!(
                            "path={} chars={}",
                            write.path,
                            write.content.chars().count()
                        ),
                    );
                    self.ledger.record_file_write(&write.path, &outcome);
                    self.emit(Event::FileWritten {
                        author: author.to_string(),
                        path: write.path,
                    })
                    .await;
                }
                Err(error) => {
                    let _ = self.audit.log(
                        "file.write_failed",
                        &format!("path={} {}", write.path, safe_error_detail(&error)),
                    );
                    self.ledger
                        .record_file_write(&write.path, &error.to_string());
                    self.emit(Event::Error(format!("write `{}`: {error}", write.path)))
                        .await;
                    all_ok = false;
                    for pending in writes {
                        self.ledger.record_file_write(
                            &pending.path,
                            "not attempted after an earlier apply failure",
                        );
                    }
                    break;
                }
            }
        }
        all_ok
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
    #[cfg(test)]
    async fn run_file_reads(&mut self, primary_label: &str, reply_text: &str) {
        self.run_file_read_requests(primary_label, SwarmLedger::parse_read_files(reply_text))
            .await;
    }

    async fn run_file_read_requests(&mut self, primary_label: &str, requests: Vec<String>) {
        // Mirrors `run_skill_reads` capping to `MAX_READ_ACTIONS_PER_TURN`: bounds how
        // much filesystem effort a single turn can trigger, independent of how many
        // of the results the ledger ends up keeping (`MAX_LOADED_READS`).
        for path in requests {
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
                        &format!("path={path} chars={}", content.chars().count()),
                    );
                    self.emit(Event::FileRead {
                        path: path.clone(),
                        chars: content.chars().count(),
                    })
                    .await;
                }
                Err(e) => {
                    let _ = self.audit.log(
                        "project.read_failed",
                        &format!("path={path} {}", safe_error_detail(&e)),
                    );
                    // Record the failure so the commander learns next turn that
                    // the file could not be read — mirrors the skill read case above.
                    self.ledger.record_file_read(&path, &format!("failed: {e}"));
                    self.emit(Event::Error(format!("read `{path}`: {e}"))).await;
                }
            }
        }
    }

    /// Executes any `list_files` lines the primary emitted, mirroring
    /// `run_file_reads` in structure and sharing the same stripped-text and
    /// non-recursion guarantees.
    #[cfg(test)]
    async fn run_file_lists(&mut self, primary_label: &str, reply_text: &str) {
        self.run_file_list_requests(primary_label, SwarmLedger::parse_list_files(reply_text))
            .await;
    }

    async fn run_file_list_requests(&mut self, primary_label: &str, requests: Vec<String>) {
        for path in requests {
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
                    let _ = self.audit.log(
                        "project.list_failed",
                        &format!("path={path} {}", safe_error_detail(&e)),
                    );
                    // Record the failure so the commander learns next turn that
                    // the listing could not be completed — mirrors the read cases above.
                    self.ledger.record_file_list(&path, &format!("failed: {e}"));
                    self.emit(Event::Error(format!("list `{path}`: {e}"))).await;
                }
            }
        }
    }

    async fn confirm_run(&mut self, author: &str, task_id: usize, command: &str) -> bool {
        self.emit(Event::RunRequested {
            author: author.to_string(),
            task_id,
            argv_display: command.to_string(),
        })
        .await;

        let Some(decisions) = self.decisions.as_mut() else {
            return false;
        };
        matches!(decisions.recv().await, Some(WriteDecision::Approve))
    }

    async fn run_command_requests(&mut self, requester: &str, requests: Vec<RunRequest>) {
        for request in requests {
            let command = display_argv(&request.argv);
            if self.classified {
                self.finish_run(
                    requester,
                    request.task_id,
                    &request.argv,
                    RunOutcome::Rejected,
                    0,
                    "proof commands are disabled in classified mode".into(),
                )
                .await;
                continue;
            }

            let Some(workspace_id) = self.ledger.resolve_live_workspace_id(request.task_id) else {
                self.finish_run(
                    requester,
                    request.task_id,
                    &request.argv,
                    RunOutcome::Rejected,
                    0,
                    format!("task {} has no live isolated copy", request.task_id),
                )
                .await;
                continue;
            };
            let Some(workspace_root) = self.workspace.task_copy_root(workspace_id) else {
                self.ledger.release_workspace(workspace_id);
                self.finish_run(
                    requester,
                    request.task_id,
                    &request.argv,
                    RunOutcome::Rejected,
                    0,
                    format!("isolated copy {workspace_id} is unavailable"),
                )
                .await;
                continue;
            };
            let validated =
                match validate_command(&request.argv, &workspace_root, &self.project_root) {
                    Ok(validated) => validated,
                    Err(error) => {
                        self.finish_run(
                            requester,
                            request.task_id,
                            &request.argv,
                            RunOutcome::Rejected,
                            0,
                            error.to_string(),
                        )
                        .await;
                        continue;
                    }
                };
            let quota = match self.workspace.task_copy_quota(workspace_id) {
                Ok(quota) => quota,
                Err(error) => {
                    self.finish_run(
                        requester,
                        request.task_id,
                        &request.argv,
                        RunOutcome::ResourceLimit,
                        0,
                        error.to_string(),
                    )
                    .await;
                    self.release_task_copy(
                        workspace_id,
                        false,
                        "task copy exceeded its storage quota".into(),
                    )
                    .await;
                    continue;
                }
            };

            let _ = self.audit.log(
                "command.requested",
                &format!(
                    "by={requester} task={} workspace={} argc={}",
                    request.task_id,
                    workspace_id,
                    request.argv.len()
                ),
            );
            if !self.confirm_run(requester, request.task_id, &command).await {
                self.ledger.record_run(
                    request.task_id,
                    &request.argv,
                    RunOutcome::Denied,
                    "denied by the user",
                    0,
                );
                let _ = self.audit.log(
                    "command.denied",
                    &format!("task={} workspace={workspace_id}", request.task_id),
                );
                self.emit(Event::RunDenied {
                    author: requester.to_string(),
                    task_id: request.task_id,
                })
                .await;
                continue;
            }

            self.emit(Event::ActivityStarted {
                label: requester.to_string(),
                kind: ActivityKind::RunningCommand,
            })
            .await;
            let _ = self.audit.log(
                "command.started",
                &format!("task={} workspace={workspace_id}", request.task_id),
            );
            let started = Instant::now();
            match execute_command(&validated, &workspace_root, COMMAND_TIMEOUT, quota).await {
                Ok(result) => {
                    let millis = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                    let resource_limited = result.resource_limit.is_some();
                    let outcome = if resource_limited {
                        RunOutcome::ResourceLimit
                    } else {
                        match result.exit_code {
                            Some(code) => RunOutcome::Exited(code),
                            None => RunOutcome::TimedOut,
                        }
                    };
                    self.finish_run(
                        requester,
                        request.task_id,
                        &request.argv,
                        outcome,
                        millis,
                        result.output,
                    )
                    .await;
                    if resource_limited {
                        self.release_task_copy(
                            workspace_id,
                            false,
                            "proof command exceeded the task-copy storage quota".into(),
                        )
                        .await;
                    }
                }
                Err(error) => {
                    let millis = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                    self.finish_run(
                        requester,
                        request.task_id,
                        &request.argv,
                        RunOutcome::SpawnFailed,
                        millis,
                        error.to_string(),
                    )
                    .await;
                }
            }
        }
    }

    async fn finish_run(
        &mut self,
        author: &str,
        task_id: usize,
        argv: &[String],
        outcome: RunOutcome,
        millis: u64,
        output: String,
    ) {
        self.ledger
            .record_run(task_id, argv, outcome.clone(), &output, millis);
        let audit_outcome = match &outcome {
            RunOutcome::Exited(code) => format!("exit_{code}"),
            RunOutcome::TimedOut => "timeout".into(),
            RunOutcome::Denied => "denied".into(),
            RunOutcome::Rejected => "rejected".into(),
            RunOutcome::SpawnFailed => "spawn_failed".into(),
            RunOutcome::ResourceLimit => "resource_limit".into(),
        };
        let _ = self.audit.log(
            "command.completed",
            &format!(
                "task={task_id} outcome={audit_outcome} millis={millis} chars={}",
                output.chars().count()
            ),
        );
        let visible_error = matches!(
            outcome,
            RunOutcome::Rejected | RunOutcome::SpawnFailed | RunOutcome::ResourceLimit
        )
        .then(|| {
            format!(
                "proof command for task {task_id}: {}",
                truncate_chars(&sanitize_transcript_detail(&output), 1000)
            )
        });
        self.emit(Event::RunCompleted {
            author: author.to_string(),
            task_id,
            outcome,
            chars: output.chars().count(),
            millis,
        })
        .await;
        if let Some(message) = visible_error {
            self.emit(Event::Error(message)).await;
        }
    }

    async fn run_copy_disposition_requests(
        &mut self,
        requester: &str,
        dispositions: Vec<CopyDisposition>,
        ran_commands_this_turn: bool,
    ) {
        for disposition in dispositions {
            let task_id = match disposition {
                CopyDisposition::Apply(task_id) | CopyDisposition::Discard(task_id) => task_id,
            };
            let Some(workspace_id) = self.ledger.resolve_live_workspace_id(task_id) else {
                let message = format!("task {task_id} has no live isolated copy");
                if self.ledger.task(task_id).is_some() {
                    self.ledger.append_result(task_id, &message);
                }
                self.emit(Event::Error(message)).await;
                continue;
            };
            if ran_commands_this_turn {
                let message = "copy disposition refused: review this turn's proof output first, then apply or discard on the next commander turn";
                self.ledger.append_result(task_id, message);
                let _ = self.audit.log(
                    "copy.disposition_refused",
                    &format!("task={task_id} workspace={workspace_id} kind=same_turn_run"),
                );
                self.emit(Event::Error(message.into())).await;
                continue;
            }

            match disposition {
                CopyDisposition::Discard(_) => {
                    if self
                        .release_task_copy(workspace_id, false, format!("discarded by {requester}"))
                        .await
                    {
                        self.ledger
                            .append_result(task_id, "isolated copy discarded");
                    }
                }
                CopyDisposition::Apply(_) => {
                    if let Err(error) = self.workspace.validate_task_copy(workspace_id) {
                        let message = format!(
                            "apply_copy refused: task copy exceeded its storage quota: {error}"
                        );
                        self.ledger.append_result(task_id, &message);
                        self.emit(Event::Error(message)).await;
                        self.release_task_copy(
                            workspace_id,
                            false,
                            "task copy exceeded its storage quota".into(),
                        )
                        .await;
                        continue;
                    }
                    let plan = match self.workspace.plan_task_copy_apply(workspace_id) {
                        Ok(plan) => plan,
                        Err(error) => {
                            let message = format!("apply_copy failed: {error}");
                            self.ledger.append_result(task_id, &message);
                            let _ = self.audit.log(
                                "copy.apply_failed",
                                &format!(
                                    "task={task_id} workspace={workspace_id} {}",
                                    safe_error_detail(&error)
                                ),
                            );
                            self.emit(Event::Error(message)).await;
                            continue;
                        }
                    };
                    if !plan.conflicts.is_empty() || !plan.deleted.is_empty() {
                        let message = format!(
                            "apply_copy refused: {} conflict(s) [{}]; {} deletion(s) [{}]. Resolve these explicitly; the main project was not overwritten.",
                            plan.conflicts.len(),
                            summarize_paths(&plan.conflicts),
                            plan.deleted.len(),
                            summarize_paths(&plan.deleted),
                        );
                        self.ledger.append_result(task_id, &message);
                        let _ = self.audit.log(
                            "copy.apply_refused",
                            &format!(
                                "task={task_id} workspace={workspace_id} conflicts={} deletions={}",
                                plan.conflicts.len(),
                                plan.deleted.len()
                            ),
                        );
                        self.emit(Event::Error(message)).await;
                        continue;
                    }
                    if plan.writes.len() > MAX_APPLY_FILES {
                        let message = format!(
                            "apply_copy refused: {} changed files exceed the {MAX_APPLY_FILES}-file apply limit",
                            plan.writes.len()
                        );
                        self.ledger.append_result(task_id, &message);
                        self.emit(Event::Error(message)).await;
                        continue;
                    }

                    let write_count = plan.writes.len();
                    let author = format!("{requester} applying copy {workspace_id}");
                    let main_root = self.workspace.root().to_path_buf();
                    let applied = if write_count == 0 {
                        true
                    } else if !self
                        .approve_write_batch(&author, &plan.writes, &main_root)
                        .await
                    {
                        false
                    } else {
                        let refreshed = self.workspace.plan_task_copy_apply(workspace_id);
                        match refreshed {
                            Ok(refreshed)
                                if refreshed.conflicts.is_empty()
                                    && refreshed.deleted.is_empty()
                                    && refreshed.writes == plan.writes =>
                            {
                                self.write_preapproved_batch(&author, plan.writes, &main_root)
                                    .await
                            }
                            Ok(_) => {
                                let message = "apply_copy refused: the main project or task copy changed while approval was pending";
                                self.ledger.append_result(task_id, message);
                                let _ = self.audit.log(
                                    "copy.apply_refused",
                                    &format!(
                                        "task={task_id} workspace={workspace_id} kind=changed_during_approval"
                                    ),
                                );
                                self.emit(Event::Error(message.into())).await;
                                false
                            }
                            Err(error) => {
                                let message =
                                    format!("apply_copy failed while rechecking changes: {error}");
                                self.ledger.append_result(task_id, &message);
                                let _ = self.audit.log(
                                    "copy.apply_failed",
                                    &format!(
                                        "task={task_id} workspace={workspace_id} {}",
                                        safe_error_detail(&error)
                                    ),
                                );
                                self.emit(Event::Error(message)).await;
                                false
                            }
                        }
                    };
                    if !applied {
                        let message = "apply_copy incomplete: one or more writes were denied or failed; the copy was retained";
                        self.ledger.append_result(task_id, message);
                        self.emit(Event::Error(message.into())).await;
                        continue;
                    }

                    self.ledger.append_result(
                        task_id,
                        &format!("isolated copy applied ({write_count} file(s))"),
                    );
                    let _ = self.audit.log(
                        "copy.applied",
                        &format!("task={task_id} workspace={workspace_id} files={write_count}"),
                    );
                    self.release_task_copy(
                        workspace_id,
                        true,
                        format!("applied {write_count} file(s)"),
                    )
                    .await;
                }
            }
        }
    }

    async fn release_task_copy(
        &mut self,
        workspace_id: usize,
        applied: bool,
        reason: String,
    ) -> bool {
        match self.workspace.release_task_copy(workspace_id) {
            Ok(()) => {
                self.ledger.release_workspace(workspace_id);
                let _ = self.audit.log(
                    "copy.released",
                    &format!(
                        "workspace={workspace_id} reason={}",
                        sanitize_transcript_detail(&reason)
                    ),
                );
                self.emit(Event::TaskCopyReleased {
                    task_id: workspace_id,
                    applied,
                })
                .await;
                true
            }
            Err(error) => {
                let _ = self.audit.log(
                    "copy.release_failed",
                    &format!("workspace={workspace_id} {}", safe_error_detail(&error)),
                );
                self.emit(Event::Error(format!(
                    "could not release isolated copy {workspace_id}: {error}"
                )))
                .await;
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn the_audit_detail_names_the_failure_kind_but_never_its_text() {
        // The invariant this guards is the whole point of `safe_error_detail`: a reader
        // of the audit log must learn *what kind* of failure happened without any of the
        // error's free text, which can carry a provider's response body or a model's own
        // output.
        let body = "SECRET-RESPONSE-BODY-marker-9f3a";
        let err = anyhow::Error::new(crate::providers::ProviderFailure::HttpStatus(429))
            .context(format!("anthropic returned 429: {body}"));

        // Fixture guard: the text really is in the error, so the "not contained"
        // assertion below cannot pass merely because the fixture was empty.
        assert!(
            err.to_string().contains(body),
            "fixture did not put the secret text into the error"
        );

        let detail = safe_error_detail(&err);
        assert!(
            !detail.contains(body),
            "audit detail leaked the error text: {detail}"
        );
        assert!(detail.contains("http_status"), "kind was lost: {detail}");
    }

    #[test]
    fn a_cli_timeout_is_recorded_as_a_timeout_not_as_unspecified() {
        // The regression: timeouts were raised with a bare `anyhow!("… timed out after
        // …")`, so classification found nothing typed and logged `kind=unspecified` —
        // losing the single most common real failure in this project. The
        // human-readable sentence must survive too, because
        // `is_retryable_delegation_error` matches on it.
        let err = anyhow::Error::new(crate::providers::ProviderFailure::Timeout)
            .context("/home/x/claude timed out after 300s".to_string());
        assert!(
            err.to_string().contains("timed out after"),
            "the retry classifier's substring must stay in Display"
        );
        assert_eq!(safe_error_detail(&err), "kind=timeout detail=withheld");
    }

    #[test]
    fn test_reproduction_classify_io_connection_reset_and_aborted_as_connection_failed() {
        for kind in [
            std::io::ErrorKind::ConnectionReset,
            std::io::ErrorKind::ConnectionAborted,
        ] {
            let err = anyhow::Error::new(std::io::Error::from(kind));
            let detail = safe_error_detail(&err);
            assert!(
                detail.contains("connection_failed"),
                "expected connection_failed for {kind:?}, got {detail}"
            );
        }
    }

    #[test]
    fn io_error_kinds_survive_into_the_audit_detail() {
        for (kind, expected) in [
            (std::io::ErrorKind::NotFound, "not_found"),
            (std::io::ErrorKind::PermissionDenied, "permission_denied"),
        ] {
            let err = anyhow::Error::new(std::io::Error::from(kind));
            let detail = safe_error_detail(&err);
            assert!(detail.contains(expected), "{kind:?} became {detail}");
        }
    }

    #[test]
    fn the_audit_detail_is_bounded_and_utf8_safe_for_an_enormous_error() {
        // Byte-index truncation panicked on multi-byte input before (fixed in 923b934);
        // this message is Lithuanian, so every possible cut point is mid-codepoint.
        let huge = "ąčęėįšųūž".repeat(100_000);
        assert!(
            huge.len() > 1_000_000,
            "fixture is not large enough to matter"
        );
        let err = anyhow::anyhow!("{huge}");
        let detail = safe_error_detail(&err);
        assert!(
            detail.len() < 200,
            "detail was not bounded: {} bytes",
            detail.len()
        );
        assert!(!detail.contains('ą'), "detail echoed the error text");
    }
    use super::*;
    use crate::isolation::IsolationLimits;
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
                usage: TokenUsage::default(),
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
                usage: TokenUsage::default(),
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

    #[derive(Clone)]
    struct QuotaWritingProvider {
        provider: String,
        model: String,
        project_root: Option<PathBuf>,
        bytes: usize,
    }

    #[async_trait]
    impl Provider for QuotaWritingProvider {
        async fn send(&self, _system: Option<&str>, _prompt: &str) -> Result<Reply> {
            let project_root = self
                .project_root
                .as_ref()
                .ok_or_else(|| anyhow!("quota-writing provider was not rerooted"))?;
            std::fs::write(
                project_root.join("provider-output.bin"),
                vec![0u8; self.bytes],
            )?;
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok(Reply {
                text: "finished".into(),
                rate_limit: RateLimit::default(),
                usage: TokenUsage::default(),
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

        fn with_project_root(&self, project_root: &Path) -> Option<Arc<dyn Provider>> {
            let mut rerooted = self.clone();
            rerooted.project_root = Some(project_root.to_path_buf());
            Some(Arc::new(rerooted))
        }
    }

    type CapturedCalls = Arc<std::sync::Mutex<Vec<(String, String)>>>;

    struct SequenceProvider {
        provider: String,
        model: String,
        replies: std::sync::Mutex<std::collections::VecDeque<String>>,
        calls: CapturedCalls,
    }

    #[async_trait]
    impl Provider for SequenceProvider {
        async fn send(&self, system: Option<&str>, prompt: &str) -> Result<Reply> {
            self.calls
                .lock()
                .unwrap()
                .push((system.unwrap_or_default().to_string(), prompt.to_string()));
            let text =
                self.replies.lock().unwrap().pop_front().ok_or_else(|| {
                    anyhow!("scripted provider received an unexpected extra call")
                })?;
            Ok(Reply {
                text,
                rate_limit: RateLimit::default(),
                usage: TokenUsage::default(),
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

        fn requires_subagent_tool_guardrails(&self) -> bool {
            false
        }
    }

    fn sequence_provider(
        provider: &str,
        model: &str,
        replies: Vec<String>,
    ) -> (Arc<SequenceProvider>, CapturedCalls) {
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        (
            Arc::new(SequenceProvider {
                provider: provider.into(),
                model: model.into(),
                replies: std::sync::Mutex::new(replies.into()),
                calls: calls.clone(),
            }),
            calls,
        )
    }

    async fn run_prompt_to_completion(
        orchestrator: Orchestrator,
        mut events: mpsc::Receiver<Event>,
        prompt: &str,
    ) -> Vec<Event> {
        let (commands_tx, commands_rx) = mpsc::channel(4);
        let runner = tokio::spawn(orchestrator.run(commands_rx));
        commands_tx
            .send(Command::Prompt(prompt.to_string()))
            .await
            .unwrap();

        let mut collected = Vec::new();
        loop {
            let event = tokio::time::timeout(Duration::from_secs(60), events.recv())
                .await
                .expect("workflow timed out")
                .expect("orchestrator event channel closed before TurnComplete");
            let complete = matches!(event, Event::TurnComplete);
            collected.push(event);
            if complete {
                break;
            }
        }

        commands_tx.send(Command::Shutdown).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), runner)
            .await
            .expect("orchestrator did not shut down")
            .unwrap();
        collected
    }

    #[test]
    fn action_budget_distinguishes_per_turn_and_workflow_caps() {
        let mut remaining = MAX_ACTIONS_PER_WORKFLOW;
        let (accepted, per_turn, workflow) =
            take_action_budget((0..11).collect(), 10, &mut remaining);
        assert_eq!(accepted.len(), 10);
        assert!(per_turn);
        assert!(!workflow);

        let mut remaining = 3;
        let (accepted, per_turn, workflow) =
            take_action_budget((0..5).collect(), 10, &mut remaining);
        assert_eq!(accepted.len(), 3);
        assert!(!per_turn);
        assert!(workflow);
    }

    fn workflow_orchestrator(
        registry: Registry,
        paths: &Paths,
        project_root: PathBuf,
        classified: bool,
        events: mpsc::Sender<Event>,
        decisions: Option<mpsc::Receiver<WriteDecision>>,
        auto_write: bool,
    ) -> Orchestrator {
        let mut workspace = Workspace::new(project_root.clone()).unwrap();
        workspace.enable_task_copies(&paths.data_dir).unwrap();
        Orchestrator {
            registry,
            ledger: SwarmLedger::new(),
            audit: AuditLogger::with_key(paths.audit_log.clone(), vec![11u8; 32]).unwrap(),
            skills: SkillsDir::new(paths.skills_dir.clone()).unwrap(),
            workspace,
            events,
            classified,
            project_root,
            decisions,
            approve_all: auto_write,
            data_dir: paths.data_dir.clone(),
        }
    }

    fn workflow_orchestrator_with_limits(
        registry: Registry,
        paths: &Paths,
        project_root: PathBuf,
        events: mpsc::Sender<Event>,
        decisions: Option<mpsc::Receiver<WriteDecision>>,
        auto_write: bool,
        limits: IsolationLimits,
    ) -> Orchestrator {
        let mut workspace = Workspace::new(project_root.clone()).unwrap();
        workspace
            .enable_task_copies_with_limits(&paths.data_dir, limits)
            .unwrap();
        Orchestrator {
            registry,
            ledger: SwarmLedger::new(),
            audit: AuditLogger::with_key(paths.audit_log.clone(), vec![11u8; 32]).unwrap(),
            skills: SkillsDir::new(paths.skills_dir.clone()).unwrap(),
            workspace,
            events,
            classified: false,
            project_root,
            decisions,
            approve_all: auto_write,
            data_dir: paths.data_dir.clone(),
        }
    }

    /// A provider that records the exact system/user context it receives, making
    /// delegated prompt isolation observable without a live model call.
    struct ContextCapturingProvider {
        provider: String,
        model: String,
        calls: Arc<std::sync::Mutex<Vec<(String, String, String)>>>,
    }

    #[async_trait]
    impl Provider for ContextCapturingProvider {
        async fn send(&self, system: Option<&str>, prompt: &str) -> Result<Reply> {
            self.calls.lock().unwrap().push((
                self.label(),
                system.unwrap_or_default().to_string(),
                prompt.to_string(),
            ));
            Ok(Reply {
                text: "done".into(),
                rate_limit: RateLimit::default(),
                usage: TokenUsage::default(),
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
        fn requires_subagent_tool_guardrails(&self) -> bool {
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
                usage: TokenUsage::default(),
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

    #[tokio::test]
    async fn a_plain_commander_reply_finishes_without_auto_continuation() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(temp.path().join("data")).unwrap();
        let project = temp.path().join("project");
        std::fs::create_dir(&project).unwrap();
        let (commander, calls) =
            sequence_provider("test", "commander", vec!["final answer".into()]);
        let mut providers: BTreeMap<String, Arc<dyn Provider>> = BTreeMap::new();
        providers.insert("test:commander".into(), commander);
        let registry = Registry {
            providers,
            primary: "test:commander".into(),
            applied: BTreeMap::new(),
            connection_ids: BTreeMap::new(),
        };
        let (event_tx, event_rx) = mpsc::channel(64);
        let orchestrator =
            workflow_orchestrator(registry, &paths, project, false, event_tx, None, false);

        let events = run_prompt_to_completion(orchestrator, event_rx, "hello").await;

        assert_eq!(calls.lock().unwrap().len(), 1);
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, Event::AutoContinuation { .. }))
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, Event::TurnComplete))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn repeated_action_and_result_state_stops_auto_continuation() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(temp.path().join("data")).unwrap();
        let project = temp.path().join("project");
        std::fs::create_dir(&project).unwrap();
        let (commander, calls) = sequence_provider(
            "test",
            "commander",
            vec!["ACTION: list_files()".into(), "ACTION: list_files()".into()],
        );
        let mut providers: BTreeMap<String, Arc<dyn Provider>> = BTreeMap::new();
        providers.insert("test:commander".into(), commander);
        let registry = Registry {
            providers,
            primary: "test:commander".into(),
            applied: BTreeMap::new(),
            connection_ids: BTreeMap::new(),
        };
        let (event_tx, event_rx) = mpsc::channel(128);
        let orchestrator =
            workflow_orchestrator(registry, &paths, project, false, event_tx, None, false);

        let events = run_prompt_to_completion(orchestrator, event_rx, "inspect").await;

        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert!(calls[1].1.contains("--- original user request ---"));
        assert!(calls[1].1.contains("inspect"));
        drop(calls);
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, Event::AutoContinuation { .. }))
                .count(),
            1
        );
        assert!(events.iter().any(|event| {
            matches!(
                event,
                Event::Error(message) if message.contains("repeated the same actions")
            )
        }));
    }

    #[tokio::test]
    async fn automatic_continuation_stops_at_the_turn_cap() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(temp.path().join("data")).unwrap();
        let project = temp.path().join("project");
        std::fs::create_dir(&project).unwrap();
        let mut replies = Vec::new();
        for index in 0..=usize::from(MAX_AUTO_CONTINUATION_TURNS) {
            let directory = format!("dir-{index}");
            std::fs::create_dir(project.join(&directory)).unwrap();
            replies.push(format!("ACTION: list_files({directory})"));
        }
        let (commander, calls) = sequence_provider("test", "commander", replies);
        let mut providers: BTreeMap<String, Arc<dyn Provider>> = BTreeMap::new();
        providers.insert("test:commander".into(), commander);
        let registry = Registry {
            providers,
            primary: "test:commander".into(),
            applied: BTreeMap::new(),
            connection_ids: BTreeMap::new(),
        };
        let (event_tx, event_rx) = mpsc::channel(256);
        let orchestrator =
            workflow_orchestrator(registry, &paths, project, false, event_tx, None, false);

        let events = run_prompt_to_completion(orchestrator, event_rx, "keep inspecting").await;

        assert_eq!(
            calls.lock().unwrap().len(),
            usize::from(MAX_AUTO_CONTINUATION_TURNS) + 1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, Event::AutoContinuation { .. }))
                .count(),
            usize::from(MAX_AUTO_CONTINUATION_TURNS)
        );
        assert!(events.iter().any(|event| {
            matches!(
                event,
                Event::Error(message) if message.contains("turn limit")
            )
        }));
    }

    #[tokio::test]
    async fn automatic_continuation_enforces_the_global_action_budget() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(temp.path().join("data")).unwrap();
        let project = temp.path().join("project");
        std::fs::create_dir(&project).unwrap();

        let mut next_task = 0usize;
        let mut replies = Vec::new();
        for count in [10usize, 10, 10, 10, 8] {
            let mut reply = String::new();
            for _ in 0..count {
                next_task += 1;
                reply.push_str(&format!(
                    "ACTION: delegate_task(test:worker, task-{next_task})\n"
                ));
            }
            replies.push(reply);
        }
        replies.push("ACTION: delegate_task(test:worker, over-budget)".into());

        let (commander, calls) = sequence_provider("test", "commander", replies);
        let mut providers: BTreeMap<String, Arc<dyn Provider>> = BTreeMap::new();
        providers.insert("test:commander".into(), commander);
        providers.insert(
            "test:worker".into(),
            Arc::new(ScriptedProvider {
                provider: "test".into(),
                model: "worker".into(),
                reply: "done".into(),
            }),
        );
        let registry = Registry {
            providers,
            primary: "test:commander".into(),
            applied: BTreeMap::new(),
            connection_ids: BTreeMap::new(),
        };
        let (event_tx, event_rx) = mpsc::channel(2048);
        let orchestrator =
            workflow_orchestrator(registry, &paths, project, false, event_tx, None, false);

        let events = run_prompt_to_completion(orchestrator, event_rx, "delegate everything").await;

        assert_eq!(calls.lock().unwrap().len(), 6);
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, Event::DelegationFinished { ok: true, .. }))
                .count(),
            MAX_ACTIONS_PER_WORKFLOW
        );
        assert!(events.iter().any(|event| {
            matches!(
                event,
                Event::Error(message) if message.contains("workflow action limit")
            )
        }));
    }

    #[tokio::test]
    async fn automatic_workflow_reruns_red_and_green_in_one_copy_then_applies_it() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(temp.path().join("data")).unwrap();
        let project = temp.path().join("project");
        std::fs::create_dir_all(project.join("src")).unwrap();
        std::fs::write(
            project.join("Cargo.toml"),
            "[package]\nname = \"proof-fixture\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        std::fs::write(
            project.join("src/lib.rs"),
            "pub fn add(left: i32, right: i32) -> i32 { left - right }\n",
        )
        .unwrap();

        let (commander, commander_calls) = sequence_provider(
            "test",
            "commander",
            vec![
                "ACTION: delegate_file_task(test:worker, Add only a deterministic regression test for add.)".into(),
                "ACTION: run_test(1)".into(),
                "ACTION: delegate_in_copy(1, test:worker, Fix add so the accepted regression passes.)".into(),
                "ACTION: run_test(1)".into(),
                "ACTION: apply_copy(1)".into(),
                "The regression failed before the fix, passed after it, and the isolated changes were applied.".into(),
            ],
        );
        let (worker, worker_calls) = sequence_provider(
            "test",
            "worker",
            vec![
                "Added the regression only.\n\
                 ACTION: write_file(tests/regression.rs)\n\
                 use proof_fixture::add;\n\
                 #[test]\n\
                 fn addition_works() { assert_eq!(add(2, 3), 5); }\n\
                 ACTION: end_file"
                    .into(),
                "Fixed the implementation.\n\
                 ACTION: write_file(src/lib.rs)\n\
                 pub fn add(left: i32, right: i32) -> i32 { left + right }\n\
                 ACTION: end_file"
                    .into(),
            ],
        );
        let mut providers: BTreeMap<String, Arc<dyn Provider>> = BTreeMap::new();
        providers.insert("test:commander".into(), commander);
        providers.insert("test:worker".into(), worker);
        let registry = Registry {
            providers,
            primary: "test:commander".into(),
            applied: BTreeMap::new(),
            connection_ids: BTreeMap::new(),
        };
        let (decision_tx, decision_rx) = mpsc::channel(2);
        decision_tx.send(WriteDecision::Approve).await.unwrap();
        decision_tx.send(WriteDecision::Approve).await.unwrap();
        let (event_tx, event_rx) = mpsc::channel(512);
        let orchestrator = workflow_orchestrator(
            registry,
            &paths,
            project.clone(),
            false,
            event_tx,
            Some(decision_rx),
            true,
        );

        let events =
            run_prompt_to_completion(orchestrator, event_rx, "Find and fix the add defect.").await;

        let outcomes: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                Event::RunCompleted { outcome, .. } => Some(outcome.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(outcomes.len(), 2);
        assert!(matches!(outcomes[0], RunOutcome::Exited(code) if code != 0));
        assert_eq!(outcomes[1], RunOutcome::Exited(0));
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, Event::RunRequested { .. }))
                .count(),
            2,
            "proof runs must still ask under --auto-write"
        );
        assert!(events.iter().any(|event| matches!(
            event,
            Event::TaskCopyReleased {
                task_id: 1,
                applied: true
            }
        )));
        assert_eq!(commander_calls.lock().unwrap().len(), 6);
        assert_eq!(worker_calls.lock().unwrap().len(), 2);
        let final_system = &commander_calls.lock().unwrap()[5].0;
        assert!(final_system.contains("outcome: Exited("));
        assert!(final_system.contains("outcome: Exited(0)"));
        assert_eq!(
            std::fs::read_to_string(project.join("src/lib.rs")).unwrap(),
            "pub fn add(left: i32, right: i32) -> i32 { left + right }"
        );
        assert!(project.join("tests/regression.rs").is_file());
        assert_eq!(
            std::fs::read_dir(paths.data_dir.join("task-copies"))
                .unwrap()
                .count(),
            0,
            "the applied copy and its session directory must be removed"
        );
    }

    #[tokio::test]
    async fn projected_worker_write_over_quota_is_rejected_without_releasing_the_copy() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(temp.path().join("data")).unwrap();
        let project = temp.path().join("project");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(project.join("base.txt"), "base\n").unwrap();

        let mut providers: BTreeMap<String, Arc<dyn Provider>> = BTreeMap::new();
        providers.insert(
            "test:worker".into(),
            Arc::new(ScriptedProvider {
                provider: "test".into(),
                model: "worker".into(),
                reply: format!(
                    "Attempted a large write.\nACTION: write_file(too-large.txt)\n{}\nACTION: end_file",
                    "x".repeat(40)
                ),
            }),
        );
        let registry = Registry {
            providers,
            primary: "test:worker".into(),
            applied: BTreeMap::new(),
            connection_ids: BTreeMap::new(),
        };
        let limits = IsolationLimits {
            max_regular_file_bytes: 128,
            max_copied_bytes: 32,
            max_entries: 64,
            max_total_live_bytes: 64,
            max_excluded_paths: 20,
        };
        let (event_tx, mut event_rx) = mpsc::channel(64);
        let mut orchestrator = workflow_orchestrator_with_limits(
            registry,
            &paths,
            project.clone(),
            event_tx,
            None,
            true,
            limits,
        );

        orchestrator
            .run_delegations(
                "test:worker",
                "ACTION: delegate_file_task(test:worker, write a large file)",
            )
            .await;

        let task = &orchestrator.ledger.tasks()[0];
        assert_eq!(task.status, TaskStatus::Failed);
        assert!(task.workspace_live);
        assert!(
            task.result
                .as_deref()
                .is_some_and(|result| result.contains("copy byte limit")),
            "{:?}",
            task.result
        );
        let copy_root = orchestrator.workspace.task_copy_root(task.id).unwrap();
        assert!(!copy_root.join("too-large.txt").exists());
        assert!(!project.join("too-large.txt").exists());
        let events: Vec<_> = std::iter::from_fn(|| event_rx.try_recv().ok()).collect();
        assert!(events.iter().any(|event| {
            matches!(event, Event::Error(message) if message.contains("copy byte limit"))
        }));
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, Event::TaskCopyReleased { .. }))
        );
    }

    #[tokio::test]
    async fn rerooted_provider_over_quota_is_cancelled_and_its_copy_is_released() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(temp.path().join("data")).unwrap();
        let project = temp.path().join("project");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(project.join("base.txt"), "base\n").unwrap();

        let mut providers: BTreeMap<String, Arc<dyn Provider>> = BTreeMap::new();
        providers.insert(
            "test:writer".into(),
            Arc::new(QuotaWritingProvider {
                provider: "test".into(),
                model: "writer".into(),
                project_root: None,
                bytes: 64,
            }),
        );
        let registry = Registry {
            providers,
            primary: "test:writer".into(),
            applied: BTreeMap::new(),
            connection_ids: BTreeMap::new(),
        };
        let limits = IsolationLimits {
            max_regular_file_bytes: 128,
            max_copied_bytes: 32,
            max_entries: 64,
            max_total_live_bytes: 64,
            max_excluded_paths: 20,
        };
        let (event_tx, mut event_rx) = mpsc::channel(64);
        let mut orchestrator = workflow_orchestrator_with_limits(
            registry,
            &paths,
            project.clone(),
            event_tx,
            None,
            true,
            limits,
        );

        orchestrator
            .run_delegations(
                "test:writer",
                "ACTION: delegate_file_task(test:writer, create output)",
            )
            .await;

        let task = &orchestrator.ledger.tasks()[0];
        assert_eq!(task.status, TaskStatus::Failed);
        assert!(!task.workspace_live);
        assert!(
            task.result
                .as_deref()
                .is_some_and(|result| result.contains("storage quota")),
            "{:?}",
            task.result
        );
        assert!(!orchestrator.workspace.has_task_copy(task.id));
        assert!(!project.join("provider-output.bin").exists());
        let events: Vec<_> = std::iter::from_fn(|| event_rx.try_recv().ok()).collect();
        assert!(events.iter().any(|event| {
            matches!(
                event,
                Event::TaskCopyReleased {
                    task_id: 1,
                    applied: false
                }
            )
        }));
    }

    #[tokio::test]
    async fn proof_command_over_quota_records_resource_limit_and_releases_the_copy() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(temp.path().join("data")).unwrap();
        let project = temp.path().join("project");
        std::fs::create_dir_all(project.join("src")).unwrap();
        std::fs::write(
            project.join("Cargo.toml"),
            "[package]\nname = \"quota-proof\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
        )
        .unwrap();
        std::fs::write(project.join("src/lib.rs"), "pub fn value() -> u8 { 1 }\n").unwrap();

        let registry = registry_with(vec![("test", "commander", false)], "test:commander");
        let limits = IsolationLimits {
            max_regular_file_bytes: 4 * 1024,
            max_copied_bytes: 2 * 1024,
            max_entries: 1_000,
            max_total_live_bytes: 4 * 1024,
            max_excluded_paths: 20,
        };
        let (decision_tx, decision_rx) = mpsc::channel(1);
        decision_tx.send(WriteDecision::Approve).await.unwrap();
        let (event_tx, mut event_rx) = mpsc::channel(128);
        let mut orchestrator = workflow_orchestrator_with_limits(
            registry,
            &paths,
            project,
            event_tx,
            Some(decision_rx),
            false,
            limits,
        );
        let task_id = orchestrator.ledger.add_task("run proof");
        orchestrator.ledger.assign_task(task_id, "test:commander");
        orchestrator.workspace.create_task_copy(task_id).unwrap();
        orchestrator
            .ledger
            .associate_workspace(task_id, task_id, Some("test copy"));

        orchestrator
            .run_command_requests(
                "test:commander",
                vec![RunRequest {
                    task_id,
                    argv: vec!["cargo".into(), "test".into(), "--quiet".into()],
                }],
            )
            .await;

        assert_eq!(orchestrator.ledger.run_records().len(), 1);
        assert_eq!(
            orchestrator.ledger.run_records()[0].outcome,
            RunOutcome::ResourceLimit
        );
        assert!(!orchestrator.workspace.has_task_copy(task_id));
        assert!(!orchestrator.ledger.tasks()[0].workspace_live);
        let events: Vec<_> = std::iter::from_fn(|| event_rx.try_recv().ok()).collect();
        assert!(events.iter().any(|event| {
            matches!(
                event,
                Event::RunCompleted {
                    outcome: RunOutcome::ResourceLimit,
                    ..
                }
            )
        }));
        assert!(events.iter().any(|event| {
            matches!(
                event,
                Event::TaskCopyReleased {
                    task_id: 1,
                    applied: false
                }
            )
        }));
    }

    #[tokio::test]
    async fn fresh_file_delegations_use_distinct_copies_and_never_write_main() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(temp.path().join("data")).unwrap();
        let project = temp.path().join("project");
        std::fs::create_dir(&project).unwrap();
        let (worker, _) = sequence_provider(
            "test",
            "worker",
            vec![
                "ACTION: write_file(first.txt)\none\nACTION: end_file".into(),
                "ACTION: write_file(second.txt)\ntwo\nACTION: end_file".into(),
            ],
        );
        let mut providers: BTreeMap<String, Arc<dyn Provider>> = BTreeMap::new();
        providers.insert(
            "test:commander".into(),
            Arc::new(StubProvider {
                provider: "test".into(),
                model: "commander".into(),
                remote: false,
            }),
        );
        providers.insert("test:worker".into(), worker);
        let registry = Registry {
            providers,
            primary: "test:commander".into(),
            applied: BTreeMap::new(),
            connection_ids: BTreeMap::new(),
        };
        let (event_tx, _event_rx) = mpsc::channel(64);
        let mut orchestrator = workflow_orchestrator(
            registry,
            &paths,
            project.clone(),
            false,
            event_tx,
            None,
            true,
        );

        orchestrator
            .run_delegations(
                "test:commander",
                "ACTION: delegate_file_task(test:worker, first)\n\
                 ACTION: delegate_file_task(test:worker, second)",
            )
            .await;

        let first_root = orchestrator.workspace.task_copy_root(1).unwrap();
        let second_root = orchestrator.workspace.task_copy_root(2).unwrap();
        assert_ne!(first_root, second_root);
        assert_eq!(
            std::fs::read_to_string(first_root.join("first.txt")).unwrap(),
            "one"
        );
        assert!(!first_root.join("second.txt").exists());
        assert_eq!(
            std::fs::read_to_string(second_root.join("second.txt")).unwrap(),
            "two"
        );
        assert!(
            !second_root.join("first.txt").exists(),
            "the second fresh copy must come from main, not from the first task copy"
        );
        assert!(!project.join("first.txt").exists());
        assert!(!project.join("second.txt").exists());
    }

    #[tokio::test]
    async fn worker_write_actions_are_bounded_and_counted() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(temp.path().join("data")).unwrap();
        let project = temp.path().join("project");
        std::fs::create_dir(&project).unwrap();
        let mut reply = String::new();
        for index in 0..11 {
            reply.push_str(&format!(
                "ACTION: write_file(file-{index}.txt)\n{index}\nACTION: end_file\n"
            ));
        }
        let (worker, _) = sequence_provider("test", "worker", vec![reply]);
        let mut providers: BTreeMap<String, Arc<dyn Provider>> = BTreeMap::new();
        providers.insert(
            "test:commander".into(),
            Arc::new(StubProvider {
                provider: "test".into(),
                model: "commander".into(),
                remote: false,
            }),
        );
        providers.insert("test:worker".into(), worker);
        let registry = Registry {
            providers,
            primary: "test:commander".into(),
            applied: BTreeMap::new(),
            connection_ids: BTreeMap::new(),
        };
        let (event_tx, _event_rx) = mpsc::channel(64);
        let mut orchestrator =
            workflow_orchestrator(registry, &paths, project, false, event_tx, None, true);

        orchestrator
            .run_delegations(
                "test:commander",
                "ACTION: delegate_file_task(test:worker, write too many files)",
            )
            .await;

        let copy_root = orchestrator.workspace.task_copy_root(1).unwrap();
        assert_eq!(
            (0..11)
                .filter(|index| copy_root.join(format!("file-{index}.txt")).exists())
                .count(),
            MAX_WRITES_PER_TURN
        );
        assert_eq!(orchestrator.ledger.tasks()[0].status, TaskStatus::Failed);
        assert!(
            orchestrator.ledger.tasks()[0]
                .result
                .as_deref()
                .unwrap()
                .contains("action limit")
        );
    }

    #[tokio::test]
    async fn auto_write_never_auto_approves_a_proof_command() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(temp.path().join("data")).unwrap();
        let project = temp.path().join("project");
        std::fs::create_dir(&project).unwrap();
        let registry = registry_with(vec![("test", "commander", false)], "test:commander");
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let (_decision_tx, decision_rx) = mpsc::channel(1);
        let mut orchestrator = workflow_orchestrator(
            registry,
            &paths,
            project,
            false,
            event_tx,
            Some(decision_rx),
            true,
        );
        let task_id = orchestrator.ledger.add_task("proof");
        orchestrator.ledger.assign_task(task_id, "test:commander");
        orchestrator.workspace.create_task_copy(task_id).unwrap();
        orchestrator
            .ledger
            .associate_workspace(task_id, task_id, Some("test copy"));

        let waiting = tokio::time::timeout(
            Duration::from_millis(50),
            orchestrator.run_command_requests(
                "test:commander",
                vec![RunRequest {
                    task_id,
                    argv: vec!["cargo".into(), "test".into()],
                }],
            ),
        )
        .await;

        assert!(
            waiting.is_err(),
            "the command should still be waiting for an explicit decision"
        );
        assert!(matches!(
            event_rx.try_recv().unwrap(),
            Event::RunRequested { task_id: id, .. } if id == task_id
        ));
        assert!(orchestrator.ledger.run_records().is_empty());
    }

    #[tokio::test]
    async fn classified_mode_rejects_proof_commands_before_approval() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(temp.path().join("data")).unwrap();
        let project = temp.path().join("project");
        std::fs::create_dir(&project).unwrap();
        let registry = registry_with(vec![("test", "commander", false)], "test:commander");
        let (event_tx, mut event_rx) = mpsc::channel(16);
        let (_decision_tx, decision_rx) = mpsc::channel(1);
        let mut orchestrator = workflow_orchestrator(
            registry,
            &paths,
            project,
            true,
            event_tx,
            Some(decision_rx),
            false,
        );
        let task_id = orchestrator.ledger.add_task("proof");
        orchestrator.ledger.assign_task(task_id, "test:commander");
        orchestrator.workspace.create_task_copy(task_id).unwrap();
        orchestrator
            .ledger
            .associate_workspace(task_id, task_id, Some("test copy"));

        orchestrator
            .run_command_requests(
                "test:commander",
                vec![RunRequest {
                    task_id,
                    argv: vec!["cargo".into(), "test".into()],
                }],
            )
            .await;

        assert_eq!(
            orchestrator.ledger.run_records()[0].outcome,
            RunOutcome::Rejected
        );
        let events: Vec<_> = std::iter::from_fn(|| event_rx.try_recv().ok()).collect();
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, Event::RunRequested { .. }))
        );
        assert!(events.iter().any(|event| matches!(
            event,
            Event::RunCompleted {
                outcome: RunOutcome::Rejected,
                ..
            }
        )));
    }

    #[tokio::test]
    async fn proof_commands_reject_text_only_and_released_tasks() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(temp.path().join("data")).unwrap();
        let project = temp.path().join("project");
        std::fs::create_dir(&project).unwrap();
        let registry = registry_with(vec![("test", "commander", false)], "test:commander");
        let (event_tx, mut event_rx) = mpsc::channel(32);
        let mut orchestrator =
            workflow_orchestrator(registry, &paths, project, false, event_tx, None, false);

        let text_task = orchestrator.ledger.add_task("text only");
        orchestrator.ledger.assign_task(text_task, "test:commander");
        let released_task = orchestrator.ledger.add_task("released copy");
        orchestrator
            .ledger
            .assign_task(released_task, "test:commander");
        orchestrator
            .workspace
            .create_task_copy(released_task)
            .unwrap();
        orchestrator
            .ledger
            .associate_workspace(released_task, released_task, Some("test copy"));
        orchestrator
            .workspace
            .release_task_copy(released_task)
            .unwrap();
        orchestrator.ledger.release_workspace(released_task);

        orchestrator
            .run_command_requests(
                "test:commander",
                vec![
                    RunRequest {
                        task_id: text_task,
                        argv: vec!["cargo".into(), "test".into()],
                    },
                    RunRequest {
                        task_id: released_task,
                        argv: vec!["cargo".into(), "test".into()],
                    },
                ],
            )
            .await;

        assert_eq!(orchestrator.ledger.run_records().len(), 2);
        assert!(
            orchestrator
                .ledger
                .run_records()
                .iter()
                .all(|record| record.outcome == RunOutcome::Rejected)
        );
        assert!(
            std::iter::from_fn(|| event_rx.try_recv().ok())
                .all(|event| !matches!(event, Event::RunRequested { .. }))
        );
    }

    #[tokio::test]
    async fn apply_copy_refuses_main_drift_and_deletions_without_partial_changes() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(temp.path().join("data")).unwrap();
        let project = temp.path().join("project");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(project.join("drift.txt"), "baseline").unwrap();
        std::fs::write(project.join("deleted.txt"), "keep").unwrap();
        let registry = registry_with(vec![("test", "commander", false)], "test:commander");
        let (event_tx, mut event_rx) = mpsc::channel(32);
        let mut orchestrator = workflow_orchestrator(
            registry,
            &paths,
            project.clone(),
            false,
            event_tx,
            None,
            true,
        );
        let task_id = orchestrator.ledger.add_task("changes");
        orchestrator.ledger.assign_task(task_id, "test:commander");
        orchestrator.workspace.create_task_copy(task_id).unwrap();
        orchestrator
            .ledger
            .associate_workspace(task_id, task_id, Some("test copy"));
        let copy_root = orchestrator.workspace.task_copy_root(task_id).unwrap();
        std::fs::write(copy_root.join("drift.txt"), "agent change").unwrap();
        std::fs::remove_file(copy_root.join("deleted.txt")).unwrap();
        std::fs::write(project.join("drift.txt"), "user change").unwrap();

        orchestrator
            .run_copy_disposition_requests(
                "test:commander",
                vec![CopyDisposition::Apply(task_id)],
                false,
            )
            .await;

        assert_eq!(
            std::fs::read_to_string(project.join("drift.txt")).unwrap(),
            "user change"
        );
        assert_eq!(
            std::fs::read_to_string(project.join("deleted.txt")).unwrap(),
            "keep"
        );
        assert!(orchestrator.workspace.has_task_copy(task_id));
        assert!(orchestrator.ledger.tasks()[0].workspace_live);
        let events: Vec<_> = std::iter::from_fn(|| event_rx.try_recv().ok()).collect();
        assert!(events.iter().any(|event| {
            matches!(
                event,
                Event::Error(message)
                    if message.contains("conflict") && message.contains("deletion")
            )
        }));
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, Event::TaskCopyReleased { .. }))
        );
    }

    #[tokio::test]
    async fn apply_copy_refuses_parent_file_conflict_without_partial_changes() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(temp.path().join("data")).unwrap();
        let project = temp.path().join("project");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(project.join("ok.txt"), "baseline").unwrap();
        let registry = registry_with(vec![("test", "commander", false)], "test:commander");
        let (event_tx, mut event_rx) = mpsc::channel(32);
        let mut orchestrator = workflow_orchestrator(
            registry,
            &paths,
            project.clone(),
            false,
            event_tx,
            None,
            true,
        );
        let task_id = orchestrator.ledger.add_task("changes");
        orchestrator.ledger.assign_task(task_id, "test:commander");
        orchestrator.workspace.create_task_copy(task_id).unwrap();
        orchestrator
            .ledger
            .associate_workspace(task_id, task_id, Some("test copy"));
        let copy_root = orchestrator.workspace.task_copy_root(task_id).unwrap();
        std::fs::write(copy_root.join("ok.txt"), "agent change").unwrap();
        std::fs::create_dir(copy_root.join("blocked")).unwrap();
        std::fs::write(copy_root.join("blocked/nested.txt"), "new file").unwrap();
        std::fs::write(project.join("blocked"), "not a directory").unwrap();

        orchestrator
            .run_copy_disposition_requests(
                "test:commander",
                vec![CopyDisposition::Apply(task_id)],
                false,
            )
            .await;

        assert_eq!(
            std::fs::read_to_string(project.join("ok.txt")).unwrap(),
            "baseline"
        );
        assert_eq!(
            std::fs::read_to_string(project.join("blocked")).unwrap(),
            "not a directory"
        );
        assert!(orchestrator.workspace.has_task_copy(task_id));
        assert!(orchestrator.ledger.tasks()[0].workspace_live);
        let events: Vec<_> = std::iter::from_fn(|| event_rx.try_recv().ok()).collect();
        assert!(events.iter().any(|event| {
            matches!(
                event,
                Event::Error(message)
                    if message.contains("conflict") && message.contains("blocked/nested.txt")
            )
        }));
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, Event::FileWritten { .. }))
        );
    }

    #[tokio::test]
    async fn apply_copy_retries_only_files_not_already_written_from_the_copy() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(temp.path().join("data")).unwrap();
        let project = temp.path().join("project");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(project.join("first.txt"), "first base").unwrap();
        std::fs::write(project.join("second.txt"), "second base").unwrap();
        let registry = registry_with(vec![("test", "commander", false)], "test:commander");
        let (event_tx, mut event_rx) = mpsc::channel(32);
        let mut orchestrator = workflow_orchestrator(
            registry,
            &paths,
            project.clone(),
            false,
            event_tx,
            None,
            true,
        );
        let task_id = orchestrator.ledger.add_task("changes");
        orchestrator.ledger.assign_task(task_id, "test:commander");
        orchestrator.workspace.create_task_copy(task_id).unwrap();
        orchestrator
            .ledger
            .associate_workspace(task_id, task_id, Some("test copy"));
        let copy_root = orchestrator.workspace.task_copy_root(task_id).unwrap();
        std::fs::write(copy_root.join("first.txt"), "first changed").unwrap();
        std::fs::write(copy_root.join("second.txt"), "second changed").unwrap();
        std::fs::write(copy_root.join("new.txt"), "new content").unwrap();

        // Model the durable prefix left by an earlier OS-level batch failure.
        std::fs::write(project.join("first.txt"), "first changed").unwrap();
        std::fs::write(project.join("new.txt"), "new content").unwrap();

        orchestrator
            .run_copy_disposition_requests(
                "test:commander",
                vec![CopyDisposition::Apply(task_id)],
                false,
            )
            .await;

        assert_eq!(
            std::fs::read_to_string(project.join("first.txt")).unwrap(),
            "first changed"
        );
        assert_eq!(
            std::fs::read_to_string(project.join("second.txt")).unwrap(),
            "second changed"
        );
        assert_eq!(
            std::fs::read_to_string(project.join("new.txt")).unwrap(),
            "new content"
        );
        assert!(!orchestrator.workspace.has_task_copy(task_id));
        assert!(!orchestrator.ledger.tasks()[0].workspace_live);
        let events: Vec<_> = std::iter::from_fn(|| event_rx.try_recv().ok()).collect();
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, Event::FileWritten { .. }))
                .count(),
            1
        );
        assert!(events.iter().any(|event| {
            matches!(
                event,
                Event::TaskCopyReleased {
                    task_id: 1,
                    applied: true
                }
            )
        }));
    }

    #[tokio::test]
    async fn preapproved_apply_batch_stops_after_the_first_write_failure() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(temp.path().join("data")).unwrap();
        let project = temp.path().join("project");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(project.join("blocked"), "not a directory").unwrap();
        let registry = registry_with(vec![("test", "commander", false)], "test:commander");
        let (event_tx, _event_rx) = mpsc::channel(32);
        let mut orchestrator = workflow_orchestrator(
            registry,
            &paths,
            project.clone(),
            false,
            event_tx,
            None,
            true,
        );

        let complete = orchestrator
            .write_preapproved_batch(
                "test:commander",
                vec![
                    crate::swarm::FileWrite {
                        path: "first.txt".into(),
                        content: "first".into(),
                    },
                    crate::swarm::FileWrite {
                        path: "blocked/nested.txt".into(),
                        content: "fails".into(),
                    },
                    crate::swarm::FileWrite {
                        path: "third.txt".into(),
                        content: "must not run".into(),
                    },
                ],
                &project,
            )
            .await;

        assert!(!complete);
        assert_eq!(
            std::fs::read_to_string(project.join("first.txt")).unwrap(),
            "first"
        );
        assert!(!project.join("third.txt").exists());
        assert!(orchestrator.ledger.written_files().iter().any(|record| {
            record.path == "third.txt"
                && record.outcome == "not attempted after an earlier apply failure"
        }));
    }

    #[tokio::test]
    async fn denied_apply_keeps_the_copy_and_leaves_main_unchanged() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(temp.path().join("data")).unwrap();
        let project = temp.path().join("project");
        std::fs::create_dir(&project).unwrap();
        let registry = registry_with(vec![("test", "commander", false)], "test:commander");
        let (event_tx, mut event_rx) = mpsc::channel(32);
        let (decision_tx, decision_rx) = mpsc::channel(2);
        decision_tx.send(WriteDecision::Approve).await.unwrap();
        decision_tx.send(WriteDecision::Deny).await.unwrap();
        let mut orchestrator = workflow_orchestrator(
            registry,
            &paths,
            project.clone(),
            false,
            event_tx,
            Some(decision_rx),
            false,
        );
        let task_id = orchestrator.ledger.add_task("changes");
        orchestrator.ledger.assign_task(task_id, "test:commander");
        orchestrator.workspace.create_task_copy(task_id).unwrap();
        orchestrator
            .ledger
            .associate_workspace(task_id, task_id, Some("test copy"));
        let copy_root = orchestrator.workspace.task_copy_root(task_id).unwrap();
        std::fs::write(copy_root.join("first.txt"), "first change").unwrap();
        std::fs::write(copy_root.join("second.txt"), "second change").unwrap();

        orchestrator
            .run_copy_disposition_requests(
                "test:commander",
                vec![CopyDisposition::Apply(task_id)],
                false,
            )
            .await;

        assert!(!project.join("first.txt").exists());
        assert!(!project.join("second.txt").exists());
        assert!(copy_root.join("first.txt").exists());
        assert!(copy_root.join("second.txt").exists());
        assert!(orchestrator.workspace.has_task_copy(task_id));
        assert!(orchestrator.ledger.tasks()[0].workspace_live);
        let events: Vec<_> = std::iter::from_fn(|| event_rx.try_recv().ok()).collect();
        assert!(
            events
                .iter()
                .any(|event| matches!(event, Event::WriteDenied { .. }))
        );
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, Event::TaskCopyReleased { .. }))
        );
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
    fn a_configured_cli_with_a_missing_executable_is_discovered_as_unavailable() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("missing-cli");
        let mut local_binaries = BTreeMap::new();
        local_binaries.insert(
            "broken".to_string(),
            crate::config::LocalBinarySpec {
                path: missing.to_string_lossy().into_owned(),
                args: Vec::new(),
                model_arg: None,
                system_arg: None,
                stream_format: None,
            },
        );
        let settings = Settings {
            local_binaries,
            ..Default::default()
        };

        let cli_tools = detect_cli_tools(&settings);
        let candidate = build_vendor_candidate("broken", &settings, false, &cli_tools).unwrap();
        assert_eq!(candidate.transports.len(), 1);
        let Availability::Unavailable(reason) = &candidate.transports[0].availability else {
            panic!("a missing configured executable must not be reported as ready");
        };
        assert!(reason.contains("missing or not executable"));
        assert!(reason.contains("missing-cli"));
    }

    #[test]
    fn a_stale_saved_cli_path_is_not_masked_by_a_working_configured_path() {
        let tmp = tempfile::tempdir().unwrap();
        let configured_path = std::env::current_exe().unwrap();
        let stale_path = tmp.path().join("removed-wrapper");
        let mut local_binaries = BTreeMap::new();
        local_binaries.insert(
            "tool".to_string(),
            crate::config::LocalBinarySpec {
                path: configured_path.to_string_lossy().into_owned(),
                args: Vec::new(),
                model_arg: None,
                system_arg: None,
                stream_format: None,
            },
        );
        let mut connections = BTreeMap::new();
        connections.insert(
            "tool".to_string(),
            ConnectionSpec {
                enabled: true,
                transport: Some(Transport::Cli),
                path: Some(stale_path.to_string_lossy().into_owned()),
                model: None,
            },
        );
        let settings = Settings {
            local_binaries,
            connections,
            ..Default::default()
        };

        let cli_tools = detect_cli_tools(&settings);
        let candidate = build_vendor_candidate("tool", &settings, false, &cli_tools).unwrap();
        let option = &candidate.transports[0];

        assert_eq!(option.detail, stale_path.to_string_lossy());
        assert_eq!(
            option.cli.as_ref().map(|cli| cli.path.as_str()),
            stale_path.to_str()
        );
        assert!(
            matches!(option.availability, Availability::Unavailable(_)),
            "status discovery must validate the same saved path provider construction will use"
        );
        let status = candidate_statuses(&[candidate], &settings).remove(0);
        assert_eq!(status.state, ConnectionState::ConnectedUnavailable);
    }

    #[test]
    fn a_saved_cli_removed_from_configuration_remains_visible_as_broken() {
        let mut connections = BTreeMap::new();
        connections.insert(
            "retired-tool".to_string(),
            ConnectionSpec {
                enabled: true,
                transport: Some(Transport::Cli),
                path: Some("/removed/retired-tool".to_string()),
                model: Some("old-model".to_string()),
            },
        );
        let settings = Settings {
            connections,
            ..Default::default()
        };

        let candidate = build_vendor_candidate("retired-tool", &settings, false, &[]).unwrap();
        let status = candidate_statuses(&[candidate], &settings).remove(0);

        assert_eq!(status.label, "retired-tool:old-model");
        assert_eq!(status.state, ConnectionState::ConnectedUnavailable);
        assert_eq!(
            status.reason.as_deref(),
            Some("CLI is no longer configured or detected")
        );
    }

    #[test]
    fn candidate_statuses_use_one_shared_three_state_classification() {
        let candidate = Candidate {
            id: "anthropic".to_string(),
            group: "ANTHROPIC".to_string(),
            model: "claude-opus-5".to_string(),
            transports: vec![
                TransportOption {
                    transport: Some(Transport::Api),
                    label: "via API".to_string(),
                    detail: "https://api.anthropic.com".to_string(),
                    availability: Availability::Unavailable("no key stored".to_string()),
                    cli: None,
                    needs_key: true,
                },
                TransportOption {
                    transport: Some(Transport::Cli),
                    label: "via CLI".to_string(),
                    detail: "/bin/claude".to_string(),
                    availability: Availability::Available,
                    cli: Some(CliSpec {
                        binary_name: "claude".to_string(),
                        path: "/bin/claude".to_string(),
                        args: Vec::new(),
                        model_arg: Some("--model".to_string()),
                        system_arg: None,
                        dialect: None,
                        workspace_arg: None,
                        models: Vec::new(),
                    }),
                    needs_key: false,
                },
            ],
        };
        let mut connections = BTreeMap::new();
        connections.insert(
            "anthropic".to_string(),
            ConnectionSpec {
                enabled: true,
                transport: Some(Transport::Api),
                path: None,
                model: None,
            },
        );
        let settings = Settings {
            connections,
            commander: Some("anthropic:claude-opus-5".to_string()),
            ..Default::default()
        };

        let statuses = candidate_statuses(&[candidate], &settings);
        let api = statuses
            .iter()
            .find(|status| status.transport == Some(Transport::Api))
            .unwrap();
        let cli = statuses
            .iter()
            .find(|status| status.transport == Some(Transport::Cli))
            .unwrap();

        assert_eq!(api.state, ConnectionState::ConnectedUnavailable);
        assert_eq!(api.reason.as_deref(), Some("no key stored"));
        assert_eq!(api.state.symbol(), "×");
        assert!(api.matches_commander(settings.commander.as_deref()));
        assert_eq!(cli.state, ConnectionState::NotConnected);
        assert_eq!(cli.state.symbol(), "○");
    }

    #[test]
    fn first_run_status_connects_only_the_first_available_transport_per_candidate() {
        let candidate = Candidate {
            id: "anthropic".to_string(),
            group: "ANTHROPIC".to_string(),
            model: "claude-opus-5".to_string(),
            transports: vec![
                TransportOption {
                    transport: Some(Transport::Cli),
                    label: "via CLI".to_string(),
                    detail: "/bin/claude".to_string(),
                    availability: Availability::Available,
                    cli: None,
                    needs_key: false,
                },
                TransportOption {
                    transport: Some(Transport::Api),
                    label: "via API".to_string(),
                    detail: "https://api.anthropic.com".to_string(),
                    availability: Availability::Available,
                    cli: None,
                    needs_key: false,
                },
            ],
        };

        let statuses = candidate_statuses(&[candidate], &Settings::default());
        assert_eq!(
            statuses
                .iter()
                .filter(|status| status.state == ConnectionState::Connected)
                .count(),
            1
        );
        assert_eq!(
            statuses
                .iter()
                .find(|status| status.transport == Some(Transport::Cli))
                .unwrap()
                .state,
            ConnectionState::Connected
        );
    }

    #[test]
    fn an_unreachable_ollama_daemon_keeps_saved_models_visible_as_broken() {
        let mut connections = BTreeMap::new();
        connections.insert(
            "ollama:llama3.2:3b".to_string(),
            ConnectionSpec {
                enabled: true,
                transport: None,
                path: None,
                model: None,
            },
        );
        let settings = Settings {
            connections,
            ..Default::default()
        };

        let candidates = unavailable_ollama_candidates(&settings, "daemon is down".to_string());
        let statuses = candidate_statuses(&candidates, &settings);

        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].label, "ollama:llama3.2:3b");
        assert_eq!(statuses[0].state, ConnectionState::ConnectedUnavailable);
        assert_eq!(statuses[0].reason.as_deref(), Some("daemon is down"));
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
        assert_eq!(defaults.model_arg, Some("--model".to_string()));
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
        assert_eq!(defaults.model_arg, Some("--model".to_string()));
    }

    #[test]
    fn copilot_is_auto_detected_in_restricted_project_json_mode() {
        let defaults = known_cli_default("copilot");
        assert_eq!(defaults.args.last().unwrap(), "--prompt");
        assert!(
            defaults
                .args
                .contains(&"--available-tools=view,grep,glob".to_string())
        );
        assert!(
            defaults
                .args
                .contains(&"--disable-builtin-mcps".to_string())
        );
        assert!(defaults.args.contains(&"json".to_string()));
        assert!(defaults.system_arg.is_none());
        assert_eq!(defaults.dialect, Some(StreamDialect::CopilotJson));
        assert_eq!(defaults.workspace_arg, Some("--add-dir".to_string()));
        assert_eq!(defaults.model_arg, Some("--model".to_string()));
    }

    #[test]
    fn an_unrecognised_binary_gets_no_streaming_dialect() {
        let defaults = known_cli_default("some-random-cli");
        assert!(defaults.args.is_empty());
        assert!(defaults.system_arg.is_none());
        assert!(defaults.dialect.is_none());
        // An unknown binary handed an unknown flag would just fail to start.
        assert!(defaults.workspace_arg.is_none());
        assert!(defaults.model_arg.is_none());
    }

    #[test]
    fn every_static_cli_catalog_is_non_empty() {
        // `llm` deliberately keeps `model_arg` (it does take `--model`) but has no
        // fixed catalog. `agy` is also excluded because its live `models` command is
        // authoritative and changes independently of simon releases.
        for binary in ["claude", "copilot", "codex"] {
            assert!(
                !known_cli_models(binary).is_empty(),
                "expected a non-empty known-model list for {binary}"
            );
        }
    }

    #[test]
    fn known_cli_models_is_empty_for_dynamic_plugin_and_unknown_binaries() {
        // `llm` is a plugin-based wrapper with no fixed model set — hardcoding a
        // list for it would just go stale — so it keeps the free-text fallback.
        assert!(known_cli_models("llm").is_empty());
        assert!(known_cli_models("agy").is_empty());
        assert!(known_cli_models("some-random-cli").is_empty());
    }

    #[test]
    fn agy_model_output_parses_ids_and_human_names() {
        let parsed = parse_agy_models(
            "Fetching available models...\n\
             gemini-3.7-flash-high\tGemini 3.7 Flash (High)\n\
             claude-sonnet-4-6\tClaude Sonnet 4.6 (Thinking)\n\
             \tMissing ID\n\
             missing-name\t \n\
             malformed row\n",
        );

        assert_eq!(
            parsed,
            vec![
                CliModelOption {
                    id: "gemini-3.7-flash-high".into(),
                    name: "Gemini 3.7 Flash (High)".into(),
                },
                CliModelOption {
                    id: "claude-sonnet-4-6".into(),
                    name: "Claude Sonnet 4.6 (Thinking)".into(),
                },
            ]
        );
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn agy_model_discovery_runs_the_installed_cli_and_ignores_banner_lines() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("agy");
        let padding = "x".repeat(2048);
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\n\
                 printf 'Fetching available models...\\n'\n\
                 printf '{padding}\\n'\n\
                 printf 'gemini-3.7-flash-high\\tGemini 3.7 Flash (High)\\n'\n"
            ),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&script, permissions).unwrap();

        let mut candidates = vec![Candidate {
            id: "agy".into(),
            group: "AGY".into(),
            model: "agy".into(),
            transports: vec![TransportOption {
                transport: Some(Transport::Cli),
                label: "via CLI".into(),
                detail: script.to_string_lossy().into_owned(),
                availability: Availability::Available,
                cli: Some(CliSpec {
                    binary_name: "agy".into(),
                    path: script.to_string_lossy().into_owned(),
                    args: Vec::new(),
                    model_arg: Some("--model".into()),
                    system_arg: None,
                    dialect: None,
                    workspace_arg: None,
                    models: Vec::new(),
                }),
                needs_key: false,
            }],
        }];

        enrich_cli_model_options(&mut candidates).await;

        assert_eq!(
            candidates[0].transports[0].cli.as_ref().unwrap().models,
            vec![CliModelOption {
                id: "gemini-3.7-flash-high".into(),
                name: "Gemini 3.7 Flash (High)".into(),
            }]
        );

        let existing = CliModelOption {
            id: "saved-id".into(),
            name: "Saved Name".into(),
        };
        candidates[0].transports[0].cli.as_mut().unwrap().models = vec![existing.clone()];
        candidates.push(Candidate {
            id: "custom".into(),
            group: "CUSTOM".into(),
            model: "custom".into(),
            transports: vec![TransportOption {
                transport: Some(Transport::Cli),
                label: "via CLI".into(),
                detail: script.to_string_lossy().into_owned(),
                availability: Availability::Available,
                cli: Some(CliSpec {
                    binary_name: "custom".into(),
                    path: script.to_string_lossy().into_owned(),
                    args: Vec::new(),
                    model_arg: Some("--model".into()),
                    system_arg: None,
                    dialect: None,
                    workspace_arg: None,
                    models: Vec::new(),
                }),
                needs_key: false,
            }],
        });
        candidates.push(Candidate {
            id: "blocked-agy".into(),
            group: "BLOCKED AGY".into(),
            model: "agy".into(),
            transports: vec![TransportOption {
                transport: Some(Transport::Cli),
                label: "via CLI".into(),
                detail: script.to_string_lossy().into_owned(),
                availability: Availability::Unavailable(
                    "CLI tools are refused under --classified".into(),
                ),
                cli: Some(CliSpec {
                    binary_name: "agy".into(),
                    path: script.to_string_lossy().into_owned(),
                    args: Vec::new(),
                    model_arg: Some("--model".into()),
                    system_arg: None,
                    dialect: None,
                    workspace_arg: None,
                    models: Vec::new(),
                }),
                needs_key: false,
            }],
        });

        enrich_cli_model_options(&mut candidates).await;

        assert_eq!(
            candidates[0].transports[0].cli.as_ref().unwrap().models,
            vec![existing],
            "an existing agy catalog must not be replaced"
        );
        assert!(
            candidates[1].transports[0]
                .cli
                .as_ref()
                .unwrap()
                .models
                .is_empty(),
            "other CLIs must not run agy's model-list command"
        );
        assert!(
            candidates[2].transports[0]
                .cli
                .as_ref()
                .unwrap()
                .models
                .is_empty(),
            "unavailable CLIs must not be executed for picker enrichment"
        );
    }

    #[test]
    fn cli_model_argument_precedes_prompt_taking_flags() {
        let defaults = known_cli_default("agy");
        let cli = CliSpec {
            binary_name: "agy".into(),
            path: "/bin/agy".into(),
            args: defaults.args,
            model_arg: defaults.model_arg,
            system_arg: defaults.system_arg,
            dialect: defaults.dialect,
            workspace_arg: defaults.workspace_arg,
            models: Vec::new(),
        };

        let args = cli_args_with_model(&cli, Some("gemini-3.1-pro"));

        assert_eq!(&args[..2], ["--model", "gemini-3.1-pro"]);
        assert_eq!(args.last().map(String::as_str), Some("-p"));
    }

    #[test]
    fn cli_model_argument_follows_a_required_subcommand() {
        let defaults = known_cli_default("codex");
        let cli = CliSpec {
            binary_name: "codex".into(),
            path: "/bin/codex".into(),
            args: defaults.args,
            model_arg: defaults.model_arg,
            system_arg: defaults.system_arg,
            dialect: defaults.dialect,
            workspace_arg: defaults.workspace_arg,
            models: Vec::new(),
        };

        assert_eq!(
            cli_args_with_model(&cli, Some("gpt-5.4")),
            ["exec", "--model", "gpt-5.4"]
        );
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
                model_arg: None,
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
                model_arg: None,
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

    #[test]
    fn a_saved_commander_falls_through_to_another_available_transport_of_the_same_candidate() {
        // Regression for Fix 4 (transport-fallback half): `/commander` persists only
        // `settings.commander`; nothing updates it when the RECORDED transport alone
        // goes stale later (here: an API key pulled from the keyring) while a
        // different transport for the very same vendor still works. Before the fix,
        // `resolve_commander` tried only the recorded transport, returned `None`,
        // and the caller fell back to `providers.keys().next()` — an unrelated
        // model, chosen alphabetically, with no warning. It must now find the
        // vendor's OTHER transport instead.
        let candidate = Candidate {
            id: "anthropic".to_string(),
            group: "ANTHROPIC".to_string(),
            model: "claude".to_string(),
            transports: vec![
                TransportOption {
                    transport: Some(Transport::Api),
                    label: "via API".to_string(),
                    detail: "no key stored".to_string(),
                    availability: Availability::Unavailable("no key stored".to_string()),
                    cli: None,
                    needs_key: true,
                },
                TransportOption {
                    transport: Some(Transport::Cli),
                    label: "via CLI".to_string(),
                    detail: "/bin/claude".to_string(),
                    availability: Availability::Available,
                    cli: Some(CliSpec {
                        binary_name: "claude".to_string(),
                        path: "/bin/claude".to_string(),
                        args: vec![],
                        model_arg: Some("--model".to_string()),
                        system_arg: None,
                        dialect: None,
                        workspace_arg: None,
                        models: Vec::new(),
                    }),
                    needs_key: false,
                },
            ],
        };

        let mut connections = BTreeMap::new();
        connections.insert(
            "anthropic".to_string(),
            ConnectionSpec {
                enabled: true,
                transport: Some(Transport::Api), // the now-stale saved choice
                path: None,
                model: None,
            },
        );
        let settings = Settings {
            connections,
            commander: Some("anthropic".to_string()),
            ..Default::default()
        };

        // Only the CLI transport actually got built — `candidate_label` collapses
        // `binary:model` to just `claude` when no model is configured, mirroring
        // `LocalBinaryProvider::label` (see that function's doc comment).
        let mut providers: BTreeMap<String, Arc<dyn Provider>> = BTreeMap::new();
        providers.insert(
            "claude".to_string(),
            Arc::new(StubProvider {
                provider: "claude".to_string(),
                model: "claude".to_string(),
                remote: false,
            }),
        );

        let resolved =
            Registry::resolve_commander(&settings, std::slice::from_ref(&candidate), &providers);
        assert_eq!(
            resolved,
            Some("claude".to_string()),
            "must fall through to the candidate's other transport, not give up"
        );
    }

    #[test]
    fn test_reproduction_saved_commander_with_full_provider_label() {
        let candidate = Candidate {
            id: "anthropic".to_string(),
            group: "ANTHROPIC".to_string(),
            model: "claude-opus-5".to_string(),
            transports: vec![TransportOption {
                transport: Some(Transport::Api),
                label: "via API".to_string(),
                detail: "https://api.anthropic.com".to_string(),
                availability: Availability::Available,
                cli: None,
                needs_key: false,
            }],
        };

        let mut connections = BTreeMap::new();
        connections.insert(
            "anthropic".to_string(),
            ConnectionSpec {
                enabled: true,
                transport: Some(Transport::Api),
                path: None,
                model: Some("claude-opus-5".to_string()),
            },
        );
        let settings = Settings {
            connections,
            commander: Some("anthropic:claude-opus-5".to_string()),
            ..Default::default()
        };

        let mut providers: BTreeMap<String, Arc<dyn Provider>> = BTreeMap::new();
        providers.insert(
            "anthropic:claude-opus-5".to_string(),
            Arc::new(StubProvider {
                provider: "anthropic".to_string(),
                model: "claude-opus-5".to_string(),
                remote: true,
            }),
        );

        let resolved =
            Registry::resolve_commander(&settings, std::slice::from_ref(&candidate), &providers);
        assert_eq!(
            resolved,
            Some("anthropic:claude-opus-5".to_string()),
            "must resolve saved commander configured as full provider label"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_saved_commander_that_resolves_nowhere_fails_loudly_instead_of_substituting() {
        // Regression for Fix 4 (fail-loudly half): when NO transport of the saved
        // candidate resolves (here: the candidate itself is no longer discoverable
        // at all — e.g. removed from config), `Registry::build` must not silently
        // hand the session to whatever provider sorts first. Another provider
        // (`agy`) is available here specifically to prove the failure is not just
        // the "no models reachable" case — resolution fails even though a perfectly
        // good model is sitting right there.
        let mut local_binaries = BTreeMap::new();
        local_binaries.insert(
            "agy".to_string(),
            crate::config::LocalBinarySpec {
                path: "/bin/echo".into(),
                args: vec![],
                model_arg: None,
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
                model: None,
            },
        );
        let settings = Settings {
            ollama_host: "http://127.0.0.1:1".into(),
            local_binaries,
            connections,
            // No candidate will ever discover under this id.
            commander: Some("ghost-vendor-that-does-not-exist".to_string()),
            ..Default::default()
        };

        let result = Registry::build(&settings, None, false, Path::new(".")).await;
        let Err(err) = result else {
            panic!("an unresolvable saved commander must fail loudly, not substitute agy");
        };
        assert!(
            err.to_string().contains("ghost-vendor-that-does-not-exist"),
            "the error should name the saved commander that could not be honoured: {err}"
        );
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
            data_dir: paths.data_dir.clone(),
        };
        orch.ledger.set_roster(orch.registry.labels());

        let handle = tokio::spawn(async move {
            orch.handle_prompt("hello there").await;
        });

        // `handle_prompt` now also emits `ActivityStarted` before the provider call;
        // skip past it to the reply, which is what this test is actually about.
        let mut saw_usage = false;
        let reply = loop {
            match event_rx.recv().await.expect("expected a reply event") {
                Event::UsageUpdated {
                    label,
                    usage,
                    rate_limit,
                    month_tokens,
                } => {
                    assert_eq!(label, "ollama:llama3");
                    assert!(usage.is_empty());
                    assert!(rate_limit.is_empty());
                    // A fresh temp data dir with no prior usage history and an empty
                    // `TokenUsage` (observed_total is `None`) adds zero tokens, so the
                    // persisted this-month total must still read zero.
                    assert_eq!(month_tokens, 0);
                    saw_usage = true;
                }
                Event::Reply { label, text } => break (label, text),
                _ => continue,
            }
        };
        assert!(saw_usage, "usage metadata must be emitted before the reply");
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
            data_dir: paths.data_dir.clone(),
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
    async fn one_turn_can_delegate_to_every_other_model_in_a_five_model_swarm() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        let reg = registry_with(
            vec![
                ("primary", "commander", false),
                ("worker", "one", false),
                ("worker", "two", false),
                ("worker", "three", false),
                ("worker", "four", false),
            ],
            "primary:commander",
        );
        let (event_tx, mut event_rx) = mpsc::channel(64);
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
            data_dir: paths.data_dir.clone(),
        };

        orch.run_delegations(
            "primary:commander",
            "ACTION: delegate_task(worker:one, reply one)\n\
             ACTION: delegate_task(worker:two, reply two)\n\
             ACTION: delegate_task(worker:three, reply three)\n\
             ACTION: delegate_task(worker:four, reply four)",
        )
        .await;

        let delegated = std::iter::from_fn(|| event_rx.try_recv().ok())
            .filter(|event| matches!(event, Event::Delegated { .. }))
            .count();
        assert_eq!(
            delegated, 4,
            "a request for all four non-commander models must not stop after three"
        );
    }

    #[tokio::test]
    async fn sequential_delegations_do_not_receive_the_shared_ledger_or_each_others_results() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let mut providers: BTreeMap<String, Arc<dyn Provider>> = BTreeMap::new();
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        for model in ["one", "two"] {
            let provider = ContextCapturingProvider {
                provider: "worker".into(),
                model: model.into(),
                calls: calls.clone(),
            };
            providers.insert(provider.label(), Arc::new(provider));
        }
        let registry = Registry {
            providers,
            primary: "primary:commander".into(),
            applied: BTreeMap::new(),
            connection_ids: BTreeMap::new(),
        };

        let (event_tx, mut event_rx) = mpsc::channel(32);
        let mut orch = Orchestrator {
            registry,
            ledger: SwarmLedger::new(),
            audit: AuditLogger::with_key(paths.audit_log.clone(), vec![4u8; 32]).unwrap(),
            skills: SkillsDir::new(paths.skills_dir.clone()).unwrap(),
            workspace: Workspace::new(project_dir.path().to_path_buf()).unwrap(),
            events: event_tx,
            classified: false,
            project_root: project_dir.path().to_path_buf(),
            decisions: None,
            approve_all: false,
            data_dir: paths.data_dir.clone(),
        };
        orch.ledger
            .record_commander_reply("COMMANDER-SECRET-MARKER and all delegation lines");

        orch.run_delegations(
            "primary:commander",
            "ACTION: delegate_task(worker:one, FIRST-TASK-MARKER)\n\
             ACTION: delegate_task(worker:two, SECOND-TASK-MARKER)",
        )
        .await;

        // Drain the channel so a sender failure cannot hide behind an unread event.
        while event_rx.try_recv().is_ok() {}

        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        for (index, (label, system, prompt)) in calls.iter().enumerate() {
            assert!(
                system.contains(&format!("connected as `{label}`")),
                "delegated model did not receive its own identity: {system}"
            );
            assert!(
                !system.contains("### File write protocol"),
                "text-only delegation received irrelevant write instructions: {system}"
            );
            assert!(
                !system.contains("## SWARM LEDGER")
                    && !system.contains("COMMANDER-SECRET-MARKER")
                    && !system.contains("FIRST-TASK-MARKER")
                    && !system.contains("SECOND-TASK-MARKER")
                    && !system.contains("### Delegation protocol")
                    && !system.contains("### Skills protocol")
                    && !system.contains("### File read protocol"),
                "delegated model received shared conversation/task context: {system}"
            );
            let own_marker = if index == 0 {
                "FIRST-TASK-MARKER"
            } else {
                "SECOND-TASK-MARKER"
            };
            let other_marker = if index == 0 {
                "SECOND-TASK-MARKER"
            } else {
                "FIRST-TASK-MARKER"
            };
            assert!(
                prompt.contains(own_marker)
                    && !prompt.contains(other_marker)
                    && !prompt.contains("COMMANDER-SECRET-MARKER"),
                "delegated model received another turn's user context: {prompt}"
            );
            assert!(
                prompt.contains("reply only with the requested prose")
                    && !prompt.contains("Do not run any shell"),
                "plain completion provider received agentic CLI guardrails: {prompt}"
            );
        }
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
            data_dir: paths.data_dir.clone(),
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
            data_dir: paths.data_dir.clone(),
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
            data_dir: paths.data_dir.clone(),
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
    async fn test_reproduction_unknown_delegation_target_records_failure_in_ledger() {
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
            data_dir: paths.data_dir.clone(),
        };

        orch.run_delegations(
            "ollama:llama3",
            "ACTION: delegate_task(ghost:model, summarize codebase)",
        )
        .await;

        let tasks = orch.ledger.tasks();
        assert_eq!(
            tasks.len(),
            1,
            "failed delegation to unknown model must be recorded in ledger"
        );
        assert_eq!(tasks[0].status, crate::swarm::TaskStatus::Failed);
        assert!(
            tasks[0]
                .result
                .as_ref()
                .unwrap()
                .contains("cannot delegate to unknown model"),
            "task result must explain that the target model was unknown"
        );
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
            data_dir: paths.data_dir.clone(),
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

    #[tokio::test(start_paused = true)]
    async fn an_empty_delegated_reply_is_retried_then_reported_as_a_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project_dir = tempfile::tempdir().unwrap();
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
            "ollama:empty".into(),
            Arc::new(ScriptedProvider {
                provider: "ollama".into(),
                model: "empty".into(),
                reply: " \n\t".into(),
            }),
        );
        let reg = Registry {
            providers,
            primary: "ollama:llama3".into(),
            applied: BTreeMap::new(),
            connection_ids: BTreeMap::new(),
        };
        let (event_tx, mut event_rx) = mpsc::channel(32);
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
            data_dir: paths.data_dir.clone(),
        };

        orch.run_delegations(
            "ollama:llama3",
            "ACTION: delegate_task(ollama:empty, answer)",
        )
        .await;

        let events: Vec<_> = std::iter::from_fn(|| event_rx.try_recv().ok()).collect();
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, Event::DelegationRetry { .. }))
                .count(),
            MAX_DELEGATION_ATTEMPTS - 1
        );
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, Event::Reply { .. }))
        );
        assert!(events.iter().any(|event| matches!(
            event,
            Event::Error(message) if message.contains("produced no output")
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            Event::DelegationFinished {
                ok: false,
                chars: 0,
                ..
            }
        )));
        assert_eq!(
            orch.ledger.tasks()[0].status,
            crate::swarm::TaskStatus::Failed
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_unterminated_write_only_reply_is_not_reported_as_a_blank_success() {
        // Captured from llama3.2:3b after prompt isolation: it returned an
        // `ACTION: write_file(/welcome_message)` opener followed by the greeting but
        // no `ACTION: end_file`. The safety parser correctly discarded that malformed
        // block, but the orchestrator had validated only the raw response and then
        // reported the stripped result as a successful zero-character answer.
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        let mut providers: BTreeMap<String, Arc<dyn Provider>> = BTreeMap::new();
        providers.insert(
            "ollama:llama3.2:3b".into(),
            Arc::new(ScriptedProvider {
                provider: "ollama".into(),
                model: "llama3.2:3b".into(),
                reply: "ACTION: write_file(/welcome_message)\n\
                        Hello! I am ollama:llama3.2:3b."
                    .into(),
            }),
        );
        let registry = Registry {
            providers,
            primary: "primary:commander".into(),
            applied: BTreeMap::new(),
            connection_ids: BTreeMap::new(),
        };
        let (event_tx, mut event_rx) = mpsc::channel(32);
        let mut orch = Orchestrator {
            registry,
            ledger: SwarmLedger::new(),
            audit: AuditLogger::with_key(paths.audit_log.clone(), vec![5u8; 32]).unwrap(),
            skills: SkillsDir::new(paths.skills_dir.clone()).unwrap(),
            workspace: Workspace::new(project_dir.path().to_path_buf()).unwrap(),
            events: event_tx,
            classified: false,
            project_root: project_dir.path().to_path_buf(),
            decisions: None,
            approve_all: false,
            data_dir: paths.data_dir.clone(),
        };

        orch.run_delegations(
            "primary:commander",
            "ACTION: delegate_task(ollama:llama3.2:3b, greet the user)",
        )
        .await;

        let events: Vec<_> = std::iter::from_fn(|| event_rx.try_recv().ok()).collect();
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, Event::DelegationRetry { .. }))
                .count(),
            MAX_DELEGATION_ATTEMPTS - 1
        );
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, Event::Reply { .. })),
            "a malformed reply must not become a blank successful answer"
        );
        assert!(events.iter().any(|event| matches!(
            event,
            Event::Error(message) if message.contains("produced no usable output")
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            Event::DelegationFinished {
                ok: false,
                chars: 0,
                ..
            }
        )));
        assert_eq!(
            orch.ledger.tasks()[0].status,
            crate::swarm::TaskStatus::Failed
        );
    }

    #[tokio::test]
    async fn a_valid_write_only_reply_gets_a_visible_summary() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        let mut providers: BTreeMap<String, Arc<dyn Provider>> = BTreeMap::new();
        providers.insert(
            "worker:builder".into(),
            Arc::new(ScriptedProvider {
                provider: "worker".into(),
                model: "builder".into(),
                reply: "ACTION: write_file(greeting.txt)\n\
                        hello\n\
                        ACTION: end_file"
                    .into(),
            }),
        );
        let registry = Registry {
            providers,
            primary: "primary:commander".into(),
            applied: BTreeMap::new(),
            connection_ids: BTreeMap::new(),
        };
        let (event_tx, mut event_rx) = mpsc::channel(32);
        let mut orch = Orchestrator {
            registry,
            ledger: SwarmLedger::new(),
            audit: AuditLogger::with_key(paths.audit_log.clone(), vec![6u8; 32]).unwrap(),
            skills: SkillsDir::new(paths.skills_dir.clone()).unwrap(),
            workspace: Workspace::new(project_dir.path().to_path_buf()).unwrap(),
            events: event_tx,
            classified: false,
            project_root: project_dir.path().to_path_buf(),
            decisions: None,
            approve_all: true,
            data_dir: paths.data_dir.clone(),
        };
        orch.workspace.enable_task_copies(&paths.data_dir).unwrap();
        orch.run_delegations(
            "primary:commander",
            "ACTION: delegate_file_task(worker:builder, create greeting.txt)",
        )
        .await;

        let workspace_id = orch.ledger.tasks()[0].workspace_id.unwrap();
        let copy_root = orch.workspace.task_copy_root(workspace_id).unwrap();
        assert_eq!(
            std::fs::read_to_string(copy_root.join("greeting.txt")).unwrap(),
            "hello"
        );
        assert!(!project_dir.path().join("greeting.txt").exists());
        let events: Vec<_> = std::iter::from_fn(|| event_rx.try_recv().ok()).collect();
        assert!(events.iter().any(|event| matches!(
            event,
            Event::Reply { text, .. } if text == "Submitted 1 file write request."
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            Event::DelegationFinished {
                ok: true,
                chars: 31,
                ..
            }
        )));
    }

    #[tokio::test]
    async fn a_text_only_delegation_cannot_execute_an_unrequested_write() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        let mut providers: BTreeMap<String, Arc<dyn Provider>> = BTreeMap::new();
        providers.insert(
            "worker:chat".into(),
            Arc::new(ScriptedProvider {
                provider: "worker".into(),
                model: "chat".into(),
                reply: "Hello from the worker.\n\
                        ACTION: write_file(unrequested.txt)\n\
                        should not land\n\
                        ACTION: end_file"
                    .into(),
            }),
        );
        let registry = Registry {
            providers,
            primary: "primary:commander".into(),
            applied: BTreeMap::new(),
            connection_ids: BTreeMap::new(),
        };
        let (event_tx, mut event_rx) = mpsc::channel(32);
        let mut orch = Orchestrator {
            registry,
            ledger: SwarmLedger::new(),
            audit: AuditLogger::with_key(paths.audit_log.clone(), vec![7u8; 32]).unwrap(),
            skills: SkillsDir::new(paths.skills_dir.clone()).unwrap(),
            workspace: Workspace::new(project_dir.path().to_path_buf()).unwrap(),
            events: event_tx,
            classified: false,
            project_root: project_dir.path().to_path_buf(),
            decisions: None,
            // Even global auto-approval must not grant write capability to a
            // text-only delegation.
            approve_all: true,
            data_dir: paths.data_dir.clone(),
        };

        orch.run_delegations(
            "primary:commander",
            "ACTION: delegate_task(worker:chat, greet the user)",
        )
        .await;

        assert!(!project_dir.path().join("unrequested.txt").exists());
        let events: Vec<_> = std::iter::from_fn(|| event_rx.try_recv().ok()).collect();
        assert!(events.iter().any(|event| matches!(
            event,
            Event::Reply { text, .. } if text == "Hello from the worker."
        )));
        assert!(
            !events
                .iter()
                .any(|event| matches!(event, Event::FileWritten { .. }))
        );
    }

    #[tokio::test]
    async fn a_long_delegated_task_is_kept_complete_for_the_scrollable_transcript() {
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
            data_dir: paths.data_dir.clone(),
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
        assert_eq!(task, long_task);
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
            data_dir: paths.data_dir.clone(),
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
            data_dir: paths.data_dir.clone(),
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
            data_dir: paths.data_dir.clone(),
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
        let skills = orch.ledger.loaded_skills();
        assert_eq!(
            skills.len(),
            1,
            "a failed skill read must record the failure in the ledger"
        );
        assert_eq!(skills[0].name, "../../../../etc/passwd");
        assert!(
            skills[0].content.starts_with("failed:"),
            "ledger entry must start with 'failed:', got: {}",
            skills[0].content
        );
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
            data_dir: paths.data_dir.clone(),
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
        let skills = orch.ledger.loaded_skills();
        assert_eq!(
            skills.len(),
            1,
            "a failed skill read must record the failure in the ledger"
        );
        assert_eq!(skills[0].name, "nope.md");
        assert!(
            skills[0].content.starts_with("failed:"),
            "ledger entry must start with 'failed:', got: {}",
            skills[0].content
        );
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
            data_dir: paths.data_dir.clone(),
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
            data_dir: paths.data_dir.clone(),
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
            data_dir: paths.data_dir.clone(),
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
            data_dir: paths.data_dir.clone(),
        };

        orch.set_commander("ghost").await;

        assert_eq!(orch.registry.primary(), "ollama:llama3");
        assert!(matches!(event_rx.try_recv(), Ok(Event::Error(_))));
    }

    #[tokio::test]
    async fn clear_ledger_drops_content_reports_sizes_and_audits() {
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
            data_dir: paths.data_dir.clone(),
        };

        // Load the ledger with content that `clear_content` is documented to drop.
        let task_id = orch.ledger.add_task("summarise the diff");
        orch.ledger
            .record_result(task_id, "the diff adds a timeout");
        orch.ledger.record_skill("notes.md", "be terse");
        orch.ledger.record_commander_reply("Plan: ship it.");

        orch.clear_ledger().await;

        match event_rx.try_recv() {
            Ok(Event::LedgerCleared {
                chars_before,
                chars_after,
            }) => {
                assert!(chars_before > chars_after);
            }
            other => panic!("expected LedgerCleared, got {other:?}"),
        }

        // The content is gone...
        assert!(orch.ledger.loaded_skills().is_empty());
        assert!(orch.ledger.last_commander_reply().is_none());
        assert!(orch.ledger.tasks()[0].result.is_none());
        // ...but the task itself, the escape hatch's whole point, survives.
        assert_eq!(orch.ledger.tasks().len(), 1);
        assert_eq!(orch.ledger.tasks()[0].description, "summarise the diff");

        let audit_text = std::fs::read_to_string(&paths.audit_log).unwrap();
        assert!(audit_text.contains("ledger.cleared"));
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
            data_dir: paths.data_dir.clone(),
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
            data_dir: paths.data_dir.clone(),
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
            data_dir: paths.data_dir.clone(),
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
            data_dir: paths.data_dir.clone(),
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
            data_dir: paths.data_dir.clone(),
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
        // Nothing is ever sent on this channel, so asking would block on `recv`.
        let (_dec_tx, dec_rx) = mpsc::channel(1);
        let mut orch = orch_with_write_gate(project.path(), &paths, event_tx, dec_rx);

        // The timeout is the assertion. Without it, a regression that made this code
        // ask the user did not fail the test — it hung the whole test binary, because
        // the harness cannot exit while a spawned test thread is parked on `recv`. The
        // rest of the suite reported its failures in under a second and the process
        // still sat there. `cargo mutants` found it: gutting either `Workspace::precheck`
        // or `Workspace::reject_git_writes` was reported as a TIMEOUT rather than a
        // caught mutant, which is the worse outcome — the next person to meet a hanging
        // suite raises the limit instead of asking why it hangs.
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            orch.run_file_writes(
                "ollama:llama3",
                vec![crate::swarm::FileWrite {
                    path: ".git/HEAD".into(),
                    content: "ref: refs/heads/pwned".into(),
                }],
            ),
        )
        .await
        .expect("a doomed write must be refused without asking, not block on the gate");

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

    #[test]
    fn a_write_preview_does_not_undercount_hidden_lines_when_both_limits_bind() {
        // 25 lines of 100 chars each: the line cap (20) says "up to 20 lines", but
        // the char cap (1200) hits first, inside line 12 — so the preview's own
        // content actually shows only 11 complete lines. The "N more line(s) not
        // shown" tail is computed from `total_lines - WRITE_PREVIEW_LINES`, which
        // silently assumes every one of the first `WRITE_PREVIEW_LINES` lines made it
        // into the char-truncated output. It did not: this is the user's ONLY signal
        // for how much of a pending write they have not reviewed before approving it.
        let content: String = (0..25).map(|_| format!("{}\n", "a".repeat(100))).collect();
        let preview = write_preview(&content);

        let shown_lines = preview
            .lines()
            .filter(|l| l.chars().all(|c| c == 'a'))
            .count();
        let claimed_hidden: usize = preview
            .lines()
            .find_map(|l| {
                l.strip_prefix("… ")?
                    .strip_suffix(" more line(s) not shown")
            })
            .and_then(|n| n.parse().ok())
            .expect("expected a '… N more line(s) not shown' line");

        // Only 11 full lines actually reached the preview (1200 / 101), so the other
        // 14 of the 25 total lines are hidden — not the 5 the current arithmetic
        // reports (25 - WRITE_PREVIEW_LINES).
        assert_eq!(
            shown_lines, 11,
            "sanity check on how much content actually shows"
        );
        assert_eq!(
            claimed_hidden,
            25 - shown_lines,
            "the preview claimed only {claimed_hidden} line(s) were hidden, but {} were \
             — a user approving from this preview is not seeing what they think they are",
            25 - shown_lines
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
            data_dir: paths.data_dir.clone(),
        };
        orch.workspace.enable_task_copies(&paths.data_dir).unwrap();

        orch.run_delegations(
            "ollama:llama3",
            "ACTION: delegate_file_task(ollama:builder, build it)",
        )
        .await;

        // The write landed only in the isolated copy, attributed to the sub-agent.
        let workspace_id = orch.ledger.tasks()[0].workspace_id.unwrap();
        let copy_root = orch.workspace.task_copy_root(workspace_id).unwrap();
        assert_eq!(
            std::fs::read_to_string(copy_root.join("made.txt")).unwrap(),
            "from the sub-agent"
        );
        assert!(!project.path().join("made.txt").exists());
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
    fn a_sub_agents_own_internal_timeout_is_retried() {
        // Captured verbatim from a failed delegation. It was abandoned without a
        // single retry because the classifier matched on bare "timed out", which is
        // simon's own timeout wording, not a sub-agent's tool reporting one.
        assert!(is_retryable_delegation_error(
            "agy failed: Grep command timed out due to the size of the codebase. \
             Use a more targeted grep search to avoid a timeout.: context deadline exceeded"
        ));
        assert!(is_retryable_delegation_error(
            "agy failed: declaring permissions: cortex tool view_file: ... \
             unsupported mime type application/octet-stream"
        ));
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
        assert!(!is_retryable_delegation_error(
            r#"agy failed: invalid model selection (--model "gemini-2.5-pro"): model is not recognized as a known model or custom model in settings"#
        ));
        assert!(!is_retryable_delegation_error(
            "claude failed: You've hit your weekly limit · resets Aug 31"
        ));
        assert!(!is_retryable_delegation_error(
            r#"openai returned 429: {"code":"insufficient_quota"}"#
        ));
        assert!(!is_retryable_delegation_error(
            "provider failed: quota exceeded for this billing period"
        ));
        assert!(!is_retryable_delegation_error(
            "You exceeded your current quota, please check your plan"
        ));
        assert!(
            is_retryable_delegation_error("provider failed: rate limit exceeded"),
            "short-lived rate limiting should still use the bounded retry path"
        );
    }

    #[test]
    fn an_authentication_failure_is_not_retried() {
        // Captured verbatim from a live run: a bad OpenRouter key was retried twice
        // (~11s wasted) before the delegation finally gave up, because nothing in
        // `PERMANENT` recognized it. A 401/403 answers every retry identically — only
        // fixing the credentials helps — so it belongs with the other
        // configuration failures, not the transient ones.
        assert!(!is_retryable_delegation_error(
            r#"openrouter returned 401 Unauthorized: {"error":{"message":"User not found.","code":401}}"#
        ));
        assert!(!is_retryable_delegation_error(
            "Ollama returned 403 Forbidden: access denied"
        ));
    }

    #[test]
    fn retry_explanations_keep_the_full_message_but_remove_terminal_controls() {
        let raw = format!("{}\nfinal detail\u{1b}[31m", "long reason ".repeat(20));
        let sanitized = sanitize_transcript_detail(&raw);

        assert!(sanitized.contains("final detail"));
        assert!(
            sanitized.chars().count() > MAX_PROGRESS_DETAIL_CHARS,
            "transcript text must not inherit the one-line status cap"
        );
        assert!(!sanitized.chars().any(char::is_control));
    }

    #[test]
    fn progress_details_are_sanitized_and_truncated() {
        let raw = format!("{}\nfinal\u{1b}[31m", "long detail ".repeat(20));
        let sanitized = sanitize_progress_detail(&raw);

        assert_eq!(sanitized.chars().count(), MAX_PROGRESS_DETAIL_CHARS + 1);
        assert!(sanitized.ends_with('…'));
        assert!(!sanitized.chars().any(char::is_control));
        assert!(sanitized.starts_with("long detail"));
    }

    #[test]
    fn an_unclassified_word_in_a_transient_error_is_still_retried() {
        // Regression for Fix 2: the PERMANENT list used to check bare "classified",
        // which also matches "unclassified"/"declassified"/"reclassified" showing
        // up in an unrelated transient error — abandoning it after one attempt
        // instead of retrying. None of these are a `--classified` policy refusal.
        assert!(is_retryable_delegation_error(
            "agy failed: field 'level' must be classified, unclassified, or secret"
        ));
        assert!(is_retryable_delegation_error(
            "agy failed: document was declassified before this request"
        ));
        assert!(is_retryable_delegation_error(
            "agy failed: request reclassified as low priority, retry shortly"
        ));
    }

    #[test]
    fn a_classified_refusal_is_not_retried() {
        // The actual policy refusal (`discover_ollama`, `build_vendor_candidate`)
        // is always worded with the flag, not the bare word — this is the case
        // narrowing to "--classified" must still catch.
        assert!(!is_retryable_delegation_error(
            "remote Ollama hosts are refused under --classified"
        ));
        assert!(!is_retryable_delegation_error(
            "cloud APIs are refused under --classified"
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
            data_dir: paths.data_dir.clone(),
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
            data_dir: paths.data_dir.clone(),
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
        assert!(preamble.contains("ACTION: delegate_file_task"));
    }

    #[test]
    fn the_commander_may_not_write_files_with_its_own_tools_either() {
        // Measured hole, not a hypothetical: a `claude` commander asked to build
        // something edited the project file directly with its own edit tool and then
        // narrated the result. The file changed correctly — and with no approval
        // prompt, no `file.written` audit entry, and no delegation. From the user's
        // side it changed by itself. `subagent_preamble` had forbidden exactly this
        // for sub-agents; the commander had no equivalent rule.
        let preamble = commander_preamble("claude", &["claude".into(), "agy".into()]).unwrap();
        assert!(preamble.contains("CREATING OR EDITING A FILE WITH YOUR OWN TOOLS IS NOT"));
        assert!(preamble.contains("never reaches the user for approval"));
        // Orienting must stay allowed, or the commander cannot do step 1 at all.
        assert!(preamble.contains("Reading and inspecting to orient yourself is fine"));
        // A `__pycache__` left behind by the commander running the project proved it
        // was executing code as well as writing it.
        assert!(preamble.contains("Do not run the project's code"));
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
    fn an_all_models_request_must_be_delegated_in_one_turn() {
        let preamble = commander_preamble(
            "commander",
            &[
                "commander".into(),
                "one".into(),
                "two".into(),
                "three".into(),
                "four".into(),
            ],
        )
        .unwrap();
        assert!(preamble.contains("every connected model"));
        assert!(preamble.contains("emit every required delegation in this reply"));
        assert!(preamble.contains("fed back to you automatically"));
        assert!(preamble.contains("do not ask the user to type `continue`"));
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
        let preamble = subagent_preamble(true, false);
        assert!(preamble.contains("Do not run any shell, terminal, or command-line tool"));
        assert!(preamble.contains("running or executing code to check that it works"));
        assert!(preamble.contains("git history or git log"));
    }

    #[test]
    fn subagent_preamble_forbids_its_own_file_writing_tools() {
        // agy's own writer already errors while declaring permissions non-interactively,
        // and separately was observed writing files simon never saw or approved. Both
        // are closed by refusing the tool outright rather than merely preferring simon's.
        let preamble = subagent_preamble(true, true);
        assert!(preamble.contains("Do not use your own file-writing or file-editing tools"));
        // A broad search timed out on an empty directory, failing the delegation.
        assert!(preamble.contains("Prefer listing a directory to searching across one"));
        assert!(preamble.contains("does not count as this task being done"));
    }

    #[test]
    fn subagent_preamble_still_tells_it_to_finish_in_turn_and_not_dispatch_a_subagent() {
        for preamble in [
            subagent_preamble(true, false),
            subagent_preamble(false, false),
        ] {
            assert!(preamble.contains("Complete this task fully in THIS reply"));
            assert!(
                preamble.contains("Do not dispatch, launch, or delegate to a subagent of your own")
            );
            assert!(preamble.contains("do not answer that you are waiting on"));
            assert!(preamble.contains("say what you found and what blocked you"));
        }
    }

    #[test]
    fn subagent_preamble_never_opens_a_write_block_at_line_start() {
        // Guards against reintroducing the bug `parse_file_writes` is sensitive to:
        // a line that STARTS with the write-block marker opens a real block, so this
        // instructional text must never contain that marker at the start of a line
        // (mid-sentence is fine — the parser only checks a line's start).
        for preamble in [
            subagent_preamble(true, true),
            subagent_preamble(true, false),
            subagent_preamble(false, true),
            subagent_preamble(false, false),
        ] {
            for line in preamble.lines() {
                assert!(
                    !line.trim().starts_with("ACTION: write_file("),
                    "preamble line would be parsed as a real write block: {line:?}"
                );
            }
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
            data_dir: paths.data_dir.clone(),
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
    async fn the_audit_log_chars_field_counts_characters_not_bytes() {
        // Regression for Fix 3: `project.read`'s `chars=` field used to be
        // `content.len()` — a byte count — so a nine-character Lithuanian fixture
        // (each letter two bytes in UTF-8) was logged as 18, not 9. Every other
        // `chars=` field in this file had the same bug; this exercises the read
        // path but the fix is identical everywhere `.chars().count()` now runs.
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        let fixture = "ąčęėįšųūž";
        assert_eq!(fixture.chars().count(), 9);
        assert_eq!(fixture.len(), 18, "fixture must actually be multi-byte");
        std::fs::write(project_dir.path().join("notes.txt"), fixture).unwrap();
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
            data_dir: paths.data_dir.clone(),
        };

        orch.run_file_reads("ollama:llama3", "ACTION: read_file(notes.txt)")
            .await;

        let log = std::fs::read_to_string(&paths.audit_log).unwrap();
        assert!(
            log.contains("chars=9"),
            "audit log should record the character count, not the byte count: {log}"
        );
        assert!(
            !log.contains("chars=18"),
            "audit log recorded bytes instead of characters: {log}"
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
            data_dir: paths.data_dir.clone(),
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
            data_dir: paths.data_dir.clone(),
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
        let reads = orch.ledger.loaded_reads();
        assert_eq!(
            reads.len(),
            1,
            "a failed read must record the failure in the ledger"
        );
        assert_eq!(reads[0].path, "../secret.txt");
        assert!(
            reads[0].content.starts_with("failed:"),
            "ledger entry must start with 'failed:', got: {}",
            reads[0].content
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
            data_dir: paths.data_dir.clone(),
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
            data_dir: paths.data_dir.clone(),
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

    // Regression tests: failed ACTION: read_skill / read_file / list_files must be
    // recorded in the SwarmLedger so the commander can see them on its next turn.
    // Previously the error was only shown in the TUI (Event::Error) but not written to
    // the ledger, so the commander's next-turn system prompt contained no trace of the
    // failure.

    #[tokio::test]
    async fn a_failed_skill_read_records_error_in_ledger() {
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
            data_dir: paths.data_dir.clone(),
        };

        orch.run_skill_reads("ollama:llama3", "ACTION: read_skill(missing.md)")
            .await;

        let skills = orch.ledger.loaded_skills();
        assert_eq!(
            skills.len(),
            1,
            "failed read_skill must write exactly one failure record to the ledger"
        );
        assert_eq!(skills[0].name, "missing.md");
        assert!(
            skills[0].content.starts_with("failed:"),
            "ledger record must use 'failed:' prefix so the commander can identify it; got: {}",
            skills[0].content
        );
        // The error must also be visible in the rendered system prompt.
        let prompt = orch.ledger.system_prompt();
        assert!(
            prompt.contains("missing.md"),
            "system prompt must name the failed skill"
        );
        assert!(
            prompt.contains("failed:"),
            "system prompt must contain the failure marker"
        );
    }

    #[tokio::test]
    async fn a_failed_file_read_records_error_in_ledger() {
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
            data_dir: paths.data_dir.clone(),
        };

        // Traversal attempt: the file exists outside the project root but must be
        // refused. The error goes to the ledger, not the file content.
        orch.run_file_reads("ollama:llama3", "ACTION: read_file(../outside.txt)")
            .await;

        let reads = orch.ledger.loaded_reads();
        assert_eq!(
            reads.len(),
            1,
            "failed read_file must write exactly one failure record to the ledger"
        );
        assert_eq!(reads[0].path, "../outside.txt");
        assert!(
            reads[0].content.starts_with("failed:"),
            "ledger record must use 'failed:' prefix so the commander can identify it; got: {}",
            reads[0].content
        );
        // The failure must surface in the system prompt the commander receives next turn.
        let prompt = orch.ledger.system_prompt();
        assert!(
            prompt.contains("../outside.txt"),
            "system prompt must name the failed path"
        );
        assert!(
            prompt.contains("failed:"),
            "system prompt must contain the failure marker"
        );
    }

    #[tokio::test]
    async fn a_failed_file_list_records_error_in_ledger() {
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
            data_dir: paths.data_dir.clone(),
        };

        // Request listing of a path that does not exist inside the project root.
        orch.run_file_lists("ollama:llama3", "ACTION: list_files(nonexistent-dir)")
            .await;

        let listings = orch.ledger.file_listings();
        assert_eq!(
            listings.len(),
            1,
            "failed list_files must write exactly one failure record to the ledger"
        );
        assert_eq!(listings[0].path, "nonexistent-dir");
        assert!(
            listings[0].outcome.starts_with("failed:"),
            "ledger record must use 'failed:' prefix so the commander can identify it; got: {}",
            listings[0].outcome
        );
        // The failure must surface in the system prompt the commander receives next turn.
        let prompt = orch.ledger.system_prompt();
        assert!(
            prompt.contains("nonexistent-dir"),
            "system prompt must name the failed path"
        );
        assert!(
            prompt.contains("failed:"),
            "system prompt must contain the failure marker"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn audit_log_never_leaks_raw_error_text_on_delegation_retry() {
        // Formerly `bug_audit_log_leaks_raw_error_text_on_delegation_retry`: an
        // external audit found `run_delegations`'s retry log built with
        // `error.to_string()` instead of `safe_error_detail(&error)`, so a raw
        // HTTP body or auth detail reached the audit file. Inverted here to assert
        // the fixed, correct behaviour instead of the bug — see this file's other
        // `.log(` call sites for the pattern this now matches.
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let secret = "SECRET_API_KEY_OR_PAYLOAD_12345";
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
                remaining_failures: std::sync::Mutex::new(1),
                error: format!("upstream refused: {secret}"),
            }),
        );
        let reg = Registry {
            providers,
            primary: "ollama:llama3".into(),
            applied: BTreeMap::new(),
            connection_ids: BTreeMap::new(),
        };

        let (event_tx, _event_rx) = mpsc::channel(64);
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
            data_dir: paths.data_dir.clone(),
        };

        orch.run_delegations(
            "ollama:llama3",
            "ACTION: delegate_task(ollama:flaky, do the thing)",
        )
        .await;

        let log_content = std::fs::read_to_string(&paths.audit_log).unwrap();
        // Look for the task.retrying line in the audit log
        let retry_line = log_content
            .lines()
            .find(|line| line.contains("task.retrying"))
            .expect("expected task.retrying entry in audit log");

        // The audit log's invariant is kinds, sizes and paths — never content. The
        // secret must never appear, and the line must carry `safe_error_detail`'s
        // fixed marker instead (proof this isn't just an accidental empty field).
        assert!(
            !retry_line.contains(secret),
            "audit log leaked secret error text: {retry_line}"
        );
        assert!(
            retry_line.contains("detail=withheld"),
            "expected the safe_error_detail marker in the retry line: {retry_line}"
        );
    }

    #[tokio::test]
    async fn file_read_event_reports_character_count_not_byte_count() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        let fixture = "ąčęėįšųūž"; // 9 chars, 18 bytes
        std::fs::write(project_dir.path().join("utf8.txt"), fixture).unwrap();
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
            data_dir: paths.data_dir.clone(),
        };

        orch.run_file_reads("ollama:llama3", "ACTION: read_file(utf8.txt)")
            .await;

        let mut read_chars = None;
        while let Ok(event) = event_rx.try_recv() {
            if let Event::FileRead { chars, .. } = event {
                read_chars = Some(chars);
            }
        }
        assert_eq!(
            read_chars,
            Some(9),
            "Event::FileRead chars should be character count (9), not byte count (18)"
        );
    }

    #[tokio::test]
    async fn skill_loaded_event_reports_character_count_not_byte_count() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project_dir = tempfile::tempdir().unwrap();
        let fixture = "ąčęėįšųūž"; // 9 chars, 18 bytes
        std::fs::write(paths.skills_dir.join("utf8.md"), fixture).unwrap();
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
            data_dir: paths.data_dir.clone(),
        };

        orch.run_skill_reads("ollama:llama3", "ACTION: read_skill(utf8.md)")
            .await;

        let mut loaded_chars = None;
        while let Ok(event) = event_rx.try_recv() {
            if let Event::SkillLoaded { chars, .. } = event {
                loaded_chars = Some(chars);
            }
        }
        assert_eq!(
            loaded_chars,
            Some(9),
            "Event::SkillLoaded chars should be character count (9), not byte count (18)"
        );
    }

    #[tokio::test]
    async fn delegation_finished_event_reports_character_count_not_byte_count() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let project_dir = tempfile::tempdir().unwrap();

        let fixture = "ąčęėįšųūž"; // 9 chars, 18 bytes
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
            "ollama:helper".into(),
            Arc::new(ScriptedProvider {
                provider: "ollama".into(),
                model: "helper".into(),
                reply: fixture.into(),
            }),
        );
        let reg = Registry {
            providers,
            primary: "ollama:llama3".into(),
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
            data_dir: paths.data_dir.clone(),
        };

        orch.run_delegations(
            "ollama:llama3",
            "ACTION: delegate_task(ollama:helper, do task)",
        )
        .await;

        let mut delegation_chars = None;
        while let Ok(event) = event_rx.try_recv() {
            if let Event::DelegationFinished { chars, .. } = event {
                delegation_chars = Some(chars);
            }
        }
        assert_eq!(
            delegation_chars,
            Some(9),
            "Event::DelegationFinished chars should be character count (9), not byte count (18)"
        );
    }

    #[test]
    fn reproduction_test_registry_match_label_case_insensitive() {
        let mut providers: BTreeMap<String, Arc<dyn Provider>> = BTreeMap::new();
        providers.insert(
            "ollama:llama3".to_string(),
            Arc::new(StubProvider {
                provider: "ollama".to_string(),
                model: "llama3".to_string(),
                remote: false,
            }),
        );

        assert_eq!(
            Registry::match_label(&providers, "OLLAMA"),
            Some("ollama:llama3".to_string())
        );
        assert_eq!(
            Registry::match_label(&providers, "Ollama"),
            Some("ollama:llama3".to_string())
        );
    }

    // The fallback search in `match_label` is three arms joined by `||`: bare model
    // name, provider name, and label prefix. A test that leaves two arms true at once
    // can't tell a real `||` from a mutant `&&`, because both read the same result off
    // an already-true expression. The three tests below each disagree on two of the
    // three arms, so exactly one arm can produce the match — that is what makes an
    // `&&` in either position (the model/provider join or the provider/label join)
    // fail to find a provider that the real `||` finds.

    #[test]
    fn match_label_resolves_by_bare_model_name_when_provider_name_and_label_prefix_disagree() {
        let mut providers: BTreeMap<String, Arc<dyn Provider>> = BTreeMap::new();
        providers.insert(
            "vendor-a:zeta".to_string(),
            Arc::new(StubProvider {
                provider: "vendor-a".to_string(),
                model: "gpteta".to_string(),
                remote: false,
            }),
        );

        assert_eq!(
            Registry::match_label(&providers, "gpteta"),
            Some("vendor-a:zeta".to_string()),
            "want matches only the model name, not the provider name or the label prefix"
        );
    }

    #[test]
    fn match_label_resolves_by_provider_name_when_model_name_and_label_prefix_disagree() {
        let mut providers: BTreeMap<String, Arc<dyn Provider>> = BTreeMap::new();
        providers.insert(
            "vendor-b:model-b".to_string(),
            Arc::new(StubProvider {
                provider: "orbit".to_string(),
                model: "model-b".to_string(),
                remote: false,
            }),
        );

        assert_eq!(
            Registry::match_label(&providers, "orbit"),
            Some("vendor-b:model-b".to_string()),
            "want matches only the provider name, not the model name or the label prefix"
        );
    }

    #[test]
    fn match_label_resolves_by_label_prefix_when_model_name_and_provider_name_disagree() {
        let mut providers: BTreeMap<String, Arc<dyn Provider>> = BTreeMap::new();
        providers.insert(
            "orbit:model-c".to_string(),
            Arc::new(StubProvider {
                provider: "vendor-c".to_string(),
                model: "model-c".to_string(),
                remote: false,
            }),
        );

        assert_eq!(
            Registry::match_label(&providers, "orbit"),
            Some("orbit:model-c".to_string()),
            "want matches only the `label:` prefix, not the model name or the provider name"
        );
    }

    #[test]
    fn reproduction_test_discover_vendors_deduplicates_case_insensitively() {
        use crate::config::{Api, CloudEndpoint, Settings};

        let mut settings = Settings::default();
        settings.custom_endpoints.insert(
            "Anthropic".to_string(),
            CloudEndpoint {
                api: Api::Anthropic,
                base_url: "https://custom.api".into(),
                default_model: "claude-3-7".into(),
            },
        );

        let candidates = discover_vendors(&settings, false);
        let anthropic_candidates: Vec<_> = candidates
            .iter()
            .filter(|c| c.group == "ANTHROPIC" || c.id.eq_ignore_ascii_case("anthropic"))
            .collect();

        assert_eq!(
            anthropic_candidates.len(),
            1,
            "expected only 1 Anthropic candidate, found: {:?}",
            anthropic_candidates
                .iter()
                .map(|c| (&c.id, &c.group))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn xai_appears_exactly_once_in_default_discovery_and_grok_alias_does_not_duplicate_it() {
        // Pins that the canonical id `xai` is included in builtin discovery and that
        // the user-facing alias `grok` — which resolves to `xai` via
        // `canonical_provider` — does not produce a second, duplicate candidate.
        let settings = Settings::default();
        let candidates = discover_vendors(&settings, false);

        let xai_candidates: Vec<_> = candidates
            .iter()
            .filter(|c| c.id.eq_ignore_ascii_case("xai"))
            .collect();
        assert_eq!(
            xai_candidates.len(),
            1,
            "expected exactly 1 xai candidate from default discovery, found: {:?}",
            xai_candidates
                .iter()
                .map(|c| (&c.id, &c.group))
                .collect::<Vec<_>>()
        );

        let grok_duplicates: Vec<_> = candidates
            .iter()
            .filter(|c| c.id.eq_ignore_ascii_case("grok"))
            .collect();
        assert!(
            grok_duplicates.is_empty(),
            "grok alias must not appear as a separate candidate alongside xai; found: {:?}",
            grok_duplicates
                .iter()
                .map(|c| (&c.id, &c.group))
                .collect::<Vec<_>>()
        );
    }

    // ---- cloud probe tests (deterministic: local TcpListener, no real network) ----

    /// Binds to an ephemeral loopback port and returns the listener plus the base URL.
    async fn bind_probe_listener() -> (tokio::net::TcpListener, String) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        (listener, format!("http://127.0.0.1:{port}"))
    }

    /// Accepts one connection, captures the HTTP request, and replies with the given
    /// status code.
    async fn serve_once_returning_request(
        listener: tokio::net::TcpListener,
        status: u16,
    ) -> String {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = tokio::io::AsyncReadExt::read(&mut stream, &mut buf)
            .await
            .unwrap_or(0);
        let request = String::from_utf8_lossy(&buf[..n]);
        let body = b"{}";
        let response = format!(
            "HTTP/1.1 {status} Status\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        use tokio::io::AsyncWriteExt;
        stream
            .write_all([response.as_bytes(), body].concat().as_slice())
            .await
            .ok();
        request.into_owned()
    }

    async fn serve_once_returning_path(listener: tokio::net::TcpListener, status: u16) -> String {
        let request = serve_once_returning_request(listener, status).await;
        request
            .lines()
            .next()
            .unwrap_or("")
            .split_whitespace()
            .nth(1)
            .unwrap_or("/")
            .to_string()
    }

    fn probe_test_client() -> reqwest::Client {
        reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(2))
            .timeout(std::time::Duration::from_secs(4))
            .build()
            .unwrap()
    }

    fn test_key() -> secrecy::SecretString {
        secrecy::SecretString::from("test-api-key".to_string())
    }

    fn openai_endpoint(base: &str) -> crate::config::CloudEndpoint {
        crate::config::CloudEndpoint {
            api: crate::config::Api::OpenAiCompatible,
            base_url: base.to_string(),
            default_model: "test".to_string(),
        }
    }

    fn anthropic_endpoint(base: &str) -> crate::config::CloudEndpoint {
        crate::config::CloudEndpoint {
            api: crate::config::Api::Anthropic,
            base_url: base.to_string(),
            default_model: "test".to_string(),
        }
    }

    #[tokio::test]
    async fn probe_2xx_returns_available() {
        let (listener, base) = bind_probe_listener().await;
        tokio::spawn(serve_once_returning_path(listener, 200));
        let result = probe_cloud_endpoint(
            "openai",
            &openai_endpoint(&base),
            true,
            &test_key(),
            &probe_test_client(),
        )
        .await;
        assert_eq!(result, Availability::Available);
    }

    #[tokio::test]
    async fn openai_probe_sends_the_key_as_a_bearer_token() {
        let (listener, base) = bind_probe_listener().await;
        let served = tokio::spawn(serve_once_returning_request(listener, 200));

        let result = probe_cloud_endpoint(
            "openai",
            &openai_endpoint(&base),
            true,
            &test_key(),
            &probe_test_client(),
        )
        .await;
        let request = served.await.unwrap().to_ascii_lowercase();

        assert_eq!(result, Availability::Available);
        assert!(request.contains("authorization: bearer test-api-key\r\n"));
    }

    #[tokio::test]
    async fn anthropic_probe_sends_the_key_and_protocol_version() {
        let (listener, base) = bind_probe_listener().await;
        let served = tokio::spawn(serve_once_returning_request(listener, 200));

        let result = probe_cloud_endpoint(
            "anthropic",
            &anthropic_endpoint(&base),
            true,
            &test_key(),
            &probe_test_client(),
        )
        .await;
        let request = served.await.unwrap().to_ascii_lowercase();

        assert_eq!(result, Availability::Available);
        assert!(request.contains("x-api-key: test-api-key\r\n"));
        assert!(request.contains(&format!(
            "anthropic-version: {}\r\n",
            crate::providers::cloud::ANTHROPIC_VERSION
        )));
    }

    #[tokio::test]
    async fn probe_401_returns_unavailable_rejected() {
        let (listener, base) = bind_probe_listener().await;
        tokio::spawn(serve_once_returning_path(listener, 401));
        let result = probe_cloud_endpoint(
            "openai",
            &openai_endpoint(&base),
            true,
            &test_key(),
            &probe_test_client(),
        )
        .await;
        assert_eq!(
            result,
            Availability::Unavailable("authentication rejected (401)".into())
        );
    }

    #[tokio::test]
    async fn probe_403_returns_unavailable_rejected() {
        let (listener, base) = bind_probe_listener().await;
        tokio::spawn(serve_once_returning_path(listener, 403));
        let result = probe_cloud_endpoint(
            "openai",
            &openai_endpoint(&base),
            true,
            &test_key(),
            &probe_test_client(),
        )
        .await;
        assert_eq!(
            result,
            Availability::Unavailable("authentication rejected (403)".into())
        );
    }

    #[tokio::test]
    async fn probe_network_failure_returns_unreachable() {
        let (listener, base) = bind_probe_listener().await;
        drop(listener);
        let endpoint = openai_endpoint(&base);
        let result =
            probe_cloud_endpoint("openai", &endpoint, true, &test_key(), &probe_test_client())
                .await;
        let Availability::Unavailable(reason) = result else {
            panic!("expected Unavailable, got {result:?}");
        };
        assert_eq!(reason, "endpoint unreachable");
        assert!(!reason.contains("test-api-key"));
    }

    #[tokio::test]
    async fn openrouter_builtin_probe_uses_the_chat_auth_path_without_generating() {
        for invalid_body_status in [400, 422] {
            let (listener, base) = bind_probe_listener().await;
            let served = tokio::spawn(serve_once_returning_request(listener, invalid_body_status));
            let endpoint = openai_endpoint(&base);
            let result = probe_cloud_endpoint(
                "openrouter",
                &endpoint,
                true,
                &test_key(),
                &probe_test_client(),
            )
            .await;
            let request = served.await.unwrap();

            assert_eq!(result, Availability::Available);
            assert!(
                request.starts_with("POST /chat/completions "),
                "OpenRouter must probe the same inference endpoint used for real turns: {request}"
            );
            assert!(
                request.ends_with("\r\n\r\n{}"),
                "the probe body must remain empty and non-generating: {request}"
            );
        }
    }

    #[tokio::test]
    async fn openrouter_chat_probe_rejects_credentials_that_inference_rejects() {
        let (listener, base) = bind_probe_listener().await;
        tokio::spawn(serve_once_returning_path(listener, 401));

        let result = probe_cloud_endpoint(
            "openrouter",
            &openai_endpoint(&base),
            true,
            &test_key(),
            &probe_test_client(),
        )
        .await;

        assert_eq!(
            result,
            Availability::Unavailable(
                "inference authentication rejected (401; check the key/account; management keys \
                 cannot generate)"
                    .into()
            )
        );
    }

    #[tokio::test]
    async fn openrouter_chat_probe_surfaces_generation_permission_failures() {
        let (listener, base) = bind_probe_listener().await;
        tokio::spawn(serve_once_returning_path(listener, 403));

        let result = probe_cloud_endpoint(
            "openrouter",
            &openai_endpoint(&base),
            true,
            &test_key(),
            &probe_test_client(),
        )
        .await;

        assert_eq!(
            result,
            Availability::Unavailable("generation access denied (403)".into())
        );
    }

    #[tokio::test]
    async fn openrouter_chat_probe_surfaces_insufficient_credits() {
        let (listener, base) = bind_probe_listener().await;
        tokio::spawn(serve_once_returning_path(listener, 402));

        let result = probe_cloud_endpoint(
            "openrouter",
            &openai_endpoint(&base),
            true,
            &test_key(),
            &probe_test_client(),
        )
        .await;

        assert_eq!(
            result,
            Availability::Unavailable("generation unavailable: insufficient credits (402)".into())
        );
    }

    #[tokio::test]
    async fn openrouter_custom_override_uses_the_generic_models_path() {
        let (listener, base) = bind_probe_listener().await;
        let served = tokio::spawn(serve_once_returning_path(listener, 200));
        let endpoint = openai_endpoint(&base);
        let _ = probe_cloud_endpoint(
            "openrouter",
            &endpoint,
            false,
            &test_key(),
            &probe_test_client(),
        )
        .await;
        let path = served.await.unwrap();
        assert_eq!(path, "/models");
    }

    #[tokio::test]
    async fn custom_endpoint_404_stays_available_unverified() {
        // A custom endpoint may not have a /models route at all; 404 must not
        // disable it — it should become AvailableUnverified with an inconclusive note.
        let (listener, base) = bind_probe_listener().await;
        tokio::spawn(serve_once_returning_path(listener, 404));
        let result = probe_cloud_endpoint(
            "my-gateway",
            &openai_endpoint(&base),
            false, // is_builtin = false → inconclusive non-auth failures
            &test_key(),
            &probe_test_client(),
        )
        .await;
        let Availability::AvailableUnverified(note) = result else {
            panic!("expected AvailableUnverified, got {result:?}");
        };
        assert!(
            note.contains("404"),
            "note should mention the HTTP status: {note}"
        );
    }

    #[tokio::test]
    async fn builtin_non_auth_http_errors_stay_available_unverified() {
        for (status, expected_note) in [
            (429, "authentication probe rate limited"),
            (503, "service error during authentication probe"),
        ] {
            let (listener, base) = bind_probe_listener().await;
            tokio::spawn(serve_once_returning_path(listener, status));
            let result = probe_cloud_endpoint(
                "anthropic",
                &anthropic_endpoint(&base),
                true,
                &test_key(),
                &probe_test_client(),
            )
            .await;
            let Availability::AvailableUnverified(note) = result else {
                panic!("expected AvailableUnverified for HTTP {status}, got {result:?}");
            };
            assert!(note.contains(expected_note), "unexpected note: {note}");
            assert!(note.contains(&status.to_string()));
        }
    }

    #[test]
    fn classified_mode_api_candidates_are_unavailable_not_unverified() {
        // Under --classified, discover_vendors sets API transports to
        // Unavailable("cloud APIs are refused under --classified"), never
        // AvailableUnverified — so run_cloud_probes would have no probe targets
        // even if called. This test verifies the classified path directly.
        let settings = Settings::default();
        let candidates = discover_vendors(&settings, /* classified = */ true);
        for candidate in &candidates {
            for transport in &candidate.transports {
                if transport.transport == Some(Transport::Api) {
                    assert!(
                        matches!(transport.availability, Availability::Unavailable(_)),
                        "classified API transport must be Unavailable, not {:?}",
                        transport.availability
                    );
                }
            }
        }
    }

    #[test]
    fn unverified_availability_is_available_and_exposes_note() {
        let av = Availability::AvailableUnverified("test note".into());
        assert!(av.is_available());
        assert_eq!(av.status_note(), Some("test note"));
        assert_eq!(av.reason(), None);
    }

    #[test]
    fn connected_unverified_state_has_correct_symbol_and_description() {
        let state = ConnectionState::ConnectedUnverified;
        assert_eq!(state.symbol(), "◐");
        assert!(state.is_connected());
        assert!(state.description().contains("unverified"));
    }

    #[test]
    fn from_availability_maps_unverified_to_connected_unverified_when_connected() {
        let av = Availability::AvailableUnverified("note".into());
        assert_eq!(
            ConnectionState::from_availability(true, &av),
            ConnectionState::ConnectedUnverified
        );
        // Not connected: stays NotConnected regardless of unverified
        assert_eq!(
            ConnectionState::from_availability(false, &av),
            ConnectionState::NotConnected
        );
    }

    #[test]
    fn candidate_statuses_expose_unverified_note_as_reason() {
        let candidate = Candidate {
            id: "anthropic".to_string(),
            group: "ANTHROPIC".to_string(),
            model: "claude-opus-5".to_string(),
            transports: vec![TransportOption {
                transport: Some(Transport::Api),
                label: "via API".to_string(),
                detail: "https://api.anthropic.com".to_string(),
                availability: Availability::AvailableUnverified(
                    "key stored; authentication not yet checked".to_string(),
                ),
                cli: None,
                needs_key: false,
            }],
        };
        let mut connections = BTreeMap::new();
        connections.insert(
            "anthropic".to_string(),
            ConnectionSpec {
                enabled: true,
                transport: Some(Transport::Api),
                path: None,
                model: None,
            },
        );
        let settings = Settings {
            connections,
            ..Default::default()
        };
        let statuses = candidate_statuses(&[candidate], &settings);
        assert_eq!(statuses[0].state, ConnectionState::ConnectedUnverified);
        assert_eq!(
            statuses[0].reason.as_deref(),
            Some("key stored; authentication not yet checked")
        );
    }
}

//! TUI state, kept free of I/O so it can be unit-tested.

use serde::{Deserialize, Serialize};
use std::time::Instant;

use crate::orchestrator::Event;

/// Who produced a line in the transcript.
///
/// `Serialize`/`Deserialize` exist so `Line` (below) can round-trip through the vault
/// as JSON — see `simon chat --vault` in `main.rs`. `Model` is the one tuple variant;
/// serde's default externally-tagged representation carries the inner label through
/// as `{"Model":"anthropic:claude-opus-5"}`, not just the discriminant, so it still
/// distinguishes which model said what after a reload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Speaker {
    You,
    Model(String),
    System,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Line {
    pub speaker: Speaker,
    pub text: String,
}

impl Line {
    pub fn render(&self) -> String {
        match &self.speaker {
            Speaker::You => format!("you › {}", self.text),
            Speaker::Model(label) => format!("{label} › {}", self.text),
            Speaker::System => format!("· {}", self.text),
            Speaker::Error => format!("! {}", self.text),
        }
    }
}

/// What a `/commander` line typed in the chat input means, resolved before it ever
/// reaches the orchestrator. Along with `/forget` (see `parse_forget_command`), this is
/// one of the two slash commands the TUI understands today — anything else starting
/// with `/` is ordinary prompt text, so these stay small dedicated recognizers rather
/// than a general command framework.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommanderCommand {
    /// Bare `/commander`: list the roster instead of sending anything to a model.
    List,
    /// `/commander <name>`: switch to it. `name` is passed through unresolved —
    /// matching it against a label, bare model name, or provider name happens on the
    /// orchestrator side, against the live registry (`Registry::set_primary`).
    SwitchTo(String),
}

/// Recognises `/commander` as exactly the first whitespace-separated token — never a
/// prefix — so `/commanders foo` or `/commander-old` are not the command and fall
/// through to the model unchanged, same as any other `/`-prefixed text a model might
/// reasonably expect verbatim (`/etc/passwd is a file`, `/help`).
pub fn parse_commander_command(text: &str) -> Option<CommanderCommand> {
    let trimmed = text.trim();
    let mut parts = trimmed.splitn(2, char::is_whitespace);
    if parts.next()? != "/commander" {
        return None;
    }
    let rest = parts.next().unwrap_or("").trim();
    Some(if rest.is_empty() {
        CommanderCommand::List
    } else {
        CommanderCommand::SwitchTo(rest.to_string())
    })
}

/// Recognises `/forget` — the escape hatch for `docs/AUDIT-2026-07-30.md` §3.2's other
/// half, clearing the ledger's accumulated content (see
/// `SwarmLedger::clear_content`). Unlike `/commander`, it takes no argument — there is
/// nothing to name, the ledger is a singleton for the session — so this is a plain
/// exact match rather than a two-variant enum like `CommanderCommand`. Same
/// never-a-prefix rule as `parse_commander_command`: `/forgetful` or `/forget now`
/// fall through to the model unchanged rather than partially matching.
pub fn parse_forget_command(text: &str) -> bool {
    text.trim() == "/forget"
}

/// What the session is currently waiting on — distinguishes *why* it's busy from the
/// existing `busy` flag, which only says *that* it is. Kept separate from `busy`
/// rather than replacing it: `busy` is set optimistically by `submit()` before the
/// orchestrator has said anything at all, and by locally-handled commands that never
/// produce an `Activity`, so it has to keep working exactly as it does today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivityKind {
    /// Waiting on the primary model's reply to the user's prompt.
    Primary,
    /// Waiting on a delegated sub-agent's reply.
    Delegating,
    /// Waiting on a skill file to be read off disk.
    ReadingSkill,
    /// Waiting on a project file to be read or listed off disk via `ACTION:
    /// read_file(...)` or `ACTION: list_files(...)`. Shared by both — from the
    /// user's point of view, either way `simon` is momentarily touching the
    /// filesystem on the model's behalf, not two meaningfully different waits.
    ReadingProject,
}

impl ActivityKind {
    fn description(self) -> &'static str {
        match self {
            ActivityKind::Primary => "awaiting reply",
            ActivityKind::Delegating => "running delegated task",
            ActivityKind::ReadingSkill => "reading skill",
            ActivityKind::ReadingProject => "reading project files",
        }
    }
}

/// One in-flight thing the status line can report on. `label` is the model actually
/// being called — during a delegation that is the sub-agent, not `App::primary` — so
/// the busy line never lies about who is doing the work.
#[derive(Debug, Clone)]
pub struct Activity {
    pub label: String,
    pub kind: ActivityKind,
    /// Not exposed outside this module: nothing outside `status_line_at` and the
    /// tests needs to read a raw `Instant`, and keeping it private is what stops a
    /// future caller from building a public API around wall-clock time this struct
    /// was never designed to expose.
    started: Instant,
    /// The most recent progress detail a streaming CLI reported (`"Bash: Read the
    /// readme"`, `"subagent: invoke_subagent"`), if any. `None` for a non-streaming
    /// provider, or before the first `Event::ActivityProgress` of this activity has
    /// arrived. Already sanitised (control characters and newlines stripped, char-
    /// boundary truncated) by the orchestrator before it ever reaches an `Event` —
    /// this is third-party CLI output and must be treated as untrusted.
    pub detail: Option<String>,
}

/// Animation frames for the busy status line: a single `●` orbiting a field of `·`,
/// the two glyphs already used elsewhere in the UI (the commander marker in the
/// picker, `Line::render`'s system-line prefix). Reusing them rather than adding a
/// braille/spinner glyph set keeps the busy line visually part of the same vocabulary
/// as everything else `simon` draws.
const SPINNER_FRAMES: [&str; 4] = ["●···", "·●··", "··●·", "···●"];

pub struct App {
    pub input: String,
    pub transcript: Vec<Line>,
    /// Lines scrolled off the top of the history pane.
    pub scroll: u16,
    /// True while the orchestrator is working on a turn.
    pub busy: bool,
    /// What the orchestrator is actually doing right now, if anything more specific
    /// than `busy` is known. `None` between `submit()` setting `busy` and the first
    /// `Event::ActivityStarted` arriving, and whenever a locally-handled command
    /// (e.g. bare `/commander`) never talks to the orchestrator at all.
    pub activity: Option<Activity>,
    /// Advanced once per UI tick; only visible content is which `SPINNER_FRAMES`
    /// entry `status_line_at` picks.
    spinner_frame: usize,
    pub primary: String,
    /// Every connected label, kept so `/commander`'s bare form can list them without
    /// a round trip to the orchestrator — this is already handed to `App::new` and
    /// refreshed on `Reconfigured`, so retaining it is the only plumbing needed.
    pub roster: Vec<String>,
    /// Set while a model is waiting for permission to write a file. While this is
    /// `Some` the input line becomes a y/n/a prompt rather than a text box — see
    /// `handle_key` in `ui/mod.rs` — because answering it is the only thing that lets
    /// the turn continue.
    pub pending_write: Option<PendingWrite>,
    pub should_quit: bool,
}

/// A write the user has been asked to allow.
#[derive(Debug, Clone)]
pub struct PendingWrite {
    pub author: String,
    pub path: String,
    pub bytes: usize,
    pub overwrites: Option<u64>,
}

impl PendingWrite {
    /// The one-line question, phrased so the destructive case is unmistakable.
    pub fn question(&self) -> String {
        match self.overwrites {
            Some(old) => format!(
                "{} wants to OVERWRITE {} ({old} bytes -> {} bytes)? [y]es  [n]o  [a]ll",
                self.author, self.path, self.bytes
            ),
            None => format!(
                "{} wants to CREATE {} ({} bytes)? [y]es  [n]o  [a]ll",
                self.author, self.path, self.bytes
            ),
        }
    }
}

impl App {
    /// `project_root` is shown once, at the top of the transcript: it is the only
    /// folder models can reach through simon's own read/list/write protocol, so the
    /// user must be able to see which folder that is without leaving the TUI.
    pub fn new(primary: impl Into<String>, roster: &[String], project_root: String) -> Self {
        let primary = primary.into();
        let mut transcript = vec![
            Line {
                speaker: Speaker::System,
                text: format!("project: {project_root}"),
            },
            Line {
                speaker: Speaker::System,
                text: format!("commander: {primary}"),
            },
        ];
        if !roster.is_empty() {
            transcript.push(Line {
                speaker: Speaker::System,
                text: format!("swarm: {}", roster.join(", ")),
            });
        }
        Self {
            input: String::new(),
            transcript,
            scroll: 0,
            busy: false,
            activity: None,
            spinner_frame: 0,
            primary,
            roster: roster.to_vec(),
            pending_write: None,
            should_quit: false,
        }
    }

    /// Advances the spinner by one frame. Called once per UI tick — see `run` in
    /// `ui/mod.rs`, which gates the call on `activity.is_some()` so an idle session
    /// doesn't churn a counter nothing is reading.
    pub fn advance_spinner(&mut self) {
        self.spinner_frame = self.spinner_frame.wrapping_add(1);
    }

    pub fn push_char(&mut self, c: char) {
        self.input.push(c);
    }

    pub fn backspace(&mut self) {
        self.input.pop();
    }

    /// Takes the pending input if there is any, recording it in the transcript.
    pub fn submit(&mut self) -> Option<String> {
        let text = self.input.trim().to_string();
        if text.is_empty() {
            return None;
        }
        self.input.clear();
        self.transcript.push(Line {
            speaker: Speaker::You,
            text: text.clone(),
        });
        self.busy = true;
        Some(text)
    }

    /// Folds an orchestrator event into the transcript.
    ///
    /// Every variant except `ActivityStarted` and `ActivityProgress` clears
    /// `self.activity` first — this is what guarantees the busy line always stops
    /// spinning: `TurnComplete`, `Reply`, `Error`, `DelegationFinished` and
    /// `SkillLoaded` all pass through here, and none of them has to remember to clear
    /// it individually. `ActivityStarted` then sets a fresh one in its own arm below;
    /// `ActivityProgress` updates the existing one in place (see its arm) rather than
    /// starting over, so a streaming CLI's progress line never resets the elapsed
    /// counter or drops the activity mid-call.
    pub fn apply(&mut self, event: Event) {
        if !matches!(
            event,
            Event::ActivityStarted { .. } | Event::ActivityProgress { .. }
        ) {
            self.activity = None;
        }
        match event {
            Event::ActivityStarted { label, kind } => {
                self.activity = Some(Activity {
                    label,
                    kind,
                    started: Instant::now(),
                    detail: None,
                });
            }
            // Updates the detail on the existing activity without touching `started`
            // — the elapsed-seconds counter in `status_line_at` must keep counting up
            // across progress updates, not restart on every line a streaming CLI
            // emits. If `label` doesn't match the current activity (a stale message
            // from a call that already finished, arriving after a new one started),
            // this is silently ignored rather than overwriting the wrong activity's
            // detail — same "don't let stray async messages corrupt current state"
            // reasoning as any other event ordering edge case here.
            Event::ActivityProgress { label, detail } => {
                if let Some(activity) = &mut self.activity
                    && activity.label == label
                {
                    activity.detail = Some(detail);
                }
            }
            Event::Reply { label, text } => self.transcript.push(Line {
                speaker: Speaker::Model(label),
                text,
            }),
            Event::Delegated { from, to, task } => self.transcript.push(Line {
                speaker: Speaker::System,
                text: format!("{from} → {to} · {task}"),
            }),
            Event::DelegationFinished {
                to,
                ok,
                chars,
                millis,
            } => {
                let duration = format_duration(millis);
                let text = if ok {
                    format!("{to} finished in {duration} · {chars} chars")
                } else {
                    format!("{to} failed after {duration}")
                };
                self.transcript.push(Line {
                    speaker: Speaker::System,
                    text,
                });
            }
            Event::DelegationRetry {
                to,
                attempt,
                max,
                reason,
            } => self.transcript.push(Line {
                speaker: Speaker::System,
                text: format!("{to} failed ({reason}) · retrying, attempt {attempt} of {max}"),
            }),
            Event::WriteRequested {
                author,
                path,
                bytes,
                overwrites,
                preview,
            } => {
                // The preview goes in the transcript, where it can scroll, rather than
                // in the one-line prompt — a 20-line file would otherwise have nowhere
                // to render.
                self.transcript.push(Line {
                    speaker: Speaker::System,
                    text: format!("--- {author} proposes writing {path} ---\n{preview}"),
                });
                self.pending_write = Some(PendingWrite {
                    author,
                    path,
                    bytes,
                    overwrites,
                });
            }
            Event::WriteDenied { author, path } => self.transcript.push(Line {
                speaker: Speaker::System,
                text: format!("refused {author}'s write: {path}"),
            }),
            Event::SkillLoaded { name, chars } => self.transcript.push(Line {
                speaker: Speaker::System,
                text: format!("loaded skill {name} · {chars} chars"),
            }),
            Event::FileWritten { author, path } => self.transcript.push(Line {
                speaker: Speaker::System,
                text: format!("{author} wrote project file: {path}"),
            }),
            Event::FileRead { path, chars } => self.transcript.push(Line {
                speaker: Speaker::System,
                text: format!("read project file: {path} · {chars} chars"),
            }),
            Event::FilesListed { path, entries } => {
                // An empty path means the project root — show it as `.` rather than
                // a blank label, same treatment as `SwarmLedger::system_prompt`'s
                // rendering of a root listing.
                let label = if path.is_empty() { "." } else { &path };
                self.transcript.push(Line {
                    speaker: Speaker::System,
                    text: format!("listed project directory: {label} · {entries} entries"),
                });
            }
            Event::Error(text) => self.transcript.push(Line {
                speaker: Speaker::Error,
                text,
            }),
            Event::TurnComplete => self.busy = false,
            Event::Reconfigured { primary, roster } => {
                self.primary = primary.clone();
                self.roster = roster.clone();
                self.transcript.push(Line {
                    speaker: Speaker::System,
                    text: format!("connections updated — commander: {primary}"),
                });
                if !roster.is_empty() {
                    self.transcript.push(Line {
                        speaker: Speaker::System,
                        text: format!("swarm: {}", roster.join(", ")),
                    });
                }
            }
            Event::CommanderChanged { label, .. } => {
                self.primary = label.clone();
                self.transcript.push(Line {
                    speaker: Speaker::System,
                    text: format!("commander: {label}"),
                });
            }
            Event::LedgerCleared {
                chars_before,
                chars_after,
            } => {
                // The concrete before/after sizes are the evidence: "cleared" alone
                // is a claim the user has no way to check.
                self.transcript.push(Line {
                    speaker: Speaker::System,
                    text: format!(
                        "ledger cleared: {chars_before} -> {chars_after} chars of system prompt \
                         (task results, loaded skills, loaded files, listings, and the previous \
                         turn dropped; the roster and task list remain)"
                    ),
                });
            }
        }
    }

    /// Renders `/commander`'s bare-form listing into the transcript: every connected
    /// label, with the current commander marked, in the same `swarm: a, b, c` shape
    /// `Event::Reconfigured`'s handler already uses so this reads as native system
    /// output rather than a bolted-on command reply. This never reaches the
    /// orchestrator, so it must clear `busy` itself — see `finish_local_command`.
    pub fn list_commander(&mut self) {
        let listing = self
            .roster
            .iter()
            .map(|label| {
                if *label == self.primary {
                    format!("{label} (commander)")
                } else {
                    label.clone()
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        self.transcript.push(Line {
            speaker: Speaker::System,
            text: format!("swarm: {listing}"),
        });
        self.finish_local_command();
    }

    /// Clears `busy` after a command handled entirely by the UI, with no round trip
    /// to the orchestrator. `submit()` optimistically sets `busy` assuming a model
    /// turn started; a locally-handled command produces no `TurnComplete` to clear
    /// it, so callers that short-circuit before sending a `Command` must call this
    /// instead.
    pub fn finish_local_command(&mut self) {
        self.busy = false;
    }

    pub fn scroll_up(&mut self) {
        self.scroll = self.scroll.saturating_sub(1);
    }

    pub fn scroll_down(&mut self) {
        self.scroll = self.scroll.saturating_add(1);
    }

    pub fn body(&self) -> String {
        self.transcript
            .iter()
            .map(Line::render)
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The chat input's title bar. It names the commander and, crucially, advertises
    /// `Ctrl+O`: without it there is nothing on the chat screen to suggest the
    /// connection set or the commander can be changed without restarting.
    ///
    /// Delegates to `status_line_at` with the real clock; see that method's doc
    /// comment for why the split exists.
    pub fn status_line(&self) -> String {
        self.status_line_at(Instant::now())
    }

    /// `status_line`'s logic, parameterised on `now` so it stays a pure function of
    /// `App` state — `App` is unit-tested with no clock control, and threading
    /// `Instant::now()` through call sites here (rather than baking it into every
    /// test's expectations) is what keeps those tests deterministic.
    pub fn status_line_at(&self, now: Instant) -> String {
        // Takes priority over every other state, including a running activity: the
        // turn is blocked on this answer, so the status line must ask for it rather
        // than keep spinning as though it were still waiting on a model.
        if let Some(pending) = &self.pending_write {
            return pending.question();
        }
        match &self.activity {
            Some(activity) => {
                let elapsed = now.saturating_duration_since(activity.started).as_secs();
                let spinner = SPINNER_FRAMES[self.spinner_frame % SPINNER_FRAMES.len()];
                // With no detail, this must stay byte-identical to the line rendered
                // before progress streaming existed — every existing caller and test
                // depends on that exact shape.
                match &activity.detail {
                    Some(detail) => format!(
                        "{} · {} · {detail} · {elapsed}s · {spinner} (Esc to quit)",
                        activity.label,
                        activity.kind.description()
                    ),
                    None => format!(
                        "{} · {} · {elapsed}s · {spinner} (Esc to quit)",
                        activity.label,
                        activity.kind.description()
                    ),
                }
            }
            // No orchestrator event has said what's happening yet (the brief window
            // right after `submit()`), or a locally-handled command set `busy` and
            // will clear it itself without ever producing an `Activity` — either way
            // this is the pre-existing busy line, unchanged.
            None if self.busy => format!("{} · working… (Esc to quit)", self.primary),
            None => format!(
                "{} · Enter send · /commander · /forget · Ctrl+O connections · Esc quit",
                self.primary
            ),
        }
    }
}

/// Formats a duration the way delegation-finished lines report it: sub-second as
/// whole milliseconds, everything else as seconds to one decimal place. Matches how
/// a human reads a stopwatch — "3.2s" is legible where "3200ms" is not, but "3.2s"
/// would be misleadingly coarse for a 400ms call.
fn format_duration(millis: u64) -> String {
    if millis < 1000 {
        format!("{millis}ms")
    } else {
        format!("{:.1}s", millis as f64 / 1000.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn app() -> App {
        App::new(
            "ollama:llama3",
            &["ollama:llama3".to_string()],
            "/tmp/project".to_string(),
        )
    }

    #[test]
    fn the_idle_status_line_is_unchanged() {
        // Pinned byte-for-byte: existing tests and muscle memory depend on this exact
        // string when nothing is in flight. `/forget` is listed here because a way to
        // clear the ledger that nobody can find only half-closes
        // `docs/AUDIT-2026-07-30.md` §3.2 — a practical run of the TUI showed the
        // command working while the hint bar still advertised only `/commander`.
        let app = app();
        assert_eq!(
            app.status_line(),
            "ollama:llama3 · Enter send · /commander · /forget · Ctrl+O connections · Esc quit"
        );
    }

    #[test]
    fn the_status_line_names_the_model_being_called_not_just_the_commander() {
        let mut app = app(); // primary is "ollama:llama3"
        app.apply(Event::ActivityStarted {
            label: "claude:claude".into(),
            kind: ActivityKind::Delegating,
        });
        let line = app.status_line();
        assert!(
            line.contains("claude:claude"),
            "must name the sub-agent actually being called: {line}"
        );
        assert!(
            !line.contains("ollama:llama3"),
            "must not fall back to the commander while a delegation is in flight: {line}"
        );
    }

    #[test]
    fn the_status_line_shows_elapsed_seconds_and_advances_the_spinner() {
        let mut app = app();
        app.apply(Event::ActivityStarted {
            label: "ollama:llama3".into(),
            kind: ActivityKind::Primary,
        });
        // Backdate the start so elapsed time is deterministic without sleeping.
        app.activity.as_mut().unwrap().started = Instant::now() - Duration::from_secs(4);

        let now = Instant::now();
        let before = app.status_line_at(now);
        assert!(
            before.contains("· 4s ·"),
            "expected elapsed seconds: {before}"
        );

        app.advance_spinner();
        let after = app.status_line_at(now);
        assert_ne!(
            before, after,
            "advancing the spinner must change the rendered frame"
        );
    }

    #[test]
    fn an_activity_always_clears_on_turn_complete() {
        let mut app = app();

        app.apply(Event::ActivityStarted {
            label: "ollama:llama3".into(),
            kind: ActivityKind::Primary,
        });
        assert!(app.activity.is_some());
        app.apply(Event::TurnComplete);
        assert!(app.activity.is_none());
        assert!(app.status_line().contains("Ctrl+O"));

        app.apply(Event::ActivityStarted {
            label: "ollama:mistral".into(),
            kind: ActivityKind::Delegating,
        });
        app.apply(Event::DelegationFinished {
            to: "ollama:mistral".into(),
            ok: true,
            chars: 10,
            millis: 5,
        });
        assert!(app.activity.is_none(), "must clear on a successful finish");

        app.apply(Event::ActivityStarted {
            label: "ollama:mistral".into(),
            kind: ActivityKind::Delegating,
        });
        app.apply(Event::DelegationFinished {
            to: "ollama:mistral".into(),
            ok: false,
            chars: 0,
            millis: 5,
        });
        assert!(app.activity.is_none(), "must clear on a failed finish too");

        app.apply(Event::ActivityStarted {
            label: "ollama:llama3".into(),
            kind: ActivityKind::ReadingSkill,
        });
        app.apply(Event::SkillLoaded {
            name: "notes.md".into(),
            chars: 20,
        });
        assert!(app.activity.is_none(), "must clear on a loaded skill");

        app.apply(Event::ActivityStarted {
            label: "ollama:llama3".into(),
            kind: ActivityKind::Primary,
        });
        app.apply(Event::Error("boom".into()));
        assert!(
            app.activity.is_none(),
            "a permanently spinning status line is the failure mode to avoid"
        );
    }

    #[test]
    fn status_line_renders_the_detail_when_present() {
        let mut app = app();
        app.apply(Event::ActivityStarted {
            label: "claude:claude".into(),
            kind: ActivityKind::Primary,
        });
        app.apply(Event::ActivityProgress {
            label: "claude:claude".into(),
            detail: "Bash: Read the readme".into(),
        });
        let line = app.status_line();
        assert!(
            line.contains("claude:claude · awaiting reply · Bash: Read the readme · "),
            "detail must appear between the description and the elapsed time: {line}"
        );
    }

    #[test]
    fn status_line_is_byte_identical_to_before_when_there_is_no_detail() {
        // Pinned regression guard: `Activity::detail` is a new field, and adding it
        // must not change a single byte of the status line for every activity that
        // never gets a progress update (every non-streaming provider, and a
        // streaming one before its first progress line arrives).
        let mut app = app();
        app.apply(Event::ActivityStarted {
            label: "ollama:llama3".into(),
            kind: ActivityKind::Primary,
        });
        app.activity.as_mut().unwrap().started = Instant::now() - Duration::from_secs(4);
        let now = Instant::now();
        assert_eq!(
            app.status_line_at(now),
            format!(
                "ollama:llama3 · awaiting reply · 4s · {} (Esc to quit)",
                SPINNER_FRAMES[0]
            )
        );
    }

    #[test]
    fn activity_progress_keeps_the_activity_and_the_original_started_instant_and_sets_the_detail() {
        let mut app = app();
        app.apply(Event::ActivityStarted {
            label: "claude:claude".into(),
            kind: ActivityKind::Delegating,
        });
        let original_started = app.activity.as_ref().unwrap().started;

        app.apply(Event::ActivityProgress {
            label: "claude:claude".into(),
            detail: "Bash: Read the readme".into(),
        });

        let activity = app
            .activity
            .as_ref()
            .expect("activity must survive a progress update");
        assert_eq!(activity.detail.as_deref(), Some("Bash: Read the readme"));
        assert_eq!(
            activity.started, original_started,
            "the elapsed-seconds counter must keep counting from the original start, \
             not reset on every progress line"
        );
    }

    #[test]
    fn activity_progress_for_a_different_label_than_the_current_activity_is_ignored() {
        // A stray forwarding message from a call that already finished (or a
        // delegation that was superseded) must never overwrite the activity that is
        // actually in flight now.
        let mut app = app();
        app.apply(Event::ActivityStarted {
            label: "ollama:llama3".into(),
            kind: ActivityKind::Primary,
        });
        app.apply(Event::ActivityProgress {
            label: "claude:claude".into(),
            detail: "stale detail".into(),
        });
        assert_eq!(app.activity.as_ref().unwrap().detail, None);
    }

    #[test]
    fn a_delegation_line_names_the_agent_and_its_task() {
        let mut app = app();
        app.apply(Event::Delegated {
            from: "agy".into(),
            to: "claude:claude".into(),
            task: "summarise the attached diff".into(),
        });
        assert!(
            app.body()
                .contains("agy → claude:claude · summarise the attached diff")
        );
    }

    #[test]
    fn a_finished_delegation_reports_outcome_and_duration() {
        let mut app = app();
        app.apply(Event::DelegationFinished {
            to: "claude:claude".into(),
            ok: true,
            chars: 412,
            millis: 3200,
        });
        assert!(
            app.body()
                .contains("claude:claude finished in 3.2s · 412 chars")
        );

        app.apply(Event::DelegationFinished {
            to: "claude:claude".into(),
            ok: false,
            chars: 0,
            millis: 1100,
        });
        assert!(app.body().contains("claude:claude failed after 1.1s"));
    }

    #[test]
    fn a_loaded_skill_is_visible_in_the_transcript() {
        let mut app = app();
        app.apply(Event::SkillLoaded {
            name: "notes.md".into(),
            chars: 1240,
        });
        assert!(app.body().contains("loaded skill notes.md · 1240 chars"));
    }

    #[test]
    fn typing_and_submitting_moves_text_into_the_transcript() {
        let mut app = app();
        for c in "hello".chars() {
            app.push_char(c);
        }
        assert_eq!(app.submit().as_deref(), Some("hello"));
        assert!(app.input.is_empty());
        assert!(app.busy);
        assert!(app.body().contains("you › hello"));
    }

    #[test]
    fn blank_input_is_not_submitted() {
        let mut app = app();
        assert!(app.submit().is_none());
        app.push_char(' ');
        assert!(
            app.submit().is_none(),
            "whitespace-only input must be ignored"
        );
        assert!(!app.busy);
    }

    #[test]
    fn backspace_removes_the_last_character() {
        let mut app = app();
        app.push_char('a');
        app.push_char('b');
        app.backspace();
        assert_eq!(app.input, "a");
        // Backspacing an empty buffer must not panic.
        app.backspace();
        app.backspace();
        assert!(app.input.is_empty());
    }

    #[test]
    fn replies_are_attributed_to_their_model() {
        let mut app = app();
        app.apply(Event::Reply {
            label: "anthropic:claude-opus-5".into(),
            text: "hi".into(),
        });
        assert!(app.body().contains("anthropic:claude-opus-5 › hi"));
    }

    #[test]
    fn turn_complete_clears_the_busy_flag() {
        let mut app = app();
        app.push_char('x');
        app.submit();
        assert!(app.busy);
        app.apply(Event::TurnComplete);
        assert!(!app.busy);
        assert!(app.status_line().contains("Ctrl+O"));
    }

    #[test]
    fn errors_are_shown_without_ending_the_session() {
        let mut app = app();
        app.apply(Event::Error("rate limited".into()));
        assert!(app.body().contains("! rate limited"));
        assert!(!app.should_quit);
    }

    #[test]
    fn reconfigured_updates_the_primary_and_status_line() {
        let mut app = app();
        app.apply(Event::Reconfigured {
            primary: "anthropic:claude-opus-5".into(),
            roster: vec!["anthropic:claude-opus-5".into(), "ollama:llama3".into()],
        });
        assert_eq!(app.primary, "anthropic:claude-opus-5");
        assert!(app.status_line().contains("anthropic:claude-opus-5"));
        assert!(app.body().contains("commander: anthropic:claude-opus-5"));
        assert!(
            app.body()
                .contains("swarm: anthropic:claude-opus-5, ollama:llama3")
        );
    }

    #[test]
    fn a_commander_change_updates_the_primary_and_status_line() {
        let mut app = app();
        app.apply(Event::CommanderChanged {
            label: "anthropic:claude-opus-5".into(),
            connection_id: Some("anthropic".into()),
        });
        assert_eq!(app.primary, "anthropic:claude-opus-5");
        assert!(app.status_line().contains("anthropic:claude-opus-5"));
        assert!(app.body().contains("commander: anthropic:claude-opus-5"));
    }

    #[test]
    fn handling_a_local_command_clears_busy() {
        // `/commander` (bare form) never reaches the orchestrator, so there is no
        // `TurnComplete` to clear the `busy` flag `submit()` set optimistically —
        // `finish_local_command` (and anything that calls it, like `list_commander`)
        // must clear it directly.
        let mut app = app();
        app.push_char('x');
        app.submit();
        assert!(app.busy);
        app.finish_local_command();
        assert!(!app.busy);
    }

    #[test]
    fn a_pending_write_takes_over_the_status_line_from_a_running_activity() {
        let mut app = app();
        app.apply(Event::ActivityStarted {
            label: "claude".into(),
            kind: ActivityKind::Primary,
        });
        app.apply(Event::WriteRequested {
            author: "agy".into(),
            path: "src/main.rs".into(),
            bytes: 120,
            overwrites: Some(80),
            preview: "fn main() {}\n".into(),
        });
        let line = app.status_line_at(Instant::now());
        // The turn is blocked on this answer, so the line must ask rather than spin.
        assert!(line.contains("agy wants to OVERWRITE src/main.rs"));
        assert!(line.contains("[y]es"));
        assert!(!line.contains("awaiting reply"));
        assert!(app.pending_write.is_some());
        // The content has to be visible somewhere, or the question is unanswerable.
        assert!(
            app.transcript
                .iter()
                .any(|l| l.text.contains("fn main() {}"))
        );
    }

    #[test]
    fn a_new_file_and_an_overwrite_ask_different_questions() {
        let create = PendingWrite {
            author: "agy".into(),
            path: "a.txt".into(),
            bytes: 10,
            overwrites: None,
        };
        assert!(create.question().starts_with("agy wants to CREATE a.txt"));

        let clobber = PendingWrite {
            author: "agy".into(),
            path: "a.txt".into(),
            bytes: 10,
            overwrites: Some(4096),
        };
        let q = clobber.question();
        assert!(q.starts_with("agy wants to OVERWRITE a.txt"));
        // The size being destroyed must appear; it is the whole basis for saying no.
        assert!(q.contains("4096 bytes"));
    }

    #[test]
    fn listing_the_commander_marks_the_current_one_and_clears_busy() {
        let mut app = App::new(
            "ollama:llama3",
            &[
                "ollama:llama3".to_string(),
                "anthropic:claude-opus-5".to_string(),
            ],
            "/tmp/project".to_string(),
        );
        app.push_char('x');
        app.submit();
        assert!(app.busy);

        app.list_commander();

        assert!(!app.busy);
        assert!(
            app.body()
                .contains("swarm: ollama:llama3 (commander), anthropic:claude-opus-5")
        );
    }

    #[test]
    fn a_bare_commander_command_is_recognised() {
        assert_eq!(
            parse_commander_command("/commander"),
            Some(CommanderCommand::List)
        );
        // Leading/trailing whitespace around the whole line must not matter.
        assert_eq!(
            parse_commander_command("  /commander  "),
            Some(CommanderCommand::List)
        );
    }

    #[test]
    fn a_commander_command_with_a_name_carries_the_name() {
        assert_eq!(
            parse_commander_command("/commander claude"),
            Some(CommanderCommand::SwitchTo("claude".to_string()))
        );
        assert_eq!(
            parse_commander_command("/commander  llama3.2:3b  "),
            Some(CommanderCommand::SwitchTo("llama3.2:3b".to_string())),
            "extra internal/trailing whitespace around the argument must be trimmed"
        );
    }

    #[test]
    fn an_ordinary_message_starting_with_a_slash_is_not_a_command() {
        assert_eq!(parse_commander_command("/etc/passwd is a file"), None);
        assert_eq!(parse_commander_command("/help"), None);
    }

    #[test]
    fn commander_command_matching_is_exact_not_a_prefix() {
        assert_eq!(parse_commander_command("/commanders foo"), None);
        assert_eq!(parse_commander_command("/commander-old"), None);
    }

    #[test]
    fn a_bare_forget_command_is_recognised() {
        assert!(parse_forget_command("/forget"));
        // Leading/trailing whitespace around the whole line must not matter, same as
        // `/commander`.
        assert!(parse_forget_command("  /forget  "));
    }

    #[test]
    fn forget_command_matching_is_exact_not_a_prefix_and_takes_no_argument() {
        assert!(!parse_forget_command("/forgetful"));
        assert!(!parse_forget_command("/forget now"));
        assert!(!parse_forget_command("just a message"));
    }

    #[test]
    fn scrolling_saturates_instead_of_wrapping() {
        let mut app = app();
        app.scroll_up();
        assert_eq!(app.scroll, 0);
        app.scroll_down();
        assert_eq!(app.scroll, 1);
    }

    #[test]
    fn speaker_round_trips_through_json_including_the_tuple_variant() {
        // The vault stores the transcript as JSON. `Speaker::Model(String)` is the
        // only variant carrying data, so it is the one most likely to lose the label
        // if the derive ever stopped matching the hand-rolled format some other
        // serializer might expect.
        for speaker in [
            Speaker::You,
            Speaker::Model("anthropic:claude-opus-5".to_string()),
            Speaker::System,
            Speaker::Error,
        ] {
            let json = serde_json::to_string(&speaker).unwrap();
            let back: Speaker = serde_json::from_str(&json).unwrap();
            assert_eq!(speaker, back, "round trip through {json}");
        }
    }

    #[test]
    fn a_transcript_restored_from_json_renders_like_a_live_one() {
        // This is exactly what the vault's load path does: deserialize a `Vec<Line>`
        // and assign it straight into `App::transcript`. If `Line`/`Speaker` ever
        // lost round-trip fidelity, this is the first thing that would catch it.
        let mut app = app();
        let saved = vec![
            Line {
                speaker: Speaker::You,
                text: "hi".into(),
            },
            Line {
                speaker: Speaker::Model("ollama:llama3".into()),
                text: "hello".into(),
            },
        ];
        let json = serde_json::to_vec(&saved).unwrap();
        let restored: Vec<Line> = serde_json::from_slice(&json).unwrap();

        app.transcript = restored;

        assert!(app.body().contains("you › hi"));
        assert!(app.body().contains("ollama:llama3 › hello"));
    }
}

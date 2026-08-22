//! The shared "blackboard" every model sees, and the ReAct delegation protocol.

use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskStatus {
    Todo,
    InProgress,
    Done,
    /// The sub-agent call errored out (transport failure, non-zero exit, timeout, …).
    /// Distinct from `InProgress` so a dead task doesn't sit on the blackboard looking
    /// like it is still being worked — other models read this ledger as fact and would
    /// otherwise wait forever on something that already failed.
    Failed,
}

impl TaskStatus {
    fn tag(self) -> &'static str {
        match self {
            TaskStatus::Todo => "[TODO]",
            TaskStatus::InProgress => "[IN_PROGRESS]",
            TaskStatus::Done => "[DONE]",
            TaskStatus::Failed => "[FAILED]",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Task {
    pub id: usize,
    pub description: String,
    pub assigned_to: Option<String>,
    pub status: TaskStatus,
    /// The sub-agent's reply on success, or the error text on failure. `None` until
    /// the delegation resolves. Rendered in the ledger so the delegating model can see
    /// what came back — or, for a failure, why it failed and whether to retry.
    pub result: Option<String>,
}

/// A delegation request parsed out of a model's plain-text reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation {
    pub target: String,
    pub prompt: String,
}

/// A file write request parsed out of a model's plain-text reply by
/// `parse_file_writes`. See that function's doc comment for the block syntax.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileWrite {
    pub path: String,
    pub content: String,
}

/// Ceiling on a stored task result, in characters. The ledger is re-injected into
/// *every* prompt for the rest of the session, so an unbounded sub-agent reply
/// (a full file dump, say) would make every subsequent turn's system prompt grow by
/// that much. 2000 chars is enough for a useful summary or error message without
/// letting one delegation dominate the token budget of every turn that follows.
const MAX_RESULT_CHARS: usize = 2000;

/// How many of the most recent tasks get rendered in the system prompt. The ledger
/// never forgets a task (older ones may still matter for the transcript), but
/// rendering all of them into every prompt would make the system prompt grow without
/// bound over a long session. Older tasks are elided rather than dropped — see
/// `system_prompt`.
const MAX_RENDERED_TASKS: usize = 20;

/// How many skills may be loaded into the ledger at once. Same reasoning as
/// `MAX_RESULT_CHARS`: the ledger is re-injected into every prompt for the rest of
/// the session, so an unbounded number of loaded skills would make every subsequent
/// turn's system prompt grow without bound. Loading a skill past this cap evicts the
/// oldest — see `record_skill`.
const MAX_LOADED_SKILLS: usize = 3;

/// Ceiling on a single loaded skill's content, in characters. Skill files may be up
/// to 256KB (`skills::MAX_SKILL_BYTES`); injecting one in full into every prompt for
/// the rest of the session would dominate the token budget of every turn that
/// follows. 4000 chars is enough for a skill's actual instructions without that.
const MAX_SKILL_CONTENT_CHARS: usize = 4000;

/// A skill a model has loaded into context via `ACTION: read_skill(...)`. Kept
/// separate from `Task` because loading a skill is not a delegation — there is no
/// sub-agent, no status, just content the model asked to see.
#[derive(Debug, Clone)]
pub struct LoadedSkill {
    pub name: String,
    pub content: String,
}

/// How many `ACTION: write_file(...)` outcomes stay in the ledger. Same
/// bound-the-ledger reasoning as `MAX_LOADED_SKILLS`: the ledger is re-injected into
/// every prompt, so an unbounded history of writes would make every subsequent turn's
/// system prompt grow without bound. Only name and status are ever stored here —
/// never file content — so this is far cheaper per entry than a loaded skill, and the
/// cap can afford to be generous.
const MAX_RECORDED_WRITES: usize = 20;

/// The recorded outcome of an `ACTION: write_file(...)` request: the path and either
/// `"ok (N bytes)"` or the error text. Deliberately holds no content — the audit
/// found the rendered system prompt already too large (see
/// `docs/AUDIT-2026-07-30.md` §3.2); echoing file content back into every future
/// prompt would make that worse for every write a model makes.
#[derive(Debug, Clone)]
pub struct WrittenFile {
    pub path: String,
    pub outcome: String,
}

#[derive(Debug, Default)]
pub struct SwarmLedger {
    tasks: Vec<Task>,
    next_id: usize,
    /// Model label -> human-readable budget line.
    budgets: BTreeMap<String, String>,
    /// Labels of every model currently reachable.
    roster: Vec<String>,
    /// Skills loaded via `ACTION: read_skill(...)`, oldest first. Capped at
    /// `MAX_LOADED_SKILLS`; see `record_skill`.
    loaded_skills: Vec<LoadedSkill>,
    /// Outcomes of `ACTION: write_file(...)` requests, oldest first. Capped at
    /// `MAX_RECORDED_WRITES`; see `record_file_write`.
    written_files: Vec<WrittenFile>,
}

impl SwarmLedger {
    pub fn new() -> Self {
        Self {
            next_id: 1,
            ..Default::default()
        }
    }

    pub fn tasks(&self) -> &[Task] {
        &self.tasks
    }

    pub fn set_roster(&mut self, roster: Vec<String>) {
        self.roster = roster;
    }

    pub fn roster(&self) -> &[String] {
        &self.roster
    }

    pub fn add_task(&mut self, description: &str) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        self.tasks.push(Task {
            id,
            description: description.to_string(),
            assigned_to: None,
            status: TaskStatus::Todo,
            result: None,
        });
        id
    }

    pub fn update_status(&mut self, id: usize, status: TaskStatus) {
        if let Some(task) = self.tasks.iter_mut().find(|t| t.id == id) {
            task.status = status;
        }
    }

    /// Records a delegation's outcome — the sub-agent's reply on success, or the
    /// error text on failure — so it becomes visible to the delegating model. The
    /// ledger is only re-rendered into the *next* prompt sent to any model, so the
    /// result does not reach the delegator within the same turn it was requested in;
    /// see `system_prompt`'s protocol text.
    pub fn record_result(&mut self, id: usize, result: &str) {
        if let Some(task) = self.tasks.iter_mut().find(|t| t.id == id) {
            // Truncate on a char boundary, not a byte index — `result` may contain
            // multi-byte UTF-8, and slicing mid-character panics. Mirrors
            // `local_binary::summarize_stderr`.
            let truncated = match result.char_indices().nth(MAX_RESULT_CHARS) {
                Some((cut, _)) => format!("{}…", &result[..cut]),
                None => result.to_string(),
            };
            task.result = Some(truncated);
        }
    }

    pub fn loaded_skills(&self) -> &[LoadedSkill] {
        &self.loaded_skills
    }

    /// Records a skill's content after a successful `ACTION: read_skill(...)`, so it
    /// becomes visible to the requesting model. Same next-turn timing as
    /// `record_result`: the ledger is only re-rendered into the *next* prompt.
    ///
    /// Re-requesting an already-loaded skill refreshes its content in place rather
    /// than adding a second entry — the name is the identity here, not the request.
    /// Otherwise, loading past `MAX_LOADED_SKILLS` evicts the oldest entry to make
    /// room, the same bound-the-ledger reasoning as `MAX_RENDERED_TASKS`.
    pub fn record_skill(&mut self, name: &str, content: &str) {
        // Truncate on a char boundary, not a byte index — mirrors `record_result`
        // and `local_binary::summarize_stderr`, for the same reason: `content` may
        // contain multi-byte UTF-8, and slicing mid-character panics.
        let truncated = match content.char_indices().nth(MAX_SKILL_CONTENT_CHARS) {
            Some((cut, _)) => format!("{}…", &content[..cut]),
            None => content.to_string(),
        };

        if let Some(existing) = self.loaded_skills.iter_mut().find(|s| s.name == name) {
            existing.content = truncated;
            return;
        }
        if self.loaded_skills.len() >= MAX_LOADED_SKILLS {
            self.loaded_skills.remove(0);
        }
        self.loaded_skills.push(LoadedSkill {
            name: name.to_string(),
            content: truncated,
        });
    }

    pub fn written_files(&self) -> &[WrittenFile] {
        &self.written_files
    }

    /// Records a file write's outcome after `ACTION: write_file(...)` runs, so it
    /// becomes visible to the requesting model. Same next-turn timing as
    /// `record_result` and `record_skill`: the ledger is only re-rendered into the
    /// *next* prompt.
    ///
    /// Re-recording the same path updates its outcome in place, mirroring
    /// `record_skill`'s in-place refresh — it does not move to the end of the list,
    /// since the path is the identity here, not the write attempt. Otherwise,
    /// recording past `MAX_RECORDED_WRITES` evicts the oldest entry to make room.
    pub fn record_file_write(&mut self, path: &str, outcome: &str) {
        if let Some(existing) = self.written_files.iter_mut().find(|w| w.path == path) {
            existing.outcome = outcome.to_string();
            return;
        }
        if self.written_files.len() >= MAX_RECORDED_WRITES {
            self.written_files.remove(0);
        }
        self.written_files.push(WrittenFile {
            path: path.to_string(),
            outcome: outcome.to_string(),
        });
    }

    pub fn assign_task(&mut self, id: usize, model_label: &str) {
        if let Some(task) = self.tasks.iter_mut().find(|t| t.id == id) {
            task.assigned_to = Some(model_label.to_string());
            task.status = TaskStatus::InProgress;
        }
    }

    pub fn update_budget(&mut self, model_label: &str, budget: &str) {
        self.budgets
            .insert(model_label.to_string(), budget.to_string());
    }

    /// Renders the ledger as the Markdown system-prompt block injected into every
    /// model's context.
    pub fn system_prompt(&self) -> String {
        let mut out = String::from("## SWARM LEDGER (shared blackboard)\n\n");

        out.push_str("### Available models\n");
        if self.roster.is_empty() {
            out.push_str("No other models are reachable.\n");
        } else {
            for label in &self.roster {
                out.push_str(&format!("- {label}\n"));
            }
        }

        out.push_str("\n### Resource budgets\n");
        if self.budgets.is_empty() {
            out.push_str("No budget information has been observed yet.\n");
        } else {
            for (model, budget) in &self.budgets {
                out.push_str(&format!("- {model}: {budget}\n"));
            }
        }

        out.push_str("\n### Tasks\n");
        if self.tasks.is_empty() {
            out.push_str("No active tasks.\n");
        } else {
            // The ledger keeps every task for the whole session and is re-injected into
            // every prompt, so rendering all of them would make each turn's system
            // prompt grow without bound. Show only the most recent `MAX_RENDERED_TASKS`
            // and say so, rather than silently dropping the older ones (they still
            // exist in `self.tasks` for anything that inspects the ledger directly).
            let total = self.tasks.len();
            let start = total.saturating_sub(MAX_RENDERED_TASKS);
            if start > 0 {
                out.push_str(&format!(
                    "(...{start} earlier task(s) elided; showing the {MAX_RENDERED_TASKS} most recent...)\n"
                ));
            }
            for task in &self.tasks[start..] {
                let assignee = task.assigned_to.as_deref().unwrap_or("unassigned");
                out.push_str(&format!(
                    "- {} Task #{}: {} (assigned: {})\n",
                    task.status.tag(),
                    task.id,
                    task.description,
                    assignee
                ));
                if let Some(result) = &task.result {
                    // Indent continuation lines so a multi-line result nests under its
                    // task instead of producing bare lines that read as separate ledger
                    // entries.
                    let indented = result.replace('\n', "\n    ");
                    out.push_str(&format!("    result: {indented}\n"));
                }
            }
        }

        out.push_str("\n### Loaded skills\n");
        if self.loaded_skills.is_empty() {
            out.push_str("No skills have been loaded into context yet.\n");
        } else {
            for skill in &self.loaded_skills {
                out.push_str(&format!("#### {}\n{}\n", skill.name, skill.content));
            }
        }

        if !self.written_files.is_empty() {
            out.push_str("\n### Workspace files\n");
            for written in &self.written_files {
                out.push_str(&format!("- {}: {}\n", written.path, written.outcome));
            }
        }

        out.push_str(
            "\n### Delegation protocol\n\
             You are one model in a multi-model swarm. To hand work to another model, \
             emit a line of exactly this form:\n\
             `ACTION: delegate_task(<model label>, <prompt>)`\n\
             Use a label from the list above. Check the budgets first and prefer a model \
             with capacity; local models have no quota. Emit nothing after the line. The \
             result (or, on failure, the error) is recorded in this ledger under the task \
             and becomes visible to you on your NEXT turn — not this one, since this reply \
             is already on its way out when the sub-agent runs.\n",
        );

        out.push_str(
            "\n### Skills protocol\n\
             If this prompt has an \"Available skills\" section, it names every skill file \
             on disk with a one-line description, if it has one. To load a skill's full \
             contents into context, emit a line of exactly this form:\n\
             `ACTION: read_skill(<name>)`\n\
             Use a name exactly as it appears in that Available skills section. Emit \
             nothing after the line. Like a delegation result, the content (or, on \
             failure, the error) becomes visible to you on your NEXT turn, not this one. \
             At most 3 skills are kept loaded at once and each is size-capped; loading \
             another past the cap evicts the oldest loaded skill.\n",
        );

        out.push_str(
            "\n### File write protocol\n\
             To create or overwrite a file in your private workspace directory, emit \
             exactly this form:\n\
             `ACTION: write_file(<relative path>)`\n\
             followed by the file's content, one line at a time, followed by a line of \
             exactly `ACTION: end_file`. Paths are relative to the workspace; \
             subdirectories are created automatically. Files are capped at 256KB. A \
             line exactly `ACTION: end_file` cannot appear inside the content — it \
             always closes the block there instead. `ACTION: delegate_task(...)` and \
             `ACTION: read_skill(...)` lines inside the content are treated as \
             content, not executed. Like a delegation result, the outcome is recorded \
             in this ledger and becomes visible to you on your NEXT turn, not this \
             one.\n",
        );

        out
    }

    /// Extracts every `ACTION: delegate_task(target, prompt)` line from a reply.
    ///
    /// Splits on the *first* comma (so the target cannot contain one) and matches to the
    /// *last* closing parenthesis on the line, so prompts may contain commas and nested
    /// parentheses.
    pub fn parse_delegations(reply: &str) -> Vec<Delegation> {
        const MARKER: &str = "ACTION: delegate_task(";
        let mut found = Vec::new();

        for line in reply.lines() {
            let line = line.trim().trim_start_matches('`').trim_end_matches('`');
            let Some(start) = line.find(MARKER) else {
                continue;
            };
            let rest = &line[start + MARKER.len()..];
            let Some(close) = rest.rfind(')') else {
                continue;
            };
            let inner = &rest[..close];
            let Some((target, prompt)) = inner.split_once(',') else {
                continue;
            };

            let target = target.trim().trim_matches(['"', '\'']).to_string();
            let prompt = prompt.trim().trim_matches(['"', '\'']).to_string();
            if target.is_empty() || prompt.is_empty() {
                continue;
            }
            found.push(Delegation { target, prompt });
        }

        found
    }

    /// Extracts every `ACTION: read_skill(name)` line from a reply. Sibling of
    /// `parse_delegations`, following the same conventions: strip a wrapping
    /// backtick, tolerate a quoted argument, and silently ignore a line that does
    /// not parse rather than erroring the whole reply out — this runs on arbitrary
    /// model output, so malformed input is an expected case, not exceptional.
    pub fn parse_read_skill(reply: &str) -> Vec<String> {
        const MARKER: &str = "ACTION: read_skill(";
        let mut found = Vec::new();

        for line in reply.lines() {
            let line = line.trim().trim_start_matches('`').trim_end_matches('`');
            let Some(start) = line.find(MARKER) else {
                continue;
            };
            let rest = &line[start + MARKER.len()..];
            let Some(close) = rest.find(')') else {
                continue;
            };
            let name = rest[..close].trim().trim_matches(['"', '\'']).to_string();
            if name.is_empty() {
                continue;
            }
            found.push(name);
        }

        found
    }

    /// Extracts every `ACTION: write_file(path)` ... `ACTION: end_file` block from a
    /// reply, returning the extracted writes AND the reply text with those blocks
    /// removed (everything else passes through unchanged).
    ///
    /// This differs from `parse_delegations`/`parse_read_skill` in shape, not just in
    /// what it looks for: those are per-line, forgiving parsers where each line
    /// stands alone. A write block spans multiple lines, and its *content* is
    /// arbitrary model-authored text — which means it can itself contain a line that
    /// looks exactly like `ACTION: delegate_task(...)` or `ACTION: read_skill(...)`
    /// (a model writing documentation about this very protocol will do exactly that).
    /// If the raw reply were handed back to `parse_delegations`/`parse_read_skill`
    /// unchanged, those lines would execute even though they were never meant as
    /// instructions — they are file content, not a request. So this is a single
    /// sequential, stateful pass: it tracks whether it is inside an open block and
    /// only ever treats a line as a delegation/skill trigger by leaving it in the
    /// stripped text for those parsers to see later. The orchestrator feeds the
    /// *stripped* text, not the raw reply, to `parse_delegations`/`parse_read_skill`.
    ///
    /// Rules:
    /// - A line matching `ACTION: write_file(<path>)` (same trimming conventions as
    ///   the siblings) opens a block; that line is consumed, not passed through.
    /// - Every following line is content until a line that, after the same trimming,
    ///   is exactly `ACTION: end_file` or `ACTION: end_file()`; that line closes the
    ///   block and is also consumed, not passed through and not part of the content.
    /// - A `write_file` line encountered while already inside an open block is
    ///   ordinary content, not a new block — blocks do not nest.
    /// - An empty (or all-whitespace) path closes as a no-op: the block is still
    ///   consumed (its lines do not leak into the stripped text), but nothing is
    ///   added to the returned writes.
    /// - An unterminated block — no `end_file` before the reply ends — is dropped
    ///   from BOTH the writes and the stripped text. This is a deliberate asymmetry
    ///   with the empty-path case: by the time an unterminated block is discovered,
    ///   whatever content lines it swallowed may already contain an unexecuted
    ///   `ACTION: delegate_task(...)`-shaped line, so there is no safe way to un-swallow
    ///   them back into the stripped text without also potentially resurrecting a
    ///   partial, truncated block marker. Silently dropping the whole thing is
    ///   consistent with this project's treatment of malformed model output as an
    ///   expected case, not an exceptional one.
    pub fn parse_file_writes(reply: &str) -> (Vec<FileWrite>, String) {
        const OPEN_MARKER: &str = "ACTION: write_file(";

        let mut writes = Vec::new();
        let mut stripped_lines: Vec<&str> = Vec::new();

        // `None` when not inside a block; `Some((path, content_lines))` while one is
        // open.
        let mut open: Option<(String, Vec<&str>)> = None;

        for line in reply.lines() {
            let trimmed = line.trim().trim_start_matches('`').trim_end_matches('`');

            if let Some((_, content_lines)) = open.as_mut() {
                if trimmed == "ACTION: end_file" || trimmed == "ACTION: end_file()" {
                    let (path, content_lines) = open.take().unwrap();
                    if !path.trim().is_empty() {
                        writes.push(FileWrite {
                            path,
                            content: content_lines.join("\n"),
                        });
                    }
                } else {
                    content_lines.push(line);
                }
                continue;
            }

            let Some(start) = trimmed.find(OPEN_MARKER) else {
                stripped_lines.push(line);
                continue;
            };
            let rest = &trimmed[start + OPEN_MARKER.len()..];
            let Some(close) = rest.find(')') else {
                stripped_lines.push(line);
                continue;
            };
            let path = rest[..close].trim().trim_matches(['"', '\'']).to_string();
            open = Some((path, Vec::new()));
        }

        // An unterminated block reaches here still `Some`: per the doc comment above,
        // it is dropped entirely — not added to `writes`, and its swallowed lines
        // never rejoin `stripped_lines`.

        (writes, stripped_lines.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_an_empty_ledger_without_panicking() {
        let text = SwarmLedger::new().system_prompt();
        assert!(text.contains("No active tasks."));
        assert!(text.contains("delegate_task"));
    }

    #[test]
    fn task_ids_are_stable_and_do_not_collide() {
        let mut ledger = SwarmLedger::new();
        let a = ledger.add_task("first");
        let b = ledger.add_task("second");
        assert_ne!(a, b);
        ledger.assign_task(a, "ollama:llama3");
        ledger.update_status(b, TaskStatus::Done);

        let text = ledger.system_prompt();
        assert!(text.contains("[IN_PROGRESS] Task #1: first (assigned: ollama:llama3)"));
        assert!(text.contains("[DONE] Task #2: second"));
    }

    #[test]
    fn roster_and_budgets_reach_the_prompt() {
        let mut ledger = SwarmLedger::new();
        ledger.set_roster(vec![
            "ollama:llama3".into(),
            "anthropic:claude-opus-5".into(),
        ]);
        ledger.update_budget("anthropic:claude-opus-5", "42 requests left");
        let text = ledger.system_prompt();
        assert!(text.contains("- ollama:llama3"));
        assert!(text.contains("anthropic:claude-opus-5: 42 requests left"));
    }

    #[test]
    fn a_recorded_result_is_rendered_beneath_its_task() {
        let mut ledger = SwarmLedger::new();
        let id = ledger.add_task("summarise the diff");
        ledger.assign_task(id, "ollama:llama3");
        ledger.record_result(id, "the diff adds a timeout");
        ledger.update_status(id, TaskStatus::Done);

        let text = ledger.system_prompt();
        assert!(text.contains("[DONE] Task #1: summarise the diff"));
        assert!(text.contains("result: the diff adds a timeout"));
    }

    #[test]
    fn a_failed_task_records_the_error_as_its_result_and_tags_failed() {
        // A failure with no explanation is useless to whoever must act on it — the
        // delegating model needs to see WHY, not just that the task stalled.
        let mut ledger = SwarmLedger::new();
        let id = ledger.add_task("call an unreachable model");
        ledger.assign_task(id, "agy:gemini-3-pro");
        ledger.update_status(id, TaskStatus::Failed);
        ledger.record_result(id, "agy:gemini-3-pro: connection refused");

        let text = ledger.system_prompt();
        assert!(text.contains("[FAILED] Task #1: call an unreachable model"));
        assert!(text.contains("result: agy:gemini-3-pro: connection refused"));
    }

    #[test]
    fn a_result_is_truncated_on_a_char_boundary_not_a_byte_index() {
        // Multi-byte UTF-8 near the cap must not panic on a mid-character slice.
        let mut ledger = SwarmLedger::new();
        let id = ledger.add_task("translate");
        let long_result = "é".repeat(MAX_RESULT_CHARS + 10);
        ledger.record_result(id, &long_result);

        let task = ledger.tasks().iter().find(|t| t.id == id).unwrap();
        let result = task.result.as_ref().unwrap();
        assert!(result.ends_with('…'));
        // MAX_RESULT_CHARS kept chars, plus the ellipsis marker.
        assert_eq!(result.chars().count(), MAX_RESULT_CHARS + 1);
    }

    #[test]
    fn results_that_fit_under_the_cap_are_stored_verbatim() {
        let mut ledger = SwarmLedger::new();
        let id = ledger.add_task("short task");
        ledger.record_result(id, "fine");
        let task = ledger.tasks().iter().find(|t| t.id == id).unwrap();
        assert_eq!(task.result.as_deref(), Some("fine"));
    }

    #[test]
    fn only_the_most_recent_tasks_are_rendered_and_older_ones_are_noted_as_elided() {
        let mut ledger = SwarmLedger::new();
        for i in 0..(MAX_RENDERED_TASKS + 5) {
            ledger.add_task(&format!("task {i}"));
        }
        let text = ledger.system_prompt();

        // The oldest task (added first) must not appear...
        assert!(!text.contains("Task #1:"));
        // ...but the ledger says so, rather than silently dropping it.
        assert!(text.contains("5 earlier task(s) elided"));
        // The most recent task must still be there.
        let last_id = MAX_RENDERED_TASKS + 5;
        assert!(text.contains(&format!("Task #{last_id}:")));
    }

    #[test]
    fn the_delegation_protocol_text_does_not_promise_a_same_turn_result() {
        // This block used to claim "the result will be returned to you," which was
        // false: `run_delegations` only writes the result into the ledger, which is
        // re-rendered on the NEXT prompt. The protocol text must not promise
        // something the code does not do.
        let text = SwarmLedger::new().system_prompt();
        assert!(!text.contains("the result will be returned to you"));
        assert!(text.contains("NEXT turn"));
    }

    #[test]
    fn parses_a_simple_delegation() {
        let found = SwarmLedger::parse_delegations(
            "Sure, I'll delegate.\nACTION: delegate_task(ollama:llama3, summarise the file)",
        );
        assert_eq!(
            found,
            vec![Delegation {
                target: "ollama:llama3".into(),
                prompt: "summarise the file".into()
            }]
        );
    }

    #[test]
    fn prompts_may_contain_commas_and_parentheses() {
        let found = SwarmLedger::parse_delegations(
            "ACTION: delegate_task(ollama:llama3, compare a, b and c (carefully))",
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].prompt, "compare a, b and c (carefully)");
    }

    #[test]
    fn tolerates_backticks_and_quotes() {
        let found = SwarmLedger::parse_delegations(
            "`ACTION: delegate_task(\"anthropic:claude-opus-5\", \"do the thing\")`",
        );
        assert_eq!(found[0].target, "anthropic:claude-opus-5");
        assert_eq!(found[0].prompt, "do the thing");
    }

    #[test]
    fn finds_multiple_delegations() {
        let found = SwarmLedger::parse_delegations(
            "ACTION: delegate_task(a, one)\nsome prose\nACTION: delegate_task(b, two)",
        );
        assert_eq!(found.len(), 2);
        assert_eq!(found[1].target, "b");
    }

    #[test]
    fn ignores_malformed_or_absent_markers() {
        assert!(SwarmLedger::parse_delegations("just a normal reply").is_empty());
        assert!(SwarmLedger::parse_delegations("ACTION: delegate_task(no-comma)").is_empty());
        assert!(SwarmLedger::parse_delegations("ACTION: delegate_task(a, )").is_empty());
        assert!(SwarmLedger::parse_delegations("ACTION: delegate_task(, prompt)").is_empty());
    }

    #[test]
    fn parses_a_simple_read_skill_request() {
        let found =
            SwarmLedger::parse_read_skill("I need more detail.\nACTION: read_skill(notes.md)");
        assert_eq!(found, vec!["notes.md".to_string()]);
    }

    #[test]
    fn read_skill_tolerates_backticks_and_quotes() {
        let found = SwarmLedger::parse_read_skill("`ACTION: read_skill(\"notes.md\")`");
        assert_eq!(found, vec!["notes.md".to_string()]);
    }

    #[test]
    fn finds_multiple_read_skill_requests() {
        let found = SwarmLedger::parse_read_skill(
            "ACTION: read_skill(a.md)\nsome prose\nACTION: read_skill(b.md)",
        );
        assert_eq!(found, vec!["a.md".to_string(), "b.md".to_string()]);
    }

    #[test]
    fn ignores_malformed_or_absent_read_skill_markers() {
        assert!(SwarmLedger::parse_read_skill("just a normal reply").is_empty());
        assert!(SwarmLedger::parse_read_skill("ACTION: read_skill(").is_empty());
        assert!(SwarmLedger::parse_read_skill("ACTION: read_skill()").is_empty());
        assert!(SwarmLedger::parse_read_skill("ACTION: read_skill(   )").is_empty());
    }

    #[test]
    fn a_loaded_skill_is_rendered_in_the_loaded_skills_section() {
        let mut ledger = SwarmLedger::new();
        ledger.record_skill("notes.md", "be terse and cite sources");
        let text = ledger.system_prompt();
        assert!(text.contains("### Loaded skills"));
        assert!(text.contains("#### notes.md"));
        assert!(text.contains("be terse and cite sources"));
    }

    #[test]
    fn re_requesting_a_loaded_skill_refreshes_it_in_place_rather_than_duplicating() {
        let mut ledger = SwarmLedger::new();
        ledger.record_skill("notes.md", "first version");
        ledger.record_skill("notes.md", "second version");
        assert_eq!(ledger.loaded_skills().len(), 1);
        assert_eq!(ledger.loaded_skills()[0].content, "second version");
    }

    #[test]
    fn loading_past_the_cap_evicts_the_oldest_loaded_skill() {
        let mut ledger = SwarmLedger::new();
        ledger.record_skill("a.md", "a");
        ledger.record_skill("b.md", "b");
        ledger.record_skill("c.md", "c");
        // Cap is MAX_LOADED_SKILLS == 3; this fourth load must evict "a.md".
        ledger.record_skill("d.md", "d");

        let names: Vec<&str> = ledger
            .loaded_skills()
            .iter()
            .map(|s| s.name.as_str())
            .collect();
        assert_eq!(names, vec!["b.md", "c.md", "d.md"]);
    }

    #[test]
    fn a_loaded_skills_content_is_truncated_on_a_char_boundary_not_a_byte_index() {
        // Mirrors the same guard on `record_result`: multi-byte UTF-8 near the cap
        // must not panic on a mid-character slice.
        let mut ledger = SwarmLedger::new();
        let long_content = "é".repeat(MAX_SKILL_CONTENT_CHARS + 10);
        ledger.record_skill("big.md", &long_content);

        let content = &ledger.loaded_skills()[0].content;
        assert!(content.ends_with('…'));
        assert_eq!(content.chars().count(), MAX_SKILL_CONTENT_CHARS + 1);
    }

    #[test]
    fn skill_content_under_the_cap_is_stored_verbatim() {
        let mut ledger = SwarmLedger::new();
        ledger.record_skill("small.md", "short and sweet");
        assert_eq!(ledger.loaded_skills()[0].content, "short and sweet");
    }

    #[test]
    fn the_skills_protocol_text_does_not_promise_a_same_turn_result() {
        // Same requirement as the delegation protocol text: must describe the real
        // next-turn timing, not promise something the code doesn't do.
        let text = SwarmLedger::new().system_prompt();
        assert!(text.contains("ACTION: read_skill"));
        assert!(text.contains("NEXT turn"));
    }

    #[test]
    fn parses_a_simple_write_file_block() {
        let (writes, stripped) = SwarmLedger::parse_file_writes(
            "Sure, here you go.\nACTION: write_file(notes/todo.md)\nline one\nline two\nACTION: end_file\nDone.",
        );
        assert_eq!(
            writes,
            vec![FileWrite {
                path: "notes/todo.md".into(),
                content: "line one\nline two".into(),
            }]
        );
        assert!(!stripped.contains("write_file"));
        assert!(!stripped.contains("end_file"));
        assert!(stripped.contains("Sure, here you go."));
        assert!(stripped.contains("Done."));
    }

    #[test]
    fn an_unterminated_write_block_is_skipped_and_stripped() {
        // No `ACTION: end_file` before the reply ends: the block, and everything it
        // swallowed, must vanish from both outputs rather than surfacing partially.
        let (writes, stripped) = SwarmLedger::parse_file_writes(
            "before\nACTION: write_file(notes.md)\nsome content\nmore content",
        );
        assert!(writes.is_empty());
        assert_eq!(stripped, "before");
    }

    #[test]
    fn action_lines_inside_file_content_are_not_parsed_as_delegations() {
        // A model documenting the delegation protocol inside a file it writes must
        // not have that example line actually execute as a delegation once the
        // stripped text reaches `parse_delegations`.
        let reply = "ACTION: write_file(README.md)\n\
                      Here is how delegation works:\n\
                      ACTION: delegate_task(ollama:llama3, do something)\n\
                      ACTION: end_file";
        let (writes, stripped) = SwarmLedger::parse_file_writes(reply);
        assert_eq!(writes.len(), 1);
        assert!(writes[0].content.contains("ACTION: delegate_task"));
        assert!(SwarmLedger::parse_delegations(&stripped).is_empty());
    }

    #[test]
    fn a_write_file_line_inside_a_block_is_content_not_a_new_block() {
        let reply = "ACTION: write_file(a.md)\n\
                      ACTION: write_file(b.md)\n\
                      ACTION: end_file";
        let (writes, stripped) = SwarmLedger::parse_file_writes(reply);
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].path, "a.md");
        assert_eq!(writes[0].content, "ACTION: write_file(b.md)");
        assert!(stripped.is_empty());
    }

    #[test]
    fn recorded_writes_are_rendered_without_content() {
        let mut ledger = SwarmLedger::new();
        ledger.record_file_write("secret_plan.md", "ok (42 bytes)");
        let text = ledger.system_prompt();
        assert!(text.contains("### Workspace files"));
        assert!(text.contains("secret_plan.md: ok (42 bytes)"));
    }

    #[test]
    fn the_file_write_protocol_text_does_not_promise_a_same_turn_result() {
        let text = SwarmLedger::new().system_prompt();
        assert!(text.contains("ACTION: write_file"));
        assert!(text.contains("ACTION: end_file"));
        assert!(text.contains("NEXT turn"));
    }

    #[test]
    fn re_recording_a_path_updates_in_place() {
        let mut ledger = SwarmLedger::new();
        ledger.record_file_write("notes.md", "ok (10 bytes)");
        ledger.record_file_write("notes.md", "ok (20 bytes)");
        assert_eq!(ledger.written_files().len(), 1);
        assert_eq!(ledger.written_files()[0].outcome, "ok (20 bytes)");
    }
}

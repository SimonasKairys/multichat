//! The shared "blackboard" every model sees, and the ReAct delegation protocol.

use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskStatus {
    Todo,
    InProgress,
    Done,
}

impl TaskStatus {
    fn tag(self) -> &'static str {
        match self {
            TaskStatus::Todo => "[TODO]",
            TaskStatus::InProgress => "[IN_PROGRESS]",
            TaskStatus::Done => "[DONE]",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Task {
    pub id: usize,
    pub description: String,
    pub assigned_to: Option<String>,
    pub status: TaskStatus,
}

/// A delegation request parsed out of a model's plain-text reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation {
    pub target: String,
    pub prompt: String,
}

#[derive(Debug, Default)]
pub struct SwarmLedger {
    tasks: Vec<Task>,
    next_id: usize,
    /// Model label -> human-readable budget line.
    budgets: BTreeMap<String, String>,
    /// Labels of every model currently reachable.
    roster: Vec<String>,
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
        });
        id
    }

    pub fn update_status(&mut self, id: usize, status: TaskStatus) {
        if let Some(task) = self.tasks.iter_mut().find(|t| t.id == id) {
            task.status = status;
        }
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
            for task in &self.tasks {
                let assignee = task.assigned_to.as_deref().unwrap_or("unassigned");
                out.push_str(&format!(
                    "- {} Task #{}: {} (assigned: {})\n",
                    task.status.tag(),
                    task.id,
                    task.description,
                    assignee
                ));
            }
        }

        out.push_str(
            "\n### Delegation protocol\n\
             You are one model in a multi-model swarm. To hand work to another model, \
             emit a line of exactly this form:\n\
             `ACTION: delegate_task(<model label>, <prompt>)`\n\
             Use a label from the list above. Check the budgets first and prefer a model \
             with capacity; local models have no quota. Emit nothing after the line — the \
             result will be returned to you.\n",
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
}

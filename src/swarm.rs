use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum TaskStatus {
    Todo,
    InProgress,
    Done,
}

#[derive(Debug, Clone)]
pub struct Task {
    pub id: usize,
    pub description: String,
    pub assigned_to: Option<String>,
    pub status: TaskStatus,
}

#[derive(Debug)]
pub struct SwarmLedger {
    pub tasks: Vec<Task>,
    pub model_budgets: HashMap<String, String>,
}

impl SwarmLedger {
    pub fn new() -> Self {
        Self {
            tasks: Vec::new(),
            model_budgets: HashMap::new(),
        }
    }

    pub fn add_task(&mut self, description: &str) -> usize {
        let id = self.tasks.len() + 1;
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

    pub fn assign_task(&mut self, id: usize, model_name: &str) {
        if let Some(task) = self.tasks.iter_mut().find(|t| t.id == id) {
            task.assigned_to = Some(model_name.to_string());
            task.status = TaskStatus::InProgress;
        }
    }

    pub fn update_budget(&mut self, model_name: &str, budget_info: &str) {
        self.model_budgets.insert(model_name.to_string(), budget_info.to_string());
    }

    /// Compiles the Swarm Ledger into a Markdown string to be injected into System Prompts
    pub fn generate_system_prompt_context(&self) -> String {
        let mut context = String::from("## SWARM LEDGER (Blackboard)\n\n");
        
        context.push_str("### Resource Budgets\n");
        if self.model_budgets.is_empty() {
            context.push_str("No budget limits detected.\n");
        } else {
            for (model, budget) in &self.model_budgets {
                context.push_str(&format!("- {}: {}\n", model, budget));
            }
        }

        context.push_str("\n### Tasks\n");
        if self.tasks.is_empty() {
            context.push_str("No active tasks.\n");
        } else {
            for task in &self.tasks {
                let status_str = match task.status {
                    TaskStatus::Todo => "[TODO]",
                    TaskStatus::InProgress => "[IN_PROGRESS]",
                    TaskStatus::Done => "[DONE]",
                };
                let assignee = task.assigned_to.as_deref().unwrap_or("Unassigned");
                context.push_str(&format!("- {} Task #{}: {} (Assigned: {})\n", status_str, task.id, task.description, assignee));
            }
        }

        context.push_str("\n### Instructions\n");
        context.push_str("You are a part of a multi-agent swarm. To delegate a task to another model, output the exact text:\n");
        context.push_str("`ACTION: delegate_task(model_name, prompt)`\n");

        context
    }
}

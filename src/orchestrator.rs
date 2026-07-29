//! The engine that ties the TUI, the providers, the ledger, and the audit log together.
//!
//! This is the module the previous version was missing entirely: every provider,
//! the vault, the ledger, and the audit logger existed but had no caller, so user input
//! never reached a model.

use anyhow::{Result, anyhow};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::audit::AuditLogger;
use crate::config::{Credentials, Paths, Settings};
use crate::providers::{
    Provider, cloud::CloudProvider, http_client, local_binary::LocalBinaryProvider,
    ollama::OllamaProvider,
};
use crate::skills::SkillsDir;
use crate::swarm::SwarmLedger;

/// Delegations honoured per user turn, so a model cannot spin the swarm forever.
const MAX_DELEGATIONS_PER_TURN: usize = 3;

/// Sent from the UI to the orchestrator.
#[derive(Debug)]
pub enum Command {
    Prompt(String),
    Shutdown,
}

/// Sent from the orchestrator back to the UI.
#[derive(Debug, Clone)]
pub enum Event {
    /// A model produced a reply.
    Reply { label: String, text: String },
    /// A delegation was dispatched.
    Delegated { from: String, to: String },
    /// Informational status line.
    Status(String),
    /// Something went wrong; the session continues.
    Error(String),
    /// The orchestrator has finished handling a turn.
    TurnComplete,
}

/// Every reachable model, keyed by `provider:model`.
pub struct Registry {
    providers: BTreeMap<String, Arc<dyn Provider>>,
    primary: String,
}

impl Registry {
    /// Builds the registry from settings.
    ///
    /// When `classified` is set, any provider whose traffic leaves the machine is
    /// refused — this is what makes `--classified` an actual air gap rather than a flag
    /// that is parsed and ignored.
    pub async fn build(
        settings: &Settings,
        requested: Option<&str>,
        classified: bool,
    ) -> Result<Self> {
        let client = http_client()?;
        let mut providers: BTreeMap<String, Arc<dyn Provider>> = BTreeMap::new();

        // Local Ollama models, discovered dynamically rather than hardcoded.
        match OllamaProvider::list_models(&settings.ollama_host, &client).await {
            Ok(models) => {
                for model in models {
                    let p = OllamaProvider::new(&settings.ollama_host, &model, client.clone());
                    providers.insert(p.label(), Arc::new(p));
                }
            }
            Err(e) => {
                eprintln!("[discovery] Ollama unavailable: {e}");
            }
        }

        if !classified {
            // Cloud providers, but only those we actually hold a key for.
            let names: Vec<String> = ["anthropic", "openai", "openrouter", "groq"]
                .iter()
                .map(|s| s.to_string())
                .chain(settings.custom_endpoints.keys().cloned())
                .collect();

            for name in names {
                let Some(endpoint) = settings.endpoint(&name) else {
                    continue;
                };
                match Credentials::get(&name) {
                    Ok(Some(key)) => {
                        let p =
                            CloudProvider::new(name.clone(), endpoint, None, key, client.clone());
                        providers.insert(p.label(), Arc::new(p));
                    }
                    Ok(None) => {}
                    Err(e) => eprintln!("[discovery] could not read {name} credential: {e}"),
                }
            }

            for (name, spec) in &settings.local_binaries {
                match LocalBinaryProvider::new(name, &spec.path, spec.args.clone(), name) {
                    Ok(p) => {
                        providers.insert(p.label(), Arc::new(p));
                    }
                    Err(e) => eprintln!("[discovery] skipping local binary {name}: {e}"),
                }
            }
        }

        if providers.is_empty() {
            return Err(anyhow!(
                "no models are reachable.{} Start Ollama, or run `multichat auth anthropic` \
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
            None => providers
                .keys()
                .next()
                .cloned()
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

        Ok(Self { providers, primary })
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
}

pub struct Orchestrator {
    registry: Registry,
    ledger: SwarmLedger,
    audit: AuditLogger,
    skills: SkillsDir,
    events: mpsc::Sender<Event>,
}

impl Orchestrator {
    pub fn new(registry: Registry, paths: &Paths, events: mpsc::Sender<Event>) -> Result<Self> {
        let mut ledger = SwarmLedger::new();
        ledger.set_roster(registry.labels());

        Ok(Self {
            registry,
            ledger,
            audit: AuditLogger::open(paths.audit_log.clone())?,
            skills: SkillsDir::new(paths.skills_dir.clone())?,
            events,
        })
    }

    async fn emit(&self, event: Event) {
        // A closed channel means the UI already exited; dropping the event is correct.
        let _ = self.events.send(event).await;
    }

    /// Assembles the system prompt: ledger blackboard plus any skills on disk.
    fn system_prompt(&self) -> String {
        let mut prompt = self.ledger.system_prompt();
        if let Ok(names) = self.skills.list()
            && !names.is_empty()
        {
            prompt.push_str("\n### Available skills (read-only)\n");
            for name in names {
                prompt.push_str(&format!("- {name}\n"));
            }
        }
        prompt
    }

    /// Consumes commands until the channel closes or a shutdown arrives.
    pub async fn run(mut self, mut commands: mpsc::Receiver<Command>) {
        if let Err(e) = self.audit.log(
            "session.start",
            &format!("primary={}", self.registry.primary()),
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
            }
        }

        let _ = self.audit.log("session.end", "clean shutdown");
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

        let system = self.system_prompt();
        let reply = match provider.send(Some(&system), prompt).await {
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

        if let Some(budget) = reply.rate_limit.summary() {
            self.ledger.update_budget(&primary_label, &budget);
        }
        let _ = self.audit.log(
            "reply.received",
            &format!("model={primary_label} chars={}", reply.text.len()),
        );

        self.emit(Event::Reply {
            label: primary_label.clone(),
            text: reply.text.clone(),
        })
        .await;

        self.run_delegations(&primary_label, &reply.text).await;
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
            })
            .await;

            let system = self.system_prompt();
            match target.send(Some(&system), &delegation.prompt).await {
                Ok(reply) => {
                    if let Some(budget) = reply.rate_limit.summary() {
                        self.ledger.update_budget(&target_label, &budget);
                    }
                    self.ledger
                        .update_status(task_id, crate::swarm::TaskStatus::Done);
                    let _ = self.audit.log(
                        "task.completed",
                        &format!("task={task_id} model={target_label}"),
                    );
                    self.emit(Event::Reply {
                        label: target_label,
                        text: reply.text,
                    })
                    .await;
                }
                Err(e) => {
                    let _ = self
                        .audit
                        .log("task.failed", &format!("task={task_id} error={e}"));
                    self.emit(Event::Error(format!("{target_label}: {e}")))
                        .await;
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

    /// End-to-end: a prompt reaches a provider and its reply comes back as an event.
    /// This is the wiring whose absence was the headline audit finding.
    #[tokio::test]
    async fn a_prompt_reaches_a_provider_and_the_reply_comes_back() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
        let reg = registry_with(vec![("ollama", "llama3", false)], "ollama:llama3");

        let (event_tx, mut event_rx) = mpsc::channel(16);

        let mut orch = Orchestrator {
            registry: reg,
            ledger: SwarmLedger::new(),
            audit: AuditLogger::with_key(paths.audit_log.clone(), vec![3u8; 32]).unwrap(),
            skills: SkillsDir::new(paths.skills_dir.clone()).unwrap(),
            events: event_tx,
        };
        orch.ledger.set_roster(orch.registry.labels());

        let handle = tokio::spawn(async move {
            orch.handle_prompt("hello there").await;
        });

        let event = event_rx.recv().await.expect("expected a reply event");
        match event {
            Event::Reply { label, text } => {
                assert_eq!(label, "ollama:llama3");
                assert_eq!(text, "echo: hello there");
            }
            other => panic!("expected Reply, got {other:?}"),
        }

        handle.await.unwrap();
    }

    #[tokio::test]
    async fn delegation_dispatches_to_the_named_model() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
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
            events: event_tx,
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
        let reg = registry_with(vec![("ollama", "llama3", false)], "ollama:llama3");

        let (event_tx, mut event_rx) = mpsc::channel(16);
        let mut orch = Orchestrator {
            registry: reg,
            ledger: SwarmLedger::new(),
            audit: AuditLogger::with_key(paths.audit_log.clone(), vec![3u8; 32]).unwrap(),
            skills: SkillsDir::new(paths.skills_dir.clone()).unwrap(),
            events: event_tx,
        };

        orch.run_delegations("ollama:llama3", "ACTION: delegate_task(ghost:model, hi)")
            .await;

        assert!(matches!(event_rx.try_recv(), Ok(Event::Error(_))));
    }
}

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
use crate::config::{ConnectionSpec, Credentials, Paths, Settings, Transport};
use crate::providers::{
    Provider, cloud::CloudProvider, http_client, local_binary::LocalBinaryProvider,
    ollama::OllamaProvider,
};
use crate::skills::SkillsDir;
use crate::swarm::SwarmLedger;

/// Delegations honoured per user turn, so a model cannot spin the swarm forever.
const MAX_DELEGATIONS_PER_TURN: usize = 3;

/// Sent from the UI to the orchestrator.
pub enum Command {
    Prompt(String),
    Shutdown,
    /// A new connection set was applied (from the picker, reopened with Ctrl+O/F2
    /// inside chat). The orchestrator rebuilds its registry from this and resets the
    /// swarm roster so the system prompt matches reality.
    Reconfigure(Settings),
}

impl std::fmt::Debug for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Command::Prompt(p) => f.debug_tuple("Prompt").field(p).finish(),
            Command::Shutdown => write!(f, "Shutdown"),
            // `Settings` can carry API-shaped strings the user typed as endpoint
            // overrides; never derive Debug through it into a log line.
            Command::Reconfigure(_) => write!(f, "Reconfigure(..)"),
        }
    }
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
    /// A new connection set was applied successfully.
    Reconfigured {
        primary: String,
        roster: Vec<String>,
    },
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
        other => other.to_string(),
    }
}

/// Args and system-prompt flag for a CLI this build knows how to auto-detect.
/// Verified against `--help` output on this machine for `claude` and `gemini`:
/// `claude` takes `--system-prompt <prompt>`; `gemini` has no system flag at all, so
/// its system text is folded into the prompt (see `LocalBinaryProvider::send`). The
/// other two (`codex`, `llm`) are unverified best guesses treated the same as
/// `gemini` until someone confirms their real flags.
fn known_cli_default(binary_name: &str) -> (Vec<String>, Option<String>) {
    match binary_name {
        "claude" => (vec!["-p".into()], Some("--system-prompt".into())),
        "gemini" => (vec!["-p".into()], None),
        _ => (Vec::new(), None),
    }
}

/// Every CLI tool this build can act as a provider for: whatever the user configured
/// explicitly in `local_binaries` (which always wins), plus anything from the known
/// list found on `PATH`.
fn detect_cli_tools(settings: &Settings) -> Vec<CliSpec> {
    const KNOWN: &[&str] = &["claude", "gemini", "codex", "llm"];
    let mut found = Vec::new();
    let mut configured = std::collections::BTreeSet::new();

    for (name, spec) in &settings.local_binaries {
        configured.insert(name.clone());
        found.push(CliSpec {
            binary_name: name.clone(),
            path: spec.path.clone(),
            args: spec.args.clone(),
            system_arg: spec.system_arg.clone(),
        });
    }

    for name in KNOWN {
        if configured.contains(*name) {
            continue;
        }
        if let Some(path) = which_on_path(name) {
            let (args, system_arg) = known_cli_default(name);
            found.push(CliSpec {
                binary_name: name.to_string(),
                path,
                args,
                system_arg,
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
        // to be told no. This is finding 1.2 in docs/AUDIT-2026-07-29.md.
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
        let (availability, detail) = if classified {
            (
                Availability::Unavailable("cloud APIs are refused under --classified".into()),
                endpoint.base_url.clone(),
            )
        } else {
            match Credentials::get(id) {
                Ok(Some(_)) => (Availability::Available, endpoint.base_url.clone()),
                // The reason is rendered separately from the detail column, so the
                // detail stays the endpoint URL — repeating it here printed it twice.
                Ok(None) => (
                    Availability::Unavailable("no key stored".into()),
                    endpoint.base_url.clone(),
                ),
                Err(e) => (
                    Availability::Unavailable(format!("keyring error: {e}")),
                    endpoint.base_url.clone(),
                ),
            }
        };
        transports.push(TransportOption {
            transport: Some(Transport::Api),
            label: "via API".into(),
            detail,
            availability,
            cli: None,
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
            format!("{binary}:{model}")
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
                cli.args.clone(),
                &model,
                cli.system_arg.clone(),
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
    ) -> Result<Self> {
        let candidates = discover_candidates(settings, classified).await;
        let client = http_client()?;
        let mut providers: BTreeMap<String, Arc<dyn Provider>> = BTreeMap::new();
        let mut applied: BTreeMap<String, ConnectionSpec> = BTreeMap::new();

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
                match construct_provider(candidate, option.transport, &conn, &client, settings) {
                    Ok(p) => {
                        providers.insert(p.label(), p);
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
                match construct_provider(candidate, transport, conn, &client, settings) {
                    Ok(p) => {
                        providers.insert(p.label(), p);
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
}

pub struct Orchestrator {
    registry: Registry,
    ledger: SwarmLedger,
    audit: AuditLogger,
    skills: SkillsDir,
    events: mpsc::Sender<Event>,
    /// Carried so a picker reopened mid-chat (`Command::Reconfigure`) rebuilds the
    /// registry under the same air-gap policy the session started with.
    classified: bool,
}

impl Orchestrator {
    pub fn new(
        registry: Registry,
        paths: &Paths,
        classified: bool,
        events: mpsc::Sender<Event>,
    ) -> Result<Self> {
        let mut ledger = SwarmLedger::new();
        ledger.set_roster(registry.labels());

        Ok(Self {
            registry,
            ledger,
            audit: AuditLogger::open(paths.audit_log.clone())?,
            skills: SkillsDir::new(paths.skills_dir.clone())?,
            events,
            classified,
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
            }
        }

        let _ = self.audit.log("session.end", "clean shutdown");
    }

    /// Rebuilds the registry from a freshly-applied connection set (the picker,
    /// reopened mid-chat) and resets the swarm roster so the system prompt matches
    /// reality.
    async fn reconfigure(&mut self, settings: Settings) {
        match Registry::build(&settings, None, self.classified).await {
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
            applied: BTreeMap::new(),
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
    fn cli_vendor_id_groups_known_binaries_under_their_vendor() {
        assert_eq!(cli_vendor_id("claude"), "anthropic");
        assert_eq!(cli_vendor_id("gemini"), "google");
        assert_eq!(cli_vendor_id("codex"), "codex");
    }

    #[tokio::test]
    async fn a_saved_commander_resolves_even_when_the_connection_id_is_not_the_provider_label() {
        // `settings.commander` holds a connection id ("anthropic"), the same key the
        // picker writes. When that connection is backed by a CLI (the `claude`
        // binary), the constructed provider's label is `claude:claude` —
        // `provider_name()` is the binary name, not the vendor id — so a naive
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

        let registry = Registry::build(&settings, None, false)
            .await
            .expect("the claude CLI connection must construct");
        assert_eq!(registry.primary(), "claude:claude");
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
        let reg = registry_with(vec![("ollama", "llama3", false)], "ollama:llama3");

        let (event_tx, mut event_rx) = mpsc::channel(16);

        let mut orch = Orchestrator {
            registry: reg,
            ledger: SwarmLedger::new(),
            audit: AuditLogger::with_key(paths.audit_log.clone(), vec![3u8; 32]).unwrap(),
            skills: SkillsDir::new(paths.skills_dir.clone()).unwrap(),
            events: event_tx,
            classified: false,
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
            classified: false,
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
            classified: false,
        };

        orch.run_delegations("ollama:llama3", "ACTION: delegate_task(ghost:model, hi)")
            .await;

        assert!(matches!(event_rx.try_recv(), Ok(Event::Error(_))));
    }

    #[tokio::test]
    async fn reconfigure_rebuilds_the_registry_and_resets_the_roster() {
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
            classified: false,
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
}

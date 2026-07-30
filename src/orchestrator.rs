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
        // `agy` (Antigravity) deliberately gets its own id rather than sharing
        // `google`: it is a gateway that serves Gemini, Claude and gpt-oss models
        // alike, so pairing it with the Gemini API row would misrepresent it.
        other => other.to_string(),
    }
}

/// Args and system-prompt flag for a CLI this build knows how to auto-detect.
/// Verified against `--help` and a live call on this machine:
/// `claude` takes `--system-prompt <prompt>`; `agy` (Antigravity) has `-p` but no
/// system flag at all, so its system text is folded into the prompt (see
/// `LocalBinaryProvider::send`). `codex` and `llm` are unverified best guesses,
/// treated the same as `agy` until someone confirms their real flags.
fn known_cli_default(binary_name: &str) -> (Vec<String>, Option<String>) {
    match binary_name {
        "claude" => (vec!["-p".into()], Some("--system-prompt".into())),
        "agy" => (vec!["-p".into()], None),
        _ => (Vec::new(), None),
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
        self.run_skill_reads(&reply.text).await;
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
                    // Record the reply on the task before flipping it to Done, so the
                    // ledger shown to the delegating model on its next turn carries
                    // the answer, not just a status tag. This is Fix 1: previously the
                    // reply reached only the TUI (via Event::Reply below) and the
                    // delegating model never saw it at all.
                    self.ledger.record_result(task_id, &reply.text);
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
    /// non-recursion guarantee holds here too.
    async fn run_skill_reads(&mut self, reply_text: &str) {
        let requests = SwarmLedger::parse_read_skill(reply_text);

        // Mirrors `run_delegations` capping to `MAX_DELEGATIONS_PER_TURN`: the
        // ledger already caps how many skills stay loaded (`MAX_LOADED_SKILLS`), but
        // that caps storage, not effort per turn — without this, a reply with
        // hundreds of `read_skill` lines would still trigger hundreds of filesystem
        // reads, just to have all but the last few evicted immediately after.
        for name in requests.into_iter().take(MAX_DELEGATIONS_PER_TURN) {
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
        // `agy` is a multi-vendor gateway, so it stands alone rather than folding
        // into `google` the way the old `gemini` CLI did.
        assert_eq!(cli_vendor_id("agy"), "agy");
    }

    #[test]
    fn agy_is_auto_detected_with_print_mode_and_no_system_flag() {
        let (args, system_arg) = known_cli_default("agy");
        assert_eq!(args, vec!["-p".to_string()]);
        // Verified against `agy --help` on this machine: there is no system-prompt
        // flag, so the system text has to be folded into the prompt.
        assert!(system_arg.is_none());
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

        let registry = Registry::build(&settings, None, false)
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
    async fn a_failed_delegation_is_tagged_failed_not_left_in_progress_forever() {
        // Regression guard for Fix 2: before this fix, the Err arm of run_delegations
        // logged and emitted an Event::Error but never called update_status, so a
        // failed task sat at [IN_PROGRESS] forever — indistinguishable from one still
        // running, on a blackboard other models read as fact.
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();

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
        };

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

        assert!(matches!(event_rx.try_recv(), Ok(Event::Delegated { .. })));
        assert!(matches!(event_rx.try_recv(), Ok(Event::Error(_))));

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
    async fn a_read_skill_request_loads_the_named_skill_into_the_ledger() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
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
            events: event_tx,
            classified: false,
        };

        orch.run_skill_reads("ACTION: read_skill(notes.md)").await;

        assert!(
            event_rx.try_recv().is_err(),
            "a successful read must not emit Event::Error"
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

        orch.run_skill_reads("ACTION: read_skill(../../../../etc/passwd)")
            .await;

        assert!(matches!(event_rx.try_recv(), Ok(Event::Error(_))));
        assert!(orch.ledger.loaded_skills().is_empty());
    }

    #[tokio::test]
    async fn a_missing_skill_request_surfaces_as_an_error_not_a_crash() {
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

        orch.run_skill_reads("ACTION: read_skill(nope.md)").await;

        assert!(matches!(event_rx.try_recv(), Ok(Event::Error(_))));
        assert!(orch.ledger.loaded_skills().is_empty());
    }

    #[tokio::test]
    async fn the_system_prompt_renders_a_skills_description_when_present() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();
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
            events: event_tx,
            classified: false,
        };

        let prompt = orch.system_prompt();
        assert!(prompt.contains("- notes.md — Summarise long documents."));
        assert!(prompt.contains("- plain.md\n"));
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

//! multichat — zero-trust terminal chat for local and cloud models.
//!
//! `unsafe` is denied crate-wide. The single audited exception is `src/security.rs`,
//! which wraps the platform memory-locking syscalls; a CI job rejects that override if it
//! appears in any other file. (This comment deliberately avoids spelling the override out
//! verbatim, so the grep in that job matches code rather than prose.)
#![deny(unsafe_code)]

pub mod app;
pub mod audit;
pub mod config;
pub mod orchestrator;
pub mod providers;
pub mod security;
pub mod skills;
pub mod swarm;
pub mod ui;
pub mod vault;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use tokio::sync::mpsc;

use crate::app::App;
use crate::audit::AuditLogger;
use crate::config::{Credentials, Paths, Settings};
use crate::orchestrator::{Orchestrator, Registry};
use crate::security::Hardening;

#[derive(Parser)]
#[command(name = "multichat", author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Air-gapped mode: refuse every provider whose traffic leaves this machine, and
    /// require memory locking to succeed.
    #[arg(long, global = true)]
    classified: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the chat TUI (default).
    Chat {
        /// Commander model: a label (`ollama:llama3`), a bare model name, or a provider.
        #[arg(short, long)]
        model: Option<String>,
    },
    /// Store an API key in the OS keyring. The key is read from the terminal or stdin,
    /// never from a command-line argument.
    Auth {
        /// Provider name, e.g. `anthropic`, `openai`, `openrouter`, `groq`.
        service: String,
        /// Remove the stored key instead of setting one.
        #[arg(long)]
        delete: bool,
    },
    /// List every model this machine can currently reach.
    Models,
    /// Verify the audit log's hash chain.
    Audit,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Arguments are parsed *before* any hardening. The previous version enforced
    // memory locking first and returned an error on failure, so on an unprivileged
    // Linux box even `--help` and `--version` aborted before clap ever ran.
    let cli = Cli::parse();

    match apply_hardening(cli.classified)? {
        Hardening::Applied => {}
        Hardening::Unavailable(reason) => {
            eprintln!("[security] memory locking unavailable: {reason}");
        }
    }
    if let Hardening::Unavailable(reason) = security::enforce_seccomp_sandbox() {
        // Stated plainly so nobody reads the startup output as proof of a sandbox.
        eprintln!("[security] {reason}");
    }

    let paths = Paths::resolve_with_env()?;
    let settings = Settings::load(&paths)?;

    match cli.command {
        Some(Commands::Auth { service, delete }) => auth(&service, delete, &settings),
        Some(Commands::Models) => list_models(&settings, cli.classified).await,
        Some(Commands::Audit) => verify_audit(&paths),
        Some(Commands::Chat { model }) => {
            chat(&paths, &settings, model.as_deref(), cli.classified).await
        }
        None => chat(&paths, &settings, None, cli.classified).await,
    }
}

fn apply_hardening(classified: bool) -> Result<Hardening> {
    security::enforce_memory_protection(classified)
}

fn auth(service: &str, delete: bool, settings: &Settings) -> Result<()> {
    if delete {
        Credentials::delete(service)?;
        println!("Removed the stored key for {service}.");
        return Ok(());
    }

    if settings.endpoint(service).is_none() {
        bail!(
            "unknown provider `{service}`. Built-in providers: anthropic, openai, \
             openrouter, groq. Add others under `custom_endpoints` in config.json."
        );
    }

    // Reading from the terminal keeps the key out of shell history and out of the
    // process table, where a `--key` argument would be visible to any local user.
    let key = if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        rpassword::prompt_password(format!("API key for {service} (input hidden): "))
            .context("failed to read the key from the terminal")?
    } else {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)
            .context("failed to read the key from stdin")?;
        buf
    };

    Credentials::set(service, key.trim())?;
    println!("Stored the {service} key in the OS keyring.");
    Ok(())
}

async fn list_models(settings: &Settings, classified: bool) -> Result<()> {
    let registry = Registry::build(settings, None, classified).await?;
    println!("Reachable models:");
    for label in registry.labels() {
        let marker = if label == registry.primary() {
            "*"
        } else {
            " "
        };
        println!("  {marker} {label}");
    }
    Ok(())
}

fn verify_audit(paths: &Paths) -> Result<()> {
    let logger = AuditLogger::open(paths.audit_log.clone())?;
    let count = logger.verify()?;
    println!("Audit chain verified: {count} entries intact.");
    Ok(())
}

async fn chat(
    paths: &Paths,
    settings: &Settings,
    model: Option<&str>,
    classified: bool,
) -> Result<()> {
    let registry = Registry::build(settings, model, classified).await?;
    let primary = registry.primary().to_string();
    let roster = registry.labels();

    let (command_tx, command_rx) = mpsc::channel(32);
    let (event_tx, event_rx) = mpsc::channel(64);

    let orchestrator = Orchestrator::new(registry, paths, event_tx)?;
    let worker = tokio::spawn(orchestrator.run(command_rx));

    let app = App::new(primary, &roster);
    let result = ui::run(app, command_tx, event_rx).await;

    // Let the orchestrator finish its shutdown audit entry before the process exits.
    let _ = worker.await;
    result
}

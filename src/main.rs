//! simon — zero-trust terminal chat for local and cloud models.
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
pub mod picker;
pub mod providers;
pub mod security;
pub mod skills;
pub mod swarm;
pub mod ui;
pub mod vault;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use secrecy::SecretString;
use tokio::sync::mpsc;

use crate::app::{App, Line};
use crate::audit::AuditLogger;
use crate::config::{Credentials, Paths, Settings};
use crate::orchestrator::{Orchestrator, Registry};
use crate::security::Hardening;
use crate::vault::{EncryptedVault, VaultError};

#[derive(Parser)]
#[command(name = "simon", author, version, about, long_about = None)]
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
        /// Persist the TUI transcript across sessions in an encrypted, password-
        /// protected vault. Off by default, so behaviour is unchanged unless asked
        /// for. This restores the user's own history — it does not give any model
        /// conversation memory; every turn is still sent with no message history.
        #[arg(long)]
        vault: bool,
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
    /// Inspect or destroy the encrypted transcript vault.
    Vault {
        #[command(subcommand)]
        action: VaultCommand,
    },
}

#[derive(Subcommand)]
enum VaultCommand {
    /// Show whether a vault exists, its path, and its plaintext header fields.
    /// Never prompts for a password — see `EncryptedVault::status`.
    Status,
    /// Permanently delete the vault file after a typed confirmation.
    Destroy,
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
        Some(Commands::Vault { action }) => vault_command(&paths, action),
        Some(Commands::Chat { model, vault }) => {
            chat(&paths, &settings, model.as_deref(), cli.classified, vault).await
        }
        None => chat(&paths, &settings, None, cli.classified, false).await,
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
            "unknown provider `{service}`. Built-in providers: anthropic, openai, google, \
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
    // Discovery, not construction: this must show every reachable model, including
    // ones the picker has not enabled, distinguishing the two — not just the
    // filtered set `Registry::build` would actually connect.
    let candidates = crate::orchestrator::discover_candidates(settings, classified).await;
    let first_run = settings.connections.is_empty();

    println!("Reachable models ([x] connected, [ ] available but not connected):");
    let mut any = false;
    for candidate in &candidates {
        for option in &candidate.transports {
            if !option.availability.is_available() {
                continue;
            }
            any = true;
            let label = crate::orchestrator::candidate_label(candidate, option, settings);
            let enabled = first_run
                || settings
                    .connections
                    .get(&candidate.id)
                    .is_some_and(|c| c.enabled && c.transport == option.transport);
            let checkbox = if enabled { "[x]" } else { "[ ]" };
            // Only the row actually enabled with this transport can be the
            // commander — a vendor with both a CLI and an API row must not show
            // "(commander)" on both just because the id matches.
            let commander =
                if enabled && settings.commander.as_deref() == Some(candidate.id.as_str()) {
                    "  (commander)"
                } else {
                    ""
                };
            println!("  {checkbox} {label}{commander}");
        }
    }
    if !any {
        println!("  (none)");
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
    vault: bool,
) -> Result<()> {
    let mut settings = settings.clone();

    // `-m <label>` bypasses the picker entirely (scripted / non-interactive use),
    // using the saved connection set with `<label>` forced as commander. Otherwise
    // the picker opens first and its choice is what gets connected.
    if model.is_none() {
        match ui::pick_connections(&mut settings, classified).await? {
            true => settings.save(paths)?,
            false => return Ok(()), // user quit from the picker
        }
    }

    let registry = Registry::build(&settings, model, classified).await?;
    let primary = registry.primary().to_string();
    let roster = registry.labels();

    let mut app = App::new(primary, &roster);

    // Password prompting and all vault I/O happen here — before the picker's result
    // is wired to a running orchestrator and, crucially, before `ui::run` ever calls
    // `TerminalGuard::enter` (raw mode + the alternate screen). A password prompt
    // read while crossterm owns the terminal shows no echo and no visible cursor, so
    // this must run in the plain terminal we still have right now.
    let vault_session = if vault {
        Some(vault_unlock_for_chat(paths, &mut app)?)
    } else {
        None
    };

    let (command_tx, command_rx) = mpsc::channel(32);
    let (event_tx, event_rx) = mpsc::channel(64);

    let orchestrator = Orchestrator::new(registry, paths, classified, event_tx)?;
    let worker = tokio::spawn(orchestrator.run(command_rx));

    let ui_result = ui::run(
        app,
        command_tx,
        event_rx,
        settings,
        paths.clone(),
        classified,
    )
    .await;

    // Let the orchestrator finish its shutdown audit entry before the process exits.
    let _ = worker.await;

    // Only a clean exit saves. `ui::run` returning `App` at all means
    // `TerminalGuard` has already been dropped and the terminal restored (see its
    // doc comment), so it is safe to print here. A crash, panic, or kill signal skips
    // this entirely and the session's new lines are lost — documented in README.md,
    // not left for a user to discover the hard way.
    if let (Some(session), Ok(app)) = (vault_session, &ui_result)
        && let Err(e) = vault_save_after_chat(paths, session, &app.transcript)
    {
        eprintln!("[vault] failed to save the transcript: {e}");
    }

    ui_result.map(|_| ())
}

/// Holds the vault's unlock/creation password for the lifetime of a chat session, so
/// the single save at the end can reuse it without prompting a second time.
struct VaultSession {
    vault: EncryptedVault,
    password: SecretString,
}

/// Prompts for and applies a vault password, restoring prior history into `app` when
/// there is any to restore. Called before the TUI takes over the terminal — see the
/// comment at its call site in `chat`.
fn vault_unlock_for_chat(paths: &Paths, app: &mut App) -> Result<VaultSession> {
    let vault = EncryptedVault::new(paths.vault_file.clone());
    let mut audit = AuditLogger::open(paths.audit_log.clone())?;

    if !vault.exists() {
        println!("No vault exists yet at {}.", vault.path().display());
        println!(
            "This will hold your saved chat transcript, encrypted under the password \
             you choose now. WARNING: the vault self-destructs — wiping that \
             transcript for good — after {} consecutive wrong passwords, or after {} \
             hours without being opened. A correct password typed after either limit \
             does not recover it.",
            crate::vault::MAX_ATTEMPTS,
            crate::vault::MAX_IDLE_SECS / 3600
        );
        let password = prompt_new_vault_password()?;
        let _ = audit.log("vault.opened", "first run: vault does not exist yet");
        return Ok(VaultSession { vault, password });
    }

    // Captured *before* unlocking: a successful `load()` immediately refreshes
    // `last_unlock` to now (vault.rs), so reading this after the fact would always
    // show a full idle window remaining and the warning below could never fire.
    let idle_remaining_before_unlock = vault.status().ok().map(|s| s.idle_secs_remaining);

    // Bounded by construction, not by a counter kept here: `EncryptedVault::load`
    // self-destructs the file once `MAX_ATTEMPTS` is reached, which turns every
    // subsequent iteration's `Err(VaultError::Destroyed(_))` arm into a `return`.
    loop {
        let password = SecretString::from(
            rpassword::prompt_password("Vault password (input hidden): ")
                .context("failed to read the vault password from the terminal")?,
        );

        match vault.load(&password) {
            Ok(bytes) => {
                if let Some(remaining) = idle_remaining_before_unlock
                    && remaining <= crate::vault::IDLE_WARNING_THRESHOLD_SECS
                {
                    println!(
                        "Warning: this vault was only {} away from self-destructing \
                         from inactivity when you unlocked it just now.",
                        fmt_hms(remaining)
                    );
                }
                match serde_json::from_slice::<Vec<Line>>(&bytes) {
                    Ok(mut restored) => {
                        // Restored history first, then the fresh "commander: …" /
                        // "swarm: …" banner `App::new` already seeded, so the
                        // transcript reads as "prior session(s) ... new session
                        // started" rather than losing the banner outright.
                        restored.append(&mut app.transcript);
                        app.transcript = restored;
                    }
                    Err(e) => {
                        // The vault decrypted fine; the payload inside it is just
                        // unusable (e.g. an older, incompatible transcript format).
                        // That is not a reason to abort — only `Corrupt` is.
                        eprintln!(
                            "[vault] decrypted, but the saved transcript could not be \
                             read ({e}); starting with an empty transcript."
                        );
                    }
                }
                let _ = audit.log("vault.opened", "unlocked existing vault");
                return Ok(VaultSession { vault, password });
            }
            Err(VaultError::WrongPassword { remaining }) => {
                let _ = audit.log(
                    "vault.unlock_failed",
                    &format!(
                        "attempt={} remaining={remaining}",
                        crate::vault::MAX_ATTEMPTS - remaining
                    ),
                );
                eprintln!(
                    "Wrong password — {remaining} attempt(s) left before the vault \
                     self-destructs and the transcript is lost for good."
                );
            }
            Err(VaultError::Destroyed(reason)) => {
                let _ = audit.log("vault.destroyed", &reason);
                // Printed verbatim: `reason` is what distinguishes "too many wrong
                // passwords" from "idle too long", and that distinction is the point.
                println!("Vault destroyed: {reason}");
                println!("Continuing with an empty transcript. Choose a new password:");
                let password = prompt_new_vault_password()?;
                return Ok(VaultSession { vault, password });
            }
            Err(VaultError::Corrupt(msg)) => {
                bail!(
                    "vault file at {} is corrupt: {msg}. Refusing to guess at a fix — \
                     run `simon vault destroy` first if you want to discard it and \
                     start over.",
                    vault.path().display()
                );
            }
            Err(VaultError::Missing) => {
                // `vault.exists()` was true a moment ago; only a concurrent delete
                // gets here. Treat it like first-run rather than looping forever.
                println!("Vault file is gone; starting fresh.");
                let password = prompt_new_vault_password()?;
                return Ok(VaultSession { vault, password });
            }
        }
    }
}

/// Prompts twice and requires the two entries to match, looping until they do.
/// Shared by every "no vault to unlock" path: first run, post-destroy, and a vault
/// that vanished underneath us.
fn prompt_new_vault_password() -> Result<SecretString> {
    loop {
        let first = rpassword::prompt_password("New vault password (input hidden): ")
            .context("failed to read the vault password from the terminal")?;
        let second = rpassword::prompt_password("Confirm vault password (input hidden): ")
            .context("failed to read the vault password from the terminal")?;
        if first.is_empty() {
            eprintln!("An empty password defeats the point of a vault; try again.");
            continue;
        }
        if first != second {
            eprintln!("Passwords did not match; try again.");
            continue;
        }
        return Ok(SecretString::from(first));
    }
}

/// Serializes `transcript` and saves it once. Called exactly once, at the end of a
/// chat session — see the "save once at clean exit" comment in `chat`.
fn vault_save_after_chat(paths: &Paths, session: VaultSession, transcript: &[Line]) -> Result<()> {
    let payload = serde_json::to_vec(transcript)
        .context("failed to serialize the transcript for the vault")?;
    session.vault.save(&payload, &session.password)?;
    // A fresh `AuditLogger` here (rather than one held across the whole session) is
    // deliberate: the orchestrator's own logger has appended `session.start` through
    // `session.end` to this same file in the meantime, so re-opening picks up the
    // real chain head instead of writing with a stale `prev` and breaking it.
    if let Ok(mut audit) = AuditLogger::open(paths.audit_log.clone()) {
        let _ = audit.log("vault.saved", &format!("lines={}", transcript.len()));
    }
    Ok(())
}

/// Formats a second count as `"12h 34m"` for human-readable vault status/warnings.
fn fmt_hms(total_secs: u64) -> String {
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    format!("{hours}h {minutes}m")
}

fn vault_command(paths: &Paths, action: VaultCommand) -> Result<()> {
    let vault = EncryptedVault::new(paths.vault_file.clone());
    match action {
        VaultCommand::Status => vault_status(&vault),
        VaultCommand::Destroy => vault_destroy(paths, &vault),
    }
}

fn vault_status(vault: &EncryptedVault) -> Result<()> {
    match vault.status() {
        Ok(status) => {
            println!("Vault: {}", status.path.display());
            println!(
                "  failed unlock attempts so far: {} (of {} before self-destruct)",
                status.failed_attempts,
                crate::vault::MAX_ATTEMPTS
            );
            if status.idle_secs_remaining == 0 {
                println!(
                    "  idle for {} — past the {} idle limit; the next \
                     `simon chat --vault` will find it already destroyed.",
                    fmt_hms(status.idle_secs),
                    fmt_hms(crate::vault::MAX_IDLE_SECS)
                );
            } else {
                println!(
                    "  idle for {}; {} left before it self-destructs from inactivity",
                    fmt_hms(status.idle_secs),
                    fmt_hms(status.idle_secs_remaining)
                );
            }
            println!(
                "  note: the attempt count and idle timer above are stored outside the \
                 encrypted payload (see the module doc in src/vault.rs), which is why \
                 no password was needed to read them — and, for the same reason, they \
                 are not tamper-proof. Someone with file access can reset both."
            );
        }
        Err(VaultError::Missing) => {
            println!("No vault exists at {}.", vault.path().display());
        }
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

fn vault_destroy(paths: &Paths, vault: &EncryptedVault) -> Result<()> {
    if !vault.exists() {
        println!(
            "No vault exists at {}; nothing to destroy.",
            vault.path().display()
        );
        return Ok(());
    }

    println!(
        "This permanently deletes {} and the transcript inside it. This cannot be undone.",
        vault.path().display()
    );
    print!("Type `yes` to confirm: ");
    std::io::Write::flush(&mut std::io::stdout()).context("failed to flush stdout")?;
    let mut confirmation = String::new();
    std::io::stdin()
        .read_line(&mut confirmation)
        .context("failed to read the confirmation from the terminal")?;

    if confirmation.trim() != "yes" {
        println!("Not confirmed; leaving the vault in place.");
        return Ok(());
    }

    vault.destroy();
    println!("Vault destroyed.");
    if let Ok(mut audit) = AuditLogger::open(paths.audit_log.clone()) {
        let _ = audit.log("vault.destroyed", "destroyed via `simon vault destroy`");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classified_and_vault_flags_combine_on_the_chat_subcommand() {
        // The vault is purely local storage, so `--classified` (no traffic may leave
        // the machine) and `--vault` (encrypt the transcript at rest) must be usable
        // together — nothing about either should disable the other. Regression guard
        // for that combination, which nothing previously exercised.
        let cli = Cli::parse_from(["simon", "chat", "--classified", "--vault"]);
        assert!(cli.classified);
        match cli.command {
            Some(Commands::Chat { vault, .. }) => assert!(vault),
            _ => panic!("expected the Chat subcommand to have been parsed"),
        }
    }

    #[test]
    fn vault_defaults_to_off_so_existing_behaviour_is_unchanged() {
        let cli = Cli::parse_from(["simon", "chat"]);
        match cli.command {
            Some(Commands::Chat { vault, .. }) => assert!(!vault),
            _ => panic!("expected the Chat subcommand to have been parsed"),
        }
    }

    #[test]
    fn hms_formatting_reads_as_hours_and_minutes() {
        assert_eq!(fmt_hms(0), "0h 0m");
        assert_eq!(fmt_hms(90 * 60), "1h 30m");
        assert_eq!(fmt_hms(crate::vault::MAX_IDLE_SECS), "24h 0m");
    }
}

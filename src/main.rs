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
pub mod workspace;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use secrecy::SecretString;
use std::fs;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;

use crate::app::{App, Line};
use crate::audit::{AnchorStatus, AuditLogger};
use crate::config::{Credentials, Paths, Settings};
use crate::orchestrator::{Orchestrator, Registry};
use crate::security::Hardening;
use crate::vault::{EncryptedVault, VaultError};

/// Flags for the chat TUI. Split into its own type, rather than inlined into
/// `Commands::Chat` the way every other subcommand's fields are, so the identical set
/// can also be flattened onto `Cli` itself and accepted at the top level (`simon
/// --vault`, not just `simon chat --vault`).
///
/// `Chat` is documented as the default subcommand — `command: None` behaves exactly
/// like `simon chat` (see `main`'s `None` arm) — so a flag that only worked once
/// `chat` was spelled out explicitly was a papercut with no safety purpose behind it.
/// Flattening one struct in two places, instead of two independent arg lists, is what
/// keeps the top-level and explicit-subcommand behaviour from drifting apart.
#[derive(Args, Debug)]
struct ChatArgs {
    /// Commander model: a label (`ollama:llama3`), a bare model name, or a provider.
    #[arg(short, long)]
    model: Option<String>,
    /// Persist the TUI transcript across sessions in an encrypted, password-
    /// protected vault. Off by default, so behaviour is unchanged unless asked
    /// for. This restores the user's own history — it does not give any model
    /// conversation memory; every turn is still sent with no message history.
    #[arg(long)]
    vault: bool,
    /// Write files without asking. By default every `write_file` a model proposes
    /// is shown — path, size, whether it overwrites, and the content — and waits
    /// for the user to allow it. This turns that gate off, which is what a
    /// scripted or unattended session wants and what an interactive one almost
    /// never does.
    #[arg(long)]
    auto_write: bool,
}

#[derive(Parser)]
#[command(name = "simon", author, version, about, long_about = None)]
// Lets `ChatArgs` be flattened onto `Cli` (below) at the same time `Commands` also
// exists, without clap treating the two as ambiguous. Without this, clap's default
// stance is that a `Command` with subcommands owns any leading positional/value
// disambiguation itself; setting it explicitly is what makes `simon -m foo` resolve
// to "no subcommand, `-m` belongs to the flattened chat args" rather than an error.
#[command(args_conflicts_with_subcommands = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// The default subcommand's own flags, also accepted at the top level — see
    /// `ChatArgs`'s doc comment for why this is flattened rather than inlined.
    #[command(flatten)]
    chat: ChatArgs,

    /// Air-gapped mode: refuse every provider whose traffic leaves this machine, and
    /// require memory locking to succeed.
    #[arg(long, global = true)]
    classified: bool,

    /// The project folder models may read, list, and write files in. Defaults to the
    /// directory `simon` was started in. Resolved and canonicalized once at startup;
    /// see `resolve_project_root`.
    #[arg(long, global = true)]
    project: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the chat TUI (default).
    Chat {
        #[command(flatten)]
        args: ChatArgs,
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
    Audit {
        /// Discard the tamper-evidence anchors for the current log and re-baseline
        /// them to whatever is on disk right now. For after a deliberate admin action
        /// (deleting or trimming the log on purpose) that would otherwise leave every
        /// future `simon audit` reporting truncation with no way to clear it. Never
        /// happens implicitly — this flag is the only way to trigger it, and if the
        /// log still has entries the reset itself is recorded into the chain first.
        #[arg(long)]
        reset_anchor: bool,
        /// Discard whatever value is currently stored in the OS keyring under the
        /// audit MAC key's service name — valid, corrupt, or absent — and generate a
        /// fresh one on next use. This is the recovery path for when `simon` refuses
        /// to start because the keyring holds a value it didn't write (wrong length,
        /// or not hex): see the error `simon audit` gives in that case. Every entry
        /// written under the discarded key becomes permanently unverifiable — this is
        /// a separate, more drastic reset than `--reset-anchor` (which only affects
        /// the anchors, not the key itself), so pair it with `--reset-anchor` to
        /// re-baseline afterwards. Never happens implicitly.
        #[arg(long)]
        reset_key: bool,
    },
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
        Some(Commands::Audit {
            reset_anchor,
            reset_key,
        }) => verify_audit(&paths, reset_anchor, reset_key),
        Some(Commands::Vault { action }) => vault_command(&paths, action),
        Some(Commands::Chat { args }) => {
            let project_root = resolve_project_root(cli.project)?;
            chat(
                &paths,
                &settings,
                args.model.as_deref(),
                cli.classified,
                args.vault,
                &project_root,
                args.auto_write,
            )
            .await
        }
        // No subcommand named: `chat` is the default, and its flags were accepted
        // directly on `cli` via the `ChatArgs` flattened onto `Cli` — see that
        // struct's doc comment. Using `cli.chat` here (instead of the all-off
        // defaults the old code hardcoded) is the actual fix: previously these
        // fields didn't exist at the top level at all, so `simon -m foo` failed to
        // parse before execution ever reached this arm.
        None => {
            let project_root = resolve_project_root(cli.project)?;
            chat(
                &paths,
                &settings,
                cli.chat.model.as_deref(),
                cli.classified,
                cli.chat.vault,
                &project_root,
                cli.chat.auto_write,
            )
            .await
        }
    }
}

/// Resolves the project folder models get confined to: `--project <dir>` if given,
/// otherwise the directory `simon` was started in. Canonicalized once here so every
/// later prefix comparison (`Workspace`'s traversal checks) runs against a stable,
/// symlink-resolved path rather than re-resolving on every call.
///
/// Deliberately separate from `Paths::resolve_with_env`: the project root is not
/// application state, it is the user's own project folder, and it moves independently
/// of where `simon` keeps its config, vault, audit log, and skills.
fn resolve_project_root(project: Option<PathBuf>) -> Result<PathBuf> {
    let requested = match project {
        Some(dir) => dir,
        None => std::env::current_dir().context("failed to determine the current directory")?,
    };
    let meta = fs::metadata(&requested).with_context(|| {
        format!(
            "project directory {} does not exist or is not accessible",
            requested.display()
        )
    })?;
    if !meta.is_dir() {
        bail!("project path {} is not a directory", requested.display());
    }
    fs::canonicalize(&requested)
        .with_context(|| format!("failed to resolve {}", requested.display()))
}

fn apply_hardening(classified: bool) -> Result<Hardening> {
    security::enforce_memory_protection(classified)
}

/// Resolves the keyring-entry name for `service` — the same name `discover_vendors`
/// (`orchestrator.rs`) asks the keyring for when deciding whether a key is already
/// stored. Split out of `auth` so this can be exercised by a test without touching
/// the real OS keyring.
///
/// `config::canonical_provider` lowercases its input only to *decide* which arm of
/// its match to take; its fallback arm (`_ => name`) then hands back the original
/// `name`, case and all. `settings.endpoint` (via `builtin_endpoint`) also lowercases
/// before comparing, so `simon auth ANTHROPIC` still found the endpoint and reported
/// success — but `Credentials::set` below stored the key under the literal string
/// `"ANTHROPIC"`, and `discover_vendors` only ever asks the keyring for the lowercase
/// canonical ids (`"anthropic"`, `"openai"`, ...). The key landed somewhere no lookup
/// ever reads from, so the picker kept reporting "(no key stored)" no matter how many
/// times the key was re-entered. Lowercasing the pass-through result here — rather
/// than inside `canonical_provider`, which this crate's file-ownership split for this
/// change does not touch — fixes it without touching the alias arms, which already
/// returned a correctly-cased id.
fn resolve_canonical_service(service: &str, settings: &Settings) -> String {
    if settings.custom_endpoints.contains_key(service) {
        // A custom endpoint literally named `gemini` or `claude` must keep that
        // exact name — only fall back to the builtin alias mapping (and the
        // lowercasing below) when no custom endpoint claims the raw name, or a
        // deliberately-named custom entry would be misfiled under an alias the
        // user's own `config.json` never used.
        service.to_string()
    } else {
        crate::config::canonical_provider(service).to_ascii_lowercase()
    }
}

fn auth(service: &str, delete: bool, settings: &Settings) -> Result<()> {
    let canonical = resolve_canonical_service(service, settings);

    if delete {
        Credentials::delete(&canonical)?;
        println!("Removed the stored key for {canonical}.");
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
        rpassword::prompt_password(format!("API key for {canonical} (input hidden): "))
            .context("failed to read the key from the terminal")?
    } else {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)
            .context("failed to read the key from stdin")?;
        buf
    };

    Credentials::set(&canonical, key.trim())?;
    println!("Stored the {canonical} key in the OS keyring.");
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

fn verify_audit(paths: &Paths, reset_anchor: bool, reset_key: bool) -> Result<()> {
    // Handled before `AuditLogger::open` below, and deliberately not by that logger's
    // own `reset_anchor` method: a corrupt key means `open` never succeeds in the
    // first place (see `audit::validate_key`), so there is no logger yet to call a
    // method on. This has to work directly against the keyring, before any log
    // instance exists.
    if reset_key {
        crate::audit::reset_key()?;
        println!(
            "Audit key reset: the value previously stored in the OS keyring has been \
             discarded. A fresh MAC key will be generated below. Every entry (and \
             anchor) written under the old key is now permanently unverifiable — run \
             with --reset-anchor too (now or on a later run) to re-baseline the \
             tamper-evidence anchors to the new key."
        );
    }

    let mut logger = AuditLogger::open(paths.audit_log.clone())?;

    if reset_anchor {
        logger.reset_anchor("reset via `simon audit --reset-anchor`")?;
        println!(
            "Anchor reset: tamper-evidence for this log's previous history has been \
             discarded and re-baselined to what's on disk now."
        );
    }

    let report = logger.verify()?;
    match report.anchor {
        AnchorStatus::Current => {
            println!("Audit chain verified: {} entries intact.", report.entries);
        }
        // Not a hard failure — see `AnchorStatus::Missing`'s doc comment for why. The
        // chain itself (printed above) is still fully verified; what's unconfirmed is
        // only whether the tail could have been silently truncated.
        AnchorStatus::Missing => {
            println!(
                "Audit chain verified: {} entries intact, but no anchor was found to \
                 confirm the tail hasn't been truncated (an old log from before this \
                 check existed, or the anchor file was removed).",
                report.entries
            );
        }
        // Also not a hard failure — see `AnchorStatus::Unreadable`'s doc comment. An
        // anchor file exists but couldn't be parsed, most likely a crash mid-write;
        // that's a reason to distrust *this* anchor, not evidence the log was tampered
        // with, so it gets the same "verified, but unconfirmed" treatment as `Missing`.
        AnchorStatus::Unreadable => {
            println!(
                "Audit chain verified: {} entries intact, but the anchor file could not \
                 be read (it may be corrupt or left over from an interrupted write), so \
                 the tail hasn't been confirmed against it.",
                report.entries
            );
        }
    }
    Ok(())
}

async fn chat(
    paths: &Paths,
    settings: &Settings,
    model: Option<&str>,
    classified: bool,
    vault: bool,
    project_root: &Path,
    auto_write: bool,
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

    let registry = Registry::build(&settings, model, classified, project_root).await?;
    let primary = registry.primary().to_string();
    let roster = registry.labels();

    let mut app = App::new(primary, &roster, project_root.display().to_string());

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
    // Capacity 1: a write gate is strictly one question at a time — the orchestrator
    // blocks on the answer before proposing the next write — so anything larger would
    // only be able to hold answers to questions nobody asked.
    let (decision_tx, decision_rx) = mpsc::channel(1);
    let write_gate = if auto_write { None } else { Some(decision_rx) };

    let orchestrator = Orchestrator::new(
        registry,
        paths,
        project_root.to_path_buf(),
        classified,
        event_tx,
        write_gate,
    )?;
    let worker = tokio::spawn(orchestrator.run(command_rx));

    let ui_result = ui::run(
        app,
        command_tx,
        decision_tx,
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
             transcript for good — after {} consecutive wrong passwords. A correct \
             password typed after that limit does not recover it. Leaving it unopened \
             for more than {} hours only warns you; unlocking it resets the timer.",
            crate::vault::MAX_ATTEMPTS,
            crate::vault::MAX_IDLE_SECS / 3600
        );
        let password = prompt_new_vault_password()?;
        let _ = audit.log("vault.opened", "first run: vault does not exist yet");
        return Ok(VaultSession { vault, password });
    }

    // Captured *before* unlocking: a successful `load()` immediately refreshes
    // `last_unlock` to now (vault.rs), so reading this after the fact would always
    // show a full idle window remaining and the warnings here could never fire.
    let status_before_unlock = vault.status().ok();
    let idle_remaining_before_unlock = status_before_unlock.as_ref().map(|s| s.idle_secs_remaining);

    // Printed *before* the prompt, unlike the near-expiry warning further down: this is
    // the case where the old build would already have deleted the file by now, so the
    // user deserves the explanation while they still have the password in their head.
    if let Some(status) = status_before_unlock.as_ref() {
        if status.idle_expired {
            println!(
                "Notice: this vault has sat unopened for {} — past its {} idle limit. \
                 Nothing has been deleted: unlocking it below works normally and resets \
                 the timer. If your system clock was wrong (an NTP correction, a VM \
                 resuming with a stale clock), this is a false alarm — the idle window \
                 is measured against the wall clock and cannot tell the two apart.",
                fmt_hms(status.idle_secs),
                fmt_hms(crate::vault::MAX_IDLE_SECS)
            );
        }
        if let Some(behind) = status.clock_behind_secs {
            println!(
                "Notice: this system's clock is {} behind the vault's recorded \
                 last-unlock time. A vault cannot have been opened in the future, so \
                 the clock is wrong; the idle numbers are not meaningful until it is \
                 fixed. Unlocking still works.",
                fmt_hms(behind)
            );
        }
    }

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
                // Only for a vault that had not yet passed the limit — the expired
                // case already got its own, stronger notice before the prompt.
                if let Some(remaining) = idle_remaining_before_unlock
                    && remaining > 0
                    && remaining <= crate::vault::IDLE_WARNING_THRESHOLD_SECS
                {
                    println!(
                        "Warning: this vault was only {} away from passing its idle \
                         limit when you unlocked it just now.",
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
                // Printed verbatim: `reason` names what actually triggered the wipe.
                // Only the attempt limit destroys a vault now — idle expiry warns
                // instead (see `EncryptedVault::load`).
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
    //
    // Best-effort by design — the vault save above has already succeeded and must not
    // be undone by an audit hiccup — but not *silent*: `AuditLogger::open` failing
    // here includes the corrupt-keyring-key case (AUDIT-2026-07-31.md §3.5), which the
    // user needs to see even though this function still returns `Ok`. Note this
    // specific failure is unlikely to be reached in practice: `Orchestrator::new`
    // already opened a logger with `?` earlier in this same process (see `chat`), so a
    // corrupt key would already have aborted the session before the vault was ever
    // saved. It would only show up here if the keyring entry was corrupted mid-session.
    match AuditLogger::open(paths.audit_log.clone()) {
        Ok(mut audit) => {
            if let Err(e) = audit.log("vault.saved", &format!("lines={}", transcript.len())) {
                eprintln!("[audit] failed to record vault.saved: {e}");
            }
        }
        Err(e) => eprintln!("[audit] failed to open the audit log to record vault.saved: {e}"),
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
            if let Some(behind) = status.clock_behind_secs {
                // Reporting "24h 0m left" here would be worse than useless: the clock
                // says the vault was last opened in the future, so say that instead.
                println!(
                    "  system clock is {} behind the vault's last-unlock time — the \
                     clock is wrong, so the idle figures below are not meaningful",
                    fmt_hms(behind)
                );
            }
            if status.idle_expired {
                println!(
                    "  idle for {} — past the {} idle limit. Nothing is destroyed by \
                     this: the next `simon chat --vault` warns you, unlocks normally \
                     with the right password, and resets the timer.",
                    fmt_hms(status.idle_secs),
                    fmt_hms(crate::vault::MAX_IDLE_SECS)
                );
            } else {
                println!(
                    "  idle for {}; {} left before it is reported as past its idle limit",
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
    // Best-effort, but surfaced rather than silently swallowed — same reasoning as
    // the equivalent audit call in `vault_save_after_chat`: the destroy itself has
    // already happened and must not be undone by an audit hiccup, but a corrupt-key
    // failure here (§3.5) is exactly the kind of thing a user needs to be told about.
    match AuditLogger::open(paths.audit_log.clone()) {
        Ok(mut audit) => {
            if let Err(e) = audit.log("vault.destroyed", "destroyed via `simon vault destroy`") {
                eprintln!("[audit] failed to record vault.destroyed: {e}");
            }
        }
        Err(e) => eprintln!("[audit] failed to open the audit log to record vault.destroyed: {e}"),
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
            Some(Commands::Chat { args }) => assert!(args.vault),
            _ => panic!("expected the Chat subcommand to have been parsed"),
        }
    }

    #[test]
    fn vault_defaults_to_off_so_existing_behaviour_is_unchanged() {
        let cli = Cli::parse_from(["simon", "chat"]);
        match cli.command {
            Some(Commands::Chat { args }) => assert!(!args.vault),
            _ => panic!("expected the Chat subcommand to have been parsed"),
        }
    }

    #[test]
    fn hms_formatting_reads_as_hours_and_minutes() {
        assert_eq!(fmt_hms(0), "0h 0m");
        assert_eq!(fmt_hms(90 * 60), "1h 30m");
        assert_eq!(fmt_hms(crate::vault::MAX_IDLE_SECS), "24h 0m");
    }

    #[test]
    fn top_level_chat_flags_are_accepted_without_the_chat_subcommand() {
        // Was `bug_top_level_chat_flags_rejected_without_explicit_chat_subcommand`,
        // which asserted the opposite (that these were rejected) as a known bug.
        // `Chat` is documented as the default subcommand — `command: None` runs
        // exactly like `simon chat` (see `main`'s `None` arm) — so a flag that only
        // worked once `chat` was spelled out explicitly was a papercut with no
        // safety property behind it worth preserving. Fixed by flattening
        // `ChatArgs` onto `Cli` itself; this asserts the flags parse *and* land in
        // the field `main`'s `None` arm actually reads, not just that parsing
        // succeeds.
        let cli = Cli::try_parse_from(["simon", "-m", "ollama:llama3"])
            .expect("top-level -m must be accepted without an explicit `chat` subcommand");
        assert!(
            cli.command.is_none(),
            "no subcommand was named, so none should have been selected"
        );
        assert_eq!(cli.chat.model.as_deref(), Some("ollama:llama3"));

        let cli = Cli::try_parse_from(["simon", "--vault"])
            .expect("top-level --vault must be accepted without an explicit `chat` subcommand");
        assert!(cli.command.is_none());
        assert!(cli.chat.vault);
    }

    #[test]
    fn auth_normalises_a_builtin_provider_name_so_discovery_can_find_the_stored_key() {
        // The bug: `canonical_provider`'s fallback arm returned its input
        // un-lowercased, so `simon auth ANTHROPIC` stored the key under the literal
        // string "ANTHROPIC" while `discover_vendors` (orchestrator.rs) only ever
        // asks the keyring for the lowercase canonical id "anthropic" — the key was
        // stored where lookup never looks, and the picker reported "(no key
        // stored)" forever regardless of how many times it was re-entered.
        let settings = Settings::default();
        assert_eq!(
            resolve_canonical_service("ANTHROPIC", &settings),
            "anthropic"
        );
        assert_eq!(
            resolve_canonical_service("OpenRouter", &settings),
            "openrouter"
        );
        // The alias arms already returned a correctly-cased id before this fix;
        // confirm they still do, whatever case the alias itself is typed in.
        assert_eq!(resolve_canonical_service("Claude", &settings), "anthropic");
        assert_eq!(resolve_canonical_service("GEMINI", &settings), "google");
    }

    #[test]
    fn auth_preserves_a_custom_endpoints_exact_name_case_and_all() {
        // The other half of the same function: a custom endpoint the user named
        // explicitly in config.json must keep that exact spelling, never routed
        // through the builtin alias/lowercasing path meant for the five builtins.
        let mut settings = Settings::default();
        settings.custom_endpoints.insert(
            "MyGateway".to_string(),
            crate::config::CloudEndpoint {
                api: crate::config::Api::OpenAiCompatible,
                base_url: "https://example.invalid/v1".into(),
                default_model: "some-model".into(),
            },
        );
        assert_eq!(
            resolve_canonical_service("MyGateway", &settings),
            "MyGateway"
        );
    }
}

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

#[cfg(test)]
mod cli_discovery_test;

#[cfg(test)]
mod copilot_stream_error_test;

#[cfg(test)]
mod action_argument_path_backslash_test;

#[cfg(test)]
mod action_argument_apostrophe_test;

#[cfg(test)]
mod action_argument_trailing_quote_test;

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
    /// for. This restores the user's own history, not the full transcript to a
    /// model: every transport call still has no message history. Only the
    /// commander's bounded previous reply is carried in the ledger; delegated
    /// models receive isolated task prompts.
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
    /// Drop the oldest lines from an existing vault down to a limit, on demand.
    ///
    /// Independent of the automatic cap `simon chat --vault` already applies to
    /// every clean exit (see `vault::MAX_TRANSCRIPT_LINES`) — this is for a user who
    /// wants to reclaim space or discard old history right now rather than wait for
    /// their next chat session. AUDIT-2026-07-30 §3.6 asked for exactly this.
    Prune {
        /// How many of the most recent lines to keep. Defaults to the same cap
        /// applied automatically on save.
        #[arg(long)]
        keep: Option<usize>,
    },
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
    if let Some((custom_name, _)) = settings
        .custom_endpoints
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(service))
    {
        // A custom endpoint literally named `gemini` or `claude` must keep that
        // exact name — only fall back to the builtin alias mapping (and the
        // lowercasing below) when no custom endpoint claims the raw name, or a
        // deliberately-named custom entry would be misfiled under an alias the
        // user's own `config.json` never used.
        custom_name.clone()
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
    let statuses = crate::orchestrator::candidate_statuses(&candidates, settings);

    println!("Models: ● connected/ready, ○ not connected, × connected but unavailable");
    for model in &statuses {
        let commander = if model.state.is_connected()
            && model.matches_commander(settings.commander.as_deref())
        {
            "  (commander)"
        } else {
            ""
        };
        let reason = model
            .reason
            .as_deref()
            .map(|reason| format!(" — {reason}"))
            .unwrap_or_default();
        println!(
            "  {} {} — {}{commander}{reason}",
            model.state.symbol(),
            model.label,
            model.state.description()
        );
    }
    if statuses.is_empty() {
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

    let candidates = crate::orchestrator::discover_candidates(&settings, classified).await;
    let model_statuses = crate::orchestrator::candidate_statuses(&candidates, &settings);
    let registry =
        Registry::build_discovered(&settings, model, classified, project_root, candidates)?;
    let primary = registry.primary().to_string();
    let roster = registry.labels();

    let mut app = App::new(primary, &roster, project_root.display().to_string());
    app.set_model_statuses(model_statuses);

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

/// Decides whether the "vault cap" notice should print, and what it says, from the
/// drop count alone. Pulled out of both call sites (load-time in
/// `vault_unlock_for_chat`, save-time in `vault_save_after_chat`) precisely because a
/// `dropped > 0` inlined at each site is untestable without going through a real
/// vault unlock or an interactive save — this way the comparison itself, the one
/// thing a mutation can flip to make the tool lie about whether it touched anything,
/// is pinned by a direct test. `subject`/`suffix` carry the two call sites' different
/// wording ("the saved transcript held" at load time vs. "this session's transcript
/// passed … before saving" at save time); everything else about the message is
/// identical.
fn cap_drop_notice(dropped: u64, cap: usize, subject: &str, suffix: &str) -> Option<String> {
    if dropped == 0 {
        return None;
    }
    Some(format!(
        "Notice: {subject} more than the {cap}-line vault cap, so the oldest \
         {dropped} line(s) were dropped (oldest first){suffix}; a marker line was \
         left in their place. Run `simon vault prune` to manage this by hand."
    ))
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
                        // Capped here, before merging in this session's fresh banner
                        // lines, so a vault that already exceeds the cap (an older
                        // build's file, or the cap having since been lowered) is
                        // trimmed on the way in rather than only at the next save —
                        // and the just-created banner lines are never at risk of
                        // being counted as "old" and dropped themselves.
                        let dropped = crate::vault::trim_transcript_to_cap(
                            &mut restored,
                            crate::vault::MAX_TRANSCRIPT_LINES,
                        );
                        if let Some(notice) = cap_drop_notice(
                            dropped,
                            crate::vault::MAX_TRANSCRIPT_LINES,
                            "the saved transcript held",
                            "",
                        ) {
                            println!("{notice}");
                        }
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
    // Capped on the way out, every save — this (not the load-time cap above) is what
    // actually bounds the vault's steady-state growth, since a session's own new
    // lines are exactly what pushes an already-capped transcript back over the line.
    // Cloned rather than trimmed in place: `transcript` is a borrow of the live
    // `App` the caller still owns (see the call site in `chat`), and this function
    // must not mutate what's on screen out from under it.
    let mut transcript = transcript.to_vec();
    let dropped =
        crate::vault::trim_transcript_to_cap(&mut transcript, crate::vault::MAX_TRANSCRIPT_LINES);
    if let Some(notice) = cap_drop_notice(
        dropped,
        crate::vault::MAX_TRANSCRIPT_LINES,
        "this session's transcript passed",
        " before saving",
    ) {
        println!("{notice}");
    }
    let transcript = transcript.as_slice();

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
        VaultCommand::Prune { keep } => vault_prune(paths, &vault, keep),
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

/// What `vault_prune` should do before it ever touches the terminal or the vault
/// file's contents, decided from two plain values: whether a vault file exists, and
/// the `--keep` the caller asked for. Split out of `vault_prune` itself so its two
/// guards — "no vault to prune" and "`--keep` must be positive" — are pinned by a
/// direct test. Inlined, both were only reachable by way of the interactive password
/// prompt a few lines below them, which a test cannot drive without a real terminal;
/// a mutation to either comparison would otherwise ship unnoticed (see the module's
/// audit note on `trim_transcript_to_cap` for why that shape is exactly the risk).
#[derive(Debug, PartialEq, Eq)]
enum PruneStart {
    /// No vault file; nothing to do, and not an error.
    NoVault,
    /// `--keep` was 0; refused before reading anything.
    KeepMustBePositive,
    /// Clear to proceed, with `--keep` resolved to the value actually in effect.
    Proceed(usize),
}

fn plan_prune_start(vault_exists: bool, keep: Option<usize>) -> PruneStart {
    if !vault_exists {
        return PruneStart::NoVault;
    }
    let keep = keep.unwrap_or(crate::vault::MAX_TRANSCRIPT_LINES);
    if keep == 0 {
        return PruneStart::KeepMustBePositive;
    }
    PruneStart::Proceed(keep)
}

/// What `vault_prune` should tell the user once the transcript is decrypted and
/// `keep` is known, decided from the drop count `trim_transcript_to_cap` already
/// computed on a preview clone. Split out for the same reason as `plan_prune_start`
/// above: `dropped == 0` gates whether a real, destructive confirmation prompt
/// appears at all, and that comparison needs to be reachable by a test without an
/// encrypted vault and a typed password in the way.
#[derive(Debug, PartialEq, Eq)]
enum PrunePlan {
    /// Already at or under `keep`; nothing would be discarded.
    NothingToDo(String),
    /// Discarding `dropped` of `total` lines requires confirmation; here is the
    /// notice to show before asking for it.
    WouldDiscard(String),
}

fn plan_prune_discard(dropped: u64, total: usize, keep: usize) -> PrunePlan {
    if dropped == 0 {
        return PrunePlan::NothingToDo(format!(
            "Transcript has {total} line(s), at or under the requested {keep}; nothing to \
             prune."
        ));
    }
    PrunePlan::WouldDiscard(format!(
        "This will permanently discard the oldest {dropped} of {total} line(s), oldest \
         first, keeping the most recent {keep}. This cannot be undone."
    ))
}

/// Whether a line typed at `vault_prune`'s confirmation prompt should be treated as
/// a decline — the default for anything that isn't an exact, trimmed `"yes"`. Named
/// for what it returns (a decline) rather than as `is_confirmed`, so the call site
/// reads as an early-exit guard (`if confirmation_declined(...) { return }`) without
/// needing its own `!`, which is exactly the operator a mutation flipped unnoticed
/// before this comparison had a test of its own.
fn confirmation_declined(raw: &str) -> bool {
    raw.trim() != "yes"
}

/// Drops the oldest lines from an existing vault down to `keep` (or
/// [`crate::vault::MAX_TRANSCRIPT_LINES`] if unspecified), independent of the
/// automatic cap `vault_save_after_chat` already applies on every clean `--vault`
/// exit. AUDIT-2026-07-30 §3.6 asked for exactly this alongside the automatic cap —
/// for a user who wants to reclaim space or discard old history right now, not on
/// their next chat session.
///
/// Requires the password: unlike `vault_status`/`vault_destroy`, which never decrypt
/// anything, pruning has to read the transcript to know what it would discard, then
/// rewrite the encrypted payload. Confirmation follows `vault_destroy`'s pattern —
/// state exactly what will be discarded, then require a typed `yes` — because the
/// dropped lines are exactly as unrecoverable as a full destroy, there are just fewer
/// of them.
fn vault_prune(paths: &Paths, vault: &EncryptedVault, keep: Option<usize>) -> Result<()> {
    let keep = match plan_prune_start(vault.exists(), keep) {
        PruneStart::NoVault => {
            println!(
                "No vault exists at {}; nothing to prune.",
                vault.path().display()
            );
            return Ok(());
        }
        PruneStart::KeepMustBePositive => {
            bail!(
                "--keep must be at least 1 (a 0-line vault is what `simon vault destroy` is for)"
            );
        }
        PruneStart::Proceed(keep) => keep,
    };

    let password = SecretString::from(
        rpassword::prompt_password("Vault password (input hidden): ")
            .context("failed to read the vault password from the terminal")?,
    );
    let bytes = match vault.load(&password) {
        Ok(bytes) => bytes,
        // Single attempt, not the retry loop `vault_unlock_for_chat` uses: this is a
        // one-shot admin command, not the start of a session, so a wrong password
        // just means "run it again" rather than needing its own loop.
        Err(VaultError::WrongPassword { remaining }) => {
            bail!("wrong password ({remaining} attempt(s) left before the vault self-destructs)")
        }
        Err(VaultError::Destroyed(reason)) => bail!("vault destroyed: {reason}"),
        Err(VaultError::Corrupt(msg)) => bail!("vault file is corrupt: {msg}"),
        Err(VaultError::Missing) => bail!("vault file disappeared before it could be read"),
    };
    let transcript: Vec<Line> = serde_json::from_slice(&bytes).context(
        "the saved transcript could not be parsed; refusing to prune a payload this build \
         cannot read back correctly",
    )?;
    let total = transcript.len();

    // Preview on a clone: state exactly what will be discarded *before* touching
    // anything on disk, and only ever write back the real thing once confirmed.
    let mut preview = transcript.clone();
    let dropped = crate::vault::trim_transcript_to_cap(&mut preview, keep);
    let notice = match plan_prune_discard(dropped, total, keep) {
        PrunePlan::NothingToDo(msg) => {
            println!("{msg}");
            return Ok(());
        }
        PrunePlan::WouldDiscard(msg) => msg,
    };

    println!("{notice}");
    print!("Type `yes` to confirm: ");
    std::io::Write::flush(&mut std::io::stdout()).context("failed to flush stdout")?;
    let mut confirmation = String::new();
    std::io::stdin()
        .read_line(&mut confirmation)
        .context("failed to read the confirmation from the terminal")?;
    if confirmation_declined(&confirmation) {
        println!("Not confirmed; leaving the vault in place.");
        return Ok(());
    }

    let payload = serde_json::to_vec(&preview)
        .context("failed to serialize the pruned transcript for the vault")?;
    vault.save(&payload, &password)?;
    println!("Pruned. Vault now holds {} line(s).", preview.len());
    // Best-effort, but surfaced — same reasoning as the equivalent audit calls in
    // `vault_destroy` and `vault_save_after_chat`: the prune itself has already
    // happened and must not be undone by an audit hiccup, but a corrupt-key failure
    // here (§3.5) is exactly the kind of thing a user needs to be told about.
    match AuditLogger::open(paths.audit_log.clone()) {
        Ok(mut audit) => {
            if let Err(e) = audit.log(
                "vault.pruned",
                &format!("kept={keep} dropped={dropped} total_before={total}"),
            ) {
                eprintln!("[audit] failed to record vault.pruned: {e}");
            }
        }
        Err(e) => eprintln!("[audit] failed to open the audit log to record vault.pruned: {e}"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::Speaker;

    #[test]
    fn vault_prune_parses_with_and_without_an_explicit_keep_count() {
        let cli = Cli::parse_from(["simon", "vault", "prune"]);
        match cli.command {
            Some(Commands::Vault {
                action: VaultCommand::Prune { keep },
            }) => assert_eq!(keep, None, "unset --keep must default inside vault_prune"),
            _ => panic!("expected the Vault Prune subcommand to have been parsed"),
        }

        let cli = Cli::parse_from(["simon", "vault", "prune", "--keep", "50"]);
        match cli.command {
            Some(Commands::Vault {
                action: VaultCommand::Prune { keep },
            }) => assert_eq!(keep, Some(50)),
            _ => panic!("expected the Vault Prune subcommand to have been parsed"),
        }
    }

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
    fn custom_endpoints_are_found_by_settings_endpoint_case_insensitively() {
        let mut settings = Settings::default();
        settings.custom_endpoints.insert(
            "my-gateway".to_string(),
            crate::config::CloudEndpoint {
                api: crate::config::Api::OpenAiCompatible,
                base_url: "https://example.invalid/v1".into(),
                default_model: "some-model".into(),
            },
        );
        assert!(
            settings.endpoint("MY-GATEWAY").is_some(),
            "settings.endpoint must resolve custom endpoints case-insensitively"
        );
    }

    #[test]
    fn auth_resolves_custom_endpoints_with_case_variations() {
        let mut settings = Settings::default();
        settings.custom_endpoints.insert(
            "my-gateway".to_string(),
            crate::config::CloudEndpoint {
                api: crate::config::Api::OpenAiCompatible,
                base_url: "https://example.invalid/v1".into(),
                default_model: "some-model".into(),
            },
        );
        let resolved = resolve_canonical_service("MY-GATEWAY", &settings);
        assert_eq!(
            resolved, "my-gateway",
            "must resolve case-insensitively to custom endpoint key"
        );
        assert!(settings.endpoint(&resolved).is_some());
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

    #[test]
    fn cap_drop_notice_is_silent_iff_nothing_was_dropped() {
        assert_eq!(
            cap_drop_notice(0, 2_000, "the saved transcript held", ""),
            None,
            "a `dropped` of 0 must not produce a notice at all"
        );

        let notice = cap_drop_notice(3, 2_000, "the saved transcript held", "")
            .expect("a nonzero `dropped` must produce a notice");
        assert!(
            notice.contains("the saved transcript held") && notice.contains("2000"),
            "notice must name the subject and the cap: {notice}"
        );
        assert!(
            notice.contains("oldest 3 line(s)"),
            "notice must name the exact drop count: {notice}"
        );

        // The two real call sites differ only in wording, carried through untouched.
        let save_notice = cap_drop_notice(
            1,
            2_000,
            "this session's transcript passed",
            " before saving",
        )
        .expect("a nonzero `dropped` must produce a notice");
        assert!(save_notice.contains("before saving"), "{save_notice}");
    }

    #[test]
    fn plan_prune_start_refuses_before_touching_a_missing_vault_or_a_zero_keep() {
        assert_eq!(plan_prune_start(false, None), PruneStart::NoVault);
        // A missing vault is checked first: an absurd `--keep` on a vault that isn't
        // even there must not surface as the wrong error.
        assert_eq!(plan_prune_start(false, Some(0)), PruneStart::NoVault);

        assert_eq!(
            plan_prune_start(true, Some(0)),
            PruneStart::KeepMustBePositive
        );
        assert_eq!(
            plan_prune_start(true, None),
            PruneStart::Proceed(crate::vault::MAX_TRANSCRIPT_LINES),
            "an unset --keep must default to the same cap the automatic trim uses"
        );
        assert_eq!(plan_prune_start(true, Some(7)), PruneStart::Proceed(7));
    }

    #[test]
    fn plan_prune_discard_is_a_no_op_notice_exactly_when_nothing_would_drop() {
        match plan_prune_discard(0, 10, 10) {
            PrunePlan::NothingToDo(msg) => assert!(msg.contains("10")),
            other => panic!("expected NothingToDo, got {other:?}"),
        }

        match plan_prune_discard(3, 10, 7) {
            PrunePlan::WouldDiscard(msg) => {
                assert!(msg.contains("oldest 3 of 10"), "{msg}");
                assert!(msg.contains("most recent 7"), "{msg}");
            }
            other => panic!("expected WouldDiscard, got {other:?}"),
        }
    }

    #[test]
    fn confirmation_declined_requires_an_exact_trimmed_yes() {
        assert!(
            !confirmation_declined("yes\n"),
            "trailing newline must be trimmed"
        );
        assert!(!confirmation_declined("yes"));
        assert!(confirmation_declined("no\n"));
        assert!(
            confirmation_declined(""),
            "an empty line must not count as consent"
        );
        assert!(
            confirmation_declined("Yes"),
            "must be exact, not case-folded — a stray typo must not confirm a destructive prune"
        );
    }

    #[test]
    fn vault_save_after_chat_actually_persists_the_transcript_for_reload() {
        // The stub this guards against (`vault_save_after_chat -> Ok(())`) would
        // report success without writing anything — no test of a helper function can
        // catch that, since the helper never runs. This drives the real function and
        // reads the encrypted file back to confirm the save actually happened.
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(dir.path().to_path_buf()).unwrap();
        let vault = EncryptedVault::new(paths.vault_file.clone());
        assert!(
            !vault.exists(),
            "fixture guard: nothing must exist before the save under test"
        );
        let password = SecretString::from("correct horse battery staple".to_string());
        let session = VaultSession {
            vault,
            password: password.clone(),
        };

        let transcript = vec![
            Line {
                speaker: Speaker::You,
                text: "hello".into(),
            },
            Line {
                speaker: Speaker::Model("anthropic:claude-opus-5".into()),
                text: "hi there".into(),
            },
        ];

        vault_save_after_chat(&paths, session, &transcript).expect("save must succeed");

        let reloaded_vault = EncryptedVault::new(paths.vault_file.clone());
        assert!(
            reloaded_vault.exists(),
            "the save must actually have created the vault file"
        );
        let bytes = reloaded_vault
            .load(&password)
            .expect("the saved vault must decrypt with the same password");
        let restored: Vec<Line> =
            serde_json::from_slice(&bytes).expect("the saved payload must be valid JSON");
        assert_eq!(
            restored.iter().map(Line::render).collect::<Vec<_>>(),
            transcript.iter().map(Line::render).collect::<Vec<_>>(),
            "the transcript actually written must match what was passed in"
        );
    }

    #[test]
    fn vault_command_dispatches_to_prune_and_propagates_its_zero_keep_refusal() {
        // Exercises the real `vault_command` dispatcher through to `vault_prune`'s
        // `--keep 0` guard, which fires before any password prompt or confirmation
        // read — the only branch reachable deterministically in a test, since
        // neither `rpassword` nor stdin can be faked here. A stub of either
        // `vault_command` or `vault_prune` to `-> Ok(())` would return success where
        // the real dispatch must bail.
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(dir.path().to_path_buf()).unwrap();
        let vault = EncryptedVault::new(paths.vault_file.clone());
        vault
            .save(b"placeholder", &SecretString::from("pw".to_string()))
            .unwrap();
        assert!(
            vault.exists(),
            "fixture guard: the vault must exist for `--keep 0` to be what's tested"
        );

        let err = vault_command(&paths, VaultCommand::Prune { keep: Some(0) })
            .expect_err("--keep 0 must be refused, not silently accepted");
        assert!(
            err.to_string().contains("--keep must be at least 1"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn reproduction_test_resolve_canonical_service_case_mismatch_for_custom_endpoints() {
        let mut settings = Settings::default();
        settings.custom_endpoints.insert(
            "MyGateway".to_string(),
            crate::config::CloudEndpoint {
                api: crate::config::Api::OpenAiCompatible,
                base_url: "https://example.invalid/v1".into(),
                default_model: "some-model".into(),
            },
        );
        settings.custom_endpoints.insert(
            "Claude".to_string(),
            crate::config::CloudEndpoint {
                api: crate::config::Api::Anthropic,
                base_url: "https://proxy.example.invalid".into(),
                default_model: "claude-custom".into(),
            },
        );

        assert_eq!(
            resolve_canonical_service("mygateway", &settings),
            "MyGateway",
            "lowercase input must resolve to the exact custom endpoint key MyGateway"
        );
        assert_eq!(
            resolve_canonical_service("MYGATEWAY", &settings),
            "MyGateway",
            "uppercase input must resolve to the exact custom endpoint key MyGateway"
        );
        assert_eq!(
            resolve_canonical_service("claude", &settings),
            "Claude",
            "custom endpoint Claude must not be redirected to builtin anthropic"
        );
    }
}

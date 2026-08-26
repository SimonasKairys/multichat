//! Append-only, tamper-evident local audit log.
//!
//! Each line is a JSON object carrying the previous line's MAC, so the file forms a
//! hash chain. The MAC is **keyed** — `HMAC-Blake2s256` under a per-install secret held
//! in the OS keyring — so an attacker who can write the log file cannot silently
//! recompute the chain without also extracting that key.
//!
//! This is a message authentication code, not a public-key signature: anyone able to
//! read the key can also forge entries, so it proves integrity against local tampering,
//! not non-repudiation to a third party.
//!
//! ## The tail-truncation gap, and why the fix is a hybrid
//!
//! A pure hash chain proves every entry follows its predecessor, but it proves nothing
//! about the chain's *length*: deleting the last N lines leaves a shorter file that
//! still walks cleanly from GENESIS. Four consecutive audits flagged this (see
//! `docs/AUDIT-2026-07-30.md` §3.3) because it matters in practice — `vault.unlock_failed`
//! entries are exactly what an attacker in progress wants to erase, and a suffix
//! deletion erases them without leaving a mark on what remains.
//!
//! The fix needs something outside the log file itself to anchor against. There are two
//! places to put that anchor, and they trade off very differently:
//!
//! 1. **A MAC'd sidecar file** (`<log path>.anchor`), rewritten on every [`log`](AuditLogger::log)
//!    call. It records the entry count and last entry's MAC, MAC'd with the same
//!    keyring-held key the log entries already use. An attacker who can edit the log
//!    file but cannot read that key can truncate the log, but cannot also produce a
//!    matching anchor — so `verify` catches the truncation. This is what closes the
//!    finding for the threat model this log already documents (README: anyone holding
//!    the key can forge entries; key-holders are out of scope). It costs one small local
//!    file write per entry, which is negligible next to the write the log entry itself
//!    already does.
//!
//! 2. **A keyring anchor**, synced only at [`open`](AuditLogger::open) and at
//!    [`Drop`] — not per entry. This is strictly a backstop for the sidecar: if an
//!    attacker deletes *both* the log and its sidecar, or rolls both back together to an
//!    older consistent pair (e.g. restoring from a stale backup), the sidecar alone has
//!    nothing left to compare against. The keyring entry, stored under a service name
//!    distinct from the existing MAC key (`"audit-anchor-hmac"` vs `"audit-hmac"`),
//!    survives that because it isn't a file at all.
//!
//!    It is deliberately *not* on the per-entry path. `Credentials::set` was measured on
//!    this machine at **30.7 ms per call** (20 calls, 614 ms total round-tripping through
//!    the OS keyring / Secret Service). `Orchestrator` calls `log()` from 23 call sites;
//!    anchoring every one of those in the keyring would add hundreds of milliseconds to
//!    a single turn for a guarantee the sidecar already provides in the common case. The
//!    keyring sync only needs to happen coarsely — once when a logger starts, once when
//!    it stops — to close the "both files gone" gap without paying that cost per entry.
//!
//! ## The keyring anchor is scoped per log, not global
//!
//! `SIMON_DATA_DIR` means a single machine can have many audit logs — a real one, a
//! per-project one, a throwaway test directory. An earlier version of this file kept
//! the keyring anchor under one fixed service name, which conflated all of them: a
//! brand-new, empty data directory would read back *another* log's anchor and get
//! accused of a truncation it never had, and the "never regress" rule (see
//! `sync_keyring_anchor`) meant neither log could recover on its own. `keyring_anchor_service`
//! now derives a distinct service name per log path, so each log gets its own entry.
//! The old fixed name (`LEGACY_KEYRING_ANCHOR_SERVICE`) is never read by this code any
//! more; `open()` best-effort deletes it so a stale value doesn't linger unexplained.
//!
//! ## Resetting an anchor is a deliberate, logged action
//!
//! `sync_keyring_anchor`'s "never regress" rule is exactly what makes the anchor worth
//! anything — but it also means a *legitimate* reason to shrink the log (an admin
//! deleting or trimming it on purpose, e.g. for retention) would otherwise leave
//! `simon audit` reporting truncation forever, with no way to clear it. An alarm that
//! can never be silenced is one people learn to ignore. [`AuditLogger::reset_anchor`]
//! is the escape hatch: it requires an explicit call (wired to `simon audit
//! --reset-anchor`, never automatic), and if the log still has entries at the time, it
//! records the reset itself as a new entry before re-baselining — so the reset is part
//! of the history it re-anchors, not a silent break in it.
//!
//! ## Crash safety
//!
//! `log()` appends to the log file **first**, then updates the sidecar anchor. If the
//! process dies in between, the file ends up one entry ahead of the anchor. That entry
//! required the MAC key to produce, so it cannot be an attacker's doing — `verify`
//! recognises this as benign lag, not tampering (see [`AnchorStatus`]). Writing the
//! anchor first would invert the failure mode: a crash there would leave the anchor
//! claiming an entry the file doesn't have yet, which is indistinguishable from an
//! attacker having truncated that entry away.
//!
//! ## Cross-process append locking (§3.5)
//!
//! `SIMON_DATA_DIR` names one log file, but nothing stops two `simon` processes from
//! opening it at once (two terminals, one `SIMON_DATA_DIR`). Each `AuditLogger` caches
//! the chain head (`last_mac`) in memory, so without locking, two processes each read
//! the same tail, each link their next entry to it, and the second write to land is a
//! second entry with the *same* `prev` — `verify()` reports that as a broken chain,
//! indistinguishable from tampering. This is the same failure mode the anchors exist to
//! catch, produced by concurrency instead of an attacker.
//!
//! [`log`](AuditLogger::log) closes this with an OS advisory lock on the log file
//! itself, taken with [`File::try_lock`]/[`File::lock`] — stabilised in Rust 1.89, no
//! extra dependency needed, and implemented on Linux, macOS *and* Windows, unlike
//! `flock`-only crates. Three decisions worth recording:
//!
//! * **What the lock covers.** The race isn't in the `write_all` call, it's between
//!   reading the chain head and writing the entry that links to it — so the lock has to
//!   span read-tail-through-append-through-sidecar-write as one critical section, not
//!   just the final write. `log()` acquires the lock before its first read and holds it
//!   until the sidecar anchor for that same entry has been written, so a second writer
//!   can never see a torn state (an appended entry whose anchor isn't there yet) or
//!   interleave its own entry between this one and its anchor.
//!
//! * **Re-read the head under the lock, every time, rather than lock for the logger's
//!   whole lifetime.** A lock is only half the fix: even serialised, a logger that
//!   trusts its in-memory `last_mac` from `open()` time still writes a broken link if
//!   another process appended since then. The alternative — hold the lock from `open()`
//!   to `Drop` — would fix that too, but it means a second `simon chat` in another
//!   terminal can never log anything for as long as the first is running, which is a
//!   worse failure than the extra read: `log()` already does one file read per call
//!   just to *append* (the `OpenOptions::open` below), so a second small read for the
//!   tail is not a new order of cost, and it's the only option that lets independent
//!   `simon` processes coexist at all.
//!
//! * **Advisory, not a lock-file's existence.** A `<log>.lock` file whose mere presence
//!   means "locked" needs something to delete it after a crash, or every subsequent run
//!   finds it still there and either hangs or refuses to log. `File::lock` is released
//!   by the OS the moment every file descriptor referencing it closes — including on
//!   process death, no cleanup code required. This is exactly the same trade the module
//!   docs above make for the keyring anchor over a plain marker file.
//!
//! **Contention** is bounded by [`APPEND_LOCK_TIMEOUT`], not blocked on forever and not
//! failed instantly: a legitimate concurrent writer holds the lock only for the length
//! of one `log()` call (microseconds), so a short wait resolves almost all contention,
//! but a bug that wedges a holder must not be able to hang every future caller
//! indefinitely. Timing out returns an `Err` from `log()` — the entry is never silently
//! dropped; the caller sees the failure and decides what to do with it, the same as any
//! other I/O error this function can already return.

use anyhow::{Context, Result, anyhow};
// Blake2 has a native keyed mode, so no separate HMAC construction is needed. `Blake2s256`
// (unkeyed) is used separately, only to derive a stable per-path keyring service name —
// see `keyring_anchor_service` — so it is not a security boundary, just a namespace.
use blake2::digest::{Digest, Mac};
use blake2::{Blake2s256, Blake2sMac256};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::Credentials;
use crate::security::LockedBuffer;

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const KEYRING_SERVICE: &str = "audit-hmac";
/// The pre-scoping keyring anchor entry: one fixed name shared by every log on the
/// machine, regardless of `SIMON_DATA_DIR`. See the module docs' "scoped per log, not
/// global" section for why that was a bug (a fresh data dir would inherit another
/// log's anchor and get accused of its truncation). Nothing in this file reads this
/// name any more — `keyring_anchor_service` derives a distinct name per log path
/// instead — so any leftover value here is inert; `open()` best-effort deletes it so
/// it doesn't sit around looking meaningful.
const LEGACY_KEYRING_ANCHOR_SERVICE: &str = "audit-anchor-hmac";

/// How long [`AuditLogger::log`] waits to acquire the cross-process append lock before
/// giving up — see the module docs' "cross-process append locking" section. A real
/// holder only keeps the lock for one `log()` call (microseconds), so this is sized to
/// absorb ordinary scheduling jitter under load, not to make a wedged holder wait
/// tolerable.
///
/// One value for tests and production alike, deliberately.
///
/// Tests used to get a 200 ms variant so the deliberate-contention test would not spend
/// real seconds proving a timeout happens. That made the *other* lock test flaky in
/// exactly the conditions this lock exists for: under `cargo mutants`, which runs the
/// suite with several jobs in parallel, two worker processes appending 40 entries each
/// legitimately needed longer than 200 ms and one of them was refused. A test that only
/// passes on an idle machine is not evidence about a contended one, and the second-order
/// cost — a suite that fails depending on machine load — is worse than a few seconds.
///
/// A legitimate writer stalled by disk or scheduler pressure should get a fair chance to
/// finish before this process gives up on it, and giving up means refusing to record an
/// audit entry, which is the outcome worth spending seconds to avoid.
const APPEND_LOCK_TIMEOUT: Duration = Duration::from_secs(5);

/// Poll interval while waiting for the append lock. `std::fs::File::lock` blocks with
/// no way to attach a timeout, so the wait below is a `try_lock` poll loop instead —
/// this is how often it retries.
const APPEND_LOCK_POLL_INTERVAL: Duration = Duration::from_millis(5);

/// One line of the log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub ts: u64,
    pub action: String,
    pub details: String,
    /// MAC of the preceding entry (or the genesis constant for the first).
    pub prev: String,
    /// MAC over `(prev, ts, action, details)`.
    pub mac: String,
}

/// The payload the MAC is computed over. Serialised through a struct with a fixed field
/// order so the bytes are deterministic — the previous implementation concatenated with
/// `|`, which could be forged by embedding a `|` in `action` or `details`.
#[derive(Serialize)]
struct MacPayload<'a> {
    prev: &'a str,
    ts: u64,
    action: &'a str,
    details: &'a str,
}

/// The sidecar/keyring anchor record: "the log had this many entries, and the last one's
/// MAC was this." Both fields are covered by `mac` below, computed with the same key as
/// log entries — see the module docs for why there are two of these (sidecar + keyring)
/// and why only one is on the per-entry path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Anchor {
    count: u64,
    last_mac: String,
    /// MAC over `(count, last_mac)`. Without this, an attacker who can write the
    /// sidecar file could truncate the log and then simply rewrite the anchor to match.
    mac: String,
}

#[derive(Serialize)]
struct AnchorPayload<'a> {
    count: u64,
    last_mac: &'a str,
}

/// What [`AuditLogger::verify`] concluded about the anchor, beyond the raw entry count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorStatus {
    /// The anchor matches the log's current tail exactly, or the log legitimately
    /// extends it (see the module docs' crash-safety section) — nothing to report.
    Current,
    /// No anchor exists anywhere (sidecar file absent, and no keyring anchor either)
    /// even though the log is non-empty. This is reported as a **warning**, not a hard
    /// failure — the chain itself is still fully verified either way; what's missing
    /// is only the ability to detect that a suffix was removed.
    ///
    /// In a real `open()`-based run this is harder to reach than it sounds: `open()`
    /// runs `sync_keyring_anchor()` before `verify()` is ever called, and that sync
    /// adopts whatever is currently on disk into a fresh keyring anchor the first time
    /// it sees a log with none — so a log that predates this feature is usually
    /// blessed as `Current` on first contact, not reported as `Missing`. That
    /// first-contact bootstrap is unavoidable (there is nothing to compare against
    /// before an anchor has ever been written), but it means this variant is mostly
    /// seen with a `with_key`-built logger (no keyring at all — every test) or when
    /// the keyring write in that bootstrap sync itself fails (e.g. no Secret Service
    /// running), not as an everyday state of a working install.
    Missing,
    /// A sidecar anchor file exists but could not be parsed — e.g. a 0-byte or
    /// partially-written file left by a process that crashed mid-`write_sidecar_anchor`.
    /// This is reported as a **warning**, like `Missing`, not a hard failure: the
    /// chain itself is still fully verified either way, and there is no basis to call
    /// this tampering (a *tampered* anchor is syntactically valid JSON whose MAC
    /// doesn't check out — that's an active forgery attempt, which is a hard failure;
    /// this file couldn't even be parsed, which is what an interrupted write looks
    /// like). It is also not the same claim as `Missing`: an anchor file *was* found
    /// here, it just isn't usable as evidence — collapsing the two would tell an
    /// operator "no anchor was ever written" when the truer statement is "one was
    /// written but this run can't read it". If a valid keyring anchor is also
    /// available, it is used as the reference and this variant is not reported —
    /// there is nothing to warn about when a working anchor still confirmed the tail.
    Unreadable,
}

/// The result of walking the chain and comparing it against its anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyReport {
    pub entries: usize,
    pub anchor: AnchorStatus,
}

pub struct AuditLogger {
    path: PathBuf,
    /// Sidecar anchor path. Defaults to `<path>.anchor`; overridable only for tests
    /// (see `with_key_and_anchor`) so a test can point two loggers at distinct anchor
    /// files, or inspect/corrupt one at a known location, without touching `path`.
    anchor_path: PathBuf,
    last_mac: String,
    count: u64,
    /// The keyed-Blake2s MAC secret, 32 bytes. `LockedBuffer` (see `security.rs`) is
    /// the same wrapper `vault::derive_key` uses for encryption key material: it
    /// zeroizes the bytes on drop and best-effort `mlock`s them so this secret does
    /// not linger in freed heap memory or get written to swap for the lifetime of the
    /// process, same as every other key in this crate. Before this, `key` was a plain
    /// `Vec<u8>` — Rust gives no guarantee a `Vec`'s backing allocation is cleared on
    /// drop, so the MAC key (and everything an attacker could forge with it) could sit
    /// in a freed heap page or a swapped-out one indefinitely.
    key: LockedBuffer,
    /// Snapshot of the keyring anchor, read at `open()` and advanced (never
    /// regressed — see `sync_keyring_anchor`) at `open()` and at `Drop`. Always `None`
    /// when `use_keyring_anchor` is false, so `with_key`/`with_key_and_anchor`-built
    /// loggers (i.e. every test) never touch the OS keyring.
    keyring_anchor: Option<Anchor>,
    use_keyring_anchor: bool,
}

impl AuditLogger {
    /// Opens (or starts) the log, recovering the chain head from the existing file.
    ///
    /// The previous implementation always restarted from the genesis hash, which meant
    /// the chain was per-process rather than per-history.
    pub fn open(path: PathBuf) -> Result<Self> {
        let key = LockedBuffer::new(load_or_create_key()?);
        let (count, last_mac) = read_chain_tail(&path)?;
        let last_mac = last_mac.unwrap_or_else(|| GENESIS.to_string());
        let anchor_path = default_anchor_path(&path);
        // Tidy up the pre-scoping global anchor entry — see `LEGACY_KEYRING_ANCHOR_SERVICE`.
        // Best-effort: a keyring that can't delete (or has no such entry) must not
        // block opening the logger.
        let _ = Credentials::delete(LEGACY_KEYRING_ANCHOR_SERVICE);
        let keyring_anchor = read_keyring_anchor(&path);
        let mut logger = Self {
            path,
            anchor_path,
            last_mac,
            count,
            key,
            keyring_anchor,
            use_keyring_anchor: true,
        };
        // Coarse-cadence sync #1: pick up wherever a previous (possibly crashed)
        // process left off. See `sync_keyring_anchor` for why this can never regress
        // or paper over a truncated log.
        logger.sync_keyring_anchor();
        Ok(logger)
    }

    /// Builds a logger with an explicit key, bypassing the keyring entirely — including
    /// the coarse-cadence keyring anchor. For tests: CI runs on platforms with no
    /// Secret Service daemon, so nothing under `with_key` may depend on one. The sidecar
    /// anchor still works normally, since it's a plain file next to the log.
    pub fn with_key(path: PathBuf, key: Vec<u8>) -> Result<Self> {
        let (count, last_mac) = read_chain_tail(&path)?;
        let last_mac = last_mac.unwrap_or_else(|| GENESIS.to_string());
        let anchor_path = default_anchor_path(&path);
        Ok(Self {
            path,
            anchor_path,
            last_mac,
            count,
            key: LockedBuffer::new(key),
            keyring_anchor: None,
            use_keyring_anchor: false,
        })
    }

    /// Like `with_key`, but with the sidecar anchor at an explicit path instead of the
    /// default `<path>.anchor`. Test-only: lets a test construct specific anchor
    /// states (missing, tampered, lagging) at a location it controls, still without a
    /// working keyring.
    #[cfg(test)]
    fn with_key_and_anchor(path: PathBuf, key: Vec<u8>, anchor_path: PathBuf) -> Result<Self> {
        let (count, last_mac) = read_chain_tail(&path)?;
        let last_mac = last_mac.unwrap_or_else(|| GENESIS.to_string());
        Ok(Self {
            path,
            anchor_path,
            last_mac,
            count,
            key: LockedBuffer::new(key),
            keyring_anchor: None,
            use_keyring_anchor: false,
        })
    }

    fn mac(&self, prev: &str, ts: u64, action: &str, details: &str) -> Result<String> {
        let payload = serde_json::to_vec(&MacPayload {
            prev,
            ts,
            action,
            details,
        })?;
        let mut mac = <Blake2sMac256 as Mac>::new_from_slice(self.key.as_slice())
            .map_err(|e| anyhow!("invalid audit key length: {e}"))?;
        mac.update(&payload);
        Ok(hex(&mac.finalize().into_bytes()))
    }

    fn anchor_mac(&self, count: u64, last_mac: &str) -> Result<String> {
        let payload = serde_json::to_vec(&AnchorPayload { count, last_mac })?;
        let mut mac = <Blake2sMac256 as Mac>::new_from_slice(self.key.as_slice())
            .map_err(|e| anyhow!("invalid audit key length: {e}"))?;
        mac.update(&payload);
        Ok(hex(&mac.finalize().into_bytes()))
    }

    fn build_anchor(&self, count: u64, last_mac: &str) -> Result<Anchor> {
        Ok(Anchor {
            count,
            last_mac: last_mac.to_string(),
            mac: self.anchor_mac(count, last_mac)?,
        })
    }

    fn anchor_is_valid(&self, anchor: &Anchor) -> bool {
        self.anchor_mac(anchor.count, &anchor.last_mac)
            .map(|recomputed| recomputed == anchor.mac)
            .unwrap_or(false)
    }

    /// Appends an event, linking it to the current chain head.
    ///
    /// Locked end-to-end against other writers — see the module docs'
    /// "cross-process append locking" section for why the lock has to cover
    /// read-tail-through-sidecar-write as one unit, and why the head is re-read from
    /// disk here rather than trusted from `self.last_mac`.
    pub fn log(&mut self, action: &str, details: &str) -> Result<()> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("failed to open audit log {}", self.path.display()))?;
        // Everything below, up to `file` going out of scope at the end of this
        // function, runs under this exclusive lock. Releasing it is just letting
        // `file` drop — see `lock_exclusive_with_timeout` for why that (an advisory
        // lock tied to the fd) is the point, not an afterthought.
        lock_exclusive_with_timeout(&file, &self.path)?;

        // Re-read the chain tail from disk now that the lock is held, instead of
        // trusting `self.last_mac`/`self.count`: those can be stale the instant
        // another process (or another `AuditLogger` on this same path) has appended
        // since this logger last read the file.
        let (count, last_mac) = read_chain_tail_from(
            file.try_clone()
                .context("failed to duplicate the audit log handle to read its tail")?,
        )?;
        let last_mac = last_mac.unwrap_or_else(|| GENESIS.to_string());

        let mac = self.mac(&last_mac, ts, action, details)?;
        let entry = AuditEntry {
            ts,
            action: action.to_string(),
            details: details.to_string(),
            prev: last_mac,
            mac: mac.clone(),
        };

        let mut line = serde_json::to_string(&entry)?;
        line.push('\n');

        // Append to the log FIRST — see the module docs' crash-safety section for why
        // this order, and not the reverse, is the one that fails safe.
        file.write_all(line.as_bytes())
            .with_context(|| format!("failed to append to {}", self.path.display()))?;
        file.flush()?;

        self.count = count + 1;
        self.last_mac = mac.clone();

        // Then the sidecar anchor, still inside the same locked section — so a second
        // writer's entry can never land between this entry and its anchor. This is a
        // small local write, not a keyring round trip, so it's cheap enough to do on
        // every entry — this is what actually closes the truncation finding day to
        // day; the keyring anchor is only the backstop for losing both files at once
        // (see module docs).
        self.write_sidecar_anchor(self.count, &mac)
    }

    fn write_sidecar_anchor(&self, count: u64, last_mac: &str) -> Result<()> {
        let anchor = self.build_anchor(count, last_mac)?;
        let json = serde_json::to_string(&anchor)?;
        std::fs::write(&self.anchor_path, json).with_context(|| {
            format!(
                "failed to write audit anchor {}",
                self.anchor_path.display()
            )
        })
    }

    /// Advances the keyring anchor to this logger's current `(count, last_mac)` — but
    /// only when that state is a legitimate extension of whatever is already there.
    /// Called at `open()` (so a long-lived process picks up wherever a previous,
    /// possibly crashed, one left off) and from `Drop` (so closing the logger normally
    /// commits this session's writes). Never called per entry — see the module docs
    /// for the 30.7 ms/call measurement that rules that out.
    ///
    /// This never overwrites a keyring anchor this process cannot prove is a prefix of
    /// its own history. Blindly writing `(self.count, self.last_mac)` on every open
    /// would let an attacker truncate the log, then simply run `simon audit` (which
    /// opens a logger) to "heal" the keyring anchor to match the doctored file —
    /// erasing the one piece of evidence outside the attacker's reach.
    fn sync_keyring_anchor(&mut self) {
        if !self.use_keyring_anchor {
            return;
        }
        let Ok(candidate) = self.build_anchor(self.count, &self.last_mac) else {
            return; // Never let anchor bookkeeping fail an open() or a Drop.
        };

        let should_write = match &self.keyring_anchor {
            None => true,
            // Existing anchor doesn't even authenticate itself — it was tampered with.
            // Leave it in place as evidence rather than overwriting it.
            Some(existing) if !self.anchor_is_valid(existing) => false,
            Some(existing) => {
                self.count >= existing.count
                    && mac_at_position(&self.path, existing.count)
                        .ok()
                        .flatten()
                        .as_deref()
                        == Some(existing.last_mac.as_str())
            }
        };

        if should_write {
            let json = match serde_json::to_string(&candidate) {
                Ok(j) => j,
                Err(_) => return,
            };
            if Credentials::set(&keyring_anchor_service(&self.path), &json).is_ok() {
                self.keyring_anchor = Some(candidate);
            }
        }
    }

    /// Unconditionally overwrites the keyring anchor with this logger's current
    /// `(count, last_mac)`, bypassing `sync_keyring_anchor`'s "never regress" check.
    /// Only ever called from [`reset_anchor`](Self::reset_anchor), where bypassing
    /// that check is the entire point — everywhere else, going around it would let an
    /// attacker heal a truncated log's anchor to match the doctored file.
    fn force_write_keyring_anchor(&mut self) {
        if !self.use_keyring_anchor {
            return;
        }
        let Ok(candidate) = self.build_anchor(self.count, &self.last_mac) else {
            return;
        };
        let Ok(json) = serde_json::to_string(&candidate) else {
            return;
        };
        if Credentials::set(&keyring_anchor_service(&self.path), &json).is_ok() {
            self.keyring_anchor = Some(candidate);
        }
    }

    /// Wipes both anchors outright rather than re-baselining them to a state. Used by
    /// [`reset_anchor`](Self::reset_anchor) when the log itself no longer exists, so
    /// there is nothing to re-baseline *to* — the next `log()` call starts a fresh
    /// chain from genesis, and should not immediately find a stale anchor claiming
    /// entries that chain never had.
    fn clear_anchors(&mut self) {
        let _ = std::fs::remove_file(&self.anchor_path);
        if self.use_keyring_anchor {
            let _ = Credentials::delete(&keyring_anchor_service(&self.path));
        }
        self.keyring_anchor = None;
    }

    /// Explicitly discards the tamper-evidence anchors for this log and re-baselines
    /// them to whatever is on disk right now. This is deliberately **not** something
    /// `verify()` or `sync_keyring_anchor` can do on their own — see the module docs'
    /// "resetting an anchor" section for why that matters: a legitimate admin action
    /// (deleting or trimming the log on purpose) would otherwise leave `simon audit`
    /// reporting truncation with no way to clear it. Wired to `simon audit
    /// --reset-anchor`, which requires the caller to ask for this by name.
    ///
    /// Does not pre-read the chain head into `self.count`/`self.last_mac` before
    /// calling `log()` below — the whole point of this method is responding to the
    /// file having changed since it was opened (that's exactly what "an admin deleted
    /// or trimmed it" means), and `log()` itself now always re-reads the true head
    /// from disk under its append lock rather than trusting this logger's in-memory
    /// state (see its doc comment), so a separate pre-read here would just be the same
    /// work done twice. If the log still exists, the reset is recorded as a new entry
    /// before the keyring anchor is re-baselined, so the reset itself is on the record
    /// rather than a silent break in it; if the log is gone entirely, both anchors are
    /// simply cleared, since there is no chain left to append a record to.
    pub fn reset_anchor(&mut self, reason: &str) -> Result<()> {
        if self.path.exists() {
            self.log("audit.anchor_reset", reason)?;
            self.force_write_keyring_anchor();
        } else {
            // The chain itself starts over from genesis too — not just the anchors —
            // otherwise the next `log()` call would link its first entry to this
            // logger's stale in-memory head instead of GENESIS, and immediately fail
            // its own chain walk against the brand-new file it just created.
            self.count = 0;
            self.last_mac = GENESIS.to_string();
            self.clear_anchors();
        }
        Ok(())
    }

    /// Walks the whole file, verifying every link, then compares the result against
    /// the anchor(s). See [`AnchorStatus`] and the module docs for what each outcome
    /// means; the pre-existing "broken at entry N" / "has been modified" errors below
    /// are unchanged — they catch tampering *within* the retained entries, which the
    /// anchor comparison that follows cannot see.
    pub fn verify(&self) -> Result<VerifyReport> {
        let mut expected_prev = GENESIS.to_string();
        let mut count = 0u64;
        // mac_history[i] is the mac of the (i+1)-th entry — lets the anchor comparison
        // below find "the mac of entry N" without a second pass over the file.
        let mut mac_history: Vec<String> = Vec::new();

        match File::open(&self.path) {
            Ok(file) => {
                for (idx, line) in BufReader::new(file).lines().enumerate() {
                    let line = line?;
                    if line.trim().is_empty() {
                        continue;
                    }
                    let entry: AuditEntry = serde_json::from_str(&line)
                        .with_context(|| format!("audit entry {} is not valid JSON", idx + 1))?;

                    if entry.prev != expected_prev {
                        return Err(anyhow!(
                            "audit chain broken at entry {}: expected prev {}, found {}",
                            idx + 1,
                            expected_prev,
                            entry.prev
                        ));
                    }
                    let recomputed =
                        self.mac(&entry.prev, entry.ts, &entry.action, &entry.details)?;
                    if recomputed != entry.mac {
                        return Err(anyhow!(
                            "audit entry {} has been modified (MAC mismatch)",
                            idx + 1
                        ));
                    }
                    expected_prev = entry.mac.clone();
                    mac_history.push(entry.mac);
                    count += 1;
                }
            }
            // A missing log is NOT automatically clean — do not turn this back into an
            // early `Ok(0)` return. Deleting the whole file is tail truncation taken to
            // its limit: strictly easier for an attacker than trimming the last few
            // lines, and if an anchor survived (sidecar or keyring), it still records
            // that entries once existed. Falling through with `count = 0` and an empty
            // `mac_history` lets the anchor comparison below catch that case as
            // truncation via the existing `reference.count > count` branch. The
            // legitimate first-run case (no log AND no anchor) still resolves to
            // `AnchorStatus::Current` below, because `reference` is `None` then.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).context("failed to open audit log for verification"),
        }

        let sidecar_corrupt;
        let sidecar = match read_sidecar_anchor(&self.anchor_path)? {
            SidecarAnchor::Present(anchor) if !self.anchor_is_valid(&anchor) => {
                return Err(anyhow!(
                    "audit anchor file has been tampered with (MAC mismatch)"
                ));
            }
            SidecarAnchor::Present(anchor) => {
                sidecar_corrupt = false;
                Some(anchor)
            }
            SidecarAnchor::Corrupt => {
                sidecar_corrupt = true;
                None
            }
            SidecarAnchor::Absent => {
                sidecar_corrupt = false;
                None
            }
        };
        let keyring = self
            .keyring_anchor
            .as_ref()
            .filter(|anchor| self.anchor_is_valid(anchor));

        // Prefer whichever valid anchor has seen more entries — that's the one closer
        // to the true history. `sync_keyring_anchor` only ever advances the keyring
        // anchor when it's a proven extension of what was already there, so trusting
        // the higher count here is safe rather than just "bigger number wins".
        let reference = match (&sidecar, keyring) {
            (Some(s), Some(k)) if k.count > s.count => Some(k),
            (Some(s), _) => Some(s),
            (None, Some(k)) => Some(k),
            (None, None) => None,
        };

        let Some(reference) = reference else {
            return Ok(VerifyReport {
                entries: count as usize,
                anchor: if sidecar_corrupt {
                    // A corrupt sidecar is worth reporting even over `Missing`: an
                    // anchor file *was* found, it just couldn't be read as one. A
                    // keyring anchor (if any) already took priority above via
                    // `reference`, so reaching here means there was truly nothing
                    // usable to compare against.
                    AnchorStatus::Unreadable
                } else if count > 0 {
                    AnchorStatus::Missing
                } else {
                    AnchorStatus::Current
                },
            });
        };

        if reference.count > count {
            return Err(anyhow!(
                "audit log tail truncated: the anchor recorded {} entries but the log now has only {}",
                reference.count,
                count
            ));
        }
        let mac_at_reference = if reference.count == 0 {
            GENESIS.to_string()
        } else {
            mac_history[(reference.count - 1) as usize].clone()
        };
        if mac_at_reference != reference.last_mac {
            return Err(anyhow!(
                "audit log tail truncated: entry {} does not match the anchor's recorded MAC — the tail was cut and replaced",
                reference.count
            ));
        }

        Ok(VerifyReport {
            entries: count as usize,
            anchor: AnchorStatus::Current,
        })
    }
}

impl Drop for AuditLogger {
    fn drop(&mut self) {
        // Coarse-cadence sync #2: commit this session's writes to the keyring anchor
        // on close. No-ops immediately when `use_keyring_anchor` is false.
        self.sync_keyring_anchor();
    }
}

/// Acquires an exclusive advisory lock on `file`, waiting up to [`APPEND_LOCK_TIMEOUT`].
///
/// `std::fs::File::lock` blocks with no built-in way to bound the wait, so this polls
/// `try_lock` instead — the only portable way to get a timeout without a second thread
/// or an extra dependency. On success the lock is held by `file` until it is dropped or
/// explicitly unlocked; on timeout, nothing has been written and the caller gets an
/// `Err` instead of `log()` either hanging forever or silently no-oping.
fn lock_exclusive_with_timeout(file: &File, path: &Path) -> Result<()> {
    let start = std::time::Instant::now();
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(()),
            Err(std::fs::TryLockError::Error(e)) => {
                return Err(e).with_context(|| {
                    format!("failed to lock audit log {} for appending", path.display())
                });
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                if start.elapsed() >= APPEND_LOCK_TIMEOUT {
                    return Err(anyhow!(
                        "timed out after {:?} waiting for the audit log lock on {} — \
                         another simon process is appending to it. If that process \
                         crashed while holding the lock, the OS releases it \
                         automatically on exit, so retrying should succeed.",
                        APPEND_LOCK_TIMEOUT,
                        path.display()
                    ));
                }
                std::thread::sleep(APPEND_LOCK_POLL_INTERVAL);
            }
        }
    }
}

/// Reads the entry count and the `mac` field of the final entry, in one pass, so a new
/// process both continues the chain and knows how many entries came before it.
fn read_chain_tail(path: &Path) -> Result<(u64, Option<String>)> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((0, None)),
        Err(e) => return Err(e).context("failed to read audit log"),
    };
    read_chain_tail_from(file)
}

/// Reads the tail from an already-open handle.
///
/// `log` must use this rather than [`read_chain_tail`], and the distinction is a
/// platform one that cost a red Windows build. `flock` on Unix is advisory and attaches
/// to the open file description, so a second handle on the same path reads straight
/// through a lock this process holds. Windows' `LockFileEx`, which `File::lock` maps to,
/// is **mandatory** and locks a byte range against every other handle — including
/// another handle in the same process. Opening the file again to read the tail while
/// holding the append lock therefore worked on Linux and macOS and failed on Windows
/// with a lock violation. Reading through the locking handle itself is correct
/// everywhere: a handle may always read the range it owns.
fn read_chain_tail_from(mut file: File) -> Result<(u64, Option<String>)> {
    // The handle is opened for append, so the write position is pinned to the end
    // regardless of where reading leaves the cursor — seeking back to the start to read
    // cannot misplace the append that follows.
    file.seek(SeekFrom::Start(0))
        .context("failed to rewind the audit log before reading its tail")?;
    let mut count = 0u64;
    let mut last = None;
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: AuditEntry = serde_json::from_str(&line)
            .context("audit log contains a malformed entry; refusing to append to it")?;
        last = Some(entry.mac);
        count += 1;
    }
    Ok((count, last))
}

/// Returns the `mac` field of the n-th entry (1-indexed), or `None` if the file has
/// fewer than `n` entries. `n == 0` trivially resolves to the genesis constant. Used
/// only by the coarse-cadence keyring sync — `verify()` gets the equivalent value for
/// free from the chain walk it already does.
fn mac_at_position(path: &Path, n: u64) -> Result<Option<String>> {
    if n == 0 {
        return Ok(Some(GENESIS.to_string()));
    }
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).context("failed to read audit log"),
    };
    let mut seen = 0u64;
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        seen += 1;
        if seen == n {
            let entry: AuditEntry =
                serde_json::from_str(&line).context("audit log contains a malformed entry")?;
            return Ok(Some(entry.mac));
        }
    }
    Ok(None)
}

/// The sidecar anchor path for a given log path: `<path>.anchor`.
fn default_anchor_path(log_path: &Path) -> PathBuf {
    let mut s = log_path.as_os_str().to_owned();
    s.push(".anchor");
    PathBuf::from(s)
}

/// What was found at the sidecar anchor path. Distinct from `Option<Anchor>` so a
/// present-but-unparseable file (see `AnchorStatus::Unreadable`) can be told apart
/// from a genuinely absent one instead of both collapsing to `None` — `verify()`
/// needs that distinction to report the honest state rather than claiming "no
/// anchor was ever written" about a file that's sitting right there, corrupt.
enum SidecarAnchor {
    Absent,
    Corrupt,
    Present(Anchor),
}

fn read_sidecar_anchor(anchor_path: &Path) -> Result<SidecarAnchor> {
    match std::fs::read_to_string(anchor_path) {
        // A parse failure here is not propagated as an `Err`: unlike a real I/O error,
        // it's the expected shape of a crash-interrupted write (0-byte or truncated
        // JSON), not something the caller should have `verify()` abort over. See
        // `AnchorStatus::Unreadable`.
        Ok(s) => Ok(match serde_json::from_str(&s) {
            Ok(anchor) => SidecarAnchor::Present(anchor),
            Err(_) => SidecarAnchor::Corrupt,
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(SidecarAnchor::Absent),
        Err(e) => Err(e).context("failed to read audit anchor file"),
    }
}

fn read_keyring_anchor(log_path: &Path) -> Option<Anchor> {
    use secrecy::ExposeSecret;
    let secret = Credentials::get(&keyring_anchor_service(log_path))
        .ok()
        .flatten()?;
    serde_json::from_str(secret.expose_secret()).ok()
}

/// Derives a keyring service name scoped to a specific log file, so multiple data
/// dirs (`SIMON_DATA_DIR`) each get their own anchor instead of one clobbering
/// another's — see the module docs' "scoped per log, not global" section. Canonicalizing
/// the parent directory before hashing means the same directory reached via a
/// different (e.g. symlinked) path still resolves to the same identity; the parent is
/// expected to exist by the time any `AuditLogger` is built (`Paths::from_data_dir`
/// creates it), but if canonicalization fails anyway (e.g. a permissions error),
/// falling back to the path as given is still safe — at worst this process just won't
/// find a previous anchor filed under the canonical form, which `verify()` treats as
/// "no anchor yet" (see `AnchorStatus::Missing`), not as tampering.
fn keyring_anchor_service(log_path: &Path) -> String {
    let parent = log_path.parent().unwrap_or_else(|| Path::new("."));
    let canonical_parent = std::fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
    let file_name = log_path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("audit.log"));
    let identity = canonical_parent.join(file_name);

    let mut hasher = Blake2s256::new();
    hasher.update(identity.to_string_lossy().as_bytes());
    format!("audit-anchor-hmac-{}", hex(&hasher.finalize()))
}

/// What to do with whatever `Credentials::get(KEYRING_SERVICE)` returned. Split out
/// from `load_or_create_key` as a pure function of `Option<&str>` — no keyring I/O —
/// so the "generate on first run" vs. "reject a corrupt existing value" decision is
/// testable without a working keyring daemon; CI runs on Windows and macOS images with
/// no Secret Service.
#[derive(Debug)]
enum KeyDecision {
    UseExisting(Vec<u8>),
    GenerateNew,
}

/// `None` (no entry yet) always means "generate a fresh key" — a legitimate first run.
/// `Some` runs the existing value through [`validate_key`]; a value that fails
/// validation is an `Err`, never treated as absent.
fn decide_key(existing: Option<&str>) -> Result<KeyDecision> {
    match existing {
        None => Ok(KeyDecision::GenerateNew),
        Some(s) => validate_key(s).map(KeyDecision::UseExisting),
    }
}

/// Validates a keyring-stored value as a usable 32-byte MAC key.
///
/// The previous implementation only rejected non-hex values (via `?`); a value that
/// was valid hex but the wrong length fell through and silently minted + stored a
/// brand-new key. The MAC key is the only thing that makes the audit log verifiable,
/// so that silently destroyed the ability to verify every entry ever written — and did
/// so with no message, at startup. An attacker able to write a short value into the
/// keyring (without being able to read the real key) could use that to invalidate the
/// whole audit history and make it look like ordinary corruption. A tamper-evidence
/// system must never rotate its own key without being told to — see the module docs'
/// "resetting an anchor is a deliberate, logged action" section for the same principle
/// applied to the anchor.
fn validate_key(existing: &str) -> Result<Vec<u8>> {
    let decoded = unhex(existing).context("audit key in keyring is not valid hex")?;
    if decoded.len() != 32 {
        // Report the length only — never `existing` or `decoded`. The length alone is
        // enough to diagnose the problem; the bytes are key material (or close enough
        // to it) and have no business in an error string that might end up in a
        // terminal scrollback or a bug report.
        return Err(anyhow!(
            "the audit MAC key stored in the OS keyring (service {KEYRING_SERVICE:?}) \
             is {} bytes long, not the required 32 — this is not a key `simon` wrote. \
             Refusing to silently generate and store a replacement: that would make \
             every existing audit entry permanently unverifiable, with no warning. If \
             you intend to accept that loss (e.g. restoring a keyring from a different \
             install, or recovering from manual tampering with the keyring entry), run \
             `simon audit --reset-key` to discard the bad value and start a fresh \
             chain from here.",
            decoded.len()
        ));
    }
    Ok(decoded)
}

/// Discards whatever is currently stored under [`KEYRING_SERVICE`] — valid, corrupt,
/// or absent — so the next [`load_or_create_key`] call takes the `GenerateNew` branch
/// instead of failing [`validate_key`]'s length check.
///
/// A **separate** escape hatch from [`AuditLogger::reset_anchor`], not a variant of
/// it: `reset_anchor` is a method on an already-open `AuditLogger`, but a corrupt key
/// means `AuditLogger::open` never succeeds in the first place — there is no logger to
/// call it on. Wired to `simon audit --reset-key`, which — like `--reset-anchor` —
/// requires the caller to ask for this by name and is never triggered automatically.
///
/// Replacing the key makes every entry (and anchor) written under the old key
/// permanently unverifiable, the same trade `reset_anchor` makes for the anchor alone.
/// Follow this with `simon audit --reset-anchor` to re-baseline the anchors to the new
/// key — otherwise `simon audit` will keep reporting the old entries as modified,
/// which is correct: their MACs genuinely cannot be reproduced without the key that
/// was just discarded.
pub fn reset_key() -> Result<()> {
    Credentials::delete(KEYRING_SERVICE)
        .context("failed to delete the corrupt audit MAC key from the OS keyring")
}

/// Fetches the per-install MAC key from the keyring, generating one on first use. See
/// `decide_key`/`validate_key` for the logic; this is just the I/O shell around it.
fn load_or_create_key() -> Result<Vec<u8>> {
    use aes_gcm::aead::OsRng;
    use aes_gcm::aead::rand_core::RngCore;
    use secrecy::ExposeSecret;

    let existing = Credentials::get(KEYRING_SERVICE)?;
    match decide_key(existing.as_ref().map(|s| s.expose_secret().as_str()))? {
        KeyDecision::UseExisting(key) => Ok(key),
        KeyDecision::GenerateNew => {
            let mut key = vec![0u8; 32];
            OsRng.fill_bytes(&mut key);
            Credentials::set(KEYRING_SERVICE, &hex(&key))
                .context("failed to store the audit MAC key in the OS keyring")?;
            Ok(key)
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// Decodes a hex string into bytes without ever slicing `s` by byte index.
///
/// The previous implementation checked `s.len()` (a byte count) for evenness, then
/// sliced `&s[i..i+2]` at those byte offsets. Both the length check and the slice
/// bounds are byte-based, but a keyring value is attacker- or corruption-controlled
/// input that can contain multi-byte UTF-8 (an emoji, a Lithuanian letter): the byte
/// length could still be even while a 2-byte cut lands inside a multi-byte
/// codepoint, and `&str` indexing panics with "byte index is not a char boundary"
/// rather than returning an error. This crate has shipped exactly this failure class
/// before (fixed in 923b934) — the fix here is the same principle: work on
/// `as_bytes()` throughout so there is no `&str` index to ever land wrong, and let
/// any byte outside `0-9a-fA-F` (which includes every continuation/lead byte of a
/// multi-byte UTF-8 sequence) fail the digit match cleanly instead of panicking.
fn unhex(s: &str) -> Result<Vec<u8>> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(anyhow!("odd-length hex string"));
    }
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Ok((hex_digit(pair[0])? << 4) | hex_digit(pair[1])?))
        .collect()
}

/// A single ASCII hex digit's value, or an error for anything else — including any
/// byte of a multi-byte UTF-8 sequence, all of which fall outside `0-9a-fA-F`.
fn hex_digit(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(anyhow!("bad hex digit: 0x{b:02x}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn logger(dir: &tempfile::TempDir) -> AuditLogger {
        AuditLogger::with_key(dir.path().join("audit.log"), vec![7u8; 32]).unwrap()
    }

    /// Rewrites the log file to keep only its first `keep` lines — simulates an
    /// attacker deleting entries from the tail without touching the sidecar anchor.
    fn truncate_log(dir: &tempfile::TempDir, keep: usize) {
        let path = dir.path().join("audit.log");
        let kept: Vec<_> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .take(keep)
            .map(str::to_string)
            .collect();
        std::fs::write(&path, kept.join("\n") + "\n").unwrap();
    }

    #[test]
    fn chain_survives_a_restart() {
        // The regression: a new AuditLogger used to restart from the genesis hash,
        // silently forking the chain on every process start.
        let dir = tempfile::tempdir().unwrap();

        let mut first = logger(&dir);
        first.log("session.start", "provider=ollama").unwrap();
        first.log("prompt.sent", "len=42").unwrap();
        let head = first.last_mac.clone();
        drop(first);

        let mut second = logger(&dir);
        assert_eq!(second.last_mac, head, "chain head must be recovered");
        second.log("session.end", "ok").unwrap();

        let report = second.verify().unwrap();
        assert_eq!(report.entries, 3);
        assert_eq!(report.anchor, AnchorStatus::Current);
    }

    #[test]
    fn verify_detects_a_modified_entry() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = logger(&dir);
        log.log("a", "one").unwrap();
        log.log("b", "two").unwrap();

        let path = dir.path().join("audit.log");
        let contents = std::fs::read_to_string(&path).unwrap();
        std::fs::write(
            &path,
            contents.replace("\"details\":\"one\"", "\"details\":\"ONE\""),
        )
        .unwrap();

        let err = log.verify().unwrap_err().to_string();
        assert!(err.contains("modified"), "unexpected error: {err}");
    }

    #[test]
    fn verify_detects_a_deleted_entry() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = logger(&dir);
        log.log("a", "one").unwrap();
        log.log("b", "two").unwrap();
        log.log("c", "three").unwrap();

        let path = dir.path().join("audit.log");
        let kept: Vec<_> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .enumerate()
            .filter(|(i, _)| *i != 1)
            .map(|(_, l)| l.to_string())
            .collect();
        std::fs::write(&path, kept.join("\n") + "\n").unwrap();

        assert!(
            log.verify().is_err(),
            "removing a link must break the chain"
        );
    }

    #[test]
    fn a_different_key_cannot_verify_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = logger(&dir);
        log.log("a", "one").unwrap();

        let impostor = AuditLogger::with_key(dir.path().join("audit.log"), vec![9u8; 32]).unwrap();
        assert!(
            impostor.verify().is_err(),
            "MAC must depend on the key, not just the contents"
        );
    }

    #[test]
    fn pipe_characters_in_fields_cannot_forge_a_link() {
        // The old format joined fields with '|', so a crafted `details` could imitate
        // a different entry. JSON serialisation removes the ambiguity.
        let dir = tempfile::tempdir().unwrap();
        let mut log = logger(&dir);
        log.log("action|with|pipes", "details|with|pipes").unwrap();
        let report = log.verify().unwrap();
        assert_eq!(report.entries, 1);
        assert_eq!(report.anchor, AnchorStatus::Current);
    }

    #[test]
    fn verifying_a_missing_log_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let report = logger(&dir).verify().unwrap();
        assert_eq!(report.entries, 0);
        assert_eq!(report.anchor, AnchorStatus::Current);
    }

    // --- §3.3: tail-truncation anchor -------------------------------------------

    #[test]
    fn verify_detects_truncation_of_the_last_entry() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = logger(&dir);
        log.log("a", "one").unwrap();
        log.log("b", "two").unwrap();
        log.log("c", "three").unwrap(); // anchor now records 3 entries

        truncate_log(&dir, 2);

        let err = log.verify().unwrap_err().to_string();
        assert!(err.contains("truncat"), "unexpected error: {err}");
    }

    #[test]
    fn verify_detects_truncation_of_several_trailing_entries() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = logger(&dir);
        log.log("a", "one").unwrap();
        log.log("b", "two").unwrap();
        log.log("c", "three").unwrap();
        log.log("d", "four").unwrap();
        log.log("e", "five").unwrap(); // anchor now records 5 entries

        truncate_log(&dir, 1); // keep only the first entry

        let err = log.verify().unwrap_err().to_string();
        assert!(err.contains("truncat"), "unexpected error: {err}");
    }

    #[test]
    fn an_untampered_log_verifies_clean() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = logger(&dir);
        log.log("a", "one").unwrap();
        log.log("b", "two").unwrap();
        log.log("c", "three").unwrap();

        let report = log.verify().unwrap();
        assert_eq!(report.entries, 3);
        assert_eq!(report.anchor, AnchorStatus::Current);
    }

    #[test]
    fn benign_lag_between_log_and_anchor_verifies_clean() {
        // Simulates the crash window `log()` documents: the entry made it to the log
        // file, but the process died before the sidecar anchor write that follows it.
        let dir = tempfile::tempdir().unwrap();
        let mut log = logger(&dir);
        log.log("a", "one").unwrap();
        log.log("b", "two").unwrap(); // anchor synced to count=2, last_mac=mac(b)

        let ts = 1_700_000_000u64;
        let mac = log.mac(&log.last_mac, ts, "c", "three").unwrap();
        let entry = AuditEntry {
            ts,
            action: "c".to_string(),
            details: "three".to_string(),
            prev: log.last_mac.clone(),
            mac,
        };
        let mut line = serde_json::to_string(&entry).unwrap();
        line.push('\n');
        let mut file = OpenOptions::new()
            .append(true)
            .open(dir.path().join("audit.log"))
            .unwrap();
        file.write_all(line.as_bytes()).unwrap();
        drop(file);
        // Note: the sidecar anchor is deliberately NOT updated here, reproducing the
        // gap `log()` can leave behind a crash.

        let report = log.verify().unwrap();
        assert_eq!(report.entries, 3, "the valid extra entry must still count");
        assert_eq!(
            report.anchor,
            AnchorStatus::Current,
            "an entry the attacker couldn't have forged must not be reported as tampering"
        );
    }

    #[test]
    fn verify_detects_a_tampered_anchor() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = logger(&dir);
        log.log("a", "one").unwrap();

        let anchor_file = default_anchor_path(&dir.path().join("audit.log"));
        let contents = std::fs::read_to_string(&anchor_file).unwrap();
        // Flip the recorded count while keeping the JSON well-formed — the anchor's
        // own `mac` field (computed over the original count) no longer matches.
        let tampered = contents.replace("\"count\":1,", "\"count\":99,");
        assert_ne!(tampered, contents, "the replacement must actually apply");
        std::fs::write(&anchor_file, tampered).unwrap();

        let err = log.verify().unwrap_err().to_string();
        assert!(
            err.contains("anchor") && err.contains("tampered"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn verify_detects_the_whole_log_file_being_deleted() {
        // Deleting the log outright is strictly easier than truncating its tail, and
        // used to slip past `verify()` entirely: the old code returned `Ok(0)` the
        // moment `File::open` reported NotFound, before ever looking at the anchor.
        let dir = tempfile::tempdir().unwrap();
        let mut log = logger(&dir);
        log.log("a", "one").unwrap();
        log.log("b", "two").unwrap();
        log.log("c", "three").unwrap(); // sidecar anchor now records 3 entries

        std::fs::remove_file(dir.path().join("audit.log")).unwrap();
        assert!(
            default_anchor_path(&dir.path().join("audit.log")).exists(),
            "the anchor must survive the log's deletion for this test to be meaningful"
        );

        let err = log.verify().unwrap_err().to_string();
        assert!(err.contains("truncat"), "unexpected error: {err}");
    }

    #[test]
    fn a_missing_log_with_no_anchor_at_all_still_verifies_clean() {
        // Guards the legitimate first-run path: no log and no anchor is not an attack,
        // just a fresh install, and must stay `Ok` after the fix above.
        let dir = tempfile::tempdir().unwrap();
        let log = logger(&dir);
        assert!(
            !default_anchor_path(&dir.path().join("audit.log")).exists(),
            "nothing has been logged yet, so there must be no anchor either"
        );

        let report = log.verify().unwrap();
        assert_eq!(report.entries, 0);
        assert_eq!(report.anchor, AnchorStatus::Current);
    }

    #[test]
    fn verify_reports_missing_anchor_beside_a_nonempty_log() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = logger(&dir);
        log.log("a", "one").unwrap();

        let anchor_file = default_anchor_path(&dir.path().join("audit.log"));
        std::fs::remove_file(&anchor_file).unwrap();

        let report = log.verify().unwrap();
        assert_eq!(
            report.entries, 1,
            "the chain itself is still fully verified"
        );
        assert_eq!(report.anchor, AnchorStatus::Missing);
    }

    #[test]
    fn with_key_and_anchor_uses_the_given_anchor_path_not_the_default() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("audit.log");
        let custom_anchor = dir.path().join("custom.anchor");
        let mut log = AuditLogger::with_key_and_anchor(
            log_path.clone(),
            vec![7u8; 32],
            custom_anchor.clone(),
        )
        .unwrap();
        log.log("a", "one").unwrap();

        assert!(
            custom_anchor.exists(),
            "anchor should be written to the explicit path"
        );
        assert!(
            !default_anchor_path(&log_path).exists(),
            "default anchor path must be untouched"
        );

        let report = log.verify().unwrap();
        assert_eq!(report.anchor, AnchorStatus::Current);
    }

    // --- keyring anchor scoping (§3.3 follow-up: SIMON_DATA_DIR means many logs) ---
    //
    // The keyring itself can't be touched in these tests (no Secret Service in CI —
    // see the module docs), so these exercise `keyring_anchor_service` directly: the
    // pure function that decides which keyring entry a given log's anchor lives
    // under. That is exactly the mechanism the false positive lived in — two logs
    // colliding on one entry — so proving the derived names never collide is proving
    // the bug is closed, without needing a real keyring round trip to do it.

    #[test]
    fn keyring_anchor_service_differs_for_different_log_paths() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let service_a = keyring_anchor_service(&dir_a.path().join("audit.log"));
        let service_b = keyring_anchor_service(&dir_b.path().join("audit.log"));

        assert_ne!(
            service_a, service_b,
            "two different data dirs (e.g. two SIMON_DATA_DIR values) must not share \
             one log's anchor — that was exactly the false-positive bug"
        );
    }

    #[test]
    fn keyring_anchor_service_is_stable_for_the_same_log_path() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("audit.log");

        assert_eq!(
            keyring_anchor_service(&log_path),
            keyring_anchor_service(&log_path),
            "the same log must always resolve to the same anchor entry, or a second \
             `open()` of the same data dir would never find its own anchor"
        );
    }

    #[test]
    fn keyring_anchor_service_never_collides_with_the_legacy_unscoped_name() {
        // Proves an anchor written under the pre-scoping global name (what a keyring
        // upgraded from an older build still has under `audit-anchor-hmac`) can never
        // be read back by the new per-path lookup — it is unconditionally treated as
        // absent, not as evidence of tampering, for every log path.
        let dir = tempfile::tempdir().unwrap();
        for name in ["audit.log", "nested/audit.log", ""] {
            let path = dir.path().join(name).join("audit.log");
            assert_ne!(keyring_anchor_service(&path), LEGACY_KEYRING_ANCHOR_SERVICE);
        }
    }

    // --- reset_anchor -----------------------------------------------------------

    #[test]
    fn reset_anchor_after_truncation_records_the_reset_and_verifies_clean() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = logger(&dir);
        log.log("a", "one").unwrap();
        log.log("b", "two").unwrap();
        log.log("c", "three").unwrap(); // anchor now records 3 entries

        truncate_log(&dir, 1); // an admin deliberately trims the log to 1 entry

        // Before reset: correctly reported as truncation, same as the earlier tests.
        let err = log.verify().unwrap_err().to_string();
        assert!(err.contains("truncat"), "unexpected error: {err}");

        log.reset_anchor("test: admin trimmed the log on purpose")
            .unwrap();

        let report = log.verify().unwrap();
        assert_eq!(report.anchor, AnchorStatus::Current);
        assert_eq!(
            report.entries, 2,
            "the surviving entry plus the reset marker itself"
        );

        let contents = std::fs::read_to_string(dir.path().join("audit.log")).unwrap();
        assert!(
            contents.contains("audit.anchor_reset"),
            "the reset must be on the record, not a silent break in the chain"
        );
    }

    #[test]
    fn reset_anchor_after_the_log_is_deleted_clears_both_anchors() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = logger(&dir);
        log.log("a", "one").unwrap();
        log.log("b", "two").unwrap();

        std::fs::remove_file(dir.path().join("audit.log")).unwrap();
        assert!(
            log.verify().is_err(),
            "a deleted log with a stale anchor must still be caught before reset"
        );

        log.reset_anchor("test: admin deleted the log on purpose")
            .unwrap();
        assert!(
            !default_anchor_path(&dir.path().join("audit.log")).exists(),
            "the sidecar anchor must not survive a reset of a deleted log"
        );

        // Nothing left to append to, so this reset left no entries of its own — but a
        // fresh chain started after it must not immediately trip over the anchor that
        // used to describe the deleted log.
        log.log("d", "four").unwrap();
        let report = log.verify().unwrap();
        assert_eq!(report.anchor, AnchorStatus::Current);
        assert_eq!(report.entries, 1);
    }

    // --- §3.5: a corrupt keyring value must not be silently rotated --------------
    //
    // `decide_key`/`validate_key` are pure functions of `Option<&str>` — no keyring
    // I/O — precisely so these can run without a working keyring daemon. CI runs on
    // Windows and macOS images with no Secret Service; nothing below touches one.

    #[test]
    fn a_valid_32_byte_hex_key_is_accepted() {
        let key = vec![0xABu8; 32];
        match decide_key(Some(&hex(&key))).unwrap() {
            KeyDecision::UseExisting(decoded) => assert_eq!(decoded, key),
            KeyDecision::GenerateNew => panic!("a valid existing key must not be discarded"),
        }
    }

    #[test]
    fn a_valid_hex_value_of_the_wrong_length_is_rejected() {
        // The actual defect: 16 bytes of perfectly valid hex, just not 32 of them.
        // The old code fell through this case and silently minted a replacement key,
        // destroying the ability to verify every prior audit entry with no warning.
        let short = hex(&[0x11u8; 16]);
        let err = decide_key(Some(&short)).unwrap_err().to_string();
        assert!(
            err.contains("16") && err.contains("32"),
            "error should name both the actual and required length: {err}"
        );
        assert!(
            err.contains(KEYRING_SERVICE),
            "error should name the keyring service so the user knows what to fix: {err}"
        );
        assert!(
            err.contains("--reset-key"),
            "error should describe the deliberate recovery action: {err}"
        );
        assert!(
            !err.contains(&short),
            "error must not leak the offending key material: {err}"
        );
    }

    #[test]
    fn a_non_hex_value_is_still_rejected() {
        // Guards the pre-existing behaviour: this case already propagated correctly
        // via `?` before this fix; must not regress while restructuring around it.
        let err = decide_key(Some("not-hex-at-all")).unwrap_err().to_string();
        assert!(err.contains("hex"), "unexpected error: {err}");
    }

    #[test]
    fn an_absent_value_still_generates_a_new_key() {
        // The first-run path must not regress: no entry yet is a legitimate reason to
        // generate a key, distinct from a present-but-unusable one.
        match decide_key(None).unwrap() {
            KeyDecision::GenerateNew => {}
            KeyDecision::UseExisting(_) => panic!("nothing existed to use"),
        }
    }

    #[test]
    fn wrong_length_key_error_never_contains_the_decoded_bytes_either() {
        // Belt-and-suspenders on top of the hex-string check above: assert the
        // *decoded* bytes (as a second, differently-shaped hex string) don't leak
        // through some other formatting path either.
        let short = vec![0x42u8; 4];
        let short_hex = hex(&short);
        let err = decide_key(Some(&short_hex)).unwrap_err().to_string();
        assert!(!err.contains("42424242"), "unexpected error: {err}");
    }

    #[test]
    fn decide_key_rejects_multibyte_utf8_in_keyring_without_panicking() {
        // Was `bug_proof_unhex_panics_on_multibyte_utf8_in_keyring`: this used to
        // reproduce a crash, not guard against one. "00\u{1f512}" is 6 bytes (an even
        // byte length, so it passed the old length check), but \u{1f512} alone is 4
        // bytes — `unhex` used to slice `&s[2..4]`, landing mid-codepoint, and panic
        // with "byte index is not a char boundary". That's reachable from a startup
        // path (`load_or_create_key` -> `decide_key` -> `validate_key` -> `unhex`) on
        // nothing more than a keyring value with a stray emoji or accented letter —
        // a crash where the surrounding code already had a `.context(...)` in place
        // that shows the intent was always to reject cleanly, not abort the process.
        let corrupt_keyring_value = "00\u{1f512}";
        let res = std::panic::catch_unwind(|| decide_key(Some(corrupt_keyring_value)));
        let decision = res.expect("decide_key must not panic on multi-byte UTF-8 input");
        assert!(
            decision.is_err(),
            "a keyring value containing non-hex UTF-8 is not a valid key and must be rejected"
        );
    }

    #[test]
    fn unhex_rejects_malformed_input_without_panicking() {
        // Broader sweep over `unhex` itself, per the audit's requested coverage: an
        // emoji and a Lithuanian string (both multi-byte UTF-8, exercising the same
        // class as the test above but at the `unhex` level directly), an odd byte
        // length, and non-hex ASCII. All four must return `Err`, never panic.
        for (label, input) in [
            ("emoji", "00\u{1f512}"),
            ("lithuanian text", "ąžuolas"),
            ("odd length", "abc"),
            ("non-hex ascii", "zzzz"),
        ] {
            let result = std::panic::catch_unwind(|| unhex(input))
                .unwrap_or_else(|_| panic!("unhex panicked on {label} input {input:?}"));
            assert!(
                result.is_err(),
                "unhex accepted invalid {label} input {input:?}"
            );
        }
    }

    #[test]
    fn a_truncated_sidecar_anchor_is_reported_not_a_verify_failure() {
        // Was `bug_proof_truncated_sidecar_anchor_causes_verify_failure`: this used to
        // reproduce `verify()` hard-failing on a 0-byte anchor — the shape left by a
        // crash mid-`write_sidecar_anchor` — with a "not valid JSON" error, which is
        // indistinguishable from an attacker's deliberate tampering (see
        // `verify_detects_a_tampered_anchor`, a syntactically valid anchor with a
        // wrong MAC). That overstated what's actually known: the log's own hash chain
        // is still fully intact either way. Correct behaviour is `verify()` succeeding
        // with `AnchorStatus::Unreadable` — the same "warning, not a hard failure"
        // treatment as `Missing`, but distinct from it, because an anchor file *was*
        // found here, just not a readable one.
        let dir = tempfile::tempdir().unwrap();
        let mut log = logger(&dir);
        log.log("session.start", "ok").unwrap();
        log.log("prompt.sent", "ok").unwrap();

        let anchor_file = default_anchor_path(&dir.path().join("audit.log"));
        std::fs::write(&anchor_file, b"").unwrap();

        let report = log.verify().unwrap();
        assert_eq!(
            report.entries, 2,
            "the chain itself is still fully verified"
        );
        assert_eq!(report.anchor, AnchorStatus::Unreadable);
    }

    // --- §3.5: cross-process append locking --------------------------------------

    #[test]
    fn two_loggers_interleaved_on_the_same_path_produce_a_valid_chain() {
        // The core §3.5 bug, reproduced without needing real concurrency: two
        // independent `AuditLogger`s on the same path each used to cache their own
        // chain head. Before the fix, `b`'s second write still carried the
        // `last_mac` it cached at `open()` (GENESIS) because nothing told it `a` had
        // since appended, so its `prev` no longer matched the file's true tail and
        // `verify()` reported a broken chain — indistinguishable from tampering. The
        // fix makes every `log()` call re-read the true tail from disk under the
        // append lock, so taking turns like this must now produce a chain `verify()`
        // accepts regardless of which logger instance wrote most recently.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let key = vec![7u8; 32];

        let mut a = AuditLogger::with_key(path.clone(), key.clone()).unwrap();
        let mut b = AuditLogger::with_key(path.clone(), key.clone()).unwrap();

        for i in 0..20 {
            a.log("a.tick", &i.to_string()).unwrap();
            b.log("b.tick", &i.to_string()).unwrap();
        }

        let verifier = AuditLogger::with_key(path, key).unwrap();
        let report = verifier.verify().unwrap();
        assert_eq!(report.entries, 40);
        assert_eq!(report.anchor, AnchorStatus::Current);
    }

    #[test]
    fn two_loggers_on_separate_threads_appending_concurrently_produce_a_valid_chain() {
        // A stronger version of the test above: real OS-thread concurrency, so the
        // interleaving is driven by the scheduler rather than program order. Threads
        // still share the process's memory, so this alone cannot rule out a bug that
        // only a separate address space would expose — see
        // `two_real_processes_interleaved_appends_produce_a_valid_chain` below for
        // that.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let key = vec![7u8; 32];
        let n = 50;

        let (path_a, key_a) = (path.clone(), key.clone());
        let handle = std::thread::spawn(move || {
            let mut logger = AuditLogger::with_key(path_a, key_a).unwrap();
            for i in 0..n {
                logger.log("a.tick", &i.to_string()).unwrap();
            }
        });

        let mut b = AuditLogger::with_key(path.clone(), key.clone()).unwrap();
        for i in 0..n {
            b.log("b.tick", &i.to_string()).unwrap();
        }
        handle.join().unwrap();

        let verifier = AuditLogger::with_key(path, key).unwrap();
        let report = verifier.verify().unwrap();
        assert_eq!(report.entries, n * 2);
        assert_eq!(report.anchor, AnchorStatus::Current);
    }

    #[test]
    fn append_lock_contention_times_out_visibly_instead_of_hanging_or_dropping_the_entry() {
        // Simulates another process's in-progress `log()` call by holding the
        // exclusive lock from outside any `AuditLogger`. Checks the contention
        // design end to end: `log()` neither hangs forever nor silently no-ops — it
        // returns an `Err` the caller can see — and nothing partial gets written
        // while it waits.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");

        let holder = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .unwrap();
        holder.lock().unwrap();

        let mut logger = AuditLogger::with_key(path.clone(), vec![7u8; 32]).unwrap();
        let err = logger.log("a", "one").unwrap_err().to_string();
        assert!(err.contains("timed out"), "unexpected error: {err}");

        drop(holder); // release the stand-in lock

        // The log must be otherwise completely unharmed by the failed attempt: no
        // partial entry, no corrupted anchor.
        logger.log("a", "one").unwrap();
        let report = logger.verify().unwrap();
        assert_eq!(
            report.entries, 1,
            "the timed-out attempt must not have written anything"
        );
        assert_eq!(report.anchor, AnchorStatus::Current);
    }

    /// Worker half of `two_real_processes_interleaved_appends_produce_a_valid_chain`.
    /// Not a `#[test]` itself — invoked by re-execing the test binary (see that test)
    /// with `SIMON_AUDIT_WORKER` set to `"<path>\n<key hex>\n<n>\n<label>"`. Appends
    /// `n` entries to the shared log as fast as possible; a failure here panics,
    /// which fails the child process's own libtest run and gives it a nonzero exit
    /// code the parent test can detect.
    fn run_audit_worker(spec: &str) {
        let mut parts = spec.split('\n');
        let path = PathBuf::from(parts.next().expect("worker spec missing path"));
        let key_hex = parts.next().expect("worker spec missing key");
        let n: usize = parts
            .next()
            .expect("worker spec missing n")
            .parse()
            .expect("worker spec n is not a number");
        let label = parts.next().expect("worker spec missing label");

        let key = unhex(key_hex).expect("worker spec key is not valid hex");
        let mut logger = AuditLogger::with_key(path, key).expect("worker failed to open logger");
        for i in 0..n {
            logger
                .log(&format!("{label}.entry"), &i.to_string())
                .expect("worker log() call failed");
        }
    }

    #[test]
    fn two_real_processes_interleaved_appends_produce_a_valid_chain() {
        // The finding as stated: "nothing stops a user running `simon chat` in two
        // terminals against the same SIMON_DATA_DIR" — two independent OS processes,
        // not threads, which share nothing but the file system and so can expose a
        // race the in-process tests above cannot rule out on their own.
        //
        // There is no subprocess-spawning dependency in this crate, and adding one
        // is out of scope (`Cargo.toml` may only change to add a *locking*
        // dependency), so this gets a second real process the cheapest way
        // available: it re-execs the test binary itself (`std::env::current_exe()`)
        // filtered to just this one test (`--exact`), with `SIMON_AUDIT_WORKER` set.
        // When that env var is present, this same function immediately diverts into
        // `run_audit_worker` instead of acting as the test orchestrator — so the
        // child process really is a second, independent audit writer in its own
        // address space, not a simulated one.
        if let Ok(spec) = std::env::var("SIMON_AUDIT_WORKER") {
            run_audit_worker(&spec);
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let key = vec![7u8; 32];
        let key_hex = hex(&key);
        let n_per_worker = 40usize;

        let exe = std::env::current_exe().expect("test binary must have a current_exe path");
        let spawn = |label: &str| -> std::process::Child {
            std::process::Command::new(&exe)
                .arg("audit::tests::two_real_processes_interleaved_appends_produce_a_valid_chain")
                .arg("--exact")
                .arg("--test-threads=1")
                .env(
                    "SIMON_AUDIT_WORKER",
                    format!(
                        "{}\n{}\n{}\n{}",
                        path.display(),
                        key_hex,
                        n_per_worker,
                        label
                    ),
                )
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("failed to spawn worker process")
        };

        // Spawned back-to-back, not spawned-then-waited, so both processes are
        // genuinely racing for the file lock rather than running one after the
        // other.
        let proc_a = spawn("a");
        let proc_b = spawn("b");

        let out_a = proc_a
            .wait_with_output()
            .expect("worker process a failed to run");
        let out_b = proc_b
            .wait_with_output()
            .expect("worker process b failed to run");
        assert!(
            out_a.status.success(),
            "worker a failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out_a.stdout),
            String::from_utf8_lossy(&out_a.stderr)
        );
        assert!(
            out_b.status.success(),
            "worker b failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out_b.stdout),
            String::from_utf8_lossy(&out_b.stderr)
        );

        let verifier = AuditLogger::with_key(path, key).unwrap();
        let report = verifier.verify().expect(
            "two real OS processes appending concurrently must produce a chain verify() \
             accepts — this is the §3.5 finding itself: without locking, an interleaved \
             write from a second process breaks the hash chain, indistinguishable from \
             tampering",
        );
        assert_eq!(report.entries, n_per_worker * 2);
        assert_eq!(report.anchor, AnchorStatus::Current);
    }
}

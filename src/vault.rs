//! Encrypted at-rest storage for sensitive local state.
//!
//! The only thing this stores is the TUI transcript (`App::transcript` in
//! `src/app.rs`), opted into with `simon chat --vault`. It hands the *user* their
//! history back across sessions; it does not replay that transcript to a model.
//! `Orchestrator::handle_prompt` still sends no transport-level message history,
//! vault or not. The commander's bounded previous reply is carried separately in the
//! ledger, while delegated models receive isolated task prompts. See the "Security
//! posture" section of `README.md` for the full picture, including the self-destruct
//! policy as a data-loss property.
//!
//! File layout (all integers big-endian):
//!
//! ```text
//! 0..8    magic  b"MCVAULT1"
//! 8       format version (currently 1)
//! 9       consecutive failed unlock attempts
//! 10..18  unix seconds of last successful unlock
//! 18      salt length in bytes
//! 19..    salt
//! ..+12   AES-GCM nonce
//! ..      ciphertext (includes the GCM tag)
//! ```
//!
//! The salt is stored **in the file**. An earlier version took the salt as a caller
//! argument and never persisted it, which meant a saved vault could not be reopened.
//!
//! The magic, version, salt length and salt are bound into the ciphertext as
//! additional authenticated data, so tampering with them fails decryption. The attempt
//! counter and timestamp are deliberately excluded from the AAD because they must be
//! rewritten without re-encrypting the payload.
//!
//! The plaintext *payload* — the transcript itself — is capped at [`MAX_TRANSCRIPT_LINES`]
//! lines by [`trim_transcript_to_cap`], applied by `main.rs` on every load and save.
//! AUDIT-2026-07-30 §3.6: without a cap, every clean exit re-encrypts (and every
//! unlock decrypts) a transcript that only ever grows, and the plaintext sits
//! `mlockall`-pinned in memory for the process's whole life. See that function's doc
//! comment for what gets dropped and how a truncated transcript stays valid.

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
};
use anyhow::{Context, Result, anyhow};
use argon2::Argon2;
use secrecy::{ExposeSecret, SecretString};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::app::{Line, Speaker};
use crate::security::LockedBuffer;

const MAGIC: &[u8; 8] = b"MCVAULT1";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
/// AES-GCM's authentication tag. Every well-formed body carries one, so a body shorter
/// than this cannot be a truncated *message* — it is a truncated *file*.
const TAG_LEN: usize = 16;
/// Argon2 refuses a salt below 8 bytes. A header claiming less is malformed, and
/// accepting it used to brick `save`, which reuses the stored salt and then cannot
/// derive a key from it ever again.
const MIN_SALT_LEN: usize = 8;
const KEY_LEN: usize = 32;
const HEADER_FIXED_LEN: usize = 8 + 1 + 1 + 8 + 1; // magic..salt_len inclusive

#[cfg(unix)]
fn regular_file_link_count(_path: &Path, meta: &fs::Metadata) -> Option<u64> {
    use std::os::unix::fs::MetadataExt as _;

    meta.is_file().then(|| meta.nlink())
}

#[cfg(windows)]
#[cfg_attr(test, mutants::skip)]
fn regular_file_link_count(path: &Path, meta: &fs::Metadata) -> Option<u64> {
    meta.is_file()
        .then(|| crate::security::windows_regular_file_link_count(path))
        .flatten()
}

#[cfg(not(any(unix, windows)))]
fn regular_file_link_count(_path: &Path, meta: &fs::Metadata) -> Option<u64> {
    meta.is_file().then_some(2)
}

fn should_zero_before_unlink(path: &Path, meta: &fs::Metadata) -> bool {
    matches!(regular_file_link_count(path, meta), Some(0 | 1))
}

/// Consecutive wrong passwords before the vault is locked aside.
pub const MAX_ATTEMPTS: u8 = 5;
/// Idle window after which the vault is reported as stale on next open.
///
/// Passing this limit no longer destroys anything — see the comment in
/// [`EncryptedVault::load`] for why. It sets [`VaultStatus::idle_expired`], which the
/// caller turns into a warning, and a successful unlock resets the window.
pub const MAX_IDLE_SECS: u64 = 24 * 60 * 60;
/// How close to `MAX_IDLE_SECS` counts as "close enough to warn the user about" at
/// unlock time. Four hours gives someone who works in a normal daily rhythm a real
/// chance to notice before a missed day quietly puts the vault past its window.
pub const IDLE_WARNING_THRESHOLD_SECS: u64 = 4 * 60 * 60;

/// Upper bound on how many [`Line`]s a vaulted transcript keeps, enforced by
/// [`trim_transcript_to_cap`].
///
/// Lines, not bytes or age. Bytes would make the limit depend on what happens to be
/// said — one long pasted file makes a single `Line` enormous while a hundred short
/// replies stay tiny — so two transcripts a user would call "the same length" could
/// hit wildly different caps. Age (the audit's `--before <date>` suggestion) was
/// rejected because `Line` (`src/app.rs`) carries no timestamp, and adding one is an
/// `app.rs` change outside this fix's file ownership. Lines is what is actually on
/// screen and what a user reasons about ("keep my last N exchanges"), and it is the
/// unit the audit itself used ("cap retained lines").
///
/// 2,000 is generous for months of ordinary daily use — a busy day of chatting is a
/// few dozen lines — while still bounding the cost that scales with transcript size:
/// Argon2id plus AES-GCM over the whole payload on every clean exit, decryption of
/// all of it on every unlock, and the `mlockall`-pinned plaintext this process holds
/// for its entire life (§3.6).
pub const MAX_TRANSCRIPT_LINES: usize = 2_000;

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("no vault exists yet")]
    Missing,
    #[error("incorrect master password ({remaining} attempt(s) before the vault is wiped)")]
    WrongPassword { remaining: u8 },
    /// The attempt limit was reached. The ciphertext is *not* gone: it has been moved
    /// to `moved_to` and this path will not open again until someone moves it back by
    /// hand. `moved_to` is `None` only when the move itself failed, in which case the
    /// vault is still where it was and `reason` says so.
    #[error("vault locked: {reason}")]
    LockedOut {
        reason: String,
        moved_to: Option<PathBuf>,
    },
    #[error("vault file is corrupt: {0}")]
    Corrupt(String),
}

pub struct EncryptedVault {
    path: PathBuf,
}

struct Header {
    attempts: u8,
    last_unlock: u64,
    salt: Vec<u8>,
    /// Byte offset at which the nonce begins.
    body_offset: usize,
}

impl Header {
    /// The bytes bound as additional authenticated data: magic, version, salt length,
    /// salt. Excludes the mutable attempt counter and timestamp.
    fn aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(MAGIC.len() + 2 + self.salt.len());
        aad.extend_from_slice(MAGIC);
        aad.push(VERSION);
        aad.push(self.salt.len() as u8);
        aad.extend_from_slice(&self.salt);
        aad
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        // A clock before the Unix epoch is nonsensical but must not panic.
        .unwrap_or(0)
}

impl EncryptedVault {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Derives a 32-byte key with Argon2id. The key lives in a locked, zeroizing buffer.
    fn derive_key(password: &SecretString, salt: &[u8]) -> Result<LockedBuffer> {
        let mut key = vec![0u8; KEY_LEN];
        Argon2::default()
            .hash_password_into(password.expose_secret().as_bytes(), salt, &mut key)
            .map_err(|e| anyhow!("Argon2 key derivation failed: {e}"))?;
        Ok(LockedBuffer::new(key))
    }

    fn parse_header(raw: &[u8]) -> Result<Header, VaultError> {
        if raw.len() < HEADER_FIXED_LEN {
            return Err(VaultError::Corrupt("file shorter than its header".into()));
        }
        if &raw[0..8] != MAGIC {
            return Err(VaultError::Corrupt("bad magic bytes".into()));
        }
        if raw[8] != VERSION {
            return Err(VaultError::Corrupt(format!(
                "unsupported format version {} (this build understands {VERSION})",
                raw[8]
            )));
        }
        let attempts = raw[9];
        let last_unlock = u64::from_be_bytes(
            raw[10..18]
                .try_into()
                .map_err(|_| VaultError::Corrupt("truncated timestamp".into()))?,
        );
        let salt_len = raw[18] as usize;
        if salt_len < MIN_SALT_LEN {
            return Err(VaultError::Corrupt(format!(
                "header claims a {salt_len}-byte salt, below Argon2's {MIN_SALT_LEN}-byte minimum"
            )));
        }
        let salt_end = HEADER_FIXED_LEN + salt_len;
        // The body must have room for the nonce *and* the GCM tag. Without this check a
        // file truncated after the nonce reached the decrypt below, failed for a
        // structural reason, and was charged to the user as a wrong password — five of
        // those and the damaged file was destroyed, with the correct password typed
        // every time. A malformed file is `Corrupt`; it is never a failed attempt.
        if raw.len() < salt_end + NONCE_LEN + TAG_LEN {
            return Err(VaultError::Corrupt(
                "file is too short to hold a nonce and an authentication tag".into(),
            ));
        }
        Ok(Header {
            attempts,
            last_unlock,
            salt: raw[HEADER_FIXED_LEN..salt_end].to_vec(),
            body_offset: salt_end,
        })
    }

    /// Encrypts `plaintext` and replaces the vault file.
    pub fn save(&self, plaintext: &[u8], password: &SecretString) -> Result<()> {
        // Reuse the existing salt so the same password keeps working; generate one on
        // first save.
        let salt = match fs::read(&self.path) {
            Ok(raw) => Self::parse_header(&raw)
                .map(|h| h.salt)
                .unwrap_or_else(|_| random_salt()),
            Err(_) => random_salt(),
        };

        let header = Header {
            attempts: 0,
            last_unlock: now_secs(),
            salt,
            body_offset: 0,
        };
        let key = Self::derive_key(password, &header.salt)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice()));
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &header.aad(),
                },
            )
            .map_err(|e| anyhow!("encryption failed: {e}"))?;

        let mut out =
            Vec::with_capacity(HEADER_FIXED_LEN + header.salt.len() + NONCE_LEN + ciphertext.len());
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.push(header.attempts);
        out.extend_from_slice(&header.last_unlock.to_be_bytes());
        out.push(header.salt.len() as u8);
        out.extend_from_slice(&header.salt);
        out.extend_from_slice(nonce.as_slice());
        out.extend_from_slice(&ciphertext);

        write_atomically(&self.path, &out)
    }

    /// Decrypts the vault.
    ///
    /// Enforces the anti-brute-force policy: after [`MAX_ATTEMPTS`] consecutive wrong
    /// passwords the file is moved aside — see [`Self::lock_aside`]. Sitting idle past
    /// [`MAX_IDLE_SECS`] does not touch it at all — see the comment in the body.
    ///
    /// Note the limitation: the attempt counter lives in the (unauthenticated) header
    /// of the same file, so an attacker who can copy the file can reset it by restoring
    /// their copy. This raises the cost of an online guessing attack; it is not a
    /// substitute for a TPM or secure enclave.
    pub fn load(&self, password: &SecretString) -> Result<Vec<u8>, VaultError> {
        let raw = match fs::read(&self.path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(VaultError::Missing),
            Err(e) => return Err(VaultError::Corrupt(e.to_string())),
        };

        let mut header = Self::parse_header(&raw)?;

        // The attempt counter is NOT acted on here, only below, and only after a
        // password has actually been tried and failed.
        //
        // This used to `destroy()` on the count alone, before the password was checked
        // — the identical mistake the idle-expiry comment below describes, three lines
        // apart in the same function, and it survived that fix because the fix was
        // written for the clock rather than for the shape. Byte 9 is outside the AEAD's
        // authenticated data (see `Header::aad`), so it is attacker-writable and
        // bit-rot-reachable; setting it to `MAX_ATTEMPTS` was enough to destroy a
        // vault irreversibly on the next unlock *with the correct password*.
        //
        // The counter was never a defence against someone who can write the file — the
        // README says plainly that such an attacker can lower it. It only ever bounded
        // guessing by someone who cannot, and the failure path below still does that:
        // a wrong password increments and, on reaching the limit, destroys. A correct
        // password unlocks and resets the count to zero, so a forged value costs the
        // legitimate user nothing.

        // Idle expiry is deliberately NOT enforced here. It used to `destroy()` the
        // file at this point, before the password was even checked. The window is pure
        // wall-clock arithmetic, and a forward clock jump — NTP correcting a clock that
        // was behind, a VM resuming with a stale clock — is indistinguishable from time
        // that genuinely passed, so no detection can rescue it: the vault was deleted
        // irreversibly while the user typed the right password.
        //
        // Weigh the two sides. The payload is AES-256-GCM encrypted, so deleting it
        // after 24 hours adds little confidentiality over what the encryption already
        // gives; it defends only against an attacker who obtains the password *later*.
        // The old behaviour, meanwhile, *guaranteed* total unrecoverable loss of the
        // user's transcript every time the clock moved forward. So the vault now opens
        // normally, the success path below resets `last_unlock`, and the staleness is
        // surfaced as a warning via [`VaultStatus::idle_expired`].
        //
        // The attempt-based wipe above is untouched: it is the anti-brute-force
        // property and does not depend on the clock at all.

        let aad = header.aad();
        let nonce_end = header.body_offset + NONCE_LEN;
        let nonce = Nonce::from_slice(&raw[header.body_offset..nonce_end]);
        let ciphertext = &raw[nonce_end..];

        let key = Self::derive_key(password, &header.salt)
            .map_err(|e| VaultError::Corrupt(e.to_string()))?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice()));

        match cipher.decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        ) {
            Ok(plaintext) => {
                header.attempts = 0;
                header.last_unlock = now_secs();
                let _ = self.rewrite_header(&raw, &header);
                Ok(plaintext)
            }
            Err(_) => {
                header.attempts = header.attempts.saturating_add(1);
                // Refuse rather than grant a free guess. This was `let _ = …`, so on a
                // read-only file or directory the increment never reached disk and the
                // count reset to its old value on every call — unlimited attempts, with
                // `remaining` cheerfully reporting the same number forever. An attempt
                // that cannot be recorded must not be spent.
                if let Err(e) = self.rewrite_header(&raw, &header) {
                    return Err(VaultError::Corrupt(format!(
                        "refusing to continue: a failed attempt could not be recorded, \
                         so the attempt limit cannot be enforced ({e})"
                    )));
                }
                if header.attempts >= MAX_ATTEMPTS {
                    return Err(match self.lock_aside() {
                        Ok(moved_to) => VaultError::LockedOut {
                            reason: format!(
                                "{MAX_ATTEMPTS} consecutive failed unlock attempts; the \
                                 encrypted transcript was moved to {} rather than \
                                 destroyed",
                                moved_to.display()
                            ),
                            moved_to: Some(moved_to),
                        },
                        Err(e) => VaultError::LockedOut {
                            reason: format!(
                                "{MAX_ATTEMPTS} consecutive failed unlock attempts, and \
                                 the vault could not be moved aside ({e}); it is still \
                                 at {}",
                                self.path.display()
                            ),
                            moved_to: None,
                        },
                    });
                }
                Err(VaultError::WrongPassword {
                    remaining: MAX_ATTEMPTS - header.attempts,
                })
            }
        }
    }

    /// Rewrites only the mutable header bytes, leaving the ciphertext untouched.
    fn rewrite_header(&self, original: &[u8], header: &Header) -> Result<()> {
        let mut updated = original.to_vec();
        updated[9] = header.attempts;
        updated[10..18].copy_from_slice(&header.last_unlock.to_be_bytes());
        write_atomically(&self.path, &updated)
    }

    /// Moves the vault out of the way instead of destroying it, and returns where it
    /// went.
    ///
    /// This is what the attempt limit does now. The old behaviour zeroed and unlinked
    /// the file on the 5th wrong password, permanently, with no recovery — and that
    /// cost fell on the legitimate owner far more reliably than on any attacker.
    /// Weigh the two adversaries the counter can actually meet:
    ///
    /// * Someone who can *write* files here was never bounded by the counter at all.
    ///   Byte 9 is outside the AEAD's authenticated data, so they can restore a copy
    ///   with the count at zero and keep guessing — the README has always said so.
    ///   Against them a rename loses nothing a wipe was protecting.
    /// * Someone who can only *type* is stopped just as hard by a rename as by a wipe:
    ///   the path no longer opens, and they cannot put it back.
    ///
    /// The owner, meanwhile, is the one who actually reaches five wrong passwords — by
    /// mistyping a password they are about to remember — and for them the difference is
    /// their entire transcript. The payload stays AES-256-GCM under an Argon2id key, so
    /// what is left behind is exactly as confidential as it was a second earlier; the
    /// wipe added little the encryption did not already give.
    ///
    /// The move is a rename in the same directory, so it is atomic and never copies
    /// plaintext anywhere new. A symlink at `self.path` renames the link, not its
    /// target, the same asymmetry [`Self::destroy`] relies on. An existing
    /// `.locked` file is not overwritten — an earlier lock-out is someone else's
    /// transcript and gets its own suffix.
    ///
    /// A crash-orphaned `<path>.tmp` still holds a complete decryptable snapshot and is
    /// still shredded: the vault itself is preserved now, so the orphan is a duplicate
    /// with no owner, and leaving it would be a leak with nothing to justify it.
    pub fn lock_aside(&self) -> Result<PathBuf> {
        let destination = self.next_locked_path();
        fs::rename(&self.path, &destination).with_context(|| {
            format!(
                "failed to move {} aside to {}",
                self.path.display(),
                destination.display()
            )
        })?;
        self.shred_orphaned_tmp();
        Ok(destination)
    }

    /// `vault.enc.locked`, or `vault.enc.locked.2`, `.3`, … if earlier lock-outs are
    /// still there. Never returns a path that already exists, so no lock-out can
    /// silently overwrite the transcript of an earlier one.
    fn next_locked_path(&self) -> PathBuf {
        let mut candidate = append_extension(&self.path, "locked");
        let mut ordinal = 2u32;
        while candidate.symlink_metadata().is_ok() {
            candidate = append_extension(&self.path, &format!("locked.{ordinal}"));
            ordinal += 1;
        }
        candidate
    }

    /// Zeroes and unlinks a `<path>.tmp` left behind by a crash mid-write, if one is
    /// there. Shared by [`Self::destroy`] and [`Self::lock_aside`].
    fn shred_orphaned_tmp(&self) {
        // `write_atomically` writes the replacement vault to `<path>.tmp` and only
        // renames it over `self.path` once the write (and, on Unix, the permission
        // copy) has fully succeeded. A crash or power loss in that window — between
        // the temp file landing on disk and the rename — leaves `<path>.tmp` behind
        // holding a complete, valid, decryptable snapshot of the vault: the exact
        // secret this function exists to erase. Destroying `self.path` alone would
        // leave that orphaned snapshot fully recoverable right next to it, so it
        // gets the same zero-then-unlink treatment (symlink caution included) as
        // the vault file itself. On the common path there is no such file, so this
        // is a harmless no-op.
        let tmp = tmp_path_for(&self.path);
        match fs::symlink_metadata(&tmp) {
            Ok(meta)
                if !meta.file_type().is_symlink() && should_zero_before_unlink(&tmp, &meta) =>
            {
                let _ = fs::write(&tmp, vec![0u8; meta.len() as usize]);
            }
            _ => {}
        }
        let _ = fs::remove_file(&tmp);
    }

    /// Overwrites the file with zeros before unlinking, so the ciphertext is not left
    /// recoverable in freed blocks on simple filesystems.
    ///
    /// This function's entire purpose is destroying the one file at `self.path` — not
    /// whatever that path might be redirected to. `fs::metadata` and `fs::write` both
    /// follow symlinks, so if `vault.enc` were ever a symlink (planted by an attacker,
    /// or left behind by some other mistake), the old `fs::metadata` + `fs::write`
    /// pair zeroed the *link's target* — an unrelated file that merely happens to
    /// share a directory entry with the vault — while reporting the vault destroyed.
    /// `fs::symlink_metadata` inspects the link itself rather than following it, so a
    /// symlink here is detected and the zero-fill is skipped entirely: there is
    /// nothing belonging to the vault to shred. Hard links need their own refusal for
    /// the opposite reason: zeroing `self.path` would modify the shared inode and
    /// therefore every sibling path too, so multi-linked regular files are also left
    /// unwiped and only unlinked at this path.
    ///
    /// The unconditional `fs::remove_file` below is safe either way without any
    /// special-casing: `remove_file` unlinks the directory entry named `self.path`
    /// (via `unlink(2)` on Unix) without ever dereferencing a symlink to do so, so it
    /// only ever removes the link — never the target — regardless of which branch ran
    /// above. That alone already satisfies "the vault path no longer resolves to
    /// anything", which is what both callers (the `MAX_ATTEMPTS` wipe and `simon
    /// vault destroy`) actually want.
    pub fn destroy(&self) {
        match fs::symlink_metadata(&self.path) {
            Ok(meta)
                if !meta.file_type().is_symlink()
                    && should_zero_before_unlink(&self.path, &meta) =>
            {
                let _ = fs::write(&self.path, vec![0u8; meta.len() as usize]);
            }
            _ => {
                // Either a symlink, a multi-linked/unsupported-platform regular file,
                // or the path is already gone; either way there is nothing safe to zero.
            }
        }
        let _ = fs::remove_file(&self.path);
        self.shred_orphaned_tmp();
    }

    /// Reads the plaintext header fields without decrypting anything, so `simon vault
    /// status` never has to ask for (or fail without) a password.
    ///
    /// This is *why* `Header` itself stays private: exposing it whole would leak the
    /// salt and body offset for no reason a caller outside this module needs. Returns
    /// [`VaultError::Missing`] if there is no file yet, matching [`Self::load`].
    pub fn status(&self) -> Result<VaultStatus, VaultError> {
        let raw = match fs::read(&self.path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(VaultError::Missing),
            Err(e) => return Err(VaultError::Corrupt(e.to_string())),
        };
        let header = Self::parse_header(&raw)?;
        let now = now_secs();
        // `saturating_sub` below is fail-safe for a clock that has moved *backwards*
        // (idle reads as 0 rather than as an absurd number), but on its own it would
        // report a cheerful full window remaining for a clock we can prove is wrong.
        // Report the discrepancy instead of hiding it; it is a diagnostic, not an error.
        let clock_behind_secs = header.last_unlock.checked_sub(now).filter(|d| *d > 0);
        let idle_secs = now.saturating_sub(header.last_unlock);
        Ok(VaultStatus {
            path: self.path.clone(),
            failed_attempts: header.attempts,
            idle_secs,
            idle_secs_remaining: MAX_IDLE_SECS.saturating_sub(idle_secs),
            idle_expired: idle_secs > MAX_IDLE_SECS,
            clock_behind_secs,
        })
    }
}

/// Plaintext status, safe to display without a password.
///
/// The magic, version, salt and ciphertext are authenticated; `failed_attempts` and
/// the timestamp `idle_secs`/`idle_secs_remaining` are derived from are not — see the
/// module doc. That means these two fields are readable *and forgeable*: an attacker
/// with file access can reset them, so treat this as diagnostic information, not as
/// evidence of tampering (or its absence).
#[derive(Debug, Clone)]
pub struct VaultStatus {
    pub path: PathBuf,
    pub failed_attempts: u8,
    pub idle_secs: u64,
    /// Seconds until the vault passes `MAX_IDLE_SECS`. Zero means it is at or past the
    /// limit; nothing is destroyed at that point — see `idle_expired`.
    pub idle_secs_remaining: u64,
    /// The vault has sat unopened for longer than `MAX_IDLE_SECS`.
    ///
    /// This is a warning, not a verdict: it is derived from the wall clock, so a system
    /// clock that jumped forward produces it with no real time having passed. Unlocking
    /// with the right password succeeds either way and resets the window.
    pub idle_expired: bool,
    /// How far the system clock sits *behind* the vault's recorded last-unlock time, if
    /// it does. `Some(_)` means the clock is provably wrong (the vault cannot have been
    /// opened in the future), so `idle_secs`/`idle_secs_remaining` above are
    /// meaningless for this vault until the clock is fixed.
    pub clock_behind_secs: Option<u64>,
}

fn random_salt() -> Vec<u8> {
    let mut salt = vec![0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Marks the single system line [`trim_transcript_to_cap`] leaves behind in place of
/// whatever it drops. Distinct enough that no ordinary transcript line is likely to
/// collide with it, and recognised by [`take_leading_marker`] so a later trim updates
/// the running total instead of stacking a second marker underneath the first.
const DROP_MARKER_PREFIX: &str = "[vault] ";

fn drop_marker(total_dropped: u64, cap: usize) -> Line {
    Line {
        speaker: Speaker::System,
        text: format!(
            "{DROP_MARKER_PREFIX}{total_dropped} earlier line(s) were dropped, oldest \
             first, to keep this transcript within its {cap}-line vault cap. Run \
             `simon vault prune` to manage this by hand."
        ),
    }
}

/// If `transcript` currently starts with a marker this module wrote, removes it and
/// returns the total it recorded (0 otherwise). Removing it before counting is what
/// keeps the marker itself from ever being treated as content subject to the cap.
fn take_leading_marker(transcript: &mut Vec<Line>) -> u64 {
    let is_marker = transcript.first().is_some_and(|l| {
        matches!(l.speaker, Speaker::System) && l.text.starts_with(DROP_MARKER_PREFIX)
    });
    if !is_marker {
        return 0;
    }
    let line = transcript.remove(0);
    line.text[DROP_MARKER_PREFIX.len()..]
        .split_whitespace()
        .next()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

/// Bounds `transcript` to at most `cap` lines, oldest first, in place. Returns how
/// many lines were newly dropped *by this call* — 0 if `transcript` was already
/// within `cap`, which callers use to decide whether to tell the user anything
/// happened (see `vault_unlock_for_chat` and `vault_save_after_chat` in `main.rs`).
///
/// A transcript at exactly `cap` is left completely untouched, not merely trimmed to
/// no visible effect: this boundary is deliberate, not incidental — the audit's
/// mutation-testing pass found every `>` vs `>=` in this codebase untested before
/// today, and getting this one backwards would either trim a transcript that fits or
/// silently let one grow one line past the cap forever.
///
/// What gets dropped is replaced with a single [`drop_marker`] line rather than left
/// unmarked, so a reloaded transcript reads as "N lines omitted, then the
/// conversation continues" instead of jumping into the middle of an exchange with no
/// indication anything is missing. Repeated calls (each save, each load) accumulate
/// into that one marker's count via [`take_leading_marker`] rather than leaving a
/// trail of markers behind — the marker's own line does not itself count against
/// `cap`, so trimming to `cap` never produces `cap + 1` lines once the marker is
/// added back.
pub fn trim_transcript_to_cap(transcript: &mut Vec<Line>, cap: usize) -> u64 {
    debug_assert!(
        cap >= 1,
        "a zero-line cap leaves no room for the marker itself"
    );
    let previously_dropped = take_leading_marker(transcript);

    // If an existing marker was present, it must be put back and will occupy one slot
    // of `cap`, so at most `cap - 1` content lines may be kept without dropping new lines.
    let keep_without_dropping = if previously_dropped > 0 {
        cap.saturating_sub(1)
    } else {
        cap
    };

    if transcript.len() <= keep_without_dropping {
        // Nothing new to drop. Put back an unchanged marker if one was already
        // there — its count is still true, it just isn't growing this time.
        if previously_dropped > 0 {
            transcript.insert(0, drop_marker(previously_dropped, cap));
        }
        return 0;
    }

    // One slot of `cap` is reserved for the marker itself, so content-plus-marker
    // never exceeds `cap` once it's inserted below.
    let keep = cap.saturating_sub(1);
    let content_len = transcript.len();
    let newly_dropped = (content_len - keep) as u64;
    transcript.drain(0..content_len - keep);
    let total_dropped = previously_dropped + newly_dropped;
    transcript.insert(0, drop_marker(total_dropped, cap));
    newly_dropped
}

/// Writes via a temporary file and rename so a crash, power loss, or full disk mid-write
/// cannot truncate an existing file. Shared with `config.rs::Settings::save`, which had
/// the identical problem for `config.json` — see the comment on `Settings::save` for why
/// that call goes through here rather than duplicating this logic. Kept in this module
/// (as `pub(crate)`) rather than moved to a new one: the crate wires its module list in
/// `main.rs`, which is outside what this change touches, and a single ~15-line helper
/// does not earn a module of its own when one of its two callers already lives next to
/// it.
///
/// The temp file is created *in `path`'s own directory*, never under a system temp dir
/// like `/tmp` — `fs::rename` is only atomic when source and destination are on the same
/// filesystem (a cross-filesystem rename has to copy, which reintroduces the exact
/// truncation window this function exists to close). Both `config.json` and `vault.enc`
/// live under the per-user data directory, so the temp file always lands there too.
///
/// Windows note: `std::fs::rename` is not POSIX `rename(2)` under the hood, but on
/// Windows it is implemented via `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING`, so it
/// does replace an existing destination atomically the same as it does on Unix — no
/// platform-specific fallback is needed here. (It can still fail if another process
/// holds the destination open without `FILE_SHARE_DELETE`, but `simon` never has two
/// processes writing the same config or vault concurrently.)
pub(crate) fn write_atomically(path: &Path, bytes: &[u8]) -> Result<()> {
    // `preserve_permissions` below carries `path`'s current mode forward onto the
    // replacement file. If `path` is a symlink, the naive way to read "its current
    // mode" (`fs::metadata`, which follows links) actually reads the *target's*
    // mode — so a `vault.enc`/`config.json` that had been replaced by a symlink to
    // some loosely-permissioned file would silently launder that file's mode onto
    // the freshly written replacement (644 instead of the documented owner-only
    // 600), while the rename itself replaces the symlink with a real file rather
    // than writing through it. Neither half of that is a sane outcome for a helper
    // whose only two callers write access-controlled secrets, so refuse outright
    // rather than pick between "honor the link" and "replace it" on the caller's
    // behalf. Checked with `symlink_metadata`, which — unlike `metadata` — inspects
    // the link itself instead of following it.
    if let Ok(meta) = fs::symlink_metadata(path)
        && meta.file_type().is_symlink()
    {
        return Err(anyhow!(
            "refusing to write {} through a symlink",
            path.display()
        ));
    }

    let tmp = tmp_path_for(path);
    if let Ok(meta) = fs::symlink_metadata(&tmp)
        && meta.file_type().is_symlink()
    {
        return Err(anyhow!(
            "refusing to write {} through a symlink",
            tmp.display()
        ));
    }

    // A failed write leaves only the temp file behind, never a touched `path`, so
    // nothing to clean up on this branch.
    fs::write(&tmp, bytes).map_err(|e| anyhow!("failed to write {}: {e}", tmp.display()))?;

    // `fs::write` on a brand-new file gets whatever the process umask allows (typically
    // world-readable). A plain `fs::write` straight to `path` would instead have
    // truncated-in-place, keeping `path`'s *existing* inode and its permission bits.
    // Renaming a new file over `path` replaces the inode outright, so without this step
    // switching to atomic writes would silently loosen `config.json`/`vault.enc` back to
    // the umask default on every single save — undoing any tightening a user (or a
    // future version of this code) had applied. Carry the current file's mode forward;
    // if there is no current file, default to owner-only rather than the umask, since
    // both files hold data — connection endpoints, an encrypted transcript — that has no
    // reason to be group- or world-readable.
    if let Err(e) = preserve_permissions(path, &tmp) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }

    // If the rename fails (e.g. a permissions or disk error on the directory entry
    // itself), the write above already succeeded, so `path` is untouched and safe — but
    // the temp file would otherwise sit there forever as debris. Best-effort clean it up;
    // its own removal failing is not worth reporting over the original error.
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(anyhow!("failed to replace {}: {e}", path.display()));
    }
    Ok(())
}

/// Derives the temp path by *appending* `.tmp` rather than `Path::with_extension`
/// (`vault.enc` → `vault.tmp`), which was the original approach here. `with_extension`
/// replaces the extension, not appends to it, so two targets in the same directory that
/// share a stem but differ only in extension would collide on the same temp path — not
/// a problem for `vault.enc` alone, but it became one the moment `config.json` started
/// sharing this helper (and would again for any future file added to the data dir).
/// Appending keeps every target's temp path unique to it: `vault.enc.tmp`,
/// `config.json.tmp`. This does rename the vault's own temp file from the historical
/// `vault.tmp` to `vault.enc.tmp` — noted because nothing else in the tree parses or
/// depends on that name (checked: it appears nowhere outside this function).
/// `vault.enc` + `locked` = `vault.enc.locked`, for the same reason `tmp_path_for`
/// appends rather than replaces: `Path::set_extension` would turn `vault.enc` into
/// `vault.locked` and lose which file it came from.
fn append_extension(target: &Path, extension: &str) -> PathBuf {
    let mut name = target.as_os_str().to_owned();
    name.push(".");
    name.push(extension);
    PathBuf::from(name)
}

fn tmp_path_for(target: &Path) -> PathBuf {
    let mut name = target.as_os_str().to_owned();
    name.push(".tmp");
    PathBuf::from(name)
}

/// See the call site in [`write_atomically`] for why this exists. Unix-only because
/// `config.rs`'s `restrict_to_owner` (which locks the data directory down to
/// owner-only) uses this same `#[cfg(unix)]` split — on other platforms file mode bits
/// either don't exist in this form or aren't how access is controlled, so there is
/// nothing analogous to preserve.
#[cfg(unix)]
fn preserve_permissions(target: &Path, tmp: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    // `symlink_metadata`, not `metadata`: `write_atomically`'s caller-facing guard
    // above already refuses the whole operation when `target` itself is a symlink,
    // but this stays consistent with that decision on its own rather than silently
    // reading through a link if that guard is ever changed. A symlink's own mode
    // bits are not a meaningful "current permissions of the vault/config file" in
    // any case — on Linux they are cosmetic and normally read back as 0o777 — so a
    // symlink is treated the same as "nothing there yet" and falls through to the
    // owner-only default below, exactly like a brand-new file would.
    let mode = fs::symlink_metadata(target)
        .ok()
        .filter(|m| !m.file_type().is_symlink())
        .map(|m| m.permissions().mode())
        .unwrap_or(0o600);
    fs::set_permissions(tmp, fs::Permissions::from_mode(mode))
        .map_err(|e| anyhow!("failed to set permissions on {}: {e}", tmp.display()))
}

#[cfg(not(unix))]
fn preserve_permissions(_target: &Path, _tmp: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault_in(dir: &tempfile::TempDir) -> EncryptedVault {
        EncryptedVault::new(dir.path().join("vault.enc"))
    }

    /// Rewrites the plaintext last-unlock timestamp in place, the same way the tests
    /// below have always simulated elapsed time: bytes 10..18 of the header are outside
    /// the AAD precisely so they can be rewritten without touching the ciphertext.
    fn set_last_unlock(vault: &EncryptedVault, unix_secs: u64) {
        let mut raw = fs::read(vault.path()).unwrap();
        raw[10..18].copy_from_slice(&unix_secs.to_be_bytes());
        fs::write(vault.path(), &raw).unwrap();
    }

    #[test]
    fn round_trips_without_an_externally_supplied_salt() {
        // The core regression: save then load with only the password. The old API
        // required a salt the caller had to store somewhere that did not exist.
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(&dir);
        let pw = SecretString::from("correct horse battery staple".to_string());

        vault.save(b"top secret history", &pw).unwrap();
        assert_eq!(vault.load(&pw).unwrap(), b"top secret history");
    }

    #[test]
    fn wrong_password_is_rejected_and_counts_down() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(&dir);
        let pw = SecretString::from("right".to_string());
        let wrong = SecretString::from("wrong".to_string());
        vault.save(b"payload", &pw).unwrap();

        match vault.load(&wrong) {
            Err(VaultError::WrongPassword { remaining }) => {
                assert_eq!(remaining, MAX_ATTEMPTS - 1)
            }
            other => panic!("expected WrongPassword, got {other:?}"),
        }
        // The correct password still works, and resets the counter.
        assert_eq!(vault.load(&pw).unwrap(), b"payload");
        match vault.load(&wrong) {
            Err(VaultError::WrongPassword { remaining }) => {
                assert_eq!(remaining, MAX_ATTEMPTS - 1, "counter should have reset")
            }
            other => panic!("expected WrongPassword, got {other:?}"),
        }
    }

    #[test]
    fn vault_self_destructs_after_max_attempts() {
        // Historical name, kept so the behaviour it guards stays findable: the vault no
        // longer self-destructs, it locks. What must not change is the half that is a
        // security property — after `MAX_ATTEMPTS`, this path stops opening — as
        // distinct from the half that was only ever data loss.
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(&dir);
        let pw = SecretString::from("right".to_string());
        let wrong = SecretString::from("wrong".to_string());
        vault.save(b"payload", &pw).unwrap();

        for _ in 0..(MAX_ATTEMPTS - 1) {
            assert!(matches!(
                vault.load(&wrong),
                Err(VaultError::WrongPassword { .. })
            ));
        }
        assert!(matches!(
            vault.load(&wrong),
            Err(VaultError::LockedOut { .. })
        ));
        assert!(!vault.exists(), "the vault path must no longer open");
        assert!(matches!(vault.load(&pw), Err(VaultError::Missing)));
    }

    #[test]
    fn the_fifth_wrong_password_locks_the_vault_aside_instead_of_destroying_it() {
        // The wipe was documented and deliberate, and it still harmed the owner far
        // more reliably than an attacker: the person who reaches five wrong passwords
        // is overwhelmingly the one who is about to remember the right one, and the
        // counter never bounded anyone who could write the file anyway (it is plaintext
        // and restorable from a copy — `a_forged_attempt_count_cannot_destroy_a_vault…`
        // is the other half of that story). So the ciphertext survives, and it must
        // survive *as ciphertext*: a lock-out that left a decryptable file readable
        // under a new name would have traded a data-loss bug for a disclosure one.
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(&dir);
        let pw = SecretString::from("right".to_string());
        let wrong = SecretString::from("wrong".to_string());
        vault
            .save(b"the transcript that must not be lost", &pw)
            .unwrap();

        for _ in 0..(MAX_ATTEMPTS - 1) {
            assert!(matches!(
                vault.load(&wrong),
                Err(VaultError::WrongPassword { .. })
            ));
        }

        let moved_to = match vault.load(&wrong) {
            Err(VaultError::LockedOut { moved_to, .. }) => {
                moved_to.expect("the move must have succeeded on a writable tempdir")
            }
            other => panic!("expected LockedOut, got {other:?}"),
        };

        assert!(
            !vault.exists(),
            "the vault path must stop opening — that is the anti-brute-force property"
        );
        assert!(moved_to.is_file(), "the ciphertext must still be on disk");
        assert_eq!(
            moved_to,
            dir.path().join("vault.enc.locked"),
            "the locked file must sit beside the vault, named after it"
        );

        let bytes = fs::read(&moved_to).unwrap();
        assert!(
            !bytes.windows(6).any(|w| w == b"transc"),
            "the set-aside file must still be encrypted"
        );

        // And it is genuinely recoverable: move it back, and the right password opens
        // it. A "kept" file that could not be reopened would be no better than a wipe.
        fs::rename(&moved_to, dir.path().join("vault.enc")).unwrap();
        assert_eq!(
            vault.load(&pw).unwrap(),
            b"the transcript that must not be lost"
        );
    }

    #[test]
    fn a_second_lock_out_does_not_overwrite_the_first_ones_transcript() {
        // `vault.enc.locked` already existing is not an edge case: it is what the
        // second bad day looks like. Overwriting it would destroy the very transcript
        // the first lock-out was preserving, quietly reintroducing the loss this change
        // exists to remove.
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(&dir);
        let wrong = SecretString::from("wrong".to_string());

        let mut locked_paths = Vec::new();
        for round in 0..2 {
            vault
                .save(
                    format!("transcript {round}").as_bytes(),
                    &SecretString::from(format!("password {round}")),
                )
                .unwrap();
            for _ in 0..(MAX_ATTEMPTS - 1) {
                assert!(matches!(
                    vault.load(&wrong),
                    Err(VaultError::WrongPassword { .. })
                ));
            }
            match vault.load(&wrong) {
                Err(VaultError::LockedOut { moved_to, .. }) => {
                    locked_paths.push(moved_to.expect("the move must have succeeded"))
                }
                other => panic!("expected LockedOut, got {other:?}"),
            }
        }

        assert_ne!(
            locked_paths[0], locked_paths[1],
            "the second lock-out reused the first one's path"
        );
        for (round, path) in locked_paths.iter().enumerate() {
            let vault_at_locked = EncryptedVault::new(path.clone());
            assert_eq!(
                vault_at_locked
                    .load(&SecretString::from(format!("password {round}")))
                    .unwrap(),
                format!("transcript {round}").as_bytes(),
                "lock-out {round} lost its transcript"
            );
        }
    }

    #[test]
    fn tampering_with_authenticated_header_fails_decryption() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(&dir);
        let pw = SecretString::from("pw".to_string());
        vault.save(b"payload", &pw).unwrap();

        // Flip a salt byte — it is bound as AAD, so decryption must fail.
        let mut raw = fs::read(vault.path()).unwrap();
        raw[HEADER_FIXED_LEN] ^= 0xff;
        fs::write(vault.path(), &raw).unwrap();

        assert!(vault.load(&pw).is_err());
    }

    #[test]
    fn missing_vault_is_distinguishable_from_a_bad_password() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(&dir);
        let pw = SecretString::from("pw".to_string());
        assert!(matches!(vault.load(&pw), Err(VaultError::Missing)));
    }

    #[test]
    fn an_idle_expired_vault_is_not_destroyed_and_still_opens_with_the_right_password() {
        // The regression this replaces: `load()` used to delete the file here, before
        // the password was checked, so a clock that jumped forward wiped the transcript
        // with no way to recover it.
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(&dir);
        let pw = SecretString::from("pw".to_string());
        vault.save(b"payload", &pw).unwrap();

        set_last_unlock(&vault, now_secs() - (MAX_IDLE_SECS + 60));

        assert_eq!(vault.load(&pw).unwrap(), b"payload");
        assert!(vault.exists(), "idle expiry must not destroy the vault");
    }

    #[test]
    fn unlocking_an_idle_expired_vault_resets_the_idle_window() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(&dir);
        let pw = SecretString::from("pw".to_string());
        vault.save(b"payload", &pw).unwrap();

        set_last_unlock(&vault, now_secs() - (MAX_IDLE_SECS + 60));
        assert!(vault.status().unwrap().idle_expired);

        vault.load(&pw).unwrap();

        let after = vault.status().unwrap();
        assert!(
            !after.idle_expired,
            "a successful unlock clears the warning"
        );
        assert!(
            after.idle_secs_remaining > MAX_IDLE_SECS - 60,
            "the window should be fresh, not merely nonzero"
        );
    }

    #[test]
    fn a_wrong_password_on_an_idle_expired_vault_still_counts_toward_the_wipe() {
        // Idle expiry stopped being destructive; the attempt limit did not. Being past
        // the idle window must not become a way to guess passwords for free.
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(&dir);
        let pw = SecretString::from("right".to_string());
        let wrong = SecretString::from("wrong".to_string());
        vault.save(b"payload", &pw).unwrap();

        let stale = now_secs() - (MAX_IDLE_SECS + 60);
        set_last_unlock(&vault, stale);

        for expected_remaining in (1..MAX_ATTEMPTS).rev() {
            match vault.load(&wrong) {
                Err(VaultError::WrongPassword { remaining }) => {
                    assert_eq!(remaining, expected_remaining)
                }
                other => panic!("expected WrongPassword, got {other:?}"),
            }
            // Each failed attempt rewrites the header, so re-stale it: the point is
            // that the lock-out below comes from the attempt count, not from the clock.
            set_last_unlock(&vault, stale);
        }

        assert!(matches!(
            vault.load(&wrong),
            Err(VaultError::LockedOut { .. })
        ));
        assert!(!vault.exists(), "the attempt-based lock-out still applies");
    }

    #[test]
    fn status_reports_idle_expiry_for_a_vault_past_the_limit() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(&dir);
        let pw = SecretString::from("pw".to_string());
        vault.save(b"payload", &pw).unwrap();

        set_last_unlock(&vault, now_secs() - (MAX_IDLE_SECS + 7200));

        let status = vault.status().unwrap();
        assert!(status.idle_expired);
        assert_eq!(status.idle_secs_remaining, 0);
        assert!(status.idle_secs > MAX_IDLE_SECS);
        assert_eq!(status.clock_behind_secs, None);
    }

    #[test]
    fn status_reports_a_clock_behind_the_last_unlock_rather_than_a_full_window() {
        // A vault cannot have been opened in the future: this says the system clock is
        // wrong, and the idle numbers derived from it mean nothing until it is fixed.
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(&dir);
        let pw = SecretString::from("pw".to_string());
        vault.save(b"payload", &pw).unwrap();

        set_last_unlock(&vault, now_secs() + 3600);

        let status = vault.status().unwrap();
        assert!(
            matches!(status.clock_behind_secs, Some(secs) if secs > 3000),
            "expected the backwards clock to be reported, got {:?}",
            status.clock_behind_secs
        );
        // Still fail-safe underneath: no wrap-around, no bogus expiry.
        assert_eq!(status.idle_secs, 0);
        assert!(!status.idle_expired);
    }

    #[test]
    fn write_atomically_appends_dot_tmp_rather_than_replacing_the_extension() {
        // Regression guard for the collision bug `with_extension("tmp")` had: it
        // replaces rather than appends, so `vault.enc` and `config.json` — sharing this
        // helper today, and any future same-stem pair — would land on the identical
        // temp path and could clobber each other's in-flight write. Assert the actual
        // path shape rather than just that saves succeed, since two colliding writes in
        // a single-threaded test could still coincidentally "succeed" while masking the
        // bug.
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            tmp_path_for(&dir.path().join("vault.enc")),
            dir.path().join("vault.enc.tmp")
        );
        assert_eq!(
            tmp_path_for(&dir.path().join("config.json")),
            dir.path().join("config.json.tmp")
        );
    }

    #[test]
    fn write_atomically_leaves_no_tmp_file_behind_on_success() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("vault.enc");
        write_atomically(&target, b"payload").unwrap();

        // Fixture guard: confirm the write actually landed before trusting an
        // empty-looking directory listing below.
        assert!(target.is_file(), "fixture write did not land");
        assert!(
            !dir.path().join("vault.enc.tmp").exists(),
            "temp file left behind after a successful write"
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_atomically_preserves_an_existing_files_tightened_permissions() {
        // The regression this guards: renaming a freshly created temp file over an
        // existing target replaces the target's *inode*, unlike an in-place
        // `fs::write`, which truncates the existing inode and keeps its mode bits. A
        // naive atomic-write helper would therefore silently reset a file the user (or
        // this crate) had tightened to owner-only back to the process umask on the very
        // next save. Assert the tightened mode survives a second write.
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("vault.enc");
        write_atomically(&target, b"first").unwrap();

        // Simulate a file that had been tightened to owner-only by some means other
        // than this helper (e.g. an older build, or a user running `chmod`).
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let tightened = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(tightened, 0o600, "fixture failed to tighten permissions");

        write_atomically(&target, b"second, longer payload").unwrap();

        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "an atomic save must not loosen an existing file's permissions"
        );
        assert_eq!(fs::read(&target).unwrap(), b"second, longer payload");
    }

    #[test]
    fn saving_twice_keeps_the_same_password_working() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(&dir);
        let pw = SecretString::from("pw".to_string());
        vault.save(b"first", &pw).unwrap();
        vault.save(b"second", &pw).unwrap();
        assert_eq!(vault.load(&pw).unwrap(), b"second");
    }

    #[test]
    fn a_truncated_file_is_reported_as_corrupt_not_silently_destroyed() {
        // Corruption (bad magic, truncated header, unsupported version) must not
        // trigger the self-destruct path — that is reserved for exhausted attempts.
        // Conflating the two would delete a vault a user might
        // otherwise be able to recover (e.g. from a backup of the file).
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(&dir);
        let pw = SecretString::from("pw".to_string());
        vault.save(b"payload", &pw).unwrap();

        let raw = fs::read(vault.path()).unwrap();
        fs::write(vault.path(), &raw[..HEADER_FIXED_LEN - 1]).unwrap();

        assert!(matches!(vault.load(&pw), Err(VaultError::Corrupt(_))));
        assert!(
            vault.exists(),
            "corrupt files must be left alone, not destroyed automatically"
        );
    }

    #[test]
    fn status_reports_header_fields_without_needing_the_password() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(&dir);
        let pw = SecretString::from("pw".to_string());
        vault.save(b"payload", &pw).unwrap();

        // Note what is absent from this call: no `SecretString` argument exists to
        // pass, which is the point — `status()`'s signature makes an unlock
        // impossible to require by accident.
        let status = vault.status().unwrap();
        assert_eq!(status.path.as_path(), vault.path());
        assert_eq!(status.failed_attempts, 0);
        assert!(
            status.idle_secs_remaining > MAX_IDLE_SECS - 60,
            "a freshly saved vault should be nowhere near idle expiry"
        );
        assert!(!status.idle_expired);
        assert_eq!(status.clock_behind_secs, None);
    }

    #[test]
    fn status_on_a_missing_vault_is_reported_as_missing() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(&dir);
        assert!(matches!(vault.status(), Err(VaultError::Missing)));
    }

    #[test]
    fn a_serialized_transcript_round_trips_through_the_vault() {
        // The actual feature: the vault stores the TUI's `Vec<Line>` transcript, not
        // arbitrary bytes. Encrypting and decrypting could "work" while the JSON
        // underneath silently lost the model label on a `Speaker::Model` line, so
        // this checks the full path, not just AES-GCM. (`Line`/`Speaker` come in via
        // this module's own top-level `use crate::app::{Line, Speaker}` now that
        // `trim_transcript_to_cap` needs them outside tests too.)

        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(&dir);
        let pw = SecretString::from("transcript password".to_string());

        let transcript = vec![
            Line {
                speaker: Speaker::You,
                text: "hello".into(),
            },
            Line {
                speaker: Speaker::Model("anthropic:claude-opus-5".into()),
                text: "hi there".into(),
            },
            Line {
                speaker: Speaker::System,
                text: "commander: anthropic:claude-opus-5".into(),
            },
        ];
        let payload = serde_json::to_vec(&transcript).unwrap();
        vault.save(&payload, &pw).unwrap();

        let loaded = vault.load(&pw).unwrap();
        let restored: Vec<Line> = serde_json::from_slice(&loaded).unwrap();

        assert_eq!(restored.len(), transcript.len());
        assert_eq!(restored[1].text, "hi there");
        assert!(
            matches!(&restored[1].speaker, Speaker::Model(m) if m == "anthropic:claude-opus-5")
        );
    }

    #[test]
    fn a_truncated_file_is_corrupt_and_never_charged_as_a_failed_attempt() {
        // Was `bug_proof_truncated_ciphertext_triggers_self_destruct_instead_of_corrupt`.
        // A file cut after the nonce has no GCM tag, so decryption fails for a
        // structural reason — which used to be reported as a wrong password and, after
        // five tries with the *correct* one, destroyed the damaged file outright.
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(&dir);
        let pw = SecretString::from("correct_pw".to_string());
        vault.save(b"my transcript", &pw).unwrap();

        let raw = fs::read(vault.path()).unwrap();
        let truncated_len = HEADER_FIXED_LEN + SALT_LEN + NONCE_LEN;
        assert!(
            raw.len() > truncated_len,
            "fixture did not actually truncate anything"
        );
        fs::write(vault.path(), &raw[..truncated_len]).unwrap();

        for _ in 0..(MAX_ATTEMPTS + 2) {
            match vault.load(&pw) {
                Err(VaultError::Corrupt(_)) => {}
                other => panic!("expected Corrupt for a structurally invalid file, got {other:?}"),
            }
            assert!(vault.exists(), "a corrupt file must never be destroyed");
        }
    }

    #[test]
    fn a_header_claiming_an_undersized_salt_is_rejected_rather_than_reused() {
        // Was `bug_proof_short_salt_breaks_save_permanently`. `save` reuses the stored
        // salt so an unchanged password keeps working; a header claiming a salt below
        // Argon2's minimum was accepted on read and then reused, so key derivation
        // failed and the vault could never be written again.
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(&dir);
        let pw = SecretString::from("password".to_string());

        let mut raw = Vec::new();
        raw.extend_from_slice(MAGIC);
        raw.push(VERSION);
        raw.push(0);
        raw.extend_from_slice(&0u64.to_be_bytes());
        raw.push(0); // salt_len = 0
        raw.extend_from_slice(&[0u8; NONCE_LEN]);
        raw.extend_from_slice(&[0u8; TAG_LEN]);
        fs::write(vault.path(), &raw).unwrap();

        vault
            .save(b"fresh transcript", &pw)
            .expect("save must recover by generating a fresh salt");
        assert_eq!(vault.load(&pw).unwrap(), b"fresh transcript");
    }

    #[test]
    fn a_forged_attempt_count_cannot_destroy_a_vault_the_password_still_opens() {
        // Was `bug_proof_unauthenticated_byte_9_causes_instant_destruction`. Byte 9 sits
        // outside the AEAD's authenticated data, so anyone who can write the file — or a
        // single flipped bit — could set it to MAX_ATTEMPTS, and `load` destroyed the
        // vault on that number alone, before the password was ever tried.
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(&dir);
        let pw = SecretString::from("secret_password".to_string());
        vault.save(b"valuable secret transcript", &pw).unwrap();

        let mut raw = fs::read(vault.path()).unwrap();
        raw[9] = MAX_ATTEMPTS;
        fs::write(vault.path(), &raw).unwrap();
        assert_eq!(
            fs::read(vault.path()).unwrap()[9],
            MAX_ATTEMPTS,
            "fixture failed to forge the attempt count, so this proves nothing"
        );

        let opened = vault
            .load(&pw)
            .expect("the correct password must still open it");
        assert_eq!(opened, b"valuable secret transcript");
        assert!(
            vault.exists(),
            "the vault was destroyed despite a correct password"
        );
        assert_eq!(
            fs::read(vault.path()).unwrap()[9],
            0,
            "a successful unlock must reset the forged count"
        );
    }

    #[test]
    #[cfg(unix)]
    fn an_attempt_that_cannot_be_recorded_is_refused_rather_than_given_away() {
        // Was `bug_proof_readonly_vault_bypasses_brute_force_limit`. The failed-attempt
        // increment was written with `let _ = …`, so on a read-only directory it never
        // reached disk: every guess re-read the same count and `remaining` reported the
        // same number forever, which is unlimited guessing wearing a limit's clothes.
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(&dir);
        let pw = SecretString::from("correct".to_string());
        let wrong = SecretString::from("wrong".to_string());
        vault.save(b"secret", &pw).unwrap();

        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o500)).unwrap();
        let result = vault.load(&wrong);
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();

        match result {
            Err(VaultError::Corrupt(msg)) => assert!(
                msg.contains("could not be recorded"),
                "unexpected refusal reason: {msg}"
            ),
            other => {
                panic!("expected a refusal when the attempt cannot be recorded, got {other:?}")
            }
        }
        assert!(vault.exists(), "refusing must not destroy the vault");
        assert_eq!(
            vault.load(&pw).unwrap(),
            b"secret",
            "the vault must still open"
        );
    }

    #[test]
    #[cfg(unix)]
    fn destroy_refuses_to_zero_a_symlinks_target() {
        // `destroy()` used `fs::metadata` + `fs::write`, both of which follow
        // symlinks. If `vault.enc` were ever a symlink, the self-destruct (on
        // `MAX_ATTEMPTS`, or `simon vault destroy`) zeroed the LINK'S TARGET — some
        // unrelated file that merely shares a directory entry with the vault — and
        // then unlinked only the link itself, leaving the caller believing the
        // vault (and only the vault) was destroyed.
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(&dir);
        let pw = SecretString::from("pw".to_string());
        vault.save(b"payload", &pw).unwrap();

        let victim = dir.path().join("victim.txt");
        fs::write(&victim, b"do not touch").unwrap();
        fs::remove_file(vault.path()).unwrap();
        std::os::unix::fs::symlink(&victim, vault.path()).unwrap();

        vault.destroy();

        assert_eq!(
            fs::read(&victim).unwrap(),
            b"do not touch",
            "destroy() zeroed the symlink's target instead of refusing to"
        );
        assert!(
            !vault.path().exists(),
            "the symlink itself should still be gone — unlinking it never touches \
             its target, so this is safe even though the target survives"
        );
    }

    #[test]
    fn destroy_refuses_to_zero_a_hard_links_other_path() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(&dir);
        let pw = SecretString::from("pw".to_string());
        vault.save(b"payload", &pw).unwrap();

        let raw = fs::read(vault.path()).unwrap();
        let inspector = dir.path().join("vault.inspector");
        fs::hard_link(vault.path(), &inspector).unwrap();

        vault.destroy();

        assert!(
            !vault.path().exists(),
            "destroy() must still unlink the configured vault path"
        );
        assert_eq!(
            fs::read(&inspector).unwrap(),
            raw,
            "destroy() zeroed the shared inode behind a hard-linked vault"
        );
    }

    #[test]
    #[cfg(unix)]
    fn destroy_zeroes_the_vault_file_before_unlinking_it() {
        // The path disappears either way, so keep its inode open across destroy:
        // Unix descriptors remain readable after unlink and let this distinguish
        // the promised zero-then-unlink from a bare unlink.
        use std::io::{Read as _, Seek as _, SeekFrom};

        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(&dir);
        let pw = SecretString::from("pw".to_string());
        vault.save(b"top secret transcript", &pw).unwrap();

        let raw_len = fs::metadata(vault.path()).unwrap().len() as usize;
        let mut inspector = fs::File::open(vault.path()).unwrap();

        vault.destroy();

        assert!(
            !vault.path().exists(),
            "destroy() must still unlink the vault file"
        );
        inspector.seek(SeekFrom::Start(0)).unwrap();
        let mut observed = Vec::new();
        inspector.read_to_end(&mut observed).unwrap();
        assert_eq!(
            observed,
            vec![0u8; raw_len],
            "destroy() unlinked the vault without zeroing it first"
        );
    }

    #[test]
    fn destroy_leaves_a_crash_orphaned_tmp_file_with_the_secret_still_recoverable() {
        // `write_atomically` writes the new vault to `vault.enc.tmp` and only then
        // renames it over `vault.enc`. A crash or power loss between those two steps
        // leaves `vault.enc.tmp` on disk holding a complete, valid, decryptable
        // snapshot of the vault — exactly the secret `destroy()` exists to erase.
        // `destroy()` must not leave that snapshot sitting untouched right next to
        // the file it just wiped.
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(&dir);
        let pw = SecretString::from("pw".to_string());
        vault.save(b"top secret transcript", &pw).unwrap();

        // Simulate the crash window: a fully-written `.tmp` snapshot that never got
        // renamed into place.
        let raw = fs::read(vault.path()).unwrap();
        let tmp = tmp_path_for(vault.path());
        fs::write(&tmp, &raw).unwrap();

        vault.destroy();

        assert!(
            !tmp.exists(),
            "destroy() left a crash-orphaned .tmp file behind with the vault's \
             secret still fully recoverable from it"
        );
    }

    #[test]
    #[cfg(unix)]
    fn destroy_refuses_to_zero_a_crash_orphaned_tmps_symlinked_target() {
        // Same hazard as `destroy_refuses_to_zero_a_symlinks_target`, one file over:
        // the crash-orphaned `.tmp` cleanup added to `destroy()` uses `symlink_metadata`
        // + a guarded `fs::write`, mirroring the guard used for `self.path` above it. If
        // that guard were ever bypassed, a `vault.enc.tmp` that is actually a SYMLINK
        // would have its target zeroed — some unrelated file that merely happens to
        // share that directory entry — even though unlinking the symlink afterward
        // never touches the target.
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(&dir);
        let pw = SecretString::from("pw".to_string());
        vault.save(b"payload", &pw).unwrap();

        let victim = dir.path().join("victim.txt");
        fs::write(&victim, b"do not touch").unwrap();
        let tmp = tmp_path_for(vault.path());
        std::os::unix::fs::symlink(&victim, &tmp).unwrap();

        vault.destroy();

        assert_eq!(
            fs::read(&victim).unwrap(),
            b"do not touch",
            "destroy() zeroed the .tmp symlink's target instead of refusing to"
        );
        assert!(
            !tmp.exists(),
            "the .tmp symlink itself should still be gone — unlinking it never \
             touches its target, so this is safe even though the target survives"
        );
    }

    #[test]
    #[cfg(unix)]
    fn destroy_zeroes_a_crash_orphaned_tmp_file_before_unlinking_it() {
        // The crash-orphaned `.tmp` cleanup in `destroy()` is supposed to zero the
        // file's contents before unlinking it, the same as it does for `self.path` —
        // not merely unlink it and leave the secret sitting in the freed disk blocks.
        // `remove_file` unlinks the `.tmp` path unconditionally either way, so
        // checking `!tmp.exists()` afterward (as the crash-orphan test above does)
        // can't tell a zero-then-unlink from a bare unlink. Open the file first and
        // keep that descriptor alive across `destroy()`: on Unix, unlinking the path
        // does not invalidate the already-open inode, so the descriptor still lets us
        // inspect the bytes after the name is gone without introducing a second hard
        // link (which is now itself something `destroy()` must refuse to zero).
        use std::io::{Read as _, Seek as _, SeekFrom};

        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(&dir);
        let pw = SecretString::from("pw".to_string());
        vault.save(b"top secret transcript", &pw).unwrap();

        let raw = fs::read(vault.path()).unwrap();
        let tmp = tmp_path_for(vault.path());
        fs::write(&tmp, &raw).unwrap();
        let mut inspector = fs::File::open(&tmp).unwrap();

        vault.destroy();

        assert!(!tmp.exists(), "destroy() must still unlink the .tmp file");
        inspector.seek(SeekFrom::Start(0)).unwrap();
        let mut observed = Vec::new();
        inspector.read_to_end(&mut observed).unwrap();
        assert_eq!(
            observed,
            vec![0u8; raw.len()],
            "destroy() unlinked the crash-orphaned .tmp file without zeroing it \
             first — the secret is still fully recoverable from the freed blocks"
        );
    }

    #[test]
    fn destroy_refuses_to_zero_a_multi_linked_crash_orphaned_tmp_file() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(&dir);
        let pw = SecretString::from("pw".to_string());
        vault.save(b"top secret transcript", &pw).unwrap();

        let raw = fs::read(vault.path()).unwrap();
        let tmp = tmp_path_for(vault.path());
        fs::write(&tmp, &raw).unwrap();
        let inspector = dir.path().join("tmp.inspector");
        fs::hard_link(&tmp, &inspector).unwrap();

        vault.destroy();

        assert!(!tmp.exists(), "destroy() must still unlink the .tmp file");
        assert_eq!(
            fs::read(&inspector).unwrap(),
            raw,
            "destroy() zeroed the shared inode behind a hard-linked tmp vault file"
        );
    }

    #[test]
    #[cfg(unix)]
    fn write_atomically_refuses_a_symlinked_target_rather_than_borrow_its_permissions() {
        // `preserve_permissions` used `fs::metadata(target)`, which follows a
        // symlink and reads the mode of whatever it points at. A `vault.enc` or
        // `config.json` replaced by a symlink to a loosely-permissioned file would
        // silently launder that file's mode onto the freshly written replacement —
        // 644 instead of the documented owner-only 600 — even though the rename
        // itself never touches the symlink's target's contents. Refusing the whole
        // write, rather than merely fixing the mode calculation, is the answer to
        // "should this be allowed at all": there is no legitimate reason `vault.enc`
        // or `config.json` would ever be a symlink.
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        // Deliberately looser than the 0o600 default, so a borrowed mode would be
        // observably different from the correct one.
        let victim = dir.path().join("victim.txt");
        fs::write(&victim, b"unrelated data").unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o644)).unwrap();

        let link = dir.path().join("vault.enc");
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        let err = write_atomically(&link, b"new contents")
            .expect_err("must refuse to write through a symlinked target");
        assert!(
            err.to_string().contains("symlink"),
            "unexpected error: {err}"
        );

        // Nothing should have replaced the symlink, and the file it points at —
        // content or permissions — must be untouched.
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the symlink itself must survive a refused write"
        );
        assert_eq!(fs::read(&victim).unwrap(), b"unrelated data");
        let victim_mode = fs::metadata(&victim).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            victim_mode, 0o644,
            "the symlink target's own permissions must be untouched"
        );
    }

    /// `n` lines of throwaway conversation, oldest first — `Speaker::You` with the
    /// index in the text so ordering/content can be asserted on directly.
    fn lines(n: usize) -> Vec<Line> {
        (0..n)
            .map(|i| Line {
                speaker: Speaker::You,
                text: format!("line {i}"),
            })
            .collect()
    }

    /// `Line` has no `PartialEq` (nothing in the product needs it, and it lives in
    /// `app.rs`, outside this fix's file ownership), so tests compare transcripts by
    /// their rendered text — `Line::render` already folds in the speaker, so two
    /// transcripts with identical rendered output are identical for every purpose
    /// this module cares about.
    fn rendered(transcript: &[Line]) -> Vec<String> {
        transcript.iter().map(Line::render).collect()
    }

    #[test]
    fn a_transcript_at_exactly_the_cap_is_left_completely_untouched() {
        // The boundary the audit's mutation-testing note called out: this must be
        // `>`, not `>=`, or a transcript that exactly fits gets needlessly mangled.
        let mut transcript = lines(MAX_TRANSCRIPT_LINES);
        let original = rendered(&transcript);

        let dropped = trim_transcript_to_cap(&mut transcript, MAX_TRANSCRIPT_LINES);

        assert_eq!(dropped, 0);
        assert_eq!(
            rendered(&transcript),
            original,
            "an at-cap transcript must be left completely unchanged"
        );
    }

    #[test]
    fn a_transcript_under_the_cap_is_left_alone_with_no_marker_inserted() {
        let mut transcript = lines(MAX_TRANSCRIPT_LINES - 1);
        let original = rendered(&transcript);

        let dropped = trim_transcript_to_cap(&mut transcript, MAX_TRANSCRIPT_LINES);

        assert_eq!(dropped, 0);
        assert_eq!(rendered(&transcript), original);
    }

    #[test]
    fn a_transcript_over_the_cap_is_trimmed_oldest_first_and_reloads_cleanly() {
        let cap = 10;
        let mut transcript = lines(15);

        let dropped = trim_transcript_to_cap(&mut transcript, cap);

        // 15 lines in, cap 10: the marker itself takes one of the 10 slots, so 9
        // lines of content survive and 6 (not 5) are dropped.
        assert_eq!(dropped, 6, "the marker occupies one of the cap's own slots");
        assert_eq!(transcript.len(), cap, "trimmed to the cap, not below it");
        // Line 0 is now the marker; the surviving content is the most recent lines,
        // still in order, with nothing from the dropped head sneaking through.
        assert!(matches!(transcript[0].speaker, Speaker::System));
        assert!(transcript[0].text.starts_with(DROP_MARKER_PREFIX));
        assert_eq!(transcript[1].text, "line 6", "oldest surviving line");
        assert_eq!(transcript[9].text, "line 14", "newest line");

        // "Reloads cleanly": the actual save/load path serializes this as JSON and
        // hands it back to `App::transcript` unmodified — round-trip it the same way.
        let payload = serde_json::to_vec(&transcript).unwrap();
        let reloaded: Vec<Line> = serde_json::from_slice(&payload).unwrap();
        assert_eq!(rendered(&reloaded), rendered(&transcript));
    }

    #[test]
    fn repeated_trims_accumulate_one_running_marker_instead_of_stacking_new_ones() {
        let cap = 10;
        let mut transcript = lines(15);
        let first_dropped = trim_transcript_to_cap(&mut transcript, cap);
        assert_eq!(first_dropped, 6);

        // Simulate a session appending more lines to an already-trimmed transcript
        // (exactly what happens between one `--vault` session's load and its own
        // save), then trimming again.
        for i in 15..23 {
            transcript.push(Line {
                speaker: Speaker::You,
                text: format!("line {i}"),
            });
        }
        let second_dropped = trim_transcript_to_cap(&mut transcript, cap);

        assert_eq!(transcript.len(), cap);
        // Exactly one marker, at the front, carrying the *cumulative* total — not
        // just this call's delta — and not a second marker line stacked below it.
        let markers = transcript
            .iter()
            .filter(|l| {
                matches!(l.speaker, Speaker::System) && l.text.starts_with(DROP_MARKER_PREFIX)
            })
            .count();
        assert_eq!(markers, 1, "must not stack a second marker line");
        assert_eq!(
            transcript[0].text,
            drop_marker(first_dropped + second_dropped, cap).text,
            "the marker must report the running total, not just the latest delta"
        );
    }

    #[test]
    fn a_transcript_back_under_cap_keeps_its_existing_marker_and_count_unchanged() {
        // The boundary the audit's mutation-testing pass found untested: once
        // `take_leading_marker` pulls the marker off the front, `previously_dropped
        // > 0` is what decides whether it goes back on. Get this backwards (`< 0`,
        // always false for a `u64`) and a transcript that already carries a marker
        // but happens to be at/under `cap` after the marker's own removal loses that
        // marker — and the record of everything it dropped earlier — silently.
        let cap = 10;
        let mut transcript = lines(15);
        let first_dropped = trim_transcript_to_cap(&mut transcript, cap);
        assert_eq!(first_dropped, 6);
        assert_eq!(transcript.len(), cap);

        // Drop content lines (never index 0, the marker) until what remains, plus
        // the marker, is back under `cap` — simulating a vault that was pruned by
        // hand after having already been auto-trimmed once.
        while transcript.len() > 4 {
            transcript.remove(1);
        }
        assert!(
            matches!(transcript[0].speaker, Speaker::System)
                && transcript[0].text.starts_with(DROP_MARKER_PREFIX),
            "fixture guard: the marker must still be present before the call under test"
        );

        let second_dropped = trim_transcript_to_cap(&mut transcript, cap);

        assert_eq!(
            second_dropped, 0,
            "already under cap; this call must not drop anything new"
        );
        assert!(
            matches!(transcript[0].speaker, Speaker::System)
                && transcript[0].text.starts_with(DROP_MARKER_PREFIX),
            "the existing marker must be preserved, not silently dropped"
        );
        assert_eq!(
            transcript[0].text,
            drop_marker(first_dropped, cap).text,
            "the preserved marker must still report the original total, unchanged"
        );
    }

    #[test]
    fn take_leading_marker_ignores_a_system_line_that_only_resembles_one() {
        // A `Speaker::System` line that merely starts with similar-looking text but
        // not the exact marker prefix must not be misread as a marker and eaten.
        let mut transcript = vec![
            Line {
                speaker: Speaker::System,
                text: "vault status: everything is fine".into(),
            },
            Line {
                speaker: Speaker::You,
                text: "hello".into(),
            },
        ];
        assert_eq!(take_leading_marker(&mut transcript), 0);
        assert_eq!(
            transcript.len(),
            2,
            "the unrelated system line must survive"
        );
    }
    #[test]
    fn reproduction_test_trim_transcript_to_cap_off_by_one_with_existing_marker() {
        let cap = 10;
        let mut transcript = lines(15);
        let first_dropped = trim_transcript_to_cap(&mut transcript, cap);
        assert_eq!(first_dropped, 6);
        assert_eq!(transcript.len(), cap);

        // Append exactly 1 new line to the already-trimmed transcript.
        // Total lines before trim: 1 marker + 9 content lines + 1 new content line = 11 lines.
        transcript.push(Line {
            speaker: Speaker::You,
            text: "line 15".into(),
        });
        assert_eq!(transcript.len(), 11);

        // Trimming must keep the transcript bounded to `cap` (10 lines total: 1 marker + 9 content lines).
        // It must drop 1 content line ("line 6") and update the cumulative marker count to 6 + 1 = 7.
        let second_dropped = trim_transcript_to_cap(&mut transcript, cap);

        assert_eq!(
            second_dropped, 1,
            "expected 1 line to be dropped to keep transcript within cap"
        );
        assert_eq!(
            transcript.len(),
            cap,
            "transcript length must be exactly cap, but got exceeding length"
        );
        assert_eq!(
            transcript[0].text,
            drop_marker(first_dropped + second_dropped, cap).text,
            "the marker must report the updated total"
        );
        assert_eq!(
            transcript[1].text, "line 7",
            "oldest surviving content line"
        );
        assert_eq!(transcript[9].text, "line 15", "newest content line");
    }

    #[test]
    #[cfg(unix)]
    fn reproduction_test_write_atomically_refuses_symlinked_tmp_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("vault.enc");
        let tmp = dir.path().join("vault.enc.tmp");
        let victim = dir.path().join("victim.txt");

        fs::write(&victim, b"victim data: do not overwrite").unwrap();
        std::os::unix::fs::symlink(&victim, &tmp).unwrap();

        let res = write_atomically(&target, b"secret payload");
        assert!(
            res.is_err(),
            "write_atomically must refuse to write when tmp is a symlink"
        );
        let err_msg = res.unwrap_err().to_string();
        assert!(
            err_msg.contains("symlink"),
            "unexpected error message: {err_msg}"
        );
        assert_eq!(
            fs::read(&victim).unwrap(),
            b"victim data: do not overwrite",
            "victim file must not be overwritten through symlink tmp"
        );
    }
}

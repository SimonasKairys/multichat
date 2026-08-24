//! Encrypted at-rest storage for sensitive local state.
//!
//! The only thing this stores is the TUI transcript (`App::transcript` in
//! `src/app.rs`), opted into with `simon chat --vault`. It hands the *user* their
//! history back across sessions; it is not conversation memory for a model —
//! `Orchestrator::handle_prompt` still sends no message history on any turn, vault or
//! not. See the "Security posture" section of `README.md` for the full picture,
//! including the self-destruct policy as a data-loss property.
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

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
};
use anyhow::{Result, anyhow};
use argon2::Argon2;
use secrecy::{ExposeSecret, SecretString};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::security::LockedBuffer;

const MAGIC: &[u8; 8] = b"MCVAULT1";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const HEADER_FIXED_LEN: usize = 8 + 1 + 1 + 8 + 1; // magic..salt_len inclusive

/// Consecutive wrong passwords before the vault is destroyed.
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

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("no vault exists yet")]
    Missing,
    #[error("incorrect master password ({remaining} attempt(s) before the vault is wiped)")]
    WrongPassword { remaining: u8 },
    #[error("vault destroyed: {0}")]
    Destroyed(String),
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
        let salt_end = HEADER_FIXED_LEN + salt_len;
        if raw.len() < salt_end + NONCE_LEN {
            return Err(VaultError::Corrupt("truncated salt or nonce".into()));
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
    /// passwords the file is destroyed. Sitting idle past [`MAX_IDLE_SECS`] does *not*
    /// destroy it — see the comment in the body.
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

        if header.attempts >= MAX_ATTEMPTS {
            self.destroy();
            return Err(VaultError::Destroyed(format!(
                "{MAX_ATTEMPTS} consecutive failed unlock attempts"
            )));
        }

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
                let _ = self.rewrite_header(&raw, &header);
                if header.attempts >= MAX_ATTEMPTS {
                    self.destroy();
                    return Err(VaultError::Destroyed(format!(
                        "{MAX_ATTEMPTS} consecutive failed unlock attempts"
                    )));
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

    /// Overwrites the file with zeros before unlinking, so the ciphertext is not left
    /// recoverable in freed blocks on simple filesystems.
    pub fn destroy(&self) {
        if let Ok(meta) = fs::metadata(&self.path) {
            let _ = fs::write(&self.path, vec![0u8; meta.len() as usize]);
        }
        let _ = fs::remove_file(&self.path);
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

/// Writes via a temporary file and rename so a crash mid-write cannot truncate an
/// existing vault.
fn write_atomically(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes).map_err(|e| anyhow!("failed to write {}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| anyhow!("failed to replace {}: {e}", path.display()))?;
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
        assert!(matches!(vault.load(&wrong), Err(VaultError::Destroyed(_))));
        assert!(!vault.exists(), "vault file should be gone");
        assert!(matches!(vault.load(&pw), Err(VaultError::Missing)));
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
            // that the wipe below comes from the attempt count, not from the clock.
            set_last_unlock(&vault, stale);
        }

        assert!(matches!(vault.load(&wrong), Err(VaultError::Destroyed(_))));
        assert!(!vault.exists(), "the attempt-based wipe still applies");
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
        // this checks the full path, not just AES-GCM.
        use crate::app::{Line, Speaker};

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
}

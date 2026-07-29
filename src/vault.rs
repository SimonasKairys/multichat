//! Encrypted at-rest storage for chat history and other sensitive local state.
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
/// Idle window after which the vault self-destructs on next open.
pub const MAX_IDLE_SECS: u64 = 24 * 60 * 60;

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
    /// passwords, or [`MAX_IDLE_SECS`] without a successful unlock, the file is
    /// destroyed.
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

        let idle = now_secs().saturating_sub(header.last_unlock);
        if idle > MAX_IDLE_SECS {
            self.destroy();
            return Err(VaultError::Destroyed(format!(
                "not unlocked for {} hours (limit is {})",
                idle / 3600,
                MAX_IDLE_SECS / 3600
            )));
        }

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
    fn idle_vault_self_destructs() {
        let dir = tempfile::tempdir().unwrap();
        let vault = vault_in(&dir);
        let pw = SecretString::from("pw".to_string());
        vault.save(b"payload", &pw).unwrap();

        // Backdate the last-unlock timestamp past the idle limit.
        let mut raw = fs::read(vault.path()).unwrap();
        let stale = now_secs() - (MAX_IDLE_SECS + 60);
        raw[10..18].copy_from_slice(&stale.to_be_bytes());
        fs::write(vault.path(), &raw).unwrap();

        assert!(matches!(vault.load(&pw), Err(VaultError::Destroyed(_))));
        assert!(!vault.exists());
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
}

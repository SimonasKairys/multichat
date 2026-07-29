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

use anyhow::{Context, Result, anyhow};
// Blake2 has a native keyed mode, so no separate HMAC construction is needed.
use blake2::Blake2sMac256;
use blake2::digest::Mac;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::Credentials;

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const KEYRING_SERVICE: &str = "audit-hmac";

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

pub struct AuditLogger {
    path: PathBuf,
    last_mac: String,
    key: Vec<u8>,
}

impl AuditLogger {
    /// Opens (or starts) the log, recovering the chain head from the existing file.
    ///
    /// The previous implementation always restarted from the genesis hash, which meant
    /// the chain was per-process rather than per-history.
    pub fn open(path: PathBuf) -> Result<Self> {
        let key = load_or_create_key()?;
        let last_mac = read_last_mac(&path)?.unwrap_or_else(|| GENESIS.to_string());
        Ok(Self {
            path,
            last_mac,
            key,
        })
    }

    /// Builds a logger with an explicit key, bypassing the keyring. For tests.
    pub fn with_key(path: PathBuf, key: Vec<u8>) -> Result<Self> {
        let last_mac = read_last_mac(&path)?.unwrap_or_else(|| GENESIS.to_string());
        Ok(Self {
            path,
            last_mac,
            key,
        })
    }

    fn mac(&self, prev: &str, ts: u64, action: &str, details: &str) -> Result<String> {
        let payload = serde_json::to_vec(&MacPayload {
            prev,
            ts,
            action,
            details,
        })?;
        let mut mac = <Blake2sMac256 as Mac>::new_from_slice(&self.key)
            .map_err(|e| anyhow!("invalid audit key length: {e}"))?;
        mac.update(&payload);
        Ok(hex(&mac.finalize().into_bytes()))
    }

    /// Appends an event, linking it to the current chain head.
    pub fn log(&mut self, action: &str, details: &str) -> Result<()> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mac = self.mac(&self.last_mac, ts, action, details)?;
        let entry = AuditEntry {
            ts,
            action: action.to_string(),
            details: details.to_string(),
            prev: self.last_mac.clone(),
            mac: mac.clone(),
        };

        let mut line = serde_json::to_string(&entry)?;
        line.push('\n');

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("failed to open audit log {}", self.path.display()))?;
        file.write_all(line.as_bytes())
            .with_context(|| format!("failed to append to {}", self.path.display()))?;
        file.flush()?;

        self.last_mac = mac;
        Ok(())
    }

    /// Walks the whole file and verifies every link. Returns the number of verified
    /// entries, or the 1-based index of the first entry that fails.
    pub fn verify(&self) -> Result<usize> {
        let file = match File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e).context("failed to open audit log for verification"),
        };

        let mut expected_prev = GENESIS.to_string();
        let mut count = 0usize;

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
            let recomputed = self.mac(&entry.prev, entry.ts, &entry.action, &entry.details)?;
            if recomputed != entry.mac {
                return Err(anyhow!(
                    "audit entry {} has been modified (MAC mismatch)",
                    idx + 1
                ));
            }
            expected_prev = entry.mac;
            count += 1;
        }

        Ok(count)
    }
}

/// Reads the `mac` field of the final entry so a new process continues the chain.
fn read_last_mac(path: &Path) -> Result<Option<String>> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).context("failed to read audit log"),
    };
    let mut last = None;
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let entry: AuditEntry = serde_json::from_str(&line)
            .context("audit log contains a malformed entry; refusing to append to it")?;
        last = Some(entry.mac);
    }
    Ok(last)
}

/// Fetches the per-install MAC key from the keyring, generating one on first use.
fn load_or_create_key() -> Result<Vec<u8>> {
    use aes_gcm::aead::OsRng;
    use aes_gcm::aead::rand_core::RngCore;
    use secrecy::ExposeSecret;

    if let Some(existing) = Credentials::get(KEYRING_SERVICE)? {
        let decoded =
            unhex(existing.expose_secret()).context("audit key in keyring is not valid hex")?;
        if decoded.len() == 32 {
            return Ok(decoded);
        }
    }

    let mut key = vec![0u8; 32];
    OsRng.fill_bytes(&mut key);
    Credentials::set(KEYRING_SERVICE, &hex(&key))
        .context("failed to store the audit MAC key in the OS keyring")?;
    Ok(key)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn unhex(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(anyhow!("odd-length hex string"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| anyhow!("bad hex: {e}")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn logger(dir: &tempfile::TempDir) -> AuditLogger {
        AuditLogger::with_key(dir.path().join("audit.log"), vec![7u8; 32]).unwrap()
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

        assert_eq!(second.verify().unwrap(), 3);
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
        assert_eq!(log.verify().unwrap(), 1);
    }

    #[test]
    fn verifying_a_missing_log_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(logger(&dir).verify().unwrap(), 0);
    }
}

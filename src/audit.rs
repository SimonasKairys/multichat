use anyhow::{Context, Result};
use blake2::{Blake2s256, Digest};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct AuditLogger {
    log_path: PathBuf,
    last_hash: String,
}

impl AuditLogger {
    pub fn new(app_dir: PathBuf) -> Self {
        let log_path = app_dir.join("audit.log");
        
        // In a real system, we would read the last line of the file to recover the last hash.
        // For initialization, we use a genesis hash.
        let genesis = "0000000000000000000000000000000000000000000000000000000000000000".to_string();

        Self {
            log_path,
            last_hash: genesis,
        }
    }

    /// Logs an event cryptographically linked to the previous event (Hash Chain)
    pub fn log_event(&mut self, action: &str, details: &str) -> Result<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // The payload we are signing
        let payload = format!("{}|{}|{}|{}", self.last_hash, timestamp, action, details);

        // Compute Blake2 hash
        let mut hasher = Blake2s256::new();
        hasher.update(payload.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        // Construct the final log line
        let log_line = format!("{}|{}|{}|{}|{}\n", timestamp, action, details, self.last_hash, hash);

        // Append to log file
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .context("Failed to open audit log file")?;

        file.write_all(log_line.as_bytes())
            .context("Failed to write to audit log")?;

        // Update the running chain
        self.last_hash = hash;

        Ok(())
    }
}

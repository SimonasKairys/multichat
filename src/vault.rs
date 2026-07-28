use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key
};
use argon2::{
    password_hash::{rand_core::OsRng as ArgonOsRng, PasswordHasher, SaltString},
    Argon2,
};
use secrecy::{ExposeSecret, SecretString};
use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;

pub struct EncryptedVault {
    storage_path: PathBuf,
}

impl EncryptedVault {
    pub fn new(app_dir: PathBuf) -> Self {
        let storage_path = app_dir.join("vault.enc");
        Self { storage_path }
    }

    /// Derives a 32-byte key from a master password and salt using Argon2
    fn derive_key(password: &SecretString, salt: &str) -> Result<Key<Aes256Gcm>> {
        let argon2 = Argon2::default();
        let salt_string = SaltString::from_b64(salt)
            .map_err(|e| anyhow::anyhow!("Failed to parse salt: {}", e))?;
        
        // Hash password to generate key material
        let password_hash = argon2
            .hash_password(password.expose_secret().as_bytes(), &salt_string)
            .map_err(|e| anyhow::anyhow!("Argon2 hash failed: {}", e))?;

        let hash_bytes = password_hash.hash.context("Missing hash output")?;
        let mut key_bytes = [0u8; 32];
        let copy_len = std::cmp::min(hash_bytes.as_bytes().len(), 32);
        key_bytes[..copy_len].copy_from_slice(&hash_bytes.as_bytes()[..copy_len]);

        Ok(Key::<Aes256Gcm>::from_slice(&key_bytes).clone())
    }

    /// Encrypts plaintext data and saves it to disk
    pub fn save(&self, plaintext: &[u8], password: &SecretString, salt: &str) -> Result<()> {
        let key = Self::derive_key(password, salt)?;
        let cipher = Aes256Gcm::new(&key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng); 

        let ciphertext = cipher.encrypt(&nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        // Format: [12-byte nonce][ciphertext]
        let mut file_data = nonce.to_vec();
        file_data.extend_from_slice(&ciphertext);

        // Save to disk securely (ideally with safe permissions, handled by config layer)
        fs::write(&self.storage_path, file_data)
            .context("Failed to write encrypted vault to disk")?;

        Ok(())
    }

    /// Reads and decrypts data from disk
    pub fn load(&self, password: &SecretString, salt: &str) -> Result<Vec<u8>> {
        let file_data = fs::read(&self.storage_path)
            .context("Failed to read vault file")?;

        if file_data.len() < 12 {
            return Err(anyhow::anyhow!("Vault file is too short/corrupted"));
        }

        let (nonce_bytes, ciphertext) = file_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        let key = Self::derive_key(password, salt)?;
        let cipher = Aes256Gcm::new(&key);

        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|_| anyhow::anyhow!("Decryption failed. Incorrect master password or corrupted vault."))?;

        Ok(plaintext)
    }
}

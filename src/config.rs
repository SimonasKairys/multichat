use anyhow::{Context, Result};
use keyring::Entry;
use secrecy::SecretString;

pub struct Config {
    // Other config fields can go here
}

impl Config {
    pub fn get_api_key(service: &str, user: &str) -> Result<Option<SecretString>> {
        let entry = Entry::new(service, user)?;
        match entry.get_password() {
            Ok(password) => Ok(Some(SecretString::from(password))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(anyhow::anyhow!("Failed to retrieve password from keyring: {}", e)),
        }
    }

    pub fn set_api_key(service: &str, user: &str, key: &str) -> Result<()> {
        let entry = Entry::new(service, user)?;
        entry.set_password(key)?;
        Ok(())
    }
}

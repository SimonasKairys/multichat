//! Application paths, persisted settings, and credential storage.

use anyhow::{Context, Result, anyhow};
use directories::ProjectDirs;
use keyring::Entry;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Keyring service namespace. Kept distinct per credential kind so an API key can
/// never be read back through the audit-key entry or vice versa.
const KEYRING_PREFIX: &str = "simon";
const DEFAULT_KEYRING_USER: &str = "default";

/// Resolved on-disk locations. Every module that persists state takes its path from
/// here — nothing constructs an app directory on its own.
#[derive(Debug, Clone)]
pub struct Paths {
    pub data_dir: PathBuf,
    pub config_file: PathBuf,
    pub vault_file: PathBuf,
    pub audit_log: PathBuf,
    pub skills_dir: PathBuf,
}

impl Paths {
    /// Resolves the per-user application directories, creating them if absent.
    pub fn resolve() -> Result<Self> {
        let dirs = ProjectDirs::from("", "", "simon")
            .context("could not determine a home directory for this user")?;
        Self::from_data_dir(dirs.data_dir().to_path_buf())
    }

    /// Builds paths rooted at an explicit directory. Used by tests and by
    /// `SIMON_DATA_DIR` overrides.
    pub fn from_data_dir(data_dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&data_dir)
            .with_context(|| format!("failed to create data directory {}", data_dir.display()))?;
        let skills_dir = data_dir.join("skills");
        fs::create_dir_all(&skills_dir).with_context(|| {
            format!("failed to create skills directory {}", skills_dir.display())
        })?;
        // The workspace root is deliberately NOT part of `Paths`: it used to be a
        // scratch tree under the data dir, but it is now the user's project folder
        // (see `workspace.rs`'s module doc and `resolve_project_root` in `main.rs`),
        // which lives wherever the user's project lives, not under application state.
        // Entangling the two would mean a `--project` override had to reach through
        // `Paths` to take effect, when nothing else in `Paths` has any reason to know
        // about it.
        restrict_to_owner(&data_dir)?;

        Ok(Self {
            config_file: data_dir.join("config.json"),
            vault_file: data_dir.join("vault.enc"),
            audit_log: data_dir.join("audit.log"),
            skills_dir,
            data_dir,
        })
    }

    /// Honours `SIMON_DATA_DIR` when set, otherwise the platform default.
    pub fn resolve_with_env() -> Result<Self> {
        match std::env::var_os("SIMON_DATA_DIR") {
            Some(dir) => Self::from_data_dir(PathBuf::from(dir)),
            None => Self::resolve(),
        }
    }
}

/// Tightens directory permissions to owner-only where the platform supports it.
#[cfg(unix)]
fn restrict_to_owner(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(dir)?.permissions();
    perms.set_mode(0o700);
    fs::set_permissions(dir, perms)
        .with_context(|| format!("failed to restrict permissions on {}", dir.display()))?;
    Ok(())
}

/// On Windows the per-user AppData directory is already ACL'd to the owner; tightening
/// it further would need explicit ACL manipulation, which is out of scope here.
#[cfg(not(unix))]
fn restrict_to_owner(_dir: &Path) -> Result<()> {
    Ok(())
}

/// Which wire protocol a cloud endpoint speaks. Chosen explicitly per provider so a
/// key for one vendor can never be sent to another vendor's endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Api {
    /// `POST /v1/messages`, `x-api-key` + `anthropic-version` headers.
    Anthropic,
    /// `POST /chat/completions`, `Authorization: Bearer`.
    OpenAiCompatible,
}

/// A cloud endpoint definition: how to reach it and how to talk to it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudEndpoint {
    pub api: Api,
    pub base_url: String,
    pub default_model: String,
}

/// Built-in endpoint definitions. Anything not listed here must be configured
/// explicitly — an unknown provider name is an error, never a silent default.
pub fn builtin_endpoint(provider: &str) -> Option<CloudEndpoint> {
    let e = match provider.to_ascii_lowercase().as_str() {
        "anthropic" | "claude" => CloudEndpoint {
            api: Api::Anthropic,
            base_url: "https://api.anthropic.com".into(),
            default_model: "claude-opus-5".into(),
        },
        "openai" => CloudEndpoint {
            api: Api::OpenAiCompatible,
            base_url: "https://api.openai.com/v1".into(),
            default_model: "gpt-4o".into(),
        },
        // Google's OpenAI-compatible surface, so this needs no new `Api` variant.
        // Shares the `google` connection id with the `gemini` CLI (see
        // `cli_vendor_id`), which gives the picker paired "via CLI" / "via API" rows.
        "google" | "gemini" => CloudEndpoint {
            api: Api::OpenAiCompatible,
            base_url: "https://generativelanguage.googleapis.com/v1beta/openai".into(),
            default_model: "gemini-2.5-pro".into(),
        },
        "openrouter" => CloudEndpoint {
            api: Api::OpenAiCompatible,
            base_url: "https://openrouter.ai/api/v1".into(),
            default_model: "openai/gpt-4o".into(),
        },
        "groq" => CloudEndpoint {
            api: Api::OpenAiCompatible,
            base_url: "https://api.groq.com/openai/v1".into(),
            default_model: "llama-3.3-70b-versatile".into(),
        },
        _ => return None,
    };
    Some(e)
}

/// Maps an alias accepted by `builtin_endpoint` (`claude`, `gemini`) to the
/// canonical id vendor discovery actually looks up in the keyring (`anthropic`,
/// `google`). A key stored under the alias would be stored successfully but never
/// found — discovery only ever asks for canonical ids. Kept visibly next to
/// `builtin_endpoint`'s alias arms so a future alias gets added to both. Anything
/// that isn't one of the two aliases — including a custom endpoint name — passes
/// through unchanged.
pub fn canonical_provider(name: &str) -> &str {
    match name.to_ascii_lowercase().as_str() {
        "claude" => "anthropic",
        "gemini" => "google",
        _ => name,
    }
}

/// Which transport carries a connection's traffic. `Api` and `Cli` are the only two
/// today; Ollama has no choice to make, so its `ConnectionSpec::transport` is `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Cli,
    Api,
}

/// A user's decision about one candidate connection the picker showed them: whether
/// to connect it, and — when the candidate offers more than one — which transport.
///
/// One `ConnectionSpec` covers every transport of a given connection id (e.g.
/// `"anthropic"` covers both its `claude` CLI and its HTTP API); `transport` says
/// which is currently in effect, so ticking the API row and ticking the CLI row are
/// mutually exclusive by construction rather than by extra bookkeeping.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ConnectionSpec {
    pub enabled: bool,
    pub transport: Option<Transport>,
    /// Resolved CLI path, when `transport == Some(Cli)`. Overrides auto-detection.
    pub path: Option<String>,
    /// Model override; when absent, the endpoint's (or CLI's) default is used.
    pub model: Option<String>,
}

/// Persisted user settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Base URL of the local Ollama daemon.
    pub ollama_host: String,
    /// Provider used when none is given on the command line.
    pub default_provider: String,
    /// Extra cloud endpoints keyed by provider name, merged over the built-ins.
    pub custom_endpoints: std::collections::BTreeMap<String, CloudEndpoint>,
    /// Local CLI tools that can act as providers, keyed by name.
    pub local_binaries: std::collections::BTreeMap<String, LocalBinarySpec>,
    /// The user's picker selections, keyed by connection id. Empty on an old config
    /// file or a fresh install — that absence is what triggers "first run" behaviour
    /// (everything available pre-ticked) rather than "connect nothing".
    pub connections: std::collections::BTreeMap<String, ConnectionSpec>,
    /// The connection id chosen as commander. `None` falls back to the first enabled
    /// connection.
    pub commander: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalBinarySpec {
    pub path: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// The flag this CLI uses to accept a system prompt, e.g. `--system-prompt` for
    /// `claude`. `None` means the CLI has no such flag (e.g. `gemini`), so the system
    /// text is folded into the prompt instead — see `LocalBinaryProvider::send`.
    #[serde(default)]
    pub system_arg: Option<String>,
    /// Which NDJSON progress dialect this CLI speaks, so a hand-configured entry can
    /// opt into streaming the same way the auto-detected `claude`/`agy` rows do.
    /// `None` (the default) keeps the plain-text, buffered-output path unchanged —
    /// auto-detection never assumes a user's custom binary streams anything. Accepts
    /// only `"claude"` or `"agy"`; parsed (and validated) in
    /// `orchestrator::detect_cli_tools` via `local_binary::StreamDialect::parse`, so
    /// an unrecognised value is a clear discovery-time error rather than a silent
    /// fallback to the non-streaming path.
    #[serde(default)]
    pub stream_format: Option<String>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            ollama_host: "http://127.0.0.1:11434".into(),
            default_provider: "ollama".into(),
            custom_endpoints: Default::default(),
            local_binaries: Default::default(),
            connections: Default::default(),
            commander: None,
        }
    }
}

impl Settings {
    pub fn load(paths: &Paths) -> Result<Self> {
        match fs::read_to_string(&paths.config_file) {
            Ok(raw) => serde_json::from_str(&raw)
                .with_context(|| format!("failed to parse {}", paths.config_file.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => {
                Err(e).with_context(|| format!("failed to read {}", paths.config_file.display()))
            }
        }
    }

    pub fn save(&self, paths: &Paths) -> Result<()> {
        let raw = serde_json::to_string_pretty(self)?;
        fs::write(&paths.config_file, raw)
            .with_context(|| format!("failed to write {}", paths.config_file.display()))
    }

    /// Resolves a provider name to an endpoint, preferring user overrides.
    pub fn endpoint(&self, provider: &str) -> Option<CloudEndpoint> {
        self.custom_endpoints
            .get(provider)
            .cloned()
            .or_else(|| builtin_endpoint(provider))
    }
}

/// OS keyring access for API keys.
pub struct Credentials;

impl Credentials {
    fn entry(service: &str) -> Result<Entry> {
        let namespaced = format!("{KEYRING_PREFIX}:{service}");
        Entry::new(&namespaced, DEFAULT_KEYRING_USER)
            .with_context(|| format!("failed to open keyring entry for {service}"))
    }

    pub fn get(service: &str) -> Result<Option<SecretString>> {
        match Self::entry(service)?.get_password() {
            Ok(secret) => Ok(Some(SecretString::from(secret))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(anyhow!(
                "failed to read {service} credential from keyring: {e}"
            )),
        }
    }

    pub fn set(service: &str, secret: &str) -> Result<()> {
        if secret.trim().is_empty() {
            return Err(anyhow!(
                "refusing to store an empty credential for {service}"
            ));
        }
        Self::entry(service)?
            .set_password(secret)
            .with_context(|| format!("failed to store {service} credential in keyring"))
    }

    pub fn delete(service: &str) -> Result<()> {
        match Self::entry(service)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(anyhow!("failed to delete {service} credential: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_provider_has_no_builtin_endpoint() {
        // Regression guard for the bug where every provider fell through to OpenAI.
        assert!(builtin_endpoint("definitely-not-a-provider").is_none());
    }

    #[test]
    fn anthropic_and_openai_route_to_different_hosts() {
        let anthropic = builtin_endpoint("anthropic").unwrap();
        let openai = builtin_endpoint("openai").unwrap();
        assert_eq!(anthropic.api, Api::Anthropic);
        assert_eq!(openai.api, Api::OpenAiCompatible);
        assert_ne!(anthropic.base_url, openai.base_url);
        assert!(anthropic.base_url.contains("anthropic.com"));
    }

    #[test]
    fn aliases_canonicalise_to_the_id_discovery_reads_back() {
        assert_eq!(canonical_provider("claude"), "anthropic");
        assert_eq!(canonical_provider("gemini"), "google");
        assert_eq!(canonical_provider("anthropic"), "anthropic");
        assert_eq!(canonical_provider("openai"), "openai");
        assert_eq!(canonical_provider("my-gateway"), "my-gateway");
    }

    #[test]
    fn settings_round_trip_through_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();

        // A missing config file is not an error — it yields defaults.
        let loaded = Settings::load(&paths).unwrap();
        assert_eq!(loaded.default_provider, "ollama");

        let settings = Settings {
            default_provider: "anthropic".into(),
            ..Default::default()
        };
        settings.save(&paths).unwrap();
        assert_eq!(
            Settings::load(&paths).unwrap().default_provider,
            "anthropic"
        );
    }

    #[test]
    fn an_old_config_file_with_no_connections_key_still_parses() {
        // Pre-picker config.json files never wrote `connections` or `commander`. The
        // struct-level `#[serde(default)]` must keep them loadable rather than
        // rejecting the file outright.
        let settings: Settings =
            serde_json::from_str(r#"{"ollama_host": "http://127.0.0.1:11434"}"#)
                .expect("an old config file must still parse");
        assert!(settings.connections.is_empty());
        assert!(settings.commander.is_none());
        assert_eq!(settings.ollama_host, "http://127.0.0.1:11434");
    }

    #[test]
    fn paths_are_created_under_the_data_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().join("nested")).unwrap();
        assert!(paths.data_dir.is_dir());
        assert!(paths.skills_dir.is_dir());
        assert!(paths.vault_file.starts_with(&paths.data_dir));
    }
}

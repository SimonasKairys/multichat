//! Application paths, persisted settings, and credential storage.

use anyhow::{Context, Result, anyhow, bail};
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
        if data_dir.as_os_str().is_empty() {
            bail!("cannot construct paths from an empty data directory path");
        }
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
    /// Honours `SIMON_DATA_DIR` when set and non-empty, otherwise the platform default.
    pub fn resolve_with_env() -> Result<Self> {
        match std::env::var_os("SIMON_DATA_DIR") {
            Some(dir) if !dir.is_empty() => Self::from_data_dir(PathBuf::from(dir)),
            _ => Self::resolve(),
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

    /// Writes `config.json` atomically (temp file + rename), not with a bare
    /// `fs::write`. `fs::write` truncates the file before writing its new content, so a
    /// crash, power loss, or full disk in that window — and this file is rewritten on
    /// every picker submit, so the window recurs constantly — leaves `config.json`
    /// truncated or empty. `Settings::load` then fails to parse it at startup, taking
    /// the user's whole connection set and provider endpoints down with it until they
    /// repair or delete the file by hand. `vault.rs` already solved exactly this problem
    /// for `vault.enc`; `write_atomically` there is reused rather than duplicated here,
    /// per the audit's own observation that the fix was "lifting an existing function."
    pub fn save(&self, paths: &Paths) -> Result<()> {
        let raw = serde_json::to_string_pretty(self)?;
        // `write_atomically`'s own errors already name the temp and target paths, so no
        // extra `.context(...)` is added here — layering one on would just repeat the
        // same path in the message twice.
        crate::vault::write_atomically(&paths.config_file, raw.as_bytes())
    }

    /// Resolves a provider name to an endpoint, preferring user overrides.
    pub fn endpoint(&self, provider: &str) -> Option<CloudEndpoint> {
        self.custom_endpoints
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(provider))
            .map(|(_, v)| v.clone())
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

    // `get` and `delete` cross into the OS keyring (Keychain, Credential Manager,
    // Secret Service) unconditionally — every line of each needs a real backend, and
    // none of CI's three platforms has one available: Secret Service needs a D-Bus
    // session and an unlocked collection that headless Linux runners don't provide,
    // and the macOS/Windows runners are equally headless. A test that opened a real
    // `Entry` would either hang waiting for a prompt or fail with a backend error
    // everywhere it matters, so it would never actually run the assertions it exists
    // to make. Rather than let that show up as a silently-green suite, both are
    // marked `#[mutants::skip]` so `cargo mutants` reports them as skipped, not
    // missed. What's untested as a result:
    // *   `get`: that `NoEntry` maps to `Ok(None)` (not an error) and that any other
    //     keyring error is wrapped and returned as `Err`, distinct from "not set".
    // *   `delete`: that `NoEntry` is treated as success (delete is idempotent) and
    //     that any other keyring error still propagates as `Err`.
    // `set` is deliberately *not* skipped: its empty-secret guard runs and returns
    // before `Self::entry` is ever called, so `set("x", "")` never touches a
    // backend and is covered by `setting_an_empty_credential_is_rejected_before_any_
    // keyring_call` below. What that test does not reach — a non-empty secret
    // actually being written through to `set_password` — is untested for the same
    // reason as `get`/`delete` above.
    // If a real keyring ever becomes available in CI (e.g. via a Secret Service
    // stub), these should gain a live test and lose the attribute rather than the
    // two states silently drifting apart.
    #[cfg_attr(test, mutants::skip)]
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

    #[cfg_attr(test, mutants::skip)]
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
    fn every_builtin_provider_is_pinned_to_its_own_wire_format() {
        // Mutation-testing regression: deleting a whole match arm (e.g. "openrouter")
        // makes that provider fall through to the `_ => None` catch-all, which
        // `unknown_provider_has_no_builtin_endpoint` cannot distinguish from a
        // genuinely unknown provider. Pinning every arm's exact base_url and
        // default_model (not just "is Some") is what catches a deleted or
        // mis-copied arm rather than just a missing one.
        let cases = [
            (
                "anthropic",
                Api::Anthropic,
                "https://api.anthropic.com",
                "claude-opus-5",
            ),
            (
                "claude",
                Api::Anthropic,
                "https://api.anthropic.com",
                "claude-opus-5",
            ),
            (
                "openai",
                Api::OpenAiCompatible,
                "https://api.openai.com/v1",
                "gpt-4o",
            ),
            (
                "google",
                Api::OpenAiCompatible,
                "https://generativelanguage.googleapis.com/v1beta/openai",
                "gemini-2.5-pro",
            ),
            (
                "gemini",
                Api::OpenAiCompatible,
                "https://generativelanguage.googleapis.com/v1beta/openai",
                "gemini-2.5-pro",
            ),
            (
                "openrouter",
                Api::OpenAiCompatible,
                "https://openrouter.ai/api/v1",
                "openai/gpt-4o",
            ),
            (
                "groq",
                Api::OpenAiCompatible,
                "https://api.groq.com/openai/v1",
                "llama-3.3-70b-versatile",
            ),
        ];
        for (provider, api, base_url, default_model) in cases {
            let endpoint = builtin_endpoint(provider)
                .unwrap_or_else(|| panic!("expected a builtin endpoint for {provider}"));
            assert_eq!(endpoint.api, api, "wrong Api dialect for {provider}");
            assert_eq!(endpoint.base_url, base_url, "wrong base_url for {provider}");
            assert_eq!(
                endpoint.default_model, default_model,
                "wrong default_model for {provider}"
            );
        }
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
    #[cfg(unix)]
    fn the_data_directory_is_tightened_to_owner_only() {
        // Found by mutation testing, not by review: replacing `restrict_to_owner` with
        // `Ok(())` — deleting the permission tightening outright — was caught by no
        // test at all. The data directory holds `vault.enc`, `config.json` and the
        // audit log, and the file-level modes lean on the directory being 0o700, so
        // this is the check the rest of that reasoning rests on.
        use std::os::unix::fs::PermissionsExt;

        let parent = tempfile::tempdir().unwrap();
        let dir = parent.path().join("data");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        // Fixture guard: the directory must start loose, or a pass below would prove
        // only that it was never tightened by anything.
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o755,
            "fixture failed to loosen the directory first"
        );

        Paths::from_data_dir(dir.clone()).unwrap();

        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700,
            "the data directory was left readable by group or others"
        );
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
    fn a_non_notfound_read_error_is_not_swallowed_as_defaults() {
        // Mutation-testing regression: replacing the `NotFound` guard with `true`
        // makes `Settings::load` treat *any* read failure as "no config file yet"
        // and silently hand back defaults. A permission error or a corrupt-directory
        // error would then look identical to a fresh install and quietly discard the
        // user's real settings instead of surfacing the problem. `settings_round_trip
        // _through_disk` already covers the genuine "file absent" case; this covers
        // the other branch — an error that is present but not `NotFound` must
        // propagate as an `Err`, not fall back to `Self::default()`.
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();

        // Put a directory where the config file is expected. Reading a directory as a
        // file fails on every platform, but with a `io::Error` whose kind is not
        // `NotFound` (the path plainly exists) — exactly the class of error the guard
        // exists to distinguish from a missing file.
        fs::create_dir(&paths.config_file).unwrap();

        let err = Settings::load(&paths).expect_err(
            "a directory in place of the config file must not be read as a fresh install",
        );
        assert!(
            err.to_string().contains("failed to read"),
            "expected the read-failure context, got: {err:#}"
        );
    }

    #[test]
    fn saving_over_a_longer_config_leaves_no_trailing_bytes() {
        // The concrete failure a bare `fs::write` hides: it truncates only up front, so
        // if a crash ever landed between the truncate and the new bytes landing, a
        // shorter save could in principle leave old bytes trailing after the new
        // content. Atomic replace (temp file + rename) never partially exposes the old
        // file at all, so this must hold for an ordinary, uninterrupted save too — a
        // long config's file length must not survive a subsequent short save.
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();

        let mut long = Settings {
            default_provider: "anthropic".into(),
            ..Default::default()
        };
        for i in 0..200 {
            long.custom_endpoints.insert(
                format!("provider-{i}"),
                CloudEndpoint {
                    api: Api::OpenAiCompatible,
                    base_url: format!("https://example.invalid/{i}"),
                    default_model: format!("model-{i}"),
                },
            );
        }
        long.save(&paths).unwrap();
        let long_len = fs::metadata(&paths.config_file).unwrap().len();

        let short = Settings {
            default_provider: "ollama".into(),
            ..Default::default()
        };
        short.save(&paths).unwrap();
        let short_len = fs::metadata(&paths.config_file).unwrap().len();

        // Fixture guard: if the long config somehow failed to actually grow the file
        // (e.g. a future change made `custom_endpoints` stop serializing), this
        // assertion would pass vacuously no matter what the second save did.
        assert!(
            long_len > short_len,
            "fixture did not produce a longer file to truncate: long={long_len} short={short_len}"
        );

        let raw = fs::read_to_string(&paths.config_file).unwrap();
        assert_eq!(
            raw.len() as u64,
            short_len,
            "file length must match its own content exactly, with nothing trailing"
        );
        let reloaded: Settings = serde_json::from_str(&raw)
            .expect("a config overwritten with a shorter one must still parse cleanly");
        assert_eq!(reloaded.default_provider, "ollama");
        assert!(
            reloaded.custom_endpoints.is_empty(),
            "endpoints from the longer, earlier save must not survive"
        );
    }

    #[test]
    fn saving_leaves_no_tmp_file_behind() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = Paths::from_data_dir(tmp.path().to_path_buf()).unwrap();

        let settings = Settings::default();
        settings.save(&paths).unwrap();

        // Fixture guard: confirm the save actually landed before concluding anything
        // from an empty-looking directory listing.
        assert!(
            paths.config_file.is_file(),
            "fixture did not produce a config file to check alongside"
        );

        let leftovers: Vec<_> = fs::read_dir(&paths.data_dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.path().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp file(s) left behind after a successful save: {leftovers:?}"
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
    fn settings_endpoint_prefers_custom_over_builtin_and_falls_back_to_it() {
        // Mutation-testing regression: `Settings::endpoint -> None` for every call is
        // undetected unless something checks it actually resolves both paths it
        // promises — the user's own override, and falling back to the builtin table.
        let mut settings = Settings::default();

        // No override and no matching builtin: None.
        assert!(settings.endpoint("definitely-not-a-provider").is_none());

        // No override: falls back to the builtin table.
        let builtin = settings.endpoint("openai").expect("openai is a builtin");
        assert_eq!(builtin.base_url, "https://api.openai.com/v1");

        // An override for a name that also has a builtin must win over the builtin,
        // not merely add to it.
        settings.custom_endpoints.insert(
            "openai".into(),
            CloudEndpoint {
                api: Api::OpenAiCompatible,
                base_url: "https://my-openai-gateway.example".into(),
                default_model: "custom-model".into(),
            },
        );
        let overridden = settings.endpoint("openai").unwrap();
        assert_eq!(overridden.base_url, "https://my-openai-gateway.example");
        assert_eq!(overridden.default_model, "custom-model");

        // An override for a name with no builtin counterpart must still resolve.
        settings.custom_endpoints.insert(
            "my-gateway".into(),
            CloudEndpoint {
                api: Api::OpenAiCompatible,
                base_url: "https://gateway.example".into(),
                default_model: "gateway-model".into(),
            },
        );
        assert_eq!(
            settings.endpoint("my-gateway").unwrap().base_url,
            "https://gateway.example"
        );
    }

    #[test]
    fn setting_an_empty_credential_is_rejected_before_any_keyring_call() {
        // Mutation-testing regression: `Credentials::set -> Ok(())` unconditionally
        // is undetected unless something calls it and checks the result. This can be
        // checked without a real OS keyring because the empty-secret guard returns
        // before `Self::entry` (and therefore any backend call) ever runs — see the
        // comment on `Credentials::get`/`delete` for why the rest of `set` is not
        // covered here.
        let err = Credentials::set("simon-test-service", "   ")
            .expect_err("an empty (or whitespace-only) secret must be rejected");
        assert!(
            err.to_string()
                .contains("refusing to store an empty credential"),
            "unexpected error message: {err}"
        );
    }

    #[test]
    fn an_empty_data_dir_path_is_rejected() {
        let err = Paths::from_data_dir(PathBuf::from(""))
            .expect_err("an empty data directory path must be rejected with a clear error");
        assert!(
            err.to_string().contains("empty data directory"),
            "expected error context for empty data dir, got: {err:#}"
        );
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

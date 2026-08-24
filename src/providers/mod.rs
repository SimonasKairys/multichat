//! Provider abstraction: one trait, several transports.

use anyhow::Result;
use async_trait::async_trait;

pub mod cloud;
pub mod local_binary;
pub mod ollama;

/// Rate-limit / quota state scraped from a provider's response headers. Feeds the
/// "Resource Budgets" section of the swarm ledger so models can route around an
/// exhausted peer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RateLimit {
    pub requests_remaining: Option<String>,
    pub tokens_remaining: Option<String>,
    pub reset_after: Option<String>,
}

impl RateLimit {
    pub fn is_empty(&self) -> bool {
        self.requests_remaining.is_none()
            && self.tokens_remaining.is_none()
            && self.reset_after.is_none()
    }

    /// Renders a one-line budget summary, or `None` when the provider told us nothing.
    pub fn summary(&self) -> Option<String> {
        if self.is_empty() {
            return None;
        }
        let mut parts = Vec::new();
        if let Some(r) = &self.requests_remaining {
            parts.push(format!("{r} requests left"));
        }
        if let Some(t) = &self.tokens_remaining {
            parts.push(format!("{t} tokens left"));
        }
        if let Some(reset) = &self.reset_after {
            parts.push(format!("resets in {reset}"));
        }
        Some(parts.join(", "))
    }

    /// Extracts the common `x-ratelimit-*` / `anthropic-ratelimit-*` headers.
    pub fn from_headers(headers: &reqwest::header::HeaderMap) -> Self {
        let get = |names: &[&str]| -> Option<String> {
            names.iter().find_map(|n| {
                headers
                    .get(*n)
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
            })
        };
        Self {
            requests_remaining: get(&[
                "anthropic-ratelimit-requests-remaining",
                "x-ratelimit-remaining-requests",
                "x-ratelimit-remaining",
            ]),
            tokens_remaining: get(&[
                "anthropic-ratelimit-tokens-remaining",
                "x-ratelimit-remaining-tokens",
            ]),
            reset_after: get(&[
                "anthropic-ratelimit-requests-reset",
                "x-ratelimit-reset-requests",
                "x-ratelimit-reset",
                "retry-after",
            ]),
        }
    }
}

/// A model's reply plus whatever metadata the transport could observe.
#[derive(Debug, Clone)]
pub struct Reply {
    pub text: String,
    pub rate_limit: RateLimit,
}

/// A one-way channel a streaming provider uses to report short, human-readable
/// progress lines ("Bash: Read the readme", "subagent: invoke_subagent") while a call
/// is still in flight, so the TUI's status line can show more than a bare "awaiting
/// reply" for however long an agentic CLI takes.
///
/// Sends are non-blocking and failure-tolerant: a dropped receiver (the UI moved on,
/// or a test never wired one up) must never turn into an error or a block inside the
/// provider call — that is the entire point of [`ProgressSink::disconnected`].
#[derive(Clone)]
pub struct ProgressSink(Option<tokio::sync::mpsc::UnboundedSender<String>>);

impl ProgressSink {
    /// Wraps a real channel: every `send` reaches `sender` unless the receiving end
    /// has already been dropped.
    pub fn new(sender: tokio::sync::mpsc::UnboundedSender<String>) -> Self {
        Self(Some(sender))
    }

    /// A no-op sink for tests and for any `Provider` that never streams: sending to
    /// it silently discards the message rather than erroring.
    pub fn disconnected() -> Self {
        Self(None)
    }

    /// Reports one progress detail. Never blocks and never fails the caller: an
    /// `UnboundedSender::send` only errors when the receiver was dropped, which is
    /// exactly the case this sink is meant to tolerate silently.
    pub fn send(&self, detail: impl Into<String>) {
        if let Some(tx) = &self.0 {
            let _ = tx.send(detail.into());
        }
    }
}

#[async_trait]
pub trait Provider: Send + Sync {
    /// Sends a prompt with an optional system prompt and returns the reply.
    async fn send(&self, system: Option<&str>, prompt: &str) -> Result<Reply>;

    /// Like `send`, but for a provider that can report progress while the call is
    /// still running (a streaming CLI). The default implementation just calls `send`
    /// and never touches `progress`, so every provider except `LocalBinaryProvider`
    /// is unaffected by this method existing.
    async fn send_with_progress(
        &self,
        system: Option<&str>,
        prompt: &str,
        _progress: &ProgressSink,
    ) -> Result<Reply> {
        self.send(system, prompt).await
    }

    /// Model identifier, as the user would type it.
    fn model_name(&self) -> &str;

    /// Provider name (`ollama`, `anthropic`, …). Used for ledger labels and routing.
    fn provider_name(&self) -> &str;

    /// Whether traffic leaves the machine. `--classified` refuses to construct any
    /// provider for which this is true.
    fn is_remote(&self) -> bool;

    /// Fully-qualified label, e.g. `anthropic:claude-opus-5`.
    fn label(&self) -> String {
        format!("{}:{}", self.provider_name(), self.model_name())
    }
}

/// Ceiling on how much of a provider's error or response body gets embedded in an
/// error message, in characters. Enough to identify what went wrong (auth failure vs
/// bad model name) without pasting a whole response into the transcript.
const MAX_ERROR_DETAIL_CHARS: usize = 300;

/// Bounds provider-controlled text (error bodies, response JSON) before embedding it
/// in an error message. Truncates on a char boundary, not a byte index — the text may
/// contain multi-byte UTF-8, and slicing mid-character panics. Mirrors
/// `swarm::record_result` and `local_binary::summarize_stderr`, for the same reason.
pub(crate) fn truncate_error_detail(s: &str) -> String {
    match s.char_indices().nth(MAX_ERROR_DETAIL_CHARS) {
        Some((cut, _)) => format!("{}…", &s[..cut]),
        None => s.to_string(),
    }
}

/// Builds the shared HTTP client. `reqwest` picks up `HTTP_PROXY`/`HTTPS_PROXY` and,
/// because the `socks` feature is enabled, `ALL_PROXY=socks5://…` as well — a
/// documented feature the rest of the app relies on, so it stays on whenever
/// `classified` is `false`.
///
/// When `classified` is `true`, that same default is a hole in the air gap. Under
/// `--classified`, `discover_candidates` refuses every provider whose traffic leaves
/// the machine and lets only Ollama through, on the strength of `is_loopback_host`
/// validating its address as loopback. But a loopback *destination* doesn't stop
/// reqwest from routing the *request* through a proxy read from the environment —
/// verified empirically: with `ALL_PROXY=socks5://127.0.0.1:9` (a closed port) set,
/// `simon --classified models` reports `(none)` instead of the Ollama model that is
/// actually running, because the request went to the proxy and failed there instead
/// of going to loopback directly. That is traffic leaving the machine, which is
/// exactly what `--classified` promises cannot happen — so `.no_proxy()` is required
/// here, not optional, whenever `classified` is `true`.
pub fn http_client(classified: bool) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .use_rustls_tls()
        .timeout(std::time::Duration::from_secs(300))
        .connect_timeout(std::time::Duration::from_secs(15));
    if classified {
        builder = builder.no_proxy();
    }
    Ok(builder.build()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};

    #[test]
    fn empty_rate_limit_has_no_summary() {
        assert!(RateLimit::default().summary().is_none());
    }

    #[test]
    fn parses_anthropic_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "anthropic-ratelimit-requests-remaining",
            HeaderValue::from_static("42"),
        );
        headers.insert(
            "anthropic-ratelimit-tokens-remaining",
            HeaderValue::from_static("1000"),
        );
        let rl = RateLimit::from_headers(&headers);
        assert_eq!(rl.requests_remaining.as_deref(), Some("42"));
        assert_eq!(rl.tokens_remaining.as_deref(), Some("1000"));
        assert!(rl.summary().unwrap().contains("42 requests left"));
    }

    #[test]
    fn parses_openai_style_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-ratelimit-remaining-requests",
            HeaderValue::from_static("7"),
        );
        assert_eq!(
            RateLimit::from_headers(&headers)
                .requests_remaining
                .as_deref(),
            Some("7")
        );
    }

    #[test]
    fn http_client_builds() {
        assert!(http_client(false).is_ok());
    }

    /// Guards only that the classified path still builds a working client — `reqwest`
    /// exposes no accessor on `Client` or `ClientBuilder` to read back whether
    /// `.no_proxy()` took effect, so there is no way to assert the proxy setting
    /// itself from here. The empirical proxy-egress check (`ALL_PROXY` routing a
    /// `--classified` request that should have stayed on loopback) lives outside the
    /// test suite, in the fix's audit trail, because it requires an actual proxy
    /// listener to observe traffic arriving.
    #[test]
    fn a_classified_http_client_still_builds() {
        assert!(http_client(true).is_ok());
    }

    #[test]
    fn error_detail_is_truncated_on_a_char_boundary_not_a_byte_index() {
        // Mirrors the same guard on `swarm::record_result` and
        // `local_binary::summarize_stderr`: one ASCII byte followed by 3-byte chars
        // puts every char boundary at 1+3k, so byte 300 lands mid-character — the
        // old byte-index slice in `cloud.rs` panicked on exactly this input.
        //
        // The count must exceed MAX_ERROR_DETAIL_CHARS, not just the old 300-*byte*
        // limit: at 120 repeats this is 361 bytes but only 121 chars, so the
        // char-based cap returns it verbatim and the truncation path never runs.
        let s = format!("a{}", "€".repeat(MAX_ERROR_DETAIL_CHARS + 100));
        let out = truncate_error_detail(&s);
        assert!(out.ends_with('…'));
        // MAX_ERROR_DETAIL_CHARS kept chars, plus the ellipsis marker.
        assert_eq!(out.chars().count(), MAX_ERROR_DETAIL_CHARS + 1);
    }

    #[test]
    fn error_detail_under_the_cap_passes_through_verbatim() {
        assert_eq!(truncate_error_detail("bad api key"), "bad api key");
    }
}

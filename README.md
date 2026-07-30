# simon

A terminal chat client for local and cloud LLMs, with multiple models able to delegate
work to each other in one session.

## Status

Working and tested, but early. `cargo test` covers 129 cases; `cargo clippy -D warnings`
and `cargo fmt --check` are clean. **Read [Security posture](#security-posture) before
relying on the security claims** — some features described in `docs/progress/` are not
implemented, and that section says exactly which.

## Install

Requires a recent stable Rust toolchain (see `rust-toolchain.toml`).

```sh
cargo build --release
./target/release/simon --help
```

## Use

```sh
simon models                 # list every model this machine can reach
simon auth anthropic         # store an API key (prompts; never pass it as an argument)
simon chat                   # start the TUI with the first available model
simon chat -m ollama:llama3  # pick a commander explicitly
simon chat --classified      # local models only, no network egress
simon audit                  # verify the audit log's hash chain
```

`-m` accepts a full label (`ollama:llama3`), a bare model name (`llama3`), or a provider
name (`anthropic`).

In the TUI: type and press **Enter** to send, **PageUp/PageDown** to scroll, **Esc** or
**Ctrl-C** to quit.

### Providers

| Provider | Transport | Discovery |
|---|---|---|
| `ollama` | local HTTP daemon | `GET /api/tags` at startup |
| `anthropic` | `POST /v1/messages` | enabled when a key is stored |
| `openai`, `openrouter`, `groq` | `POST /chat/completions` | enabled when a key is stored |
| local CLI tools | subprocess (argv, no shell) | configured in `config.json` |

Routing is per provider. A key stored for one vendor is only ever sent to that vendor's
endpoint.

### Configuration

`config.json` lives in the platform data directory (override with `SIMON_DATA_DIR`):

```json
{
  "ollama_host": "http://127.0.0.1:11434",
  "default_provider": "ollama",
  "custom_endpoints": {
    "my-gateway": {
      "api": "open_ai_compatible",
      "base_url": "https://gateway.internal/v1",
      "default_model": "llama-3.3-70b"
    }
  },
  "local_binaries": {
    "copilot": { "path": "gh", "args": ["copilot", "suggest"] }
  }
}
```

### Delegation

Every model receives a shared ledger in its system prompt listing the other reachable
models, observed rate-limit budgets, and open tasks. A model delegates by emitting:

```
ACTION: delegate_task(ollama:mistral, summarise the attached diff)
```

The orchestrator runs the sub-task and records the reply (or, on failure, the error) on
that task in the shared ledger, tagged `[DONE]` or `[FAILED]`. Because the ledger is
only re-rendered into the *next* prompt sent to any model, the result becomes visible to
the delegating model on its next turn, not within the turn that requested it. Sub-agent
replies are not re-scanned for delegations, and at most 3 delegations run per turn, so
the swarm cannot recurse indefinitely.

### Skills

The system prompt also lists every file in the read-only skills directory, each with the
one-line description parsed from its optional frontmatter:

```
---
name: whatever
description: One line saying when this skill applies.
---
```

A file without that block is still listed, just with no description. To load a skill's
full contents, a model emits:

```
ACTION: read_skill(notes.md)
```

The name is resolved and read through the same path-traversal-hardened lookup as any
other skill access — a model's reply is untrusted input, no different from a name typed
by a user, so the same `..`/absolute-path/symlink checks apply. The content (or, on
failure, the error) is recorded in the ledger and becomes visible on the model's next
turn, same timing as a delegation result. At most 3 skills are kept loaded at once, each
capped in size; loading a fourth evicts the oldest.

## Security posture

Be precise about what exists. This table is the source of truth; the numbered files in
`docs/progress/` are a development narrative, not a specification.

### Implemented

- **API keys in the OS keyring**, read from a hidden terminal prompt or stdin — never
  from `argv`, where any local user could read them from the process table.
- **Tamper-evident audit log** — a chain of JSON entries, each carrying a keyed
  `Blake2s256` MAC over the previous entry. The key lives in the OS keyring, so writing
  the log file is not enough to forge it. Recovers the chain head across restarts.
  `simon audit` verifies the whole file.
- **`--classified`** — refuses any provider whose traffic leaves the machine, and
  requires process-wide memory locking to succeed rather than warning.
- **Process-wide memory locking on Linux** — `mlockall` at startup (`main.rs`), pinning
  the whole process into RAM so nothing is swapped to disk. The other half of this
  claim, per-allocation `mlock`/`VirtualLock` of derived key material, exists too (see
  below) but only runs inside the vault, which no code path currently reaches.
- **Path-traversal protection** on the read-only skills directory: `..`, absolute paths,
  and symlinks escaping the root are all rejected. This is reachable from model output
  via `ACTION: read_skill(<name>)` (see [Skills](#skills)), not just from trusted
  callers, so the rejection is load-bearing, not defensive dead code.
- **Proxy support** — honours `HTTP_PROXY`/`HTTPS_PROXY` and, via reqwest's `socks`
  feature, `ALL_PROXY=socks5://…`.
- **`unsafe` confined to one file** — `#![deny(unsafe_code)]` crate-wide with a single
  audited override in `src/security.rs`, enforced by a CI job that rejects the override
  anywhere else.

### Implemented and unit-tested, but not reachable from the app

- **Encrypted vault** — AES-256-GCM, Argon2id key derivation, salt persisted in the file
  header and bound as authenticated data. Self-destructs after 5 consecutive wrong
  passwords or 24 hours idle. The derived key is held in a buffer that is locked into RAM
  per-allocation (`mlock`/`VirtualLock`) and zeroized on drop. All of this is real and
  covered by tests in `src/vault.rs` — but no command in `simon` constructs an
  `EncryptedVault`. Nothing currently opens a vault, and nothing is stored in one.

### Not implemented

- **seccomp sandboxing.** A useful filter must permit `socket`/`connect` while denying
  `execve`, which needs a hand-written BPF program. `SECCOMP_MODE_STRICT` would kill the
  process on its first network call. The function is a documented no-op that reports
  itself as unavailable at startup.
- **TLS certificate pinning.** Pinning third-party API certificates breaks on every
  rotation, which is an operational hazard for endpoints we do not control. If added, it
  should be opt-in per endpoint.
- **Process-wide memory locking on Windows and macOS.** Windows has no `mlockall`
  equivalent; macOS declares it but returns `ENOSYS`. The vault's per-allocation lock
  (see above) would stand in for it on those platforms if the vault were wired up, but
  today `--classified` on Windows/macOS simply refuses to start, since the process-wide
  guarantee it requires is unavailable there.
- **Clipboard clearing.** The app does not touch the clipboard.

### Known limits of what is implemented

- The vault's failed-attempt counter lives in the same file it protects. An attacker who
  can copy the file can reset it by restoring their copy. This raises the cost of online
  guessing; it is not a substitute for a TPM or secure enclave. (A property of the vault
  code itself, which — see above — nothing in the app currently opens.)
- The audit log uses a MAC, not a signature. Anyone who can read the keyring key can
  forge entries, so it proves integrity against local tampering, not non-repudiation.
- A local CLI tool is treated as remote for `--classified` purposes, because we cannot
  see whether it calls a cloud API internally.

## Development

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test
cargo audit
```

CI runs all of the above on Linux, Windows, and macOS, plus the unsafe-boundary check.

## History

**On the name:** the command, package, and on-disk state are all `simon`. The git
repository is still called `multichat`, after the Python project that used to live here.

The repository previously held a Python/FastAPI implementation, replaced by this Rust
one in commit `9a51fc6`. That version is recoverable at commit `06c6c76`.
`docs/AUDIT.md` records the audit of the initial Rust commit and the defects this
version fixes.

## License

MIT OR Apache-2.0.

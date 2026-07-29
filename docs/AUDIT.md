# Project Audit — `multichat` / `simon`

**Date:** 2026-07-29
**Scope:** Full repository at `main` (`9a51fc6`)
**Method:** Static read of all 12 Rust source files (~670 lines) and all 23 docs; git history comparison against `06c6c76`.

> **Status: remediated.** This document records the state of commit `9a51fc6` and is kept
> as the historical finding, not as a description of the current tree. Every Tier 1–4
> item below has since been fixed: the application is wired end to end, the Tier 3
> defects are corrected, and the docs no longer claim unimplemented features. A Rust
> toolchain was installed, so the "could not be verified" caveat below no longer applies —
> the current tree builds clean, passes 65 tests, is clippy- and `cargo audit`-clean, and
> the binary has been run. Current status: `README.md` → "Security posture" and
> `docs/progress/22_status.md`.
>
> One resolution differs from what this document assumed. The "Name mismatch" finding was
> settled in favour of **`simon`**, not `multichat`: the package, binary, data directory,
> keyring namespace, and `SIMON_DATA_DIR` all use it. The git repository is still named
> `multichat`. References to `multichat` below describe the state at `9a51fc6` and the
> deleted Python package, and are left as written.

---

## Headline

Commit `9a51fc6` ("feat: complete Simon Swarm Orchestrator architecture in Rust") deleted a ~3,100-line working Python application and replaced it with ~670 lines of Rust scaffolding **in which no user input can reach any model**. Meanwhile `docs/progress/21_integration_completion.md` states the project is *"fully complete, tested, and verified."*

Deleted in that single commit:

| File | Lines |
|---|---|
| `src/multichat/providers.py` | 440 |
| `tests/test_multichat.py` | 375 |
| `src/multichat/api.py` | 323 |
| `src/multichat/core.py` | 207 |
| `src/multichat/database.py` | 138 |
| `src/multichat/config.py` | 72 |
| `src/multichat/ws.py` | 51 |
| `static/index.html` | 1,287 |
| `README.md` | 100 |
| `.env.example` | 17 |

The Python application is fully recoverable at commit **`06c6c76`**.

This audit does not argue against a Rust rewrite. The finding is narrower and factual: **the replacement does not yet do what the replaced code did, and the documentation asserts that it does.**

---

## A note on compile status

**The build was not verified, and could not be.** This machine has no `cargo`, no `rustc`, no `~/.cargo`, no `~/.rustup`, and the repo has no `target/` directory. No claim in this report depends on the code compiling or failing to compile.

Two related observations:

- `docs/progress/15` through `20` each assert "`cargo check` fully passes." Doc `21` claims only that `cargo build --release` verification was *"initiated"* — it never states that it completed.
- `Cargo.toml` sets `edition = "2024"` (requires Rust ≥ 1.85), and doc `04` describes installing rustup "via curl script" — a Linux idiom. If verification happened, it happened in an environment that is not this checkout.

A few constructs should simply be confirmed on first successful build rather than treated as defects: `aead::OsRng` feature gating in `vault.rs`, `SecretString::from(String)` under `secrecy` 0.8, and `Key::<Aes256Gcm>::from_slice(..).clone()`.

**Dependencies were likewise not audited.** No toolchain means no `cargo-audit`, so the 3,221-line `Cargo.lock` has not been checked against the advisory database — which matters precisely because doc 07 mandates `cargo-audit` in CI. Without asserting any specific CVE: the pinned set is roughly a generation behind current releases (`ratatui` 0.26, `secrecy` 0.8, `thiserror` 1.0, `rand` 0.8, `directories` 5.0). Run `cargo audit` and `cargo outdated` as part of establishing a baseline.

---

## Tier 1 — The application is not wired together

A repository-wide search for call sites returns **definitions only, no callers**:

| Item | Defined at | Constructed / called |
|---|---|---|
| `Provider::send_message` | `src/providers/mod.rs:11` | **never** |
| `CloudProvider` | `src/providers/cloud.rs:7` | **never** |
| `OllamaProvider` | `src/providers/ollama.rs:6` | **never** |
| `LocalBinaryProvider` | `src/providers/local_binary.rs:6` | **never** |
| `EncryptedVault` | `src/vault.rs:14` | **never** |
| `AuditLogger` | `src/audit.rs:8` | **never** |
| `SwarmLedger` | `src/swarm.rs:19` | **never** |
| `Config::get_api_key` | `src/config.rs:10` | **never** |
| `AppEvent::UiInput` | `src/app.rs:4` | **never** |
| `App::ui_tx` | `src/app.rs:12` | created, **never sent on** |
| `Cli::classified` | `src/main.rs:23` | parsed, **never read** |

What the program actually does today: `src/ui/mod.rs:63` responds to every message with `format!("Acknowledged: {}", msg)`. The adjacent comment is explicit — *"Send to background swarm orchestrator (mocked here for now)."*

Consequences:

1. **Zero LLM functionality.** No network call, no subprocess, no key retrieval.
2. **The `ui_rx` select branch is dead.** Nothing holds a clone of `ui_tx`, so `AppEvent::AgentResponse` and `AppEvent::Quit` can never arrive.
3. **`Commands::Chat { model }` discards its argument.** `ui::run_tui()` takes no parameters; the selected model is only printed.
4. **Nothing produces the `app_dir: PathBuf`** that `EncryptedVault::new` and `AuditLogger::new` both require. The vault and audit log have no location, not merely no callers. `directories` is declared in `Cargo.toml` and never imported — as are `thiserror` and `rand`.
5. **No tests exist.** Plan step 7 ("E2E Testing") was never performed, and `docs/progress/README.md` rule 5 requires every step be explicitly verified before proceeding.

---

## Tier 2 — Security features documented as present, absent in code

`docs/progress/` describes a "military-grade," "zero-trust" system. Claim against implementation:

| Documented claim | Doc | Actual state |
|---|---|---|
| `mlock` swap protection | 01, 15 | Linux only (`security.rs:7`). |
| Windows `VirtualLock` | 06 | **Absent.** Windows hits the no-op stub. |
| macOS `mlock` | 06 | **Absent.** macOS also falls to the non-Linux no-op stub. |
| `seccomp` sandbox | 01, 05, 15 | **Stub.** `security.rs:26` returns `Ok(())`; the comment admits it. |
| TLS certificate pinning | 01, 05 | **Absent entirely.** Default rustls, no pinning anywhere. |
| Encrypted vault (AES-256-GCM) | 01, 06, 16 | Code exists, never called; salt never generated or stored (see Tier 3). |
| `--classified` air-gap / disables outbound network | 01, 06 | Flag parsed, **never read**. No effect. |
| Dynamic model discovery (`ollama list`, `/v1/models`) | 09 | **Absent.** |
| `delegate_task` orchestration engine | 10, 12 | **Absent.** Only the instruction *text* in `swarm.rs:90`. |
| Ledger injected into every model's system prompt | 11 | Generator exists (`swarm.rs:61`), **never called**. |
| Rate-limit interception / budget tracking | 13 | **Absent.** No header inspection anywhere. |
| SOCKS5 proxy support | 14 | **Absent.** `reqwest` lacks the `socks` feature. Doc 20 claims env-var support "covers" this; env vars give HTTP(S) proxying only, not SOCKS5. |
| Vault anti-brute-force / auto-wipe (5 attempts, 24h idle) | 14 | **Absent.** |
| "Cryptographically signed" audit log | 14, 20 | **Hashed, not signed** (see Tier 3). |
| `#![forbid(unsafe_code)]` project-wide | 07 | Code uses `deny` (`main.rs:1`) with a module-level `allow` override (`security.rs:1`). `forbid` is precisely what would prevent that override. |
| `cargo-audit` required for CI | 07 | **No CI exists.** No `.github/` directory. |
| Shared skills dir + path-traversal protection | 07 | **Absent.** |
| Clipboard clearing after timeout | 07 | **Absent.** |

Doc `20`'s claim that proxy support is satisfied because `reqwest` "respects standard proxy environment variables natively" is the one case where documentation actively papers over an unmet requirement rather than merely running ahead of implementation.

**What does hold.** The table above is unbalanced by construction — it lists claims, and claims run ahead of code. Several things are genuinely right: `Cargo.lock` is committed, satisfying doc 07's supply-chain pinning requirement; `#![deny(unsafe_code)]` is present and `unsafe` really is confined to `security.rs`; `reqwest` is configured with `rustls-tls` and `default-features = false`, and does honor `HTTP_PROXY`/`HTTPS_PROXY`. In `vault.rs` the primitive choices — AES-256-GCM with a 12-byte random nonce, Argon2 for key derivation — are the correct ones. The vault's defects are wiring and salt persistence, not cryptographic selection.

---

## Tier 3 — Real defects that will bite once wiring exists

**1. On Linux, the binary aborts before it parses arguments.**
`main.rs:46` calls `enforce_memory_protection()?` *before* `Cli::parse()`. On Linux, `security.rs:10-13` returns `Err` when `mlockall` fails — and its own error message concedes it requires `CAP_IPC_LOCK` or a raised `ulimit -l`. On a stock unprivileged Linux box the process therefore exits before argument parsing: `simon --help` and `simon --version` die along with everything else. Second-order risk: if `MCL_CURRENT` fits under `RLIMIT_MEMLOCK` at startup, `MCL_FUTURE` will cause later allocations to fail once the process grows past the limit.

The net effect is inverted: the only platform where memory protection is actually implemented is the only platform where the app will not start, while Windows and macOS — where it is a documented no-op — launch normally. Doc 15 frames "enforcers invoked BEFORE parsing any CLI args" as a feature; as written it is a startup defect. Fail soft with a warning unless `--classified` is set, and parse args first.

**2. `CloudProvider` ignores `provider_name` and always posts to OpenAI.**
`src/providers/cloud.rs:30` hardcodes `https://api.openai.com/v1/chat/completions`; `provider_name` is stored and never read. An Anthropic or Gemini key routed through this struct would be transmitted to OpenAI's endpoint as a bearer token — a credential disclosure to the wrong party.
This is a **regression**: commit `7a60cd4` in the Python era is titled *"Fix provider identity confusion."* The bug was found, fixed, and reintroduced by the rewrite.

**3. Vault salt is never generated, stored, or recovered.**
`save()` (`vault.rs:44`) writes `[12-byte nonce][ciphertext]` — the salt is **not** in the file. Both `save` and `load` take `salt: &str` from the caller, and no caller exists. As written the vault cannot round-trip without an out-of-band salt source that the codebase does not provide. The salt must be persisted in the file header alongside the nonce.

**4. Audit hash chain resets to genesis on every start.**
`AuditLogger::new` (`audit.rs:19`) always begins from the zero hash; the comment concedes the last hash should be recovered from the file. The chain is therefore per-process, not per-history. Compounding this: the log is hashed with Blake2 but **not signed** — no key is involved — so anyone who can write the file can rewrite entries and recompute every hash. It is tamper-*evident* only against an attacker who does not recompute, which is not a meaningful adversary. Doc 14/20's "cryptographically signed" is an overclaim.

**5. Blocking subprocess call inside an `async fn`.**
`src/providers/local_binary.rs:25` uses `std::process::Command::output()`, which blocks the calling thread until the child exits. Inside a `#[tokio::main]` runtime this stalls a worker thread and will freeze the TUI for the duration of every CLI-model call. Use `tokio::process::Command` and `.await`.

**6. API keys passed on the command line.**
`multichat auth --service X --key Y` (`main.rs:35-40`) places the secret in `argv`, where it lands in shell history and is readable from the process table by any local user. The vault and keyring work is undermined at the entry point. Read the key from stdin or an interactive prompt.

**7. Dropped `EventStream` future per loop iteration.**
`src/ui/mod.rs:46` constructs `reader.next().fuse()` fresh inside `tokio::select!` each iteration. Confirm no input events are lost under load when the branch is not selected.

---

## Tier 4 — Repository hygiene

- **`.gitignore` lost its credential and database ignore rules.** Verified via `git show 06c6c76:.gitignore`: the Python-era file ignored `.env`, `*.db`, `*.db-journal`, `*.db-wal`, `*.db-shm`, and `Thumbs.db`. The current file is a single line, `/target`. A future `.env` in this repo is **no longer ignored** — a concrete credential-commit exposure. `.env.example` was also deleted.
- **No top-level `README.md`** (deleted in `9a51fc6`), no `LICENSE`, no `.github/`, no CI, no `rust-toolchain.toml` despite `edition = "2024"` requiring a recent toolchain.
- **Name mismatch.** `Cargo.toml` declares `name = "simon"`, producing a `simon` binary, while every doc and all CLI help text says `multichat`. Doc 06's example invocation `multichat --classified` names a binary that will not exist.
- **Progress docs are ordered by claim, not by state.** Each is capped at 500 characters by `docs/progress/README.md`, which pushes toward assertion over evidence. Docs 15–21 read as completion records for work that is scaffolded but unconnected.

---

## Design coherence

`docs/progress/08_default_unlimited_perms.md` states: *"By default, ALL models have FULL read/write/execute permissions across the system. No read-only limits or path sandboxes are enforced initially."*

This flatly contradicts the zero-trust threat model in docs 01, 05, and 07 — particularly 07's path-traversal protections and read-only skills directory. The contradiction is currently vacuous, because neither the permissions nor the sandbox exist. But as specified, doc 08 inverts the stated security posture: it grants arbitrary execution to remote model output by default and treats restriction as opt-in. This should be resolved as a design decision before any provider is wired to a tool-execution path, because `LocalBinaryProvider` is exactly that path.

---

## Recommended sequence

1. **Correct the documentation first.** Doc 21's "fully complete, tested, and verified" is the most damaging artifact here — it makes every other doc unreliable. Restate 15–21 as "scaffolded, not integrated."
2. **Restore `.gitignore`** ignore rules for `.env` and database files.
3. **Establish a verified baseline:** install the toolchain, get `cargo build` and `cargo clippy` green, commit a `rust-toolchain.toml`, and add CI running both plus `cargo-audit`.
4. **Wire one path end to end** — TUI input → `OllamaProvider::send_message` → response in history — with a test. This converts the scaffold into an application and validates the trait design against one real caller.
5. **Fix Tier 3 items 1 through 4, and 6** — Linux startup abort, OpenAI misrouting, vault salt, audit chain recovery, and keys-in-argv — before any key or user data touches the vault or cloud path.
6. **Resolve the doc 08 / doc 07 contradiction** before wiring `LocalBinaryProvider`.
7. **Reconcile against `06c6c76`** — the Python version's provider routing, database layer, and 375 lines of tests encode solved problems. Port the behavior deliberately rather than rediscovering it.

# simon

A terminal chat client for local and cloud LLMs, with multiple models able to delegate
work to each other in one session.

## Status

Working and tested, but early. `cargo test` covers 209 cases; `cargo clippy -D warnings`
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
simon chat                   # choose connections and a commander, then chat
simon chat -m ollama:llama3  # pick a commander explicitly
simon chat --classified      # local models only, no network egress
simon chat --vault           # persist the transcript, encrypted, across sessions
simon chat --project ~/code/myapp  # confine models to this folder instead of cwd
simon vault status           # vault path, failed attempts, time to idle self-destruct
simon vault destroy          # permanently delete the vault (typed "yes" to confirm)
simon audit                  # verify the audit log's hash chain
```

`-m` accepts a full label (`ollama:llama3`), a bare model name (`llama3`), or a provider
name (`anthropic`).

`--project <dir>` sets the **project folder** — the one part of the filesystem models
can list, read, and write through `simon`'s own protocol (see
[Project files](#project-files)). It defaults to the directory `simon` was started in,
and is resolved and canonicalized once at startup.

`simon auth` also accepts `claude` and `gemini` as aliases, storing the key under
`anthropic`/`google` respectively so vendor discovery finds it.

The connection picker can also prompt for a key directly: press **space** on an API
row marked `(no key stored)` to open a masked entry field instead of quitting to run
`simon auth`. Either way, the key lands in the OS keyring only — never in
`config.json`.

In the picker: **space** ticks a connection, **c** marks the highlighted row
commander, **tab** cycles a candidate's transport, and **enter** connects — but only
once a commander has been chosen; until then it just flashes a reminder to press
**c**. `simon chat -m <label>` skips the picker and picks the commander
non-interactively instead.

In the TUI: type and press **Enter** to send, **PageUp/PageDown** to scroll, **Esc** or
**Ctrl-C** to quit. Type `/commander` on its own to list every connected model with
the current commander marked, or `/commander <name>` (a full label, a bare model
name, or a provider name) to switch commanders live, without leaving the
conversation — the choice persists across restarts, same as the picker's. Neither
form is ever sent to a model as a prompt.

`--vault` persists the TUI transcript — what you and the models said — to an encrypted
file so it survives between runs of `simon chat --vault`. It is **not** conversation
memory: no model ever receives the transcript or any prior turn as context, vault or
not (see [Delegation](#delegation) — every prompt still goes out on its own). The vault
only gives the *user* their own history back on screen. It is off by default and changes
nothing about `simon chat` without the flag. See
[Security posture](#security-posture) for what it protects against, its self-destruct
policy, and what a crash costs you.

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

None of this has to be inferred from timing: the status line names whichever model is
actually being called — the sub-agent, not the commander — along with what it's doing
and how long it's taken so far, and the transcript gets a line the moment a delegation
is dispatched (naming the agent and its task) and another when it finishes, reporting
outcome and duration. The full sub-agent reply still arrives afterward as an ordinary
reply line.

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
capped in size; loading a fourth evicts the oldest. The skills directory itself stays
read-only to models — see [Project files](#project-files) for the one place they may
write.

A successful load also gets a transcript line naming the skill and its size, so a read
that would otherwise be silent (only a failure previously reached the TUI) is visible
too; while the read is in flight the status line shows it the same way it shows a
delegation.

### Project files

Models can list, read, and write files in the **project folder** — the directory
`simon` was started in, or whatever `--project <dir>` points at (see
[Use](#use)). This is a real change from earlier versions: it used to be a private
scratch directory under `simon`'s own data directory, and is now the user's own
project. Every access still goes through the same path-traversal hardening as the
read-only skills directory (`..`, absolute paths, and symlinks escaping the root are
all rejected) — a model's reply is untrusted input, no different from a path typed by
a user.

To list a directory's immediate entries:

```
ACTION: list_files(notes)
```

An empty path (`ACTION: list_files()`) lists the project root. Listing is never
recursive — a model descends into a subdirectory it saw with a further `list_files`
call naming it. To read a file's full contents:

```
ACTION: read_file(notes/todo.md)
```

To create or overwrite a file, emit a block:

```
ACTION: write_file(notes/todo.md)
- write the summary
- send it to review
ACTION: end_file
```

Everything between the `write_file` line and the `end_file` line is written verbatim as
the file's content. Paths are relative to the project root and subdirectories are
created automatically on write; there is no cap on how many files may exist under the
root, but a single read or write is capped at 256KB and a single listing at 500
entries (truncation is reported, not silent). A line containing
`ACTION: delegate_task(...)`, `ACTION: read_skill(...)`, `ACTION: read_file(...)`, or
`ACTION: list_files(...)` inside a `write_file` block's content is treated as content,
not executed — this matters because a model writing documentation about its own
protocol will naturally include example lines that look like real requests. Writes
into `.git/` are refused outright; reading `.git/` is not special-cased, since only a
write can corrupt a repository. Every list, read, and write, successful or not, is
audited (`project.list`/`project.list_failed`, `project.read`/`project.read_failed`,
`file.written`/`file.write_failed`) and shown in the TUI as it happens — the audit
entries and the ledger record paths, byte counts, and entry counts only, **never file
content**. The outcome becomes visible to the requesting model on its next turn, same
timing as a delegation result; at most 3 loaded reads are kept at once (each
size-capped), evicting the oldest, the same discipline as loaded skills.

**This is not a sandbox for spawned CLI providers.** A `claude`/`gemini`/`codex` CLI
configured as a local binary provider is started with its working directory set to
the project folder (`Command::current_dir`), so it doesn't stumble onto whatever was
lying around in `simon`'s own launch directory — but that only sets the starting
point. A CLI agent with its own shell or filesystem tool access can `cd` anywhere the
invoking user can reach and read or write outside the project folder freely; none of
that filesystem activity passes through `simon`'s audit log or the `list_files`/
`read_file`/`write_file` protocol above, which exists only for `simon`'s own
in-process model calls (the cloud APIs and Ollama).

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
  claim, per-allocation `mlock`/`VirtualLock` of derived key material, is genuinely live
  too now: `simon chat --vault` runs `EncryptedVault::save`/`load`, both of which call
  `derive_key`, which allocates the Argon2id output through `LockedBuffer::new` (see
  `src/security.rs`) — not just exercised by `src/vault.rs`'s own tests.
- **Encrypted transcript vault (`simon chat --vault`)** — the TUI transcript
  (`App::transcript`: what you and the models said, nothing else) encrypted with
  AES-256-GCM under an Argon2id-derived key, opt-in and off by default. The salt lives
  in the file header and is bound as authenticated data, so tampering with it breaks
  decryption. This is **user-visible history, not model memory** — no model ever
  receives the transcript or any prior turn as context; every prompt is still sent
  alone (see [Delegation](#delegation)). `simon vault status` reports the vault's path,
  failed-attempt count, and time left before idle self-destruct without ever asking for
  a password (those two fields are plaintext header data — see
  [Known limits](#known-limits-of-what-is-implemented)). `simon vault destroy` deletes
  it after a typed `yes`.
- **Path-traversal protection** on the read-only skills directory: `..`, absolute paths,
  and symlinks escaping the root are all rejected. This is reachable from model output
  via `ACTION: read_skill(<name>)` (see [Skills](#skills)), not just from trusted
  callers, so the rejection is load-bearing, not defensive dead code.
- **Model-initiated file listing, reading, and writing confined to the project
  folder** (see [Project files](#project-files)) — the same traversal hardening as
  skills (`..`, absolute paths, and symlinks escaping the root are all rejected),
  size-capped per read/write and entry-capped per listing, and every access is
  audited and rendered in the TUI so the user sees everything a model has listed,
  read, or written. Writes into `.git/` are refused outright. The skills directory
  itself remains read-only to models — a model that could write a skill file could
  inject its own content into the system prompt sent to every model for the rest of
  the session — so this is deliberately a separate tree, not a relaxation of that
  guarantee. **This confinement is `simon`'s own protocol only** — it does not extend
  to a spawned CLI provider (`claude`, `gemini`, `codex`, …), which merely *starts* in
  the project folder and is free to read or write anywhere its own shell/filesystem
  access reaches; see [Project files](#project-files) for the honest boundary.
- **Proxy support** — honours `HTTP_PROXY`/`HTTPS_PROXY` and, via reqwest's `socks`
  feature, `ALL_PROXY=socks5://…`.
- **`unsafe` confined to one file** — `#![deny(unsafe_code)]` crate-wide with a single
  audited override in `src/security.rs`, enforced by a CI job that rejects the override
  anywhere else.

### Not implemented

- **Filesystem sandboxing of spawned CLI providers.** `simon`'s own list/read/write
  protocol is confined to the project folder, but a local CLI provider (`claude`,
  `gemini`, `codex`, …) only has its working directory *set* to the project folder at
  spawn time; it is otherwise an ordinary subprocess with whatever shell and
  filesystem access the invoking user has, and none of that access is mediated or
  audited by `simon`. See [Project files](#project-files).
- **seccomp sandboxing.** A useful filter must permit `socket`/`connect` while denying
  `execve`, which needs a hand-written BPF program. `SECCOMP_MODE_STRICT` would kill the
  process on its first network call. The function is a documented no-op that reports
  itself as unavailable at startup.
- **TLS certificate pinning.** Pinning third-party API certificates breaks on every
  rotation, which is an operational hazard for endpoints we do not control. If added, it
  should be opt-in per endpoint.
- **Process-wide memory locking on Windows and macOS.** Windows has no `mlockall`
  equivalent; macOS declares it but returns `ENOSYS`. The vault's per-allocation lock
  (see above) stands in for it **only while the vault is deriving a key** — it protects
  the vault's own key material on those platforms, not the process as a whole — so
  `--classified` on Windows/macOS still simply refuses to start, since the process-wide
  guarantee it requires is unavailable there regardless of `--vault`.
- **Clipboard clearing.** The app does not touch the clipboard.

### Known limits of what is implemented

- **The vault's self-destruct is a data-loss feature, not just a security one.** 5
  consecutive wrong passwords, or 24 hours since the vault was last opened, wipes the
  saved transcript — permanently, with no recovery. The idle check in particular runs
  **before** the password is even checked (`EncryptedVault::load`, `src/vault.rs`), so
  typing the correct password after a 24-hour gap does not save it; the file is already
  gone by the time the password would have been checked. `simon vault status` shows time
  remaining before this happens, and `simon chat --vault` warns at unlock time if the
  vault is within a few hours of it.
- **Only a clean exit saves.** `simon chat --vault` serializes and encrypts the
  transcript once, after the TUI loop returns normally — not after every turn, because
  Argon2id key derivation is deliberately slow and running it per-message would stall
  the UI. A crash, panic, or `kill -9` skips that save, so anything typed since the last
  clean exit (or vault open, on the first run) is lost. This is a real trade-off, not an
  oversight: continuous session-to-session use is safe, but do not rely on `--vault` as
  a crash-safe log.
- The vault's failed-attempt counter and last-unlock timestamp live in the same file
  they protect and are deliberately excluded from the authenticated data (see
  `src/vault.rs`), so they are plaintext and unauthenticated — an attacker who can copy
  the file can reset both by restoring their copy. `simon vault status` reads them
  without a password for exactly this reason: they were never tamper-proof to begin
  with. This raises the cost of online guessing; it is not a substitute for a TPM or
  secure enclave.
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
`docs/AUDIT-2026-07-30.md` is the current audit. The two earlier audits (of the
initial Rust commit and of `2cca5da`) described trees that no longer exist and were
removed as superseded; both are recoverable at commit `2e7984e`.

## License

MIT OR Apache-2.0.

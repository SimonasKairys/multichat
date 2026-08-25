# simon

A terminal chat client for local and cloud LLMs, with multiple models able to delegate
work to each other in one session.

## Status

Working and tested, but early. `cargo test` covers 276 cases; `cargo clippy -D warnings`
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
simon vault status           # vault path, failed attempts, idle window
simon vault destroy          # permanently delete the vault (typed "yes" to confirm)
simon audit                  # verify the audit log's hash chain
simon audit --reset-anchor   # re-baseline tamper-evidence after deleting the log
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

`chat` is the default subcommand, and its flags work without naming it: `simon --vault`
and `simon chat --vault` are the same thing.

In the TUI: type and press **Enter** to send, **PageUp/PageDown** to scroll, **Esc** or
**Ctrl-C** to quit. The prompt line edits like a normal one — **left/right** move the
caret, **Home/End** jump to either edge, **Backspace/Delete** cut on either side of it,
and modified chords are not typed as text (a stray **Ctrl-A** used to insert a bare
`a`). `/forget` clears the ledger's accumulated content when a long session has piled
up more than the commander needs. Type `/commander` on its own to list every connected model with
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
    "copilot": { "path": "gh", "args": ["copilot", "suggest"] },
    "claude": { "path": "/opt/claude/bin/claude", "stream_format": "claude" }
  }
}
```
## What models can do

Beyond answering, a model can act by emitting a line in its reply. Five actions exist,
all parsed out of the model's plain text — there is no function-calling API involved:

| Action | Effect | Result arrives |
|---|---|---|
| `ACTION: delegate_task(<label>, <prompt>)` | Runs a sub-task on another model | next turn |
| `ACTION: read_skill(<name>)` | Loads a skill file into context | next turn |
| `ACTION: list_files(<path>)` | Lists one directory in the project | next turn |
| `ACTION: read_file(<path>)` | Reads one project file | next turn |
| `ACTION: write_file(<path>)` … `ACTION: end_file` | Writes a project file | immediately, after you approve |

Two rules apply to all of them, and both matter more than they look:

**Results arrive on the model's *next* turn.** The ledger that carries them is only
rendered into the next prompt, so a model that reads a file cannot also act on its
contents in the same reply. A single "read this and fix it" request will only read; the
fix comes when you send the next message.

**A sub-agent's reply is scanned for writes, and for nothing else.** It cannot delegate
further, load a skill, or read/list files — so no reply can spawn more work, which is
what bounds the swarm. A write spawns nothing, so sub-agents *can* author files, and
that is how a swarm builds a project: the commander delegates the authoring and the
cheap model writes the files. Every such write still passes the same two gates a
commander's does — path hardening and your approval, which names the sub-agent as the
one asking.

### Delegation

Every model receives a shared ledger in its system prompt listing the other reachable
models, observed rate-limit budgets, and open tasks. A model delegates by emitting:

```
ACTION: delegate_task(ollama:mistral, summarise the attached diff)
```

The orchestrator runs the sub-task and records the reply — or, on failure, the error —
on that task in the ledger, tagged `[DONE]` or `[FAILED]`, where the delegating model
sees it on its next turn. At most 3 delegations run per turn, and they run one after
another, not concurrently.

**The commander orients and proposes before it delegates.** Given anything more than a
direct question it works in three steps: look at the project first (listing directories
and reading the few files that decide the answer, with its own read requests — not by
delegating discovery, since a sub-agent sees only the prompt it is given); then say what
it found, what it intends to do, any alternative worth weighing, and which tasks would go
to which model — and stop there for you to answer; and only then delegate. A plan is far
cheaper to correct than finished files are. Asked to add word counting to a small project,
this is the difference between delegating a guess and noticing that the project's notes
claim tabs while its only source file is indented with spaces.

The commander is held to the same rule as a sub-agent about *how* files get written: it
may read and inspect freely to orient itself, but it may not create or edit a file with
its own tools, and may not run the project's code. Every file it writes goes out as a
write block and waits for your approval. Without that rule it was observed editing a
project file correctly and completely invisibly — no prompt, no `file.written` entry,
and a `__pycache__` left behind showing it had executed the code too.

Because every prompt is sent with no message history, the commander's own previous turn is
carried in the ledger — without it a proposed plan evaporates before the turn that would
act on it, and answering "approved, go ahead" produced nothing at all.

**Delegating is the commander's default, not a fallback.** The roster in the system
prompt annotates each model with roughly what it costs and how much context it holds,
and the commander is told to pick the cheapest model that can do the task, keeping only
judgement and synthesis for itself.

That instruction is prepended to your own message rather than left in the system prompt
alone. An agentic CLI (`claude`, `agy`) ships its own system prompt and tool loop, and
given the mandate only in the system prompt it ignores it and does the work itself —
measured, not assumed. Only what reaches the model is augmented: the transcript and the
audit log record what you actually typed. The directive is omitted when the commander is
the only model connected.

A delegated prompt carries its own short directive, for the same reason. It tells the
sub-agent to finish in that reply (its answer is the *entire* result that reaches
`simon`, so anything it defers is lost), and it forbids two things outright rather than
merely discouraging them: running any shell command, and using the sub-agent's own
file-writing or file-editing tools. Both come from the same root cause, measured against
the real `agy` binary — its permission system does not function at all in non-interactive
print mode, because there is nobody present to approve anything. That showed up as
`permission check failed for command "python3 -c ..."` (agy shelling out to check its own
work), `permission check failed for command "git log -p -n 5"` (agy shelling out to read
history), and, hitting agy's own tools rather than ours, `declaring permissions: cortex
tool write_to_file: convert tool call for permissions: model output error: invalid tool
call error (invalid_args) <path>`. Reading and listing files needs no permission and
works reliably, so that is what the sub-agent is left with; when a task is to create or
edit a file, it is told to emit the content as plain text using `simon`'s own write
protocol instead of its own writer. `simon` cannot grant the missing permission itself —
the only switch on offer is `agy`'s blanket `--dangerously-skip-permissions`, which is
deliberately not used: it would auto-approve every tool call agy makes, and agy's own
writes were separately observed bypassing `simon`'s write-approval gate and audit log
entirely — four files appeared during delegations `simon` had recorded as *failed*.
Routing every write back through `simon`'s protocol closes that hole, since the write
is then plain text in the reply, not a tool call agy made on its own.

A delegation that fails transiently is retried up to 3 times with a 3s then 8s backoff,
each retry announced in the transcript with its reason. Agentic CLI sub-agents fail
intermittently in several unrelated ways, and a failed delegation is expensive in a way
a failed HTTP call is not, since the commander does not learn of it until its next turn.
A timeout, a missing binary, and a `--classified` refusal are *not* retried: those fail
identically forever.

None of this has to be inferred from timing. The status line names whichever model is
actually being called — the sub-agent, not the commander — with what it is doing and how
long it has taken, including the latest progress detail from a streaming CLI (see
[CLI provider streaming and timeouts](#cli-provider-streaming-and-timeouts)). The
transcript gets a line when a delegation is dispatched and another when it finishes,
with outcome and duration.

### Skills

The system prompt lists every file in the read-only skills directory, each with the
one-line description parsed from its optional frontmatter:

```
---
name: whatever
description: One line saying when this skill applies.
---
```

A file without that block is still listed, just without a description. To load one:

```
ACTION: read_skill(notes.md)
```

The name is resolved through the same path-traversal-hardened lookup as any other skill
access — a model's reply is untrusted input, no different from a name typed by a user.
At most 3 skills stay loaded at once, each size-capped; loading a fourth evicts the
oldest. A successful load gets a transcript line naming the skill and its size.

The skills directory stays **read-only** to models. A model that could write a skill
file could inject its own content into the system prompt sent to every model for the
rest of the session, so it is deliberately a separate tree from the project folder.

### Project files

Models can list, read, and write files in the **project folder** — the directory `simon`
was started in, or whatever `--project <dir>` points at. Every access goes through the
same path-traversal hardening as the skills directory: `..`, absolute paths, and
symlinks escaping the root are all rejected.

```
ACTION: list_files(notes)          # one directory's immediate entries
ACTION: list_files()               # the project root
ACTION: read_file(notes/todo.md)   # a file's full contents

ACTION: write_file(notes/todo.md)
- write the summary
- send it to review
ACTION: end_file
```

Listing is never recursive — a model descends by issuing another `list_files`.
Everything between `write_file` and `end_file` is written verbatim, and subdirectories
are created automatically.

An `ACTION:` line of any kind **inside** a `write_file` block is content, not a request.
This matters because a model writing documentation about this protocol will naturally
include lines that look exactly like real ones.

Limits: a single read or write is capped at 256KB, a single listing at 500 entries
(truncation is reported, not silent), at most 10 writes and 3 reads happen per turn.
At most 3 loaded reads are kept, evicting the oldest. There is no cap on how many files
may exist under the root. Writes into `.git/` are refused outright — a bad write there
can corrupt the repository in ways you cannot easily undo. Reading `.git/` is not
special-cased, since only a write can corrupt it.

Everything is audited (`project.list`, `project.read`, `file.written`, and their
`_failed` counterparts) and shown in the TUI as it happens. **The audit log and the
ledger record paths, byte counts, and entry counts only — never file content.**

#### Writes are not applied silently

Every `write_file` a model proposes is shown first — path, exact byte size, whether it
creates or overwrites (and how many bytes that would destroy), and the head of the
content — and the turn blocks until you answer:

```
OVERWRITE src/report.py (353 bytes -> 415 bytes)? [y]es  [n]o  [a]ll
```

Nothing reaches disk **through this protocol** before you answer. A refusal is recorded
in the ledger, so the model learns on its next turn that the file was not written rather
than building on one that does not exist, and is audited as `file.write_denied`.

Read that scope literally. The gate governs `write_file` blocks, which is every write by
a cloud or Ollama model — those have no other way to touch a disk. It does **not** govern
a spawned CLI provider's own file tools. Observed directly: asked to build a package,
three delegations to `agy` failed and were recorded as failed, yet four files appeared in
the project anyway, with no gate prompt and no audit entry. `agy` had written them itself.
See [This is not a sandbox for spawned CLI providers](#this-is-not-a-sandbox-for-spawned-cli-providers)
— if you need every write to pass the gate, the commander and the swarm must be API or
Ollama models, not CLI ones.

If the UI goes away while a question is pending, the write is refused, not applied —
with nobody left to ask, nobody has consented. A write that `Workspace` would reject
anyway (a `.git/` path, an oversized file, a traversal attempt) is refused *without*
asking, so a prompt never appears for a write your answer could not affect. `a` applies
for the rest of the session and is never persisted.

`--auto-write` skips the gate entirely, which is what an unattended or scripted run
wants and an interactive one generally does not.

#### This is not a sandbox for spawned CLI providers

A `claude`/`gemini`/`codex` CLI configured as a local binary provider is started with
its working directory set to the project folder and, where the CLI supports it,
`--add-dir <project root>`. That stops it stumbling onto whatever was lying around in
`simon`'s own launch directory, and stops it searching elsewhere for files it was asked
about — but it only sets a starting point.

A CLI agent with its own shell or filesystem access can `cd` anywhere the invoking user
can reach and read or write outside the project folder freely. None of that activity
passes through `simon`'s audit log or the protocol above, which governs only `simon`'s
own in-process model calls: the cloud APIs and Ollama.

### CLI provider streaming and timeouts

`claude` and `agy` (Antigravity) are auto-detected with progress streaming already on.
Each is invoked with its NDJSON stream flag, and every tool call or step the CLI reports
while it works is parsed and shown live in the status line:

```
claude · awaiting reply · Bash: Read the readme · 42s · ●···
```

Both are also passed `--add-dir <project root>`, and `agy` additionally gets
`--sandbox` (its own terminal restrictions, which let it use tools without a permission
prompt it cannot answer non-interactively) and `--print-timeout 30m` (its own default is
5m, short enough to cut off a real task before any of the limits below apply). Flag
order is not cosmetic for `agy`: its `-p` takes the next argument as the prompt, so
every other flag must precede it.

A hand-configured entry under `local_binaries` stays on the buffered-output path unless
it opts in with `"stream_format": "claude"` or `"stream_format": "agy"` — whichever
NDJSON shape the binary actually speaks. Any other value is a startup error, not a
silent fallback to buffering.

Progress details are third-party process output: control characters and newlines are
stripped and the length capped before they reach the TUI, and they are never written to
the audit log, which stays limited to sizes, paths, and outcomes.

The two paths are timed differently:

- **Streaming**: an **idle timeout of 180s**, reset on every line the CLI emits, so an
  agent that is genuinely working is never killed for taking a while — only for going
  silent. A **total timeout of 3600s** is an absolute backstop.
- **Non-streaming**: a flat **900s wall clock**. There is nothing to reset it on,
  because a plain `binary -p <prompt>` buffers all output until exit.

Either way, the timeout is what actually kills a wedged child: the subprocess is spawned
with `kill_on_drop`, which reaps it only once something drops the future awaiting it, so
the timeout firing is what triggers that drop.

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
- **The chain is anchored outside itself, so a cut tail is visible.** A forward walk
  alone cannot see truncation: delete the last N lines and what remains is a shorter,
  perfectly valid chain. Every append therefore also rewrites `<log>.anchor`, a small
  record of the entry count and the tail's MAC, authenticated with the same keyring
  key — so an attacker who can write files but cannot read the keyring can cut the log
  but cannot make the anchor agree. A second anchor in the keyring, synced only when a
  logger opens or closes, additionally survives deletion of both files. The keyring is
  deliberately off the per-entry path: a round trip costs ~30 ms here, and the
  orchestrator writes many entries per turn. Deleting a log on purpose is legitimate,
  so `simon audit --reset-anchor` re-baselines the evidence, says plainly that it is
  discarding it, and records the reset in the new chain.
- **Failures are logged by kind, never by text.** The log's invariant is sizes, counts,
  and paths only — but every error path used to format the error's own message into it,
  and an error can carry a fragment of a provider's response or a path a model chose. A
  failure now records `kind=timeout`, `kind=permission_denied`, `kind=http_status` and
  the like, with `detail=withheld` in place of the text. The kind is read from the
  error's typed cause rather than by scanning its words, so the two failures that
  dominate in practice — a model CLI that never answered, a provider returning non-2xx —
  are named rather than lumped into "unspecified".
- **A damaged MAC key stops the program instead of replacing itself.** The key is the
  only thing that makes the log verifiable, so silently generating a new one invalidates
  every entry ever written — and anyone able to write a short value into the keyring
  could have triggered exactly that, making a forged history look like ordinary
  corruption. A keyring entry that is present but unusable is now a hard error naming
  the service and what to do about it. An absent entry is still a normal first run.
- **Symlinks are never followed where a file's identity is the point.** The vault's
  self-destruct used `fs::write`, which follows a link: pointing `vault.enc` at another
  file made the wipe zero *that* file and unlink only the link. The atomic writer took
  its permission bits through a link the same way, so `vault.enc` and `config.json`
  could land at 644 instead of owner-only. And a symlink named after anything, pointing
  at `.git`, let `create_dir_all` build directories inside the real repository before
  the write was refused. All three now use `symlink_metadata` and refuse.
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
  failed-attempt count, and where it stands in its idle window without ever asking for
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
  read, or written. Writes into `.git/` are refused outright.
- **Every model-proposed write requires explicit approval** (see [Writes are not
  applied silently](#writes-are-not-applied-silently)) — the path, the exact size,
  whether it overwrites and how many bytes that destroys, and the head of the content
  are shown, and the turn blocks until the user answers. Nothing reaches disk
  unapproved; a lost UI denies rather than allows, and a refusal is audited as
  `file.write_denied`. Scope: this covers `write_file` blocks — every write available to
  a cloud or Ollama model — but **not** a spawned CLI provider's own file tools, which
  have been observed writing files during a delegation `simon` recorded as failed. Note the scope of the check: it establishes that the *user*
  consented, not that the content is correct — nothing inspects what is being written. The skills directory
  itself remains read-only to models — a model that could write a skill file could
  inject its own content into the system prompt sent to every model for the rest of
  the session — so this is deliberately a separate tree, not a relaxation of that
  guarantee. **This confinement is `simon`'s own protocol only** — it does not extend
  to a spawned CLI provider (`claude`, `gemini`, `codex`, …), which merely *starts* in
  the project folder and is free to read or write anywhere its own shell/filesystem
  access reaches; see [Project files](#project-files) for the honest boundary.
- **Proxy support** — honours `HTTP_PROXY`/`HTTPS_PROXY` and, via reqwest's `socks`
  feature, `ALL_PROXY=socks5://…`. Disabled outright under `--classified`: a proxy
  routes even a loopback request off the machine, which is the one thing that flag
  promises cannot happen.
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
  consecutive wrong passwords wipes the saved transcript — automatically, permanently,
  with no recovery. That is the anti-brute-force property and it is unchanged: a correct
  password typed after the 5th failure does not bring the file back. `simon vault status`
  shows the count so far.
- **Sitting idle past 24 hours warns; it no longer destroys the vault.** It used to:
  `EncryptedVault::load` checked the idle window **before** the password, so a 24-hour
  gap deleted the transcript with the right password powerless to stop it. The window is
  measured against the wall clock, and a forward clock jump — an NTP correction to a
  clock that was behind, a VM resuming with a stale clock — is indistinguishable from
  time that really passed, so that check could and did destroy a transcript
  irreversibly when no time had passed at all. The payload is AES-256-GCM encrypted;
  deleting it after a day bought little beyond what the encryption already gives, and
  cost guaranteed unrecoverable loss whenever the clock moved. Now `simon chat --vault`
  warns before prompting (saying plainly that a wrong clock can cause it), unlocking
  works normally, and a successful unlock resets the timer. `simon vault status` reports
  the idle window, whether it has been passed, and a system clock that is behind the
  vault's own last-unlock time.
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
  That is the threat model the anchor above is built for too: it stops someone who can
  edit files, not someone who already holds the key.
- The ledger is re-sent in full on every call, so a long session used to grow the
  system prompt without bound — a maximally-loaded ledger measured 241,945 characters.
  It is now capped at 16,000. The protocol sections are rendered in full and their cost
  reserved first, since a model that loses the protocol stops following it. The roster
  and budget lists are load-bearing too — a model cannot delegate to one it cannot see —
  but they are capped rather than unlimited: rendering them before computing the budget,
  with no ceiling of their own, was how a 600-model roster produced 63,819 characters
  and made the cap meaningless. Accumulated content (task results, loaded skills, loaded
  files, listings, the previous turn) is what gets dropped, newest kept, and every drop
  is announced in the prompt so the model is not misled into thinking it sees
  everything. `/forget` clears that content on demand, keeping the roster and
  the task list, and is recorded in the audit log with the before and after sizes.
- A local CLI tool is treated as remote for `--classified` purposes, because we cannot
  see whether it calls a cloud API internally.
- Output from a local CLI is bounded as it is read, not after. The cap used to apply to
  what was *kept*, while the whole of a child's output was buffered first — and since
  `mlockall` pins the process into RAM, that buffer could not even be paged out. Both
  streams are now read concurrently, each capped, with the remainder drained rather than
  dropped: closing the pipe early kills a chatty child with SIGPIPE and misreports it as
  a crash, which is a bug this project already shipped once.

## Development

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test
cargo audit
```

CI runs all of the above on Linux, Windows, and macOS, plus the unsafe-boundary check
and mutation coverage of whatever the commit changed.

That last one exists because a passing test is not evidence on its own. Two tests in
this repository passed with the fix they guarded deleted — one flooded stderr through a
`dd | tr` pipeline, so the subprocess took the signal and the shell survived to exit
normally either way; the other asserted a condition that held whether or not the guard
was there. Both were caught by hand, by removing the fix and re-running.
`cargo mutants` does that mechanically: it deletes a branch, flips a comparison or
stubs a function, and reports anything the suite still accepts.

It is scoped to the diff. A full run is 953 mutants, roughly three and a half hours,
and it would fail immediately — `src/config.rs` alone has nine misses, among them
`restrict_to_owner -> Ok(())`, which is the entire data-directory permission tightening
deleted with nothing to notice. Those are worth closing, but blocking every push on a
backlog that predates the check teaches people to ignore a red job. Requiring it of
changed lines stops the backlog growing.

## History

**On the name:** the command, package, and on-disk state are all `simon`. The git
repository is still called `multichat`, after the Python project that used to live here.

The repository previously held a Python/FastAPI implementation, replaced by this Rust
one in commit `9a51fc6`. That version is recoverable at commit `06c6c76`.

Two audits are current, and they split the tree rather than supersede each other.
`docs/AUDIT-2026-07-30.md` covers `9540ace` — the delegation, skills, and vault-wiring
changes — and is the one the source cites: `src/swarm.rs` points at its §3.2,
`src/orchestrator.rs` at its §3.5. `docs/AUDIT-2026-07-31.md` covers `6da2772`, a tree
whose `src/` differs from `9540ace` only in comment text, and deliberately reads what
the first one skimmed or never reached: `picker.rs`, `ui/`, `app.rs`, `config.rs`,
`main.rs`, and the provider transports.

Both describe a July tree. The code has moved since and later fixes live in the git
history, not in these documents, so read their findings as claims to re-check rather
than as current status. §3.2 and §3.3 of the 07-30 audit — the unbounded system prompt
and the silently truncatable tail — are closed, and the sections above describe what
replaced them. Others are still open, among them the non-atomic `Settings::save`
(07-31 §3.4).

The two earlier audits (of the initial Rust commit and of `2cca5da`) described trees
that no longer exist and were removed as superseded; both are recoverable at commit
`2e7984e`.

## License

MIT OR Apache-2.0.

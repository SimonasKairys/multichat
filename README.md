# simon

A terminal chat client for local and cloud LLMs, with multiple models able to delegate
work to each other in one session.

## Status

Working and tested, but early. `cargo test` covers more than 680 cases; `cargo clippy -D warnings`
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
simon auth grok              # store an xAI key (`grok` is an alias for `xai`)
simon chat                   # choose connections and a commander, then chat
simon chat -m ollama:llama3  # pick a commander explicitly
simon chat --classified      # local models only, no network egress
simon chat --vault           # persist the transcript, encrypted, across sessions
simon chat --project ~/code/myapp  # confine models to this folder instead of cwd
simon vault status           # vault path, failed attempts, idle window
simon vault destroy          # permanently delete the vault (typed "yes" to confirm)
simon vault prune --keep 500 # discard all but the newest 500 transcript lines
simon audit                  # verify the audit log's hash chain
simon audit --reset-anchor   # re-baseline tamper-evidence after deleting the log
```

`-m` accepts a full label (`ollama:llama3`), a bare model name (`llama3`), or a provider
name (`anthropic`).

`--project <dir>` sets the **project folder** — the one part of the filesystem models
can list, read, and write through `simon`'s own protocol (see
[Project files](#project-files)). It defaults to the directory `simon` was started in,
and is resolved and canonicalized once at startup.

`simon auth` also accepts `claude`, `gemini`, and `grok` as aliases, storing the key
under `anthropic`/`google`/`xai` respectively so vendor discovery finds it.

The connection picker can also prompt for a key directly: press **space** on an API
row marked `(no key stored)` to open a masked entry field instead of quitting to run
`simon auth`. Either way, the key lands in the OS keyring only — never in
`config.json`.

In the picker, status dots show **● connected/verified**, **◐ connected but
authentication unverified**, **○ not connected**, and **× connected but
unavailable** (with the reason shown on that row). The same legend is used by
`simon models`, `/commander`, and the startup chat transcript. Cloud API keys are
checked with a short, no-token authentication request; **●** means the provider's
inference authentication accepted the key, not that credits or the selected model
were exercised. Ollama is verified through its live model list. A CLI executable
remains **◐** until its first real request because an automatic test prompt could
cost money or let an agentic CLI run tools.
**Space** toggles a connection, **c** marks the highlighted row, **m** opens a model
picker, **tab** cycles a candidate's transport, and **enter** connects — but only
once a commander has been chosen; until then it just flashes a reminder to press
**c**. The model picker works for every cloud API and for CLI providers with a model
flag (all auto-detected CLIs); Ollama already exposes each installed model as its own
row, so **m** does not apply there. For a vendor or CLI `simon` knows, **m** shows a
scrollable list — **↑/↓** move the highlight and **enter** confirms it, no typing
required. `agy` choices come directly from the installed CLI's `agy models` command,
so the picker shows its current human-readable names while saving the underlying
model IDs. Typing narrows the list to matching names or IDs, and — for OpenRouter's
long tail, or any id not in a discovered/curated list — unmatched text is used
verbatim (for example `anthropic/claude-sonnet-4`). Submitting an empty field without
selecting anything restores the provider default. `simon chat -m <label>` skips the
picker and picks the commander non-interactively instead.

`chat` is the default subcommand, and its flags work without naming it: `simon --vault`
and `simon chat --vault` are the same thing.

In the TUI: type and press **Enter** to send, **PageUp/PageDown** to scroll, **Esc** or
**Ctrl-C** to quit. The prompt line edits like a normal one — **left/right** move the
caret, **Home/End** jump to either edge, **Backspace/Delete** cut on either side of it,
and modified chords are not typed as text (a stray **Ctrl-A** used to insert a bare
`a`). Drag normally to select transcript text and use your terminal's copy shortcut;
paste with its paste shortcut (commonly **Ctrl-Shift-V** or **Shift-Insert**). Pasted
line breaks and tabs become spaces because the prompt, model, and API-key editors are
single-line fields. `/forget` clears the ledger's accumulated content when a long
session has piled up more than the commander needs. Type `/commander` on its own to
list every discovered model, including connected-but-unavailable choices and their
reason. `/commander
<name>` (a full label, a bare model name, or a provider name) switches to any connected
choice live, without leaving the conversation — the choice persists across restarts,
same as the picker's. Neither form is ever sent to a model as a prompt.

`--vault` persists the TUI transcript — what you and the models said — to an encrypted
file so it survives between runs of `simon chat --vault`. It is **not** conversation
memory: no model ever receives the transcript or any prior turn as context, vault or
not (see [Delegation](#delegation) — every prompt still goes out on its own). The vault
only gives the *user* their own history back on screen. It is off by default and changes
nothing about `simon chat` without the flag. See
[Security posture](#security-posture) for what it protects against, its lock-out
policy, and what a crash costs you.

### Providers

| Provider | Transport | Discovery |
|---|---|---|
| `ollama` | local HTTP daemon | `GET /api/tags` at startup |
| `anthropic` | `POST /v1/messages` | key checked with `GET /v1/models` |
| `openai`, `google`, `groq`, `xai` | `POST /chat/completions` | key checked with `GET /models` |
| `openrouter` | `POST /chat/completions` | inference auth checked with an empty, non-generating request to the same endpoint |
| local CLI tools | subprocess (argv, no shell) | executable auto-detected; authentication remains unverified until first use |

`xai` uses `https://api.x.ai/v1` (not `grok.com`, which is the consumer web app).
`grok` is accepted as an alias for `xai`: `simon auth grok` and `simon auth xai` are
equivalent and both store the key under the canonical id `xai`.

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
    "copilot-enterprise": { "path": "/opt/copilot/bin/copilot", "args": ["--silent", "--prompt"], "model_arg": "--model", "stream_format": "copilot" },
    "claude": { "path": "/opt/claude/bin/claude", "model_arg": "--model", "stream_format": "claude" }
  },
  "session_token_limit": 200000,
  "daily_token_limit": 500000,
  "monthly_token_limit": 2000000,
  "provider_token_limits": { "anthropic": 1000000 }
}
```

There are four spending ceilings, all optional and all off by default. Each is checked
before every commander call and every delegation; past any of them `simon` refuses the
call and names both the window and the work it stopped, and from 80% of a ceiling the
session says once that it is close and keeps working. Omit a field — which is what
every config file written before these existed does — or set it to `0` for no ceiling.

| Field | Window | Resets |
|---|---|---|
| `session_token_limit` | one run of the program | on exit; never persisted |
| `daily_token_limit` | one UTC day | at midnight UTC |
| `monthly_token_limit` | one UTC calendar month | at the turn of the month |
| `provider_token_limits` | one vendor, per UTC month | at the turn of the month |

The narrowest spent window is the one named, because the answer differs: a spent
session is fixed by restarting, a spent day by waiting, a spent provider by delegating
elsewhere. `provider_token_limits` is keyed by provider name rather than model label,
so one entry covers every model reached through that vendor — which is how the metering
it stands in for actually works, and it is what stops a metered vendor and a free local
daemon sharing one budget.

The monthly total lives in `usage_history.json` (the same number the status line shows);
the daily and per-provider totals live in `usage_windows.json`. Both are under the data
directory — see `src/usage_ledger.rs`.

It bounds **tokens, not money**: tokens are what providers actually report, and
per-model pricing is not something this project can track, for the same reason the
roster states relative cost in words rather than numbers. It cannot see spending from
outside this application, and a provider that reports no usage metadata contributes
nothing to the total (the status line already labels those `tokens unavailable`) — so
it is a brake on a runaway delegation loop, not a billing guarantee. A ledger that
cannot be read allows the call and records `usage.cap_unreadable` in the audit log: a
disk fault is not evidence that the budget is gone, and one unreadable file should not
end the session.

## What models can do

Beyond answering, a model can act by emitting a line in its reply. The actions are
parsed out of plain text — there is no function-calling API involved:

| Action | Effect | Result arrives |
|---|---|---|
| `ACTION: delegate_task(<label>, <prompt>)` | Runs an isolated, text-only sub-task | next automatic commander turn |
| `ACTION: delegate_file_task(<label>, <prompt>)` | Creates a fresh project snapshot and runs a file-producing sub-task there | next automatic commander turn |
| `ACTION: delegate_in_copy(<task id>, <label>, <prompt>)` | Continues work in that task's existing snapshot | next automatic commander turn |
| `ACTION: read_skill(<name>)` | Loads a skill file into context | next automatic commander turn |
| `ACTION: list_files(<path>)` | Lists one directory in the main project | next automatic commander turn |
| `ACTION: read_file(<path>)` | Reads one main-project file | next automatic commander turn |
| `ACTION: write_file(<path>)` … `ACTION: end_file` | Writes main when emitted by the commander, or the active task copy when emitted by a file worker | immediately, after you approve |
| `ACTION: run_command(<task id>, <program>, <arg1>, ...)` | Runs one validated argv-only proof command in a live task copy | next automatic commander turn, after you approve |
| `ACTION: run_test(<task id>)` | Shorthand for `cargo test` in a live task copy | next automatic commander turn, after you approve |
| `ACTION: run_test(<task id>, <filter>)` | Shorthand for `cargo test -- <filter>` | next automatic commander turn, after you approve |
| `ACTION: apply_copy(<task id>)` | Preflights and applies changed/new files from a task copy, then releases it | next automatic commander turn |
| `ACTION: discard_copy(<task id>)` | Deletes a task copy without changing the main project | next automatic commander turn |

Three rules matter:

**Action results automatically return to the commander.** The ledger is still rendered
only into a later prompt — a model cannot read a file and act on unseen contents in the
same reply — but you no longer have to type `continue`. One user message may cause up
to five internal continuation calls after the initial commander call. The workflow
stops when the commander gives a reply with no actions, repeats the same normalized
actions against the same resulting state, reaches 48 total actions (including accepted
worker write blocks), or reaches the turn limit. Each continuation repeats the original
user request alongside the updated
ledger, so the task does not disappear with the stateless transport. The TUI remains
busy throughout and emits one final `TurnComplete`. A write or proof approval pauses
the loop until you answer.

**A sub-agent's reply is scanned for writes, and for nothing else.** It cannot delegate
further, load a skill, or read/list files — so no reply can spawn more work, which is
what bounds the swarm. Write blocks execute only for an explicit
`delegate_file_task`; a regular `delegate_task` is text-only and any unsolicited write
block is discarded. A permitted write spawns nothing, so sub-agents can still author
files when the commander deliberately delegates authoring. `delegate_in_copy` is also
write-capable because it continues an already isolated file task.

**Nothing is merged automatically.** A worker's writes stay in its task copy.
`apply_copy` is a later, explicit commander decision; `discard_copy` removes the copy.
Proof output is evidence for the commander to inspect, not an automatic declaration
that a finding or fix is valid.

### Delegation

**A delegation result leaves the machine too.** A local Ollama model can be asked to
summarise a private document, and its reply is recorded in the ledger and then sent to
whichever cloud provider is primary on the next commander turn. Delegating *to* a local model does
not keep the answer local. Same mitigation, same caveat as skills above: `--classified`
refuses every remote provider, and there is no narrower control.

The commander receives a shared ledger in its system prompt listing the other reachable
models, observed rate-limit budgets, and open tasks. A model delegates by emitting:

```
ACTION: delegate_task(ollama:mistral, summarise the attached diff)
```

For a task that must create or edit project files, the commander uses the explicit
write-capable form instead:

```
ACTION: delegate_file_task(ollama:mistral, create src/report.rs as specified)
```

That action first makes a bounded plain-filesystem snapshot of the project exactly as
it exists on disk, including dirty tracked files and untracked files. It does not run
Git, stash, clean, or require a clean worktree. The worker's approved write blocks land
inside that copy, never directly in the main project. To send a later instruction to
the same copy:

```
ACTION: delegate_in_copy(12, ollama:mistral, fix the implementation but keep the failing test)
```

The number is any task whose ledger entry names that live copy; continuation tasks
inherit the same copy. Fresh `delegate_file_task` calls always create separate copies,
so one worker cannot accidentally build on another worker's unaccepted changes.

The orchestrator records each reply — or, on failure, the error — on its task in the
ledger, tagged `[DONE]` or `[FAILED]`. The commander receives that result automatically
on the next bounded internal turn. Each sub-agent receives only its self-contained task,
its own connection label, the applicable instructions, and, for local CLI transports,
the isolated copy as its working directory — not the shared ledger, conversation, or
other models' prompts and results. This prevents sequential workers from copying one
another's answers or identities. Ordinary `delegate_task` calls are text-only; only
file-task forms receive the write protocol. At most 10 delegations run per commander
turn.

Plain `delegate_task` calls run **concurrently**, up to four at a time: they have no
isolated copy, no write protocol and no approval gate, so nothing about them has to
happen one at a time. Everything that touches a task copy — `delegate_file_task`,
`delegate_in_copy`, worker writes and proof commands — still runs strictly one after
another, because copy quotas are accounted serially and a write approval pauses the
loop until you answer. Launch order is the order the commander wrote the lines, so
ledger task ids and the transcript's dispatch lines do not depend on which model
answers first; only the order results arrive in does. While more than one call is in
flight the status line names the batch (`4 models`) rather than a single model, and
per-model streaming detail is not shown for its duration.

The width is capped at four because it is also the blind spot of
`monthly_token_limit`: a call already in flight has not recorded its tokens yet, so a
batch can pass the ceiling by at most the cost of one in-flight window. The ceiling is
re-read before every launch, so delegations queued behind that window do see what the
calls ahead of them spent.

Snapshots exclude `.git`, credential-shaped files such as `.env` and private keys,
symlinks, sockets/FIFOs/devices, `.simon-run`, and common dependency/build caches such
as `target`, `node_modules`, and `__pycache__`. Limits are 16 MiB per regular file,
256 MiB and 50,000 entries per copy, and 512 MiB across all live copies in the session.
A copy that cannot be made fails the delegation; it never falls back to writing the
main project. Current on-disk usage, including files created after the snapshot, counts
toward those limits. Protocol writes are rejected before they would cross a limit;
local CLI providers and proof commands are monitored while they run. A copy found over
quota is stopped and released. Otherwise copies are retained until explicitly
applied/discarded or until the session ends. A fresh copy is also released if its
provider fails before producing usable work.

**The commander orients and proposes before it delegates.** Given anything more than a
direct question it works in three steps: look at the project first (listing directories
and reading the few files that decide the answer, with its own read requests — not by
delegating discovery, since a sub-agent sees only the prompt it is given); then say what
it found, what it intends to do, any alternative worth weighing, and which tasks would go
to which model — and stop there for you to answer; and only then delegate. A plan is far
cheaper to correct than finished files are. Asked to add word counting to a small project,
this is the difference between delegating a guess and noticing that the project's notes
claim tabs while its only source file is indented with spaces.

The commander is held to the same rule as a sub-agent about *how* files and commands are
handled: it may read and inspect freely to orient itself, but it may not edit with its
own tools or run the project with its own shell. Direct write blocks still wait for your
approval. Multi-step file work should use an isolated file task, and project commands
must use the proof runner described below. Without those rules an agentic CLI was
observed editing a project file invisibly — no prompt, no `file.written` entry — and
leaving a `__pycache__` behind after executing code on its own.

Because every prompt is sent with no message history, the commander's own previous turn
is carried in the ledger. That preserves a user-approved plan across user turns and
also lets each automatic continuation see what the commander just requested.

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
edit a file, it is told to emit the content as plain text using `simon`'s write protocol
instead of its own writer. In a file task those writes target the isolated copy.
`simon` cannot grant the missing permission itself — the only switch on offer is
`agy`'s blanket `--dangerously-skip-permissions`, which is deliberately not used: it
would auto-approve every tool call agy makes, and agy's own
writes were separately observed bypassing `simon`'s write-approval gate and audit log
entirely — four files appeared during delegations `simon` had recorded as *failed*.
Routing every write back through `simon`'s protocol closes that normal path, since the
write is then plain text in the reply, not a tool call agy made on its own. This is
instruction/tool-policy enforcement, not a kernel sandbox; a disobedient CLI process
can still escape its working directory as described below.

A delegation that fails transiently is retried up to 3 times with a 3s then 8s backoff,
each retry announced in the transcript with its reason. Agentic CLI sub-agents fail
intermittently in several unrelated ways, and a failed delegation is expensive in a way
a failed HTTP call is not, since the commander does not learn of it until its next
automatic turn.
A timeout, a missing binary, and a `--classified` refusal are *not* retried: those fail
identically forever.

None of this has to be inferred from timing. The status line names whichever model is
actually being called — the sub-agent, not the commander — with what it is doing and how
long it has taken, including the latest progress detail from a streaming CLI (see
[CLI provider streaming and timeouts](#cli-provider-streaming-and-timeouts)). It also
keeps per-model and whole-session token totals, shows the last call's input/output split,
and includes token/request quota plus reset information when the provider reports it.
Providers that expose no usage metadata are labelled `tokens unavailable` rather than
shown an estimate. A running total of tokens spent this UTC calendar month is also
shown once any usage has been reported; it is persisted to `usage_history.json` in the
application data directory (see `usage_ledger.rs`) so it survives restarts and rolls
over to zero automatically at the start of the next month, rather than resetting on
every launch the way the per-session total does. The transcript gets a line when a
delegation is dispatched and another when it finishes, with outcome and duration.

### Proof commands and copy disposition

The commander can request a proof only in a live task copy:

```
ACTION: run_command(12, cargo, test, parser_regression, --, --nocapture)
ACTION: run_test(12)
ACTION: run_test(12, parser_regression)
```

`run_command` is an argv vector, not a shell string. Shell operators, substitutions,
absolute paths, parent traversal, path-prefixed executables, oversized arguments, and
unapproved programs/subcommands are rejected before anything is spawned. The allowlist
covers constrained test/check/build/lint forms of Cargo, Go, pytest/Python unittest,
Node's test runner, npm/pnpm/yarn scripts, make/just targets, Deno, and Bun. Executables
are resolved from absolute `PATH` directories outside both the main project and task
copy; the child receives a cleared environment plus a small non-secret
locale/toolchain set and task-local `HOME`, temporary, Cargo-home, and Cargo-target
directories under `.simon-run`.

Every proof run asks explicitly with **y/n**. There is no "approve all" choice for
commands, and `--auto-write` does not bypass this gate. `--classified` refuses all proof
commands before asking. A run has a 120-second wall-clock timeout; on Unix its process
group is terminated at completion or timeout. The tail of stdout and stderr is retained
with a 16 KiB cap per stream and recorded in the ledger. Exit zero, nonzero, timeout,
resource-limit termination, denial, validation rejection, and spawn failure remain
distinct outcomes. A nonzero exit or timeout is evidence, not an automatically verified
defect. Command artifacts count toward the task-copy quota; crossing it terminates the
command and releases that copy.

**Proof output leaves the machine when the commander is remote.** The captured tail is
inserted into the commander's next system prompt, so a test that prints source,
credentials, customer data, or environment-derived secrets can disclose them to that
provider. The snapshot excludes common credential files and the runner clears the
environment, but neither can guarantee that trusted project code will not print
sensitive data.

The intended defect workflow is:

1. `delegate_file_task` asks an unfamiliar worker for a deterministic failing test or
   exact proof, without a fix.
2. `run_command` reruns that proof in the worker's copy.
3. The commander inspects whether RED failed for the claimed reason, not because the
   test or setup was malformed.
4. `delegate_in_copy` asks for the fix in the same copy.
5. The commander reruns the same proof for GREEN and any relevant regression commands.
6. On a later commander turn, `apply_copy` accepts the copy or `discard_copy` removes it.

An `apply_copy` or `discard_copy` in the same reply as a proof run is refused so the
commander must first receive and inspect that run's output. Application compares the
copy with its baseline and the current main project. It accepts at most 500 changed/new
UTF-8 files, each still subject to the 256 KiB protocol write limit; it refuses
main-project drift, deletions, parent-path shape conflicts, symlinks/special files,
non-UTF-8 changes, and over-quota copies, and never performs an automatic merge. All
file approvals are collected before the first main project write, then the plan is
recomputed to catch changes made while approval was pending. The copy is released only
after every write succeeds. An operating-system I/O failure during a multi-file apply
can still leave earlier files written; the batch stops at the first failure and retains
the copy rather than reporting success. A later `apply_copy` treats main-project files
already identical to that copy as completed and retries only the remaining writes.

This runner is constrained, **not sandboxed**. Setting `current_dir` and clearing the
environment does not stop trusted project code from reading absolute paths, opening
network connections, or spawning programs indirectly. Approve commands only for a
project and machine you trust; it is not safe for hostile test code.

### Skills

**A loaded skill leaves the machine.** Once a model emits `ACTION: read_skill(...)`, that
file's contents sit in the ledger and go into the system prompt of *every* subsequent
call for the rest of the session — including calls to Anthropic, OpenAI, OpenRouter or
Groq if any of them is connected. Nothing about typing a skill name looks like sending a
file to a cloud provider, so it is said here plainly: it is. This is what "shared
blackboard" means and it is what makes the feature work, but it is a real change in where
your data goes. `--classified` is the complete mitigation — it refuses every provider
whose traffic leaves the machine, so nothing egresses — and it is currently the only one.

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
file could inject its own content into the commander's system prompt for the rest of
the session, including when the commander is remote, so it is deliberately a separate
tree from the project folder.

### Project files

Commander `list_files` and `read_file` actions target the **main project folder** — the
directory `simon` was started in, or whatever `--project <dir>` points at. A commander's
direct `write_file` block also targets main for backward compatibility; a worker's
write block targets only the live copy created by `delegate_file_task` or reused by
`delegate_in_copy`. Multi-step changes should use the copy workflow.

Every protocol access goes through the same path-traversal hardening as the skills
directory: `..`, absolute paths, symlinks escaping the root, and multi-linked regular
files are rejected. An in-root hard link can share an inode with a path outside the
root, so accepting one would defeat confinement.

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

Limits: a single protocol read or write is capped at 256KB, a single listing at 500
entries (truncation is reported, not silent), a commander reply accepts at most 10
direct writes and 3 reads, and each worker result accepts at most 10 writes before the
48-action workflow cap applies. At most 3 loaded reads are kept, evicting the oldest.
There is no cap on how many files may exist under the main root. Writes into `.git/` are refused
outright — a bad write there can corrupt the repository in ways you cannot easily undo.
Reading `.git/` is not special-cased, since only a write can corrupt it.

Everything is audited (`project.list`, `project.read`, `file.written`, and their
`_failed` counterparts) and shown in the TUI as it happens. **The audit log records
paths and counts only — never file content.** Successful reads enter the bounded ledger
because that is how their content reaches the model; failed reads and listings enter it
as bounded failure text, so they remain visible to the commander on its next automatic
turn.

#### Writes are not applied silently

Every `write_file` a model proposes is shown first — author, path, exact byte size,
whether it creates or overwrites (and how many bytes that would destroy), and the head
of the content — and the workflow blocks until you answer:

```
OVERWRITE src/report.py (353 bytes -> 415 bytes)? [y]es  [n]o  [a]ll
```

Nothing reaches either main or a task copy **through this protocol** before you answer.
A refusal is recorded in the ledger, so the commander learns on its next automatic turn
that the file was not written rather than building on one that does not exist, and is
audited as `file.write_denied`.

A delegated write approval changes only the task copy. `apply_copy` later preflights
the diff and asks again for the writes that would change main. For a multi-file apply,
all approvals are collected before the first main-project write, so denying a later file
does not leave the earlier approved files partially applied.

Read that scope literally. The gate governs `write_file` blocks, which is every write by
a cloud or Ollama model — those have no other way to touch a disk. It does **not** govern
a spawned CLI provider's own file tools. File-task CLIs now start in an isolated copy,
which protects main from ordinary relative writes, and their instructions explicitly
forbid using those tools. It is still possible for a disobedient CLI to escape the copy
and write anywhere the invoking user can. See
[This is not a sandbox for spawned CLI providers](#this-is-not-a-sandbox-for-spawned-cli-providers).

If the UI goes away while a question is pending, the write is refused, not applied —
with nobody left to ask, nobody has consented. A write that `Workspace` would reject
anyway (a `.git/` path, an oversized file, a traversal attempt) is refused *without*
asking, so a prompt never appears for a write your answer could not affect. `a` applies
for the rest of the session and is never persisted.

`--auto-write` skips file-write approvals, including writes into a copy and later
application to main. It never approves a proof command; every command still needs a
fresh **y/n** answer.

#### This is not a sandbox for spawned CLI providers

A `copilot`/`claude`/`gemini`/`codex` CLI configured as a local binary provider is
started with its working directory set to the main project for commander/text work, or
to the specific isolated copy for a file task. Where the CLI supports it, its
`--add-dir` argument is rerooted to the same location. That prevents ordinary relative
reads and writes from accidentally crossing task boundaries — but it only sets a
starting point.

A CLI agent with its own shell or filesystem access can `cd` anywhere the invoking user
can reach and read or write outside the project/copy freely. None of that activity
passes through `simon`'s audit log or write gate. The same boundary applies to approved
proof commands: the runner constrains the model-controlled argv and environment, but
the project code executed by a test runner has the invoking user's OS permissions.

### CLI provider streaming and timeouts

`copilot`, `claude`, and `agy` (Antigravity) are auto-detected with progress streaming already on.
Each is invoked with its NDJSON stream flag, and every tool call or step the CLI reports
while it works is parsed and shown live in the status line:

```
claude · awaiting reply · Bash: Read the readme · 42s · ●···
```

All three are also passed `--add-dir <active project or task-copy root>`. Copilot runs with only its
`view`, `grep`, and `glob` tools available and with its built-in GitHub MCP disabled,
so its non-interactive auto-approval cannot execute commands, edit files, or make
GitHub API calls. `agy` additionally gets
`--sandbox` (its own terminal restrictions, which let it use tools without a permission
prompt it cannot answer non-interactively) and `--print-timeout 30m` (its own default is
5m, short enough to cut off a real task before any of the limits below apply). Flag
order is not cosmetic for `agy`: its `-p` takes the next argument as the prompt, so
every other flag must precede it.

A hand-configured entry under `local_binaries` stays on the buffered-output path unless
it opts in with `"stream_format": "claude"`, `"stream_format": "agy"`, or
`"stream_format": "copilot"` — whichever
NDJSON shape the binary actually speaks. Any other value is a startup error, not a
silent fallback to buffering.

Progress details are third-party process output: control characters and newlines are
stripped and the length capped before they reach the TUI, and they are never written to
the audit log, which stays limited to sizes, paths, and outcomes.

Each logical NDJSON line is bounded before parsing as well. The line allowance is larger
than the retained 1 MiB reply cap so a valid result with JSON escaping can still be
decoded and then truncated normally; an even larger line fails explicitly rather than
allocating without limit. A structured stream error is returned immediately, so a later
idle or process-exit timeout cannot replace the real reason.

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
  <!-- proof: main::tests::no_command_line_argument_anywhere_accepts_a_secret_value -->
  <!-- proof: config::tests::setting_an_empty_credential_is_rejected_before_any_keyring_call -->
- **Tamper-evident audit log** — a chain of JSON entries, each carrying a keyed
  `Blake2s256` MAC over the previous entry. The key lives in the OS keyring, so writing
  the log file is not enough to forge it. Recovers the chain head across restarts.
  `simon audit` verifies the whole file.
  <!-- proof: audit::tests::chain_survives_a_restart -->
  <!-- proof: audit::tests::a_different_key_cannot_verify_the_chain -->
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
  <!-- proof: audit::tests::verify_detects_truncation_of_several_trailing_entries -->
  <!-- proof: audit::tests::verify_detects_a_tampered_anchor -->
  <!-- proof: audit::tests::reset_anchor_after_truncation_records_the_reset_and_verifies_clean -->
- **Appends are serialised, so two `simon` processes cannot break the chain.** Each
  logger used to cache the chain head in memory and append without coordination, so a
  second process linked its entry to a `prev` that was no longer the file's tail — and
  `simon audit` then reported the result as a broken chain, indistinguishable from
  tampering. Appending now takes an exclusive advisory lock on the log and re-reads the
  tail underneath it, because the race is between reading the head and writing the entry
  that links to it, not in the write alone. The lock lives on the file descriptor, so the
  kernel releases it if a process dies holding it; a lock *file* whose existence meant
  "locked" would strand the log after a crash.
  <!-- proof: audit::tests::two_real_processes_interleaved_appends_produce_a_valid_chain -->
  <!-- proof: audit::tests::append_lock_contention_times_out_visibly_instead_of_hanging_or_dropping_the_entry -->
- **The saved transcript is bounded.** It used to grow forever: every clean exit
  re-derived a key and re-encrypted the entire history, every unlock decrypted all of it,
  and the whole plaintext sat in memory that `mlockall` pins and so cannot be paged out.
  It is now capped at 2,000 lines, oldest dropped first, with a marker line left in their
  place so a shortened history is visible rather than silent. `simon vault prune --keep N`
  does it deliberately.
  <!-- proof: vault::tests::a_transcript_over_the_cap_is_trimmed_oldest_first_and_reloads_cleanly -->
  <!-- proof: vault::tests::repeated_trims_accumulate_one_running_marker_instead_of_stacking_new_ones -->
- **Failures are logged by kind, never by text.** The log's invariant is sizes, counts,
  and paths only — but every error path used to format the error's own message into it,
  and an error can carry a fragment of a provider's response or a path a model chose. A
  failure now records `kind=timeout`, `kind=permission_denied`, `kind=http_status` and
  the like, with `detail=withheld` in place of the text. The kind is read from the
  error's typed cause rather than by scanning its words, so the two failures that
  dominate in practice — a model CLI that never answered, a provider returning non-2xx —
  are named rather than lumped into "unspecified".
  <!-- proof: orchestrator::tests::the_audit_detail_names_the_failure_kind_but_never_its_text -->
  <!-- proof: orchestrator::tests::io_error_kinds_survive_into_the_audit_detail -->
- **A damaged MAC key stops the program instead of replacing itself.** The key is the
  only thing that makes the log verifiable, so silently generating a new one invalidates
  every entry ever written — and anyone able to write a short value into the keyring
  could have triggered exactly that, making a forged history look like ordinary
  corruption. A keyring entry that is present but unusable is now a hard error naming
  the service and what to do about it. An absent entry is still a normal first run.
  <!-- proof: audit::tests::wrong_length_key_error_never_contains_the_decoded_bytes_either -->
  <!-- proof: audit::tests::an_absent_value_still_generates_a_new_key -->
  <!-- proof: audit::tests::decide_key_rejects_multibyte_utf8_in_keyring_without_panicking -->
- **Links are refused where a file's identity is the point.** The vault's
  self-destruct used `fs::write`, which follows a link: pointing `vault.enc` at another
  file made the wipe zero *that* file and unlink only the link. The atomic writer took
  its permission bits through a link the same way, so `vault.enc` and `config.json`
  could land at 644 instead of owner-only. And a symlink named after anything, pointing
  at `.git`, let `create_dir_all` build directories inside the real repository before
  the write was refused. All three now use `symlink_metadata` and refuse. Skills and
  project files also reject multi-linked regular files; vault destruction unlinks its
  own path but never zeroes an inode shared by another hard link.
  <!-- proof: vault::tests::destroy_refuses_to_zero_a_symlinks_target -->
  <!-- proof: vault::tests::write_atomically_refuses_a_symlinked_target_rather_than_borrow_its_permissions -->
  <!-- proof: workspace::tests::a_symlink_to_dot_git_is_refused_before_any_directory_is_created -->
  <!-- proof: skills::tests::a_hard_link_escaping_the_root_leaks_no_description_and_fails_to_read -->
- **`--classified`** — refuses any provider whose traffic leaves the machine, and
  requires process-wide memory locking to succeed rather than warning.
  <!-- proof: providers::ollama::tests::a_non_loopback_ollama_host_reports_remote_and_is_refused_under_classified -->
  <!-- proof: providers::local_binary::tests::cli_tools_count_as_remote_for_classified_mode -->
  <!-- proof: picker::tests::classified_blocks_tab_and_submit_on_a_remote_transport -->
- **Process-wide memory locking on Linux** — `mlockall` at startup (`main.rs`), pinning
  the whole process into RAM so nothing is swapped to disk. The other half of this
  claim, per-allocation `mlock`/`VirtualLock` of derived key material, is genuinely live
  too now: `simon chat --vault` runs `EncryptedVault::save`/`load`, both of which call
  `derive_key`, which allocates the Argon2id output through `LockedBuffer::new` (see
  `src/security.rs`) — not just exercised by `src/vault.rs`'s own tests.
  <!-- proof: security::tests::non_strict_memory_protection_never_fails_startup -->
  <!-- proof: security::tests::locked_buffer_exposes_contents -->
  <!-- proof: security::tests::dropping_a_locked_buffer_releases_the_lock_it_took -->
- **Encrypted transcript vault (`simon chat --vault`)** — the TUI transcript
  (`App::transcript`: what you and the models said, nothing else) encrypted with
  AES-256-GCM under an Argon2id-derived key, opt-in and off by default. The salt lives
  in the file header and is bound as authenticated data, so tampering with it breaks
  decryption. This is **user-visible history, not replayed model memory** — the full
  transcript is never sent back to a model. Every transport call has no message
  history; only the commander's bounded previous reply is carried through the ledger,
  while sub-agents receive isolated task prompts (see [Delegation](#delegation)).
  `simon vault status` reports the vault's path, failed-attempt count, and where it
  stands in its idle window without ever asking for a password (those two fields are
  plaintext header data — see
  [Known limits](#known-limits-of-what-is-implemented)). `simon vault destroy` deletes
  it after a typed `yes`.
  <!-- proof: vault::tests::tampering_with_authenticated_header_fails_decryption -->
  <!-- proof: vault::tests::round_trips_without_an_externally_supplied_salt -->
  <!-- proof: vault::tests::status_reports_header_fields_without_needing_the_password -->
- **Path-traversal protection** on the read-only skills directory: `..`, absolute paths,
  symlinks escaping the root, and multi-linked regular files are all rejected. This is
  reachable from model output via `ACTION: read_skill(<name>)` (see [Skills](#skills)),
  not just from trusted callers, so the rejection is load-bearing, not defensive dead
  code.
  <!-- proof: skills::tests::rejects_parent_directory_traversal -->
  <!-- proof: skills::tests::rejects_absolute_paths -->
  <!-- proof: skills::tests::a_symlink_escaping_the_root_leaks_no_description_and_still_fails_to_read -->
- **Model-initiated file access confined to its selected main-project or task-copy
  root** (see [Project files](#project-files)) — the same traversal hardening as
  skills (`..`, absolute paths, and symlinks escaping the root are all rejected),
  size-capped per read/write and entry-capped per listing, and every access is
  audited and rendered in the TUI so the user sees everything a model has listed,
  read, or written through the protocol. Delegated file writes are further confined
  to a per-task copy until explicitly applied. Writes into `.git/` are refused
  outright.
  <!-- proof: workspace::tests::a_write_lands_under_the_workspace_root -->
  <!-- proof: workspace::tests::a_traversal_attempt_surfaces_as_an_error_not_a_crash -->
  <!-- proof: workspace::tests::an_uppercase_git_directory_write_is_refused -->
  <!-- proof: workspace::tests::a_directory_one_entry_over_the_max_is_truncated -->
- **Bounded isolated copies for file-producing delegations.** Snapshots preserve dirty
  tracked and untracked on-disk files without touching Git, while excluding Git
  metadata, likely credentials, links/special files, command-run artifacts, and common
  build caches. Per-file, per-copy, entry-count, and total-live-copy limits prevent an
  unbounded snapshot or later copy growth. Fresh tasks never fall back to main, copies
  are not silently merged, main-project drift and deletions block application, over-
  quota copies are stopped and released, and session shutdown removes retained copies.
  <!-- proof: isolation::tests::snapshot_fidelity_preserves_regular_and_untracked_files -->
  <!-- proof: isolation::tests::limit_breach_cleans_the_partial_new_copy -->
  <!-- proof: isolation::tests::changed_files_conflict_when_main_has_drifted -->
  <!-- proof: isolation::tests::release_all_removes_the_unique_session_directory -->
- **Every model-proposed write requires explicit approval** (see [Writes are not
  applied silently](#writes-are-not-applied-silently)) — the path, the exact size,
  whether it overwrites and how many bytes that destroys, and the head of the content
  are shown, and the turn blocks until the user answers. Nothing reaches disk
  unapproved; a lost UI denies rather than allows, and a refusal is audited as
  `file.write_denied`. A copy must be explicitly applied before it changes main, and a
  multi-file apply collects all approvals before its first write. `--auto-write`
  bypasses file approvals only. Scope: this establishes that the *user* consented, not
  that the content is correct — nothing inspects what is being written. It covers
  `write_file` blocks and copy application, but **not** a spawned CLI provider's own
  file tools. The skills directory itself remains read-only to models — a model that
  could write a skill file could inject its own content into the commander's system
  prompt for the rest of the session, including when the commander is remote — so this
  is deliberately a separate tree.
  <!-- proof: orchestrator::tests::a_denied_write_never_reaches_disk_and_is_recorded_as_denied -->
  <!-- proof: orchestrator::tests::a_closed_decision_channel_denies_rather_than_writes -->
  <!-- proof: orchestrator::tests::denied_apply_keeps_the_copy_and_leaves_main_unchanged -->
  <!-- proof: ui::tests::chat_paste_cannot_answer_a_pending_write_confirmation -->
- **Commander proof execution is argv-only, copy-only, bounded, and separately
  approved.** There is no shell; program/subcommand and argument policies are checked
  before approval, the environment is cleared, runtime directories are task-local,
  output, duration, and copy growth are capped, and process groups are terminated.
  Commands cannot target main, a text-only task, or a released copy. `--auto-write`
  never approves them, and `--classified` refuses them before asking. This constrains
  Simon's launch surface; it does not sandbox the project code a permitted test runner
  executes.
  <!-- proof: command_runner::tests::permits_cargo_test_and_rejects_shells_and_dangerous_subcommands -->
  <!-- proof: command_runner::tests::rejects_shell_tokens_and_paths_that_escape_the_copy -->
  <!-- proof: command_runner::tests::safe_path_excludes_both_main_and_task_copy_directories -->
  <!-- proof: ui::tests::chat_paste_cannot_answer_a_pending_run_confirmation -->
- **Proxy support** — honours `HTTP_PROXY`/`HTTPS_PROXY` and, via reqwest's `socks`
  feature, `ALL_PROXY=socks5://…`. Disabled outright under `--classified`: a proxy
  routes even a loopback request off the machine, which is the one thing that flag
  promises cannot happen.
  <!-- proof: providers::tests::a_classified_http_client_still_builds -->
- **`unsafe` confined to one file** — `#![deny(unsafe_code)]` crate-wide with a single
  audited override in `src/security.rs`, enforced by a CI job that rejects the override
  anywhere else.
  <!-- unproven: no test; the `unsafe-boundary` job in .github/workflows/ci.yml enforces it, because the property is about which files may carry an attribute, not about behaviour a test can observe -->

### Not implemented

- **Filesystem/network sandboxing of spawned CLI providers and proof commands.**
  `simon`'s own protocol is root-confined, and file-task CLIs are rerooted into their
  isolated copies, but a local CLI provider (`claude`, `gemini`, `codex`, …) remains an
  ordinary subprocess with the invoking user's permissions. An approved test runner is
  likewise able to execute trusted project code that reads absolute paths, opens
  sockets, or spawns other programs. None of that indirect activity is mediated or
  audited by `simon`. See [Project files](#project-files) and
  [Proof commands and copy disposition](#proof-commands-and-copy-disposition).
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

- **5 consecutive wrong passwords lock the vault; they no longer destroy it.** They
  used to: the 5th failure zeroed and unlinked the file, permanently, with no recovery.
  That cost fell on the owner far more reliably than on an attacker — the person who
  reaches five wrong passwords is overwhelmingly the one who is about to remember the
  right one, while an attacker who can *write* the file was never bounded by the counter
  at all (it is plaintext and restorable from a copy — see below). The anti-brute-force
  half is unchanged: after the 5th failure `vault.enc` stops opening, and someone who
  can only type cannot bring it back. The file is moved to `vault.enc.locked` (`.locked.2`,
  `.3`, … if earlier lock-outs are still there, so one never overwrites another) and is
  still AES-256-GCM ciphertext under the same Argon2id key — exactly as confidential as
  it was a second earlier, since the wipe added little the encryption did not already
  give. If it is yours, move it back over `vault.enc` and unlock it. `simon vault status`
  shows the count so far.
  <!-- proof: vault::tests::vault_self_destructs_after_max_attempts -->
  <!-- proof: vault::tests::a_wrong_password_on_an_idle_expired_vault_still_counts_toward_the_wipe -->
  <!-- proof: vault::tests::the_fifth_wrong_password_locks_the_vault_aside_instead_of_destroying_it -->
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
  <!-- proof: vault::tests::an_idle_expired_vault_is_not_destroyed_and_still_opens_with_the_right_password -->
  <!-- proof: vault::tests::unlocking_an_idle_expired_vault_resets_the_idle_window -->
  <!-- proof: vault::tests::status_reports_a_clock_behind_the_last_unlock_rather_than_a_full_window -->
- **Only a clean exit saves.** `simon chat --vault` serializes and encrypts the
  transcript once, after the TUI loop returns normally — not after every turn, because
  Argon2id key derivation is deliberately slow and running it per-message would stall
  the UI. A crash, panic, or `kill -9` skips that save, so anything typed since the last
  clean exit (or vault open, on the first run) is lost. This is a real trade-off, not an
  oversight: continuous session-to-session use is safe, but do not rely on `--vault` as
  a crash-safe log.
  <!-- unproven: no test; the save runs after the TUI loop returns, and nothing here exercises a crash mid-session -->
- The vault's failed-attempt counter and last-unlock timestamp live in the same file
  they protect and are deliberately excluded from the authenticated data (see
  `src/vault.rs`), so they are plaintext and unauthenticated — an attacker who can copy
  the file can reset both by restoring their copy. `simon vault status` reads them
  without a password for exactly this reason: they were never tamper-proof to begin
  with. This raises the cost of online guessing; it is not a substitute for a TPM or
  secure enclave.
  <!-- proof: vault::tests::a_forged_attempt_count_cannot_destroy_a_vault_the_password_still_opens -->
  <!-- proof: vault::tests::status_reports_header_fields_without_needing_the_password -->
- The audit log uses a MAC, not a signature. Anyone who can read the keyring key can
  forge entries, so it proves integrity against local tampering, not non-repudiation.
  That is the threat model the anchor above is built for too: it stops someone who can
  edit files, not someone who already holds the key.
  <!-- proof: audit::tests::a_different_key_cannot_verify_the_chain -->
  <!-- proof: audit::tests::verify_detects_a_tampered_anchor -->
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
  <!-- proof: swarm::tests::a_maximally_stuffed_ledger_renders_within_the_total_budget -->
  <!-- proof: swarm::tests::load_bearing_sections_survive_a_maximally_stuffed_prompt -->
  <!-- proof: swarm::tests::elision_from_the_whole_prompt_budget_is_announced_not_silent -->
- A local CLI tool is treated as remote for `--classified` purposes, because we cannot
  see whether it calls a cloud API internally.
  <!-- proof: providers::local_binary::tests::cli_tools_count_as_remote_for_classified_mode -->
- Output from a local CLI is bounded as it is read, not after. The cap used to apply to
  what was *kept*, while the whole of a child's output was buffered first — and since
  `mlockall` pins the process into RAM, that buffer could not even be paged out. Both
  streams are now read concurrently, each capped, with the remainder drained rather than
  dropped: closing the pipe early kills a chatty child with SIGPIPE and misreports it as
  a crash, which is a bug this project already shipped once.
  <!-- proof: providers::local_binary::tests::stderr_summary_caps_a_single_enormous_line -->
  <!-- proof: providers::local_binary::tests::stderr_summary_keeps_the_message_and_drops_the_stack_trace -->

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

It is scoped to the diff. A full run is about 953 mutants and roughly three and a half
hours, so it is not the per-push gate. The 2026-08-26 audit re-measured its accumulated
diff at 107 mutants: 97 caught, 9 unviable, and 1 equivalent survivor. Full-crate
coverage remains a backlog; requiring changed lines stops that backlog growing.

The backlog is now measured rather than described. `--in-diff` by construction never
looks at code nobody touched, so the untouched orchestrator, provider, and security
paths had no number at all, and the full-crate figure quoted above sat in
`docs/progress/23_mutation_debt.md` for months marked "not recently re-measured".
`.github/workflows/mutation-audit.yml` runs the whole crate weekly, uploads the
per-mutant lists, and files the score in a rolling issue. It does not gate: a
full-crate run would be red on day one against the pre-existing backlog, and a job
that is always red is a job people learn to ignore.

The security-posture table is checked the same way. Every load-bearing bullet in it
carries a `<!-- proof: module::tests::name -->` marker, and `posture_proofs_test`
fails if a named test stops existing — the moment a claim loses its witness is the
moment someone has to decide whether the claim or the code is now wrong. A claim
nothing exercises says `<!-- unproven: ... -->` instead, and those are budgeted.

## History

**On the name:** the command, package, and on-disk state are all `simon`. The git
repository is still called `multichat`, after the Python project that used to live here.

The repository previously held a Python/FastAPI implementation, replaced by this Rust
one in commit `9a51fc6`. That version is recoverable at commit `06c6c76`.

Three audits are retained. The latest, `docs/AUDIT-2026-08-26.md`, covers the complete
Rust tree and now includes the follow-up reliability and boundary fixes verified after
the original audit.
`docs/AUDIT-2026-07-30.md` covers `9540ace` — the delegation, skills, and vault-wiring
changes — and is the one the source cites: `src/swarm.rs` points at its §3.2,
`src/orchestrator.rs` at its §3.5. `docs/AUDIT-2026-07-31.md` covers `6da2772`, a tree
whose `src/` differs from `9540ace` only in comment text, and deliberately reads what
the first one skimmed or never reached: `picker.rs`, `ui/`, `app.rs`, `config.rs`,
`main.rs`, and the provider transports.

The July documents describe historical trees, so read their findings as claims to
re-check rather than current status. Their unbounded system prompt, silently
truncatable audit tail, and non-atomic `Settings::save` findings are closed; the
2026-08-26 audit and the sections above describe the current implementation.

The two earlier audits (of the initial Rust commit and of `2cca5da`) described trees
that no longer exist and were removed as superseded; both are recoverable at commit
`2e7984e`.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option. `Cargo.toml` has declared `MIT OR
Apache-2.0` since the first Rust commit, but the repository tracked neither file until
v0.1.0 — a declaration with nothing behind it, which is a licence nobody can rely on.

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in this crate by you, as defined in the Apache-2.0 licence, shall be dual
licensed as above, without any additional terms or conditions.

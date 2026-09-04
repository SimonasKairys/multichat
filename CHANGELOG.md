# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- A `Consultations` section in the ledger: when two or more *different* models have
  answered the same request, it names the group, reports each member's proof-run
  outcome, and asks for the answers to be read against each other rather than one after
  another. Left to the plain task list a model tends to relay the last answer it read.

  No new action was added, and none was needed — now that plain `delegate_task` calls
  run concurrently, one commander reply carrying the same prompt to several models
  already *is* a consultation. The missing piece was never orchestration, only the
  comparative presentation, so this is rendering rather than protocol surface: no new
  verb, no parser, no action budget, no guard tests for any of that.

  Proof outcomes are what the members are annotated with. Ranking answers by how they
  read is what a tool with no ground truth has to do; this one can run the tests, so
  the instruction says a proof that ran beats a majority that did not. The most recent
  run wins, because a red-then-green workflow runs a failing test before a passing one
  on the same task and where it ended up is the state that matters.

  The section points at the task entries rather than repeating their results — printing
  them twice would spend the prompt budget twice on the same text — and is dropped
  whole when the budget is tight, since it is an aid to reading results the commander
  already has rather than a load-bearing section. One model asked the same thing twice
  is a retry, not a consultation, and produces nothing.

- The roster now carries what delegating to each model has actually achieved on this
  machine, not only a hand-written guess at what it costs. `swarm::model_hint`'s own
  doc comment explains why it is coarse — real per-token pricing changes under this
  project and cannot be tracked — and that trade is right for cost. It is wrong for
  reliability, which is not a property of the vendor at all but of this machine, and
  which `simon` already observes on every single delegation. The commander is told to
  pick the cheapest model that can do a task; without this it has no way to learn that
  one particular local model times out on anything longer than a paragraph.

  `delegation_history.json` keeps counts, an exponential moving average of the success
  rate, and an average duration, keyed by model and by the *form* of the delegation.
  The form, not a classification of the prompt's prose: it is a fact the orchestrator
  already holds and cannot be wrong about, whereas a prose classifier would add a way
  for the record to be confidently mistaken about what it observed — and the form is
  the distinction that matters, since a model can be good at summarising and hopeless
  at producing a file. Local, never sent anywhere, nothing `--classified` has to refuse.

  A model with fewer than three observations of a class annotates nothing, so a fresh
  install's roster is byte-identical to what it was before this existed, and a model
  that had one bad afternoon does not get routed around. Observations refresh after
  every delegation rather than only at startup, so a model that has just failed twice is
  reflected in the very next turn's prompt — which is the turn where it matters.

  `cargo mutants` on the new file: 37 of 37 caught. One survivor was found and killed
  first — `load`'s `NotFound` guard could widen to `true`, which would make every read
  failure look like "no history yet", hand back an empty record, and let the next write
  save that emptiness over the top, wiping every model's history without a word. The
  same mutant is already covered in `usage_ledger` and `config`; this file was missing
  the equivalent test.

- Three more spending ceilings alongside `monthly_token_limit`:
  `session_token_limit`, `daily_token_limit`, and `provider_token_limits` (keyed by
  provider name, so one entry covers every model reached through that vendor). A month
  is the billing period, but a day is the blast radius — an agent loop that goes wrong
  burns a month's budget in an afternoon, and a monthly ceiling only notices once it is
  gone. The narrowest spent window is the one named in the refusal, because the answer
  differs per window: a spent session is fixed by restarting, a spent day by waiting, a
  spent provider by delegating elsewhere.

  The daily and per-provider totals live in a new `usage_windows.json` rather than
  being added to `usage_history.json`. `MonthlyUsage` deserializes with no field-level
  defaults and `load` turns a parse failure into an error, so extending it would have
  made every existing ledger on every machine fail to parse. A file that has never
  existed has no such history, and every field in it carries `#[serde(default)]` so the
  next window added does not repeat the problem. The session total is not persisted at
  all: a session ends with the process, so a counter that outlived it would be
  measuring something else.

### Fixed

- The keyring-anchor test leaked one OS credential per failing run and could not
  detect the condition that made it fail. It names its credential after its own
  temporary directory, so every run creates a new entry, and the entry was deleted
  only on the passing path — while `cargo mutants` runs this suite once per mutant
  with failure as the expected outcome. Several hundred accumulated, the Windows
  credential store reached its per-user capacity, and from then on the anchor write
  failed and the test failed on every run for a reason unrelated to what it tests.
  Measured: with the store in that state, writing 220 bytes fails with "Not enough
  memory resources are available to process this command" while a five-byte write
  still succeeds — which is why `keyring_is_available`'s five-byte probe reported the
  keyring as usable and the test ran instead of skipping. Cleanup is now an RAII guard
  that runs on the panicking paths too, and the probe writes an anchor-sized value, so
  a store with no room skips the test the same way a machine with no keyring does.

- A second, larger leak of the same credentials, from
  `vault_save_after_chat_actually_persists_the_transcript_for_reload`. It drives the
  real `vault_save_after_chat`, which opens a real `AuditLogger` to record
  `vault.saved` — and that files a keyring anchor named after the test's temporary
  directory. Unlike the keyring-anchor test it had no cleanup at all, so it leaked one
  credential on *every* run, passing or failing. Measured before the fix: one new
  credential per full-suite run; after it, four consecutive suite runs add none. The
  cleanup guard now lives in `audit.rs` as `KeyringAnchorGuard` so both tests use one
  implementation, and so the next test that opens a real logger has something to reach
  for.

### Changed

- Plain `delegate_task` calls now run concurrently, four at a time, instead of one
  after another. A commander that hands four independent analyses to four models no
  longer costs the sum of four round trips. Everything touching a task copy —
  `delegate_file_task`, `delegate_in_copy`, worker writes, proof commands — stays
  strictly sequential: copy quotas are accounted serially and a write approval pauses
  the loop until the user answers. The boundary is one predicate,
  `may_run_concurrently`, which tests both `allow_writes` and `workspace_task` rather
  than whichever is sufficient today — `delegate_file_task` creates a fresh copy and so
  carries no `workspace_task`, and a predicate testing only for an existing copy would
  route exactly the snapshot-creating delegations into the concurrent set.

  Launch order stays the order the commander wrote its lines, so ledger task ids and
  dispatch lines are unchanged; only the order results arrive in varies. Every result
  is still folded into the ledger and the audit log by the single task that owns them,
  which keeps the audit chain single-writer. The delegation protocol in the system
  prompt now says which forms run together, and its guard test asserts the new wording
  rather than being deleted — that assertion is what keeps prompt and behaviour from
  drifting apart.

  Four rather than ten because the width of the fan-out is also the blind spot of
  `monthly_token_limit`: a call in flight has not recorded its tokens yet, so a batch
  can pass the ceiling by at most one window's cost. The ceiling is re-read before every
  launch, so anything queued behind that window still sees what ran ahead of it.

  While several calls are in flight the status line names the batch rather than a
  single model, because `App` keeps one activity and applies streaming progress only
  when its label matches; a batch of one is unchanged.

### Added

- `monthly_token_limit` in `config.json`: an optional ceiling on the tokens spent in a
  UTC calendar month, checked before every commander call and every delegation. Past
  it, the call is refused and named rather than made; from 80% of it the session says
  once that the ceiling is close. The monthly total has been on the status line since
  it was added, but nothing consulted it — a gauge with no brake, and the failure it
  could not prevent was an unattended auto-continuation loop discovered after the
  invoice. Absent (every config file written before now) or `0` means no ceiling, so
  an installation that sets nothing behaves exactly as it did.

  A refused delegation is recorded on its ledger task as failed, so the commander
  learns on its next automatic turn that the work did not run and why. A ledger that
  will not load allows the call and records `usage.cap_unreadable`: a disk fault is not
  evidence that the budget is spent, and this counter is not worth ending a session
  over — the same trade `record_month_usage` already makes for write failures.

## [0.1.1] — 2026-09-02

Test-suite fixes. No change to shipped behaviour.

### Fixed

- The three tests that failed on macOS on every run, all of them fixtures rather
  than product defects. Two executor tests spawned `/usr/bin/sleep`, which is where
  Linux keeps it and not where macOS does, and reported a bare `No such file or
  directory` that read like the executor failing to spawn; they now search the same
  directories the executor puts on the child's PATH and name what was missing. The
  provider-rerooting test handed over a raw temporary directory but asserted against
  a canonical path, which only agrees where the two are equal — not on macOS, where
  `/var/folders/...` is a symlink to `/private/var/folders/...`.
- Eight mutants in `usage_ledger.rs` that no test noticed: `load`'s NotFound guard
  could widen to swallow every read error, turning an unreadable or corrupt ledger
  into a silent reset to zero; `record` and `current_month_utc` could return
  constants; `record_month_usage` could return `0` forever, because the only test
  covering it asserted a total of zero; and `civil_from_days` could have most of its
  arithmetic perturbed. The calendar function is now round-tripped day by day against
  its documented inverse, over a range that crosses an era boundary in both
  directions. `cargo mutants` on the file: 96 of 96 caught, from 88.
- A flaky orchestrator test. The shared harness stopped collecting at `TurnComplete`,
  so an event still in flight behind it was missed under load; it now drains the
  channel to close.

## [0.1.0] — 2026-09-02

First tagged release. The code has been working and tested for a while; what was
missing was distribution — `Cargo.toml` declared `MIT OR Apache-2.0` while the
repository tracked no licence file, no tag, and no release, which meant the project
was build-from-source-only and, strictly, not licensed to anyone.

### Added

- `LICENSE-MIT` and `LICENSE-APACHE`, matching the dual licence `Cargo.toml` has
  declared since the first Rust commit.
- This changelog.
- `posture_proofs_test`: every load-bearing bullet in the README's security-posture
  table names the test that proves it, and the suite fails when a named test no longer
  exists. Claims with no test say so explicitly and are budgeted.
- `no_command_line_argument_anywhere_accepts_a_secret_value`: walks every `clap`
  subcommand and refuses any value-taking argument that reads like a secret, so the
  "keys never appear in `argv`" claim cannot be lost to a convenience flag added later.
- `.github/workflows/mutation-audit.yml`: a weekly, non-blocking full-crate
  `cargo mutants` run that files the score in a rolling issue. The per-push gate is
  still `--in-diff`.
- `the_two_readers_of_an_action_line_agree`: a generated-corpus differential test over
  the action grammar.

### Changed

- The action grammar is one scanner instead of two. `action_argument` and
  `split_top_level_fields_limited` each carried their own copy of the same quote,
  escape, and nesting rules; every divergence between the copies dropped a delegation
  silently, and a dropped `write_file` open line let its content execute as actions.
  Both now drive `ActionScan`, parameterised only by what may follow a closing quote.
- The field limit passed to the splitter no longer affects tokenization, only where a
  field is cut. It did before, and the difference was a live defect: with a limit of
  two, `worker, ,'('` stopped treating the second comma as a field start, so a quote
  after it never opened and the splitter refused a line the scanner had accepted.
- **The vault no longer destroys itself.** Five consecutive wrong passwords used to
  zero and unlink `vault.enc`, permanently. They now move it to `vault.enc.locked`
  (`.locked.2`, `.3`, … so one lock-out never overwrites another). The
  anti-brute-force property is unchanged — `vault.enc` stops opening, and someone who
  can only type cannot move it back — while the owner, who is overwhelmingly the person
  who actually reaches five failures, keeps their transcript. It remains AES-256-GCM
  ciphertext under the same Argon2id key throughout. `VaultError::Destroyed` is now
  `VaultError::LockedOut { reason, moved_to }`.

### Fixed

- A stale claim in `ci.yml` and `docs/progress/23_mutation_debt.md`: both cited
  `restrict_to_owner -> Ok(())` as a mutant caught by nothing, months after
  `config::tests::the_data_directory_is_tightened_to_owner_only` was written to catch
  it.

[0.1.1]: https://github.com/SimonasKairys/multichat/releases/tag/v0.1.1
[0.1.0]: https://github.com/SimonasKairys/multichat/releases/tag/v0.1.0

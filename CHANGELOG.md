# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

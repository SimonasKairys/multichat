//! The security-posture table in `README.md`, checked against the code.
//!
//! The table calls itself the source of truth, and it is maintained by hand next to
//! four audit documents and two dozen progress files. Prose drifts from code silently:
//! a claim stays written after the behaviour changes, and the only signal is that
//! someone eventually reads it and is wrong about what the program does. That has
//! already happened here in the small — `ci.yml` and `docs/progress/23` both described
//! `restrict_to_owner -> Ok(())` as caught by no test, months after
//! `config::tests::the_data_directory_is_tightened_to_owner_only` was written to catch
//! exactly that.
//!
//! So every load-bearing bullet in "Implemented" and "Known limits of what is
//! implemented" must name the test that proves it:
//!
//! ```text
//! <!-- proof: vault::tests::vault_self_destructs_after_max_attempts -->
//! ```
//!
//! This test fails when a named test no longer exists — renamed, deleted, or moved to
//! another module — which is the moment the claim stops being backed by anything and
//! the moment someone has to decide whether the claim or the code is now wrong.
//!
//! A claim that nothing exercises says so instead, and those are budgeted rather than
//! unlimited:
//!
//! ```text
//! <!-- unproven: no test; reason -->
//! ```
//!
//! `UNPROVEN_BUDGET` is a ratchet. It may go down. Raising it is a decision to ship a
//! security claim with nothing behind it, and it should look like one in review.
//!
//! What this does **not** do is check that the named test proves what the bullet says —
//! nothing mechanical can. It checks that the witness exists, which is the half that
//! rots on its own.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Bullets in these sections must carry a marker. "Not implemented" is exempt: those
/// bullets claim an absence, and there is no test for code that was never written.
const PROVEN_SECTIONS: [&str; 2] = ["### Implemented", "### Known limits of what is implemented"];

/// The number of `unproven:` markers allowed. A ratchet: lower it when a claim gains a
/// test, and treat raising it as the decision it is.
const UNPROVEN_BUDGET: usize = 3;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Resolves `config::tests::some_test` to the file that must contain it. The `tests`
/// segments are module bookkeeping, not path components.
fn source_file_for(module_path: &[&str]) -> Option<PathBuf> {
    let segments: Vec<&str> = module_path
        .iter()
        .copied()
        .filter(|segment| *segment != "tests")
        .collect();
    let (_, modules) = segments.split_last()?;
    if modules.is_empty() {
        return None;
    }
    let base = repo_root().join("src");
    let direct = modules
        .iter()
        .fold(base.clone(), |acc, segment| acc.join(segment))
        .with_extension("rs");
    if direct.is_file() {
        return Some(direct);
    }
    let as_directory = modules
        .iter()
        .fold(base, |acc, segment| acc.join(segment))
        .join("mod.rs");
    as_directory.is_file().then_some(as_directory)
}

/// Whether `file` defines `name` as a test function.
///
/// Attribute-aware on purpose: `fn mac(...)` exists in `audit.rs` as a helper, and a
/// marker naming it would otherwise pass while proving nothing. Walks back over the
/// attributes and comments above the definition looking for `#[test]` or
/// `#[tokio::test]`.
fn defines_test(file: &Path, name: &str) -> bool {
    let source = fs::read_to_string(file).unwrap_or_default();
    let lines: Vec<&str> = source.lines().collect();
    let signature = format!("fn {name}(");

    lines
        .iter()
        .enumerate()
        .filter(|(_, line)| {
            // `async fn`, `pub fn`, `pub(crate) async fn` — the modifiers vary, the
            // definition is what matters.
            let trimmed = line.trim_start();
            match trimmed.find(&signature) {
                Some(0) => true,
                Some(offset) => trimmed[..offset]
                    .split_whitespace()
                    .all(|word| matches!(word, "pub" | "async" | "unsafe" | "const" | "extern")),
                None => false,
            }
        })
        .any(|(index, _)| {
            lines[..index]
                .iter()
                .rev()
                .take_while(|above| {
                    let above = above.trim();
                    above.starts_with('#') || above.starts_with("//") || above.is_empty()
                })
                .any(|above| {
                    let above = above.trim();
                    above == "#[test]" || above.starts_with("#[tokio::test")
                })
        })
}

struct Bullet {
    section: String,
    first_line: String,
    body: String,
}

fn posture_bullets(readme: &str) -> Vec<Bullet> {
    let mut bullets: Vec<Bullet> = Vec::new();
    let mut section = String::new();

    for line in readme.lines() {
        if line.starts_with("## ") || line.starts_with("### ") {
            section = line.trim().to_string();
            continue;
        }
        if !PROVEN_SECTIONS.contains(&section.as_str()) {
            continue;
        }
        if line.starts_with("- ") {
            bullets.push(Bullet {
                section: section.clone(),
                first_line: line.trim().to_string(),
                body: line.to_string(),
            });
        } else if let Some(current) = bullets.last_mut() {
            current.body.push('\n');
            current.body.push_str(line);
        }
    }

    bullets
}

fn markers<'a>(body: &'a str, kind: &str) -> Vec<&'a str> {
    let opening = format!("<!-- {kind}: ");
    let mut found = Vec::new();
    let mut rest = body;
    while let Some(start) = rest.find(&opening) {
        let after = &rest[start + opening.len()..];
        let Some(end) = after.find("-->") else {
            break;
        };
        found.push(after[..end].trim());
        rest = &after[end..];
    }
    found
}

/// A short, stable label for a bullet, for failure messages.
fn label(bullet: &Bullet) -> String {
    let text: String = bullet.first_line.chars().take(70).collect();
    format!("[{}] {text}", bullet.section)
}

#[test]
fn every_posture_claim_names_a_test_or_admits_it_has_none() {
    let readme = fs::read_to_string(repo_root().join("README.md")).expect("README.md is readable");
    let bullets = posture_bullets(&readme);

    assert!(
        bullets.len() >= 20,
        "only {} posture bullets were found; the section headings this test keys on \
         ({PROVEN_SECTIONS:?}) have probably been renamed, which would make it pass by \
         checking nothing",
        bullets.len()
    );

    let mut unproven = 0usize;
    let mut failures: Vec<String> = Vec::new();

    for bullet in &bullets {
        let proofs = markers(&bullet.body, "proof");
        let excuses = markers(&bullet.body, "unproven");

        if proofs.is_empty() && excuses.is_empty() {
            failures.push(format!(
                "{}\n    no marker. Add `<!-- proof: module::tests::name -->` naming the \
                 test that proves it, or `<!-- unproven: no test; why -->`.",
                label(bullet)
            ));
            continue;
        }

        unproven += excuses.len();

        for proof in proofs {
            let path: Vec<&str> = proof.split("::").collect();
            if path.len() < 2 {
                failures.push(format!(
                    "{}\n    `{proof}` is not a module path; expected `module::tests::name`.",
                    label(bullet)
                ));
                continue;
            }
            let name = path.last().expect("checked length");
            let Some(file) = source_file_for(&path) else {
                failures.push(format!(
                    "{}\n    `{proof}` names no source file under src/.",
                    label(bullet)
                ));
                continue;
            };
            if !defines_test(&file, name) {
                failures.push(format!(
                    "{}\n    `{proof}` names no `#[test]` in {}. The claim has lost its \
                     witness: either the test was renamed or removed, or the behaviour \
                     it proved is gone and the claim is now false.",
                    label(bullet),
                    file.display()
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "the security posture table has {} unbacked claim(s):\n\n{}\n",
        failures.len(),
        failures.join("\n\n")
    );

    assert!(
        unproven <= UNPROVEN_BUDGET,
        "{unproven} posture claims are marked `unproven`, over the budget of \
         {UNPROVEN_BUDGET}. Raising the budget means shipping another security claim \
         with nothing behind it; write the test instead."
    );
}

#[test]
fn the_proof_checker_rejects_a_marker_that_names_a_helper_rather_than_a_test() {
    // Fixture guard for the guard: `audit::mac` is a real function in a real file, so a
    // marker naming it would resolve — and prove nothing. If this ever starts passing,
    // the checker above has stopped distinguishing a test from any other function and
    // every marker in the README becomes decorative.
    let file = source_file_for(&["audit", "tests", "mac"]).expect("src/audit.rs exists");
    assert!(
        !defines_test(&file, "mac"),
        "`mac` is a helper, not a test; the checker must not accept it as a witness"
    );
    assert!(
        defines_test(&file, "chain_survives_a_restart"),
        "the checker must still recognise a real test"
    );
}

#[test]
fn unique_proof_markers_are_not_one_test_pasted_everywhere() {
    // A single popular test name copied onto twenty bullets would satisfy the checker
    // while proving one thing. Not a strong property — bullets may legitimately share a
    // witness — but a table where nearly every marker is the same string is not
    // evidence of anything.
    let readme = fs::read_to_string(repo_root().join("README.md")).expect("README.md is readable");
    let bullets = posture_bullets(&readme);
    let all: Vec<String> = bullets
        .iter()
        .flat_map(|bullet| {
            markers(&bullet.body, "proof")
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect();
    let unique: BTreeSet<&String> = all.iter().collect();

    assert!(
        unique.len() * 2 >= all.len(),
        "{} proof markers resolve to only {} distinct tests",
        all.len(),
        unique.len()
    );
}

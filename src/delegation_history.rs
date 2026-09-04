//! What delegating to each model has actually cost and achieved on this machine.
//!
//! `swarm::model_hint` annotates every roster entry with a hand-written phrase — "local
//! · free · no quota · smallest context", "most expensive · strongest reasoning". Its
//! own doc comment explains why it is coarse: real per-token pricing changes under this
//! project and is not something it can track, while the relative ordering is stable
//! enough to be worth stating. That trade is right for cost. It is not right for
//! *reliability*, which is not a property of the vendor at all — it is a property of
//! this machine, this binary, and this user's tasks, and it is observed on every single
//! delegation already.
//!
//! So this module keeps the half `model_hint` cannot: how often a given model finished
//! the kind of work it was handed, and how long it took. The commander is told to pick
//! the cheapest model that can do a task; without this it has no way to learn that one
//! particular local model times out on anything longer than a paragraph.
//!
//! Deliberately local, and deliberately not telemetry: one small JSON file beside the
//! usage ledger, never sent anywhere, and nothing `--classified` has to refuse.
//!
//! **On the task class.** It is derived from the *form* of the delegation —
//! `delegate_task`, `delegate_file_task`, `delegate_in_copy` — and not from classifying
//! the prompt's prose. That is a choice, not an expedient: the form is a fact the
//! orchestrator already holds and cannot be wrong about, whereas a prose classifier
//! would add a way for this record to be confidently mistaken about what it observed.
//! It is also the distinction that matters, since a model can be perfectly good at
//! summarising and hopeless at producing a file.

use crate::vault::write_atomically;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Weight given to each new observation in the success-rate moving average.
///
/// Matches the value `usage_ledger`'s neighbours would recognise from the same family
/// of estimators: high enough that a model which has started failing is reflected
/// within a handful of delegations, low enough that one transient network error does
/// not rewrite a long good record.
const EMA_ALPHA: f32 = 0.3;

/// Observations required before a model's record is shown to the commander.
///
/// One success and one failure is not evidence of anything, and a roster annotated from
/// noise is worse than an unannotated one — it invites the commander to route around a
/// model that had a bad afternoon. Three is the smallest number at which the moving
/// average has seen more than a single outcome twice over.
const MIN_OBSERVATIONS: u32 = 3;

/// Which form of delegation an observation came from.
///
/// Derived from the action the commander emitted, never from its prose — see the module
/// docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskClass {
    /// `delegate_task`: text in, text out, no filesystem.
    Text,
    /// `delegate_file_task`: a fresh isolated copy the worker may write into.
    File,
    /// `delegate_in_copy`: more work in a copy that already exists.
    InCopy,
}

impl TaskClass {
    /// The stable on-disk spelling. Written into the key, so it must not change
    /// casually: a rename silently resets every model's record for that class.
    pub fn as_str(self) -> &'static str {
        match self {
            TaskClass::Text => "text",
            TaskClass::File => "file",
            TaskClass::InCopy => "in_copy",
        }
    }

    /// How the class reads in a roster annotation the commander is shown.
    fn describe(self) -> &'static str {
        match self {
            TaskClass::Text => "text tasks",
            TaskClass::File => "file tasks",
            TaskClass::InCopy => "copy follow-ups",
        }
    }

    /// The classes in the order a roster annotation should list them, most consequential
    /// first: a model that cannot be trusted with a file task is a more important fact
    /// than its prose record.
    fn ordered() -> [TaskClass; 3] {
        [TaskClass::File, TaskClass::InCopy, TaskClass::Text]
    }
}

/// One model's record for one class of task.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
struct Record {
    #[serde(default)]
    attempts: u32,
    #[serde(default)]
    successes: u32,
    /// Exponential moving average of the success rate, 0.0 to 1.0. Kept alongside the
    /// raw counts rather than derived from them because the counts answer "how has this
    /// gone overall" and the average answers "how is it going lately"; a model that
    /// worked for months and broke yesterday looks fine by the first measure.
    #[serde(default)]
    ema_success: f32,
    #[serde(default)]
    total_millis: u64,
}

impl Record {
    fn median_ish_millis(&self) -> u64 {
        // The mean, not the median: keeping every duration to compute a true median
        // would make this file grow without bound, which is the thing the ledger's own
        // caps exist to prevent. The mean is the wrong statistic for a distribution with
        // one 300-second timeout in it, so it is reported as "average", not as "typical".
        if self.attempts == 0 {
            0
        } else {
            self.total_millis / u64::from(self.attempts)
        }
    }
}

/// On-disk shape of `delegation_history.json`, keyed `"<label>|<class>"`.
///
/// A flat map with a composite key rather than nested maps: it serializes to something
/// a person can read and diff, and it makes adding a class a matter of writing a new
/// key rather than migrating a structure.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
struct History {
    #[serde(default)]
    records: BTreeMap<String, Record>,
}

fn history_file(data_dir: &Path) -> PathBuf {
    data_dir.join("delegation_history.json")
}

fn key(label: &str, class: TaskClass) -> String {
    format!("{label}|{}", class.as_str())
}

fn load(data_dir: &Path) -> Result<History> {
    let path = history_file(data_dir);
    match fs::read_to_string(&path) {
        Ok(raw) => serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(History::default()),
        Err(e) => Err(e).with_context(|| format!("failed to read {}", path.display())),
    }
}

fn save(data_dir: &Path, history: &History) -> Result<()> {
    let encoded = serde_json::to_vec_pretty(history)?;
    write_atomically(&history_file(data_dir), &encoded)
}

/// Folds one finished delegation into `label`'s record for `class`.
///
/// The first observation seeds the moving average with its own outcome rather than
/// blending against zero, so a model whose first delegation succeeded does not start
/// life looking 30% reliable.
pub fn record(data_dir: &Path, label: &str, class: TaskClass, ok: bool, millis: u64) -> Result<()> {
    let mut history = load(data_dir)?;
    let entry = history.records.entry(key(label, class)).or_default();
    let outcome = if ok { 1.0 } else { 0.0 };
    entry.ema_success = if entry.attempts == 0 {
        outcome
    } else {
        EMA_ALPHA * outcome + (1.0 - EMA_ALPHA) * entry.ema_success
    };
    entry.attempts = entry.attempts.saturating_add(1);
    if ok {
        entry.successes = entry.successes.saturating_add(1);
    }
    entry.total_millis = entry.total_millis.saturating_add(millis);
    save(data_dir, &history)
}

/// A short phrase describing what has been observed of `label`, or `None` when nothing
/// has been observed often enough to be worth saying.
///
/// Kept short on purpose. This is appended to a roster line inside
/// `swarm::ROSTER_MAX_CHARS`, which drops whole entries when the section overflows — an
/// annotation verbose enough to push a model off the roster would cost the commander
/// far more than it told it.
pub fn annotation_at(history_json: &Path, label: &str) -> Option<String> {
    let history = load(history_json.parent()?).ok()?;
    let mut parts = Vec::new();
    for class in TaskClass::ordered() {
        let Some(record) = history.records.get(&key(label, class)) else {
            continue;
        };
        if record.attempts < MIN_OBSERVATIONS {
            continue;
        }
        parts.push(format!(
            "{}/{} {} ok, ~{}s",
            record.successes,
            record.attempts,
            class.describe(),
            record.median_ish_millis().div_ceil(1000)
        ));
    }
    (!parts.is_empty()).then(|| parts.join("; "))
}

/// `annotation_at` for a data directory, which is how every caller has it.
pub fn annotation(data_dir: &Path, label: &str) -> Option<String> {
    annotation_at(&history_file(data_dir), label)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_observation_seeds_the_average_rather_than_blending_against_zero() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        record(dir, "ollama:llama3", TaskClass::Text, true, 1_000).unwrap();
        let history = load(dir).unwrap();
        let entry = &history.records["ollama:llama3|text"];
        assert_eq!(entry.attempts, 1);
        assert_eq!(entry.successes, 1);
        // Blending against a zeroed default would put this at 0.3, which reads as an
        // unreliable model on the strength of one success.
        assert!((entry.ema_success - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn failures_pull_the_average_down_without_erasing_the_raw_counts() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        for _ in 0..5 {
            record(dir, "ollama:llama3", TaskClass::File, true, 1_000).unwrap();
        }
        record(dir, "ollama:llama3", TaskClass::File, false, 1_000).unwrap();
        let entry = load(dir).unwrap().records["ollama:llama3|file"].clone();
        assert_eq!(entry.attempts, 6);
        assert_eq!(entry.successes, 5);
        assert!(
            entry.ema_success < 1.0 && entry.ema_success > 0.5,
            "one failure should move the average without wiping a good record: {}",
            entry.ema_success
        );
    }

    #[test]
    fn a_non_notfound_read_error_is_not_swallowed_as_an_empty_history() {
        // Mutation-testing regression, and the same one `usage_ledger` and `config`
        // already carry a test for: widening `load`'s `NotFound` guard to `true` makes
        // every read failure look like "no history yet". A permissions problem or a
        // corrupt file would then hand back an empty record — and the next `record`
        // call would save that emptiness over the top, wiping every model's history
        // without a word. The genuine "file absent" case is covered by
        // `nothing_is_annotated_until_there_is_enough_to_say`; this covers the other
        // branch, which must propagate rather than reset.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        // A directory where the file is expected. Reading it as a file fails on every
        // platform, with an error whose kind is not `NotFound` — the path plainly
        // exists.
        fs::create_dir(history_file(dir)).unwrap();

        assert!(
            load(dir).is_err(),
            "an unreadable history is an error, not an empty one"
        );
        assert!(
            record(dir, "a:m", TaskClass::Text, true, 1).is_err(),
            "recording over an unreadable history would destroy it"
        );
    }

    #[test]
    fn records_are_kept_separately_per_model_and_per_class() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        record(dir, "a:m", TaskClass::Text, true, 100).unwrap();
        record(dir, "a:m", TaskClass::File, false, 100).unwrap();
        record(dir, "b:m", TaskClass::Text, false, 100).unwrap();
        let history = load(dir).unwrap();
        // A model good at prose and bad at files is exactly the distinction this exists
        // to record; collapsing the classes would average it into "mediocre".
        assert_eq!(history.records["a:m|text"].successes, 1);
        assert_eq!(history.records["a:m|file"].successes, 0);
        assert_eq!(history.records["b:m|text"].successes, 0);
        assert_eq!(history.records.len(), 3);
    }

    #[test]
    fn nothing_is_annotated_until_there_is_enough_to_say() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        // A fresh install must not change the roster at all.
        assert_eq!(annotation(dir, "ollama:llama3"), None);
        assert!(!history_file(dir).exists());

        for _ in 0..(MIN_OBSERVATIONS - 1) {
            record(dir, "ollama:llama3", TaskClass::Text, true, 1_000).unwrap();
        }
        assert_eq!(annotation(dir, "ollama:llama3"), None);

        record(dir, "ollama:llama3", TaskClass::Text, true, 1_000).unwrap();
        let annotation = annotation(dir, "ollama:llama3").expect("three observations is enough");
        assert!(annotation.contains("3/3 text tasks ok"), "{annotation}");
        assert!(annotation.contains("~1s"), "{annotation}");
    }

    #[test]
    fn file_tasks_lead_the_annotation_and_unknown_models_say_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        for _ in 0..3 {
            record(dir, "a:m", TaskClass::Text, true, 1_000).unwrap();
            record(dir, "a:m", TaskClass::File, false, 2_000).unwrap();
        }
        let observed = annotation(dir, "a:m").unwrap();
        assert!(
            observed.starts_with("0/3 file tasks ok"),
            "a model that cannot be trusted with a file task is the more important \
             fact, so it leads: {observed}"
        );
        assert_eq!(annotation(dir, "never:seen"), None);
    }

    #[test]
    fn an_average_is_reported_over_the_attempts_that_produced_it() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        record(dir, "a:m", TaskClass::Text, true, 1_000).unwrap();
        record(dir, "a:m", TaskClass::Text, true, 2_000).unwrap();
        record(dir, "a:m", TaskClass::Text, true, 3_000).unwrap();
        // 6000ms over 3 attempts is 2s, not the 6s a running total would report.
        assert!(annotation(dir, "a:m").unwrap().contains("~2s"));
    }
}

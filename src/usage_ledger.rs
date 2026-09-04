//! Persisted, cross-session running total of tokens spent this calendar month.
//!
//! `App`'s status line already shows per-call and per-session token counts (see
//! `app.rs`'s `usage_summary`), but both reset the moment the process restarts —
//! neither can answer "how much have I used this month", which is the number that
//! actually matters for anyone watching a metered quota. This module gives the
//! orchestrator a single small on-disk counter for that, keyed by UTC calendar month
//! so it survives restarts and rolls over on its own at the month boundary.
//!
//! UTC (not local time) is used for the month boundary deliberately: local time
//! would need a timezone database this crate doesn't otherwise depend on, and would
//! make the rollover instant depend on the user's OS clock settings rather than being
//! a pure function of the epoch timestamp — which is what makes this module testable
//! without any wall-clock mocking beyond the timestamps already threaded through
//! `record_at`.

use crate::vault::write_atomically;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// On-disk shape of `usage_history.json`: the UTC year-month this total covers
/// (`"YYYY-MM"`) and the running token count for it. A month that doesn't match the
/// current one when loaded is stale and is discarded rather than displayed — see
/// `record_at`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
struct MonthlyUsage {
    month: String,
    tokens: u64,
}

fn usage_file(data_dir: &Path) -> PathBuf {
    data_dir.join("usage_history.json")
}

fn load(data_dir: &Path) -> Result<MonthlyUsage> {
    let path = usage_file(data_dir);
    match fs::read_to_string(&path) {
        Ok(raw) => serde_json::from_str(&raw)
            .with_context(|| format!("failed to parse {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(MonthlyUsage::default()),
        Err(e) => Err(e).with_context(|| format!("failed to read {}", path.display())),
    }
}

fn save(data_dir: &Path, usage: &MonthlyUsage) -> Result<()> {
    let raw = serde_json::to_string_pretty(usage)?;
    write_atomically(&usage_file(data_dir), raw.as_bytes())
}

/// Adds `tokens` to the running total for `current_month` (an UTC `"YYYY-MM"`
/// string, see `current_month_utc`), persists the result under `data_dir`
/// (`Paths::data_dir`), and returns the new total.
///
/// If the file on disk covers a different month than `current_month` — including
/// "no file yet" — the stored total is treated as belonging to a month that has
/// already ended and is reset to zero before `tokens` is added, which is the
/// rollover: nothing has to notice the month changed and clear the counter itself,
/// the next call to `record_at` does it as a side effect of reading stale state.
pub fn record_at(data_dir: &Path, tokens: u64, current_month: &str) -> Result<u64> {
    let mut usage = load(data_dir)?;
    if usage.month != current_month {
        usage.month = current_month.to_string();
        usage.tokens = 0;
    }
    usage.tokens = usage.tokens.saturating_add(tokens);
    save(data_dir, &usage)?;
    Ok(usage.tokens)
}

/// `record_at` against the real clock — the only entry point production code calls.
pub fn record(data_dir: &Path, tokens: u64) -> Result<u64> {
    record_at(data_dir, tokens, &current_month_utc())
}

/// The running total for `current_month`, read without recording anything.
///
/// `record_at(data_dir, 0, current_month)` returns the same number, and the
/// orchestrator's own test uses it that way to prove persistence. It is the wrong
/// call for a spending check: that check runs *before* any tokens are spent, on every
/// turn and every delegation, and asking a question should not write to disk.
/// Recording zero would also create `usage_history.json` on a fresh install the first
/// time a user merely started a session under a configured ceiling, and would roll a
/// stale month over as a side effect of asking whether work may proceed.
///
/// A file covering a month that has already ended reads as zero here, for the same
/// reason `record_at` resets it: last month's spending is not this month's, and a
/// ceiling enforced against a stale total would refuse work the user has budget for.
pub fn total_at(data_dir: &Path, current_month: &str) -> Result<u64> {
    let usage = load(data_dir)?;
    Ok(if usage.month == current_month {
        usage.tokens
    } else {
        0
    })
}

/// `total_at` against the real clock — the only entry point production code calls.
pub fn total(data_dir: &Path) -> Result<u64> {
    total_at(data_dir, &current_month_utc())
}

/// The current UTC calendar month as `"YYYY-MM"`.
pub fn current_month_utc() -> String {
    month_utc(SystemTime::now())
}

fn month_utc(time: SystemTime) -> String {
    let secs = time
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let (year, month, _day) = civil_from_days(days);
    format!("{year:04}-{month:02}")
}

/// Converts a day count since the Unix epoch (1970-01-01) to a proleptic-Gregorian
/// `(year, month, day)` triple. This is Howard Hinnant's well-known `civil_from_days`
/// algorithm (public domain, see
/// <https://howardhinnant.github.io/date_algorithms.html>) — chosen over pulling in a
/// full date/time crate because a single calendar-month boundary is the only date
/// computation this crate needs anywhere, and the algorithm is small, allocation-free,
/// and exhaustively unit-tested below against known dates rather than trusted blind.
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    (year as i32, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_from_days_matches_known_dates() {
        // Epoch day 0 is 1970-01-01.
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // 2024 is a leap year; day 31 (0-indexed) is 2024-02-01, one day before the
        // leap day the non-leap-year arithmetic would get wrong.
        let leap_day_epoch = 19_782; // 2024-02-29, precomputed via Python's `date` subtraction.
        assert_eq!(civil_from_days(leap_day_epoch), (2024, 2, 29));
        assert_eq!(civil_from_days(leap_day_epoch + 1), (2024, 3, 1));
        // A century year not divisible by 400 (2100) is NOT a leap year under the
        // Gregorian rule the /100 and /400 terms encode; if the algorithm dropped
        // either term this would come out as 2100-02-29 instead.
        let year_2100_mar_1 = 47_541; // 2100-03-01, precomputed via Python's `date` subtraction.
        assert_eq!(civil_from_days(year_2100_mar_1 - 1), (2100, 2, 28));
        assert_eq!(civil_from_days(year_2100_mar_1), (2100, 3, 1));
    }

    #[test]
    fn month_utc_formats_year_and_month_from_epoch_seconds() {
        // 2024-01-15T00:00:00Z.
        let t = UNIX_EPOCH + std::time::Duration::from_secs(1_705_276_800);
        assert_eq!(month_utc(t), "2024-01");
        // 2024-12-31T23:59:59Z stays in December, not rolling to next year.
        let t = UNIX_EPOCH + std::time::Duration::from_secs(1_735_689_599);
        assert_eq!(month_utc(t), "2024-12");
    }

    #[test]
    fn record_at_accumulates_within_the_same_month() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        assert_eq!(record_at(dir, 100, "2024-06").unwrap(), 100);
        assert_eq!(record_at(dir, 50, "2024-06").unwrap(), 150);
        assert_eq!(record_at(dir, 0, "2024-06").unwrap(), 150);
    }

    #[test]
    fn record_at_resets_the_total_when_the_month_rolls_over() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        assert_eq!(record_at(dir, 900, "2024-06").unwrap(), 900);
        // A new month must start from zero, not carry June's total forward.
        assert_eq!(record_at(dir, 10, "2024-07").unwrap(), 10);
        assert_eq!(record_at(dir, 5, "2024-07").unwrap(), 15);
    }

    #[test]
    fn total_at_reads_the_stored_total_for_the_current_month() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        record_at(dir, 100, "2024-06").unwrap();
        record_at(dir, 50, "2024-06").unwrap();
        assert_eq!(total_at(dir, "2024-06").unwrap(), 150);
    }

    #[test]
    fn total_at_reports_zero_for_a_month_that_has_already_ended() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        record_at(dir, 900, "2024-06").unwrap();
        // July has spent nothing yet. Reporting June's 900 here would make a ceiling
        // refuse the first call of a month the user has their whole budget for.
        assert_eq!(total_at(dir, "2024-07").unwrap(), 0);
        // And reading it did not perform the rollover write itself: June's total is
        // still on disk for `record_at` to reset when tokens are actually spent.
        assert_eq!(total_at(dir, "2024-06").unwrap(), 900);
    }

    #[test]
    fn total_at_neither_creates_nor_modifies_the_file() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        // A ceiling check on a fresh install must not leave a ledger behind: the file
        // appearing is what tells a later reader that tokens were spent this month.
        assert_eq!(total_at(dir, "2024-06").unwrap(), 0);
        assert!(!usage_file(dir).exists());

        record_at(dir, 120, "2024-06").unwrap();
        let before = fs::read_to_string(usage_file(dir)).unwrap();
        assert_eq!(total_at(dir, "2024-06").unwrap(), 120);
        assert_eq!(fs::read_to_string(usage_file(dir)).unwrap(), before);
    }

    #[test]
    fn record_at_survives_a_reload_from_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        record_at(dir, 42, "2024-06").unwrap();
        // A second call against the same directory simulates a fresh process reading
        // back what a previous one persisted.
        assert_eq!(record_at(dir, 8, "2024-06").unwrap(), 50);
    }

    #[test]
    fn record_at_with_no_prior_file_starts_from_zero() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(record_at(tmp.path(), 7, "2024-06").unwrap(), 7);
    }

    /// `load` treats a missing file as "no usage yet" and every other read error as an
    /// error. Widening that guard to accept any error would turn an unreadable ledger
    /// into a silent reset to zero: the month's total would appear to vanish and the
    /// next `record_at` would overwrite the file that could not be read.
    #[test]
    fn a_read_error_that_is_not_a_missing_file_is_never_treated_as_no_usage_yet() {
        let tmp = tempfile::tempdir().unwrap();
        // A directory where the file belongs fails `read_to_string` with something
        // other than NotFound on every platform.
        fs::create_dir(usage_file(tmp.path())).unwrap();
        let err = record_at(tmp.path(), 5, "2024-06")
            .expect_err("an unreadable ledger must not be reported as an empty one");
        assert!(
            err.to_string().contains("failed to read"),
            "unexpected error: {err}"
        );
    }

    /// A parse failure is likewise an error, not an implicit reset.
    #[test]
    fn a_corrupt_ledger_is_an_error_rather_than_a_silent_reset() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(usage_file(tmp.path()), b"{not json").unwrap();
        let err = record_at(tmp.path(), 5, "2024-06")
            .expect_err("a corrupt ledger must not be reported as an empty one");
        assert!(
            err.to_string().contains("failed to parse"),
            "unexpected error: {err}"
        );
    }

    /// `record` is the only entry point production code calls; every test above goes
    /// through `record_at` instead, so without this one the real-clock wrapper could
    /// return a constant and nothing would notice.
    #[test]
    fn record_against_the_real_clock_accumulates_a_running_total() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        assert_eq!(record(dir, 300).unwrap(), 300);
        assert_eq!(record(dir, 45).unwrap(), 345);
        // And it landed on disk under the month the real clock reports, so a later
        // call in the same month keeps accumulating rather than starting over.
        assert_eq!(
            record_at(dir, 5, &current_month_utc()).unwrap(),
            350,
            "record must persist under the same month key current_month_utc returns"
        );
    }

    #[test]
    fn current_month_utc_is_this_month_in_year_dash_month_form() {
        let month = current_month_utc();
        let (year, rest) = month
            .split_once('-')
            .unwrap_or_else(|| panic!("expected YYYY-MM, got {month:?}"));
        assert_eq!(year.len(), 4, "expected a four-digit year in {month:?}");
        assert_eq!(rest.len(), 2, "expected a two-digit month in {month:?}");
        let year: i32 = year.parse().unwrap();
        let rest: u32 = rest.parse().unwrap();
        // Not a fixed string: it has to track the clock. The lower bound is when this
        // module was written, the upper bound is loose enough never to expire.
        assert!(
            (2024..=2999).contains(&year),
            "implausible year in {month:?}"
        );
        assert!((1..=12).contains(&rest), "impossible month in {month:?}");
        assert_eq!(month, month_utc(SystemTime::now()));
    }

    /// `civil_from_days` is pure arithmetic with no branches to speak of, so spot
    /// checks against a handful of known dates leave most of its terms free to be
    /// perturbed without any test noticing. Round-tripping every day across a wide
    /// range against an independent inverse pins all of them: the inverse is a
    /// separate implementation, so a change to either side breaks the identity.
    #[test]
    fn civil_from_days_round_trips_every_day_across_eras() {
        // Hinnant's `days_from_civil`, the documented inverse of the function above.
        fn days_from_civil(y: i32, m: u32, d: u32) -> i64 {
            let y = y as i64 - if m <= 2 { 1 } else { 0 };
            let era = if y >= 0 { y } else { y - 399 } / 400;
            let yoe = (y - era * 400) as u64; // [0, 399]
            let m = m as u64;
            let doy = (153 * if m > 2 { m - 3 } else { m + 9 } + 2) / 5 + d as u64 - 1;
            let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
            era * 146_097 + doe as i64 - 719_468
        }

        // The range has to cross an era boundary in both directions. `civil_from_days`
        // shifts the epoch by 719_468 days and then takes a *different* branch for a
        // negative shifted value, so a range that starts at 1970 — or even at 1900 —
        // never executes the `z - 146_096` correction at all and leaves it free to be
        // anything. Starting before 0000-03-01 (shifted day zero) exercises it.
        let mut previous_day: Option<i64> = None;
        for z in -800_000..120_000i64 {
            let (year, month, day) = civil_from_days(z);
            assert_eq!(
                days_from_civil(year, month, day),
                z,
                "epoch day {z} decoded to {year:04}-{month:02}-{day:02}, a different day"
            );
            assert!(
                (1..=12).contains(&month),
                "epoch day {z} gave month {month}"
            );
            assert!((1..=31).contains(&day), "epoch day {z} gave day {day}");
            // Consecutive epoch days must be consecutive calendar days, so no
            // arithmetic change can stay hidden by cancelling out across the triple.
            if let Some(previous) = previous_day {
                assert_eq!(
                    z - previous,
                    1,
                    "epoch day {z} did not follow the day before"
                );
            }
            previous_day = Some(z);
        }

        // Spot-check the far end against dates computed independently — by walking the
        // calendar a day at a time backwards from the epoch under plain leap-year
        // rules — so the round-trip cannot pass by both implementations being wrong in
        // the same way. Year numbering is astronomical (there is a year 0, and it is a
        // leap year), which is what "proleptic Gregorian" means here.
        assert_eq!(civil_from_days(-800_000), (-221, 9, 4));
        assert_eq!(civil_from_days(-719_468), (0, 3, 1)); // shifted day zero
        assert_eq!(civil_from_days(-719_469), (0, 2, 29)); // one day earlier, negative branch
    }
}

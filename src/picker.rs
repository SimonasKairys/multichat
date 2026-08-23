//! Interactive connection-picker state, kept free of I/O so it can be unit-tested,
//! exactly as `src/app.rs` does for the chat TUI.

use std::collections::BTreeMap;

use zeroize::Zeroize;

use crate::config::ConnectionSpec;
use crate::orchestrator::{Availability, Candidate};

/// One rendered, cursor-addressable line: a candidate's `transports[transport]`.
#[derive(Debug, Clone, Copy)]
pub struct RowRef {
    pub candidate: usize,
    pub transport: usize,
}

#[derive(Debug, Clone, Copy)]
struct Selection {
    enabled: bool,
    /// Index into `candidates[_].transports`: which transport is in effect when
    /// `enabled` is true, and which one a bare `space` will turn on next.
    chosen: usize,
}

/// Browsing the row list, or entering a masked API key for a row that has none
/// stored yet. Kept as an explicit mode rather than a bool so there is exactly one
/// place ([`PickerState::key_entry`]) the UI has to ask "are we editing text right
/// now" before routing a keypress.
enum Mode {
    Browsing,
    EnteringKey { candidate: usize, buffer: String },
}

/// Picker state: candidates discovered up front, plus the user's in-progress
/// choices. Nothing here touches the filesystem, the network, or a terminal — in
/// particular, key entry never calls the keyring itself; it only hands a typed key
/// back to the caller (`src/ui/mod.rs::run_picker`), which is the one place that does.
pub struct PickerState {
    candidates: Vec<Candidate>,
    rows: Vec<RowRef>,
    selections: Vec<Selection>,
    cursor: usize,
    commander: Option<usize>,
    mode: Mode,
    /// Set when `space`/`enter`/`c` was a no-op, to show in the hint line.
    pub flash: Option<String>,
}

impl PickerState {
    /// Builds the initial state. On first run (`first_run` — the saved config has no
    /// `connections` at all) every available candidate starts ticked with its first
    /// available transport, but no commander is chosen — the user must explicitly
    /// pick one with `c` before `submit` will succeed; a silent auto-pick would let
    /// a session start against a model the user never meant to be primary.
    /// Otherwise the saved `connections`/`commander` are restored verbatim.
    pub fn new(
        candidates: Vec<Candidate>,
        connections: &BTreeMap<String, ConnectionSpec>,
        commander: Option<&str>,
        first_run: bool,
    ) -> Self {
        let selections: Vec<Selection> = candidates
            .iter()
            .map(|c| Self::initial_selection(c, connections, first_run))
            .collect();

        let rows: Vec<RowRef> = candidates
            .iter()
            .enumerate()
            .flat_map(|(candidate, c)| {
                (0..c.transports.len()).map(move |transport| RowRef {
                    candidate,
                    transport,
                })
            })
            .collect();

        // A prior explicit choice (the saved `commander`) is honored regardless of
        // `first_run`. There is no first-run fallback here: the user must pick a
        // commander themselves, via `set_commander`, before `submit` will succeed.
        let commander_idx = commander
            .and_then(|label| candidates.iter().position(|c| c.id == label))
            .filter(|&i| selections[i].enabled);

        Self {
            candidates,
            rows,
            selections,
            cursor: 0,
            commander: commander_idx,
            mode: Mode::Browsing,
            flash: None,
        }
    }

    fn initial_selection(
        candidate: &Candidate,
        connections: &BTreeMap<String, ConnectionSpec>,
        first_run: bool,
    ) -> Selection {
        if first_run {
            let chosen = candidate
                .transports
                .iter()
                .position(|t| t.availability.is_available())
                .unwrap_or(0);
            let enabled = candidate
                .transports
                .iter()
                .any(|t| t.availability.is_available());
            Selection { enabled, chosen }
        } else if let Some(conn) = connections.get(&candidate.id) {
            let chosen = conn
                .transport
                .and_then(|t| {
                    candidate
                        .transports
                        .iter()
                        .position(|opt| opt.transport == Some(t))
                })
                .unwrap_or(0);
            Selection {
                enabled: conn.enabled,
                chosen,
            }
        } else {
            Selection {
                enabled: false,
                chosen: 0,
            }
        }
    }

    // --- rendering support ---------------------------------------------------

    pub fn candidates(&self) -> &[Candidate] {
        &self.candidates
    }

    pub fn rows(&self) -> &[RowRef] {
        &self.rows
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// Whether the given candidate is currently enabled with the given transport
    /// index — i.e. whether that row's checkbox should render ticked. Two rows of
    /// the same candidate (e.g. "via CLI" / "via API") can never both be checked:
    /// they share one `Selection`, so ticking one always un-ticks the other.
    pub fn is_checked(&self, candidate: usize, transport: usize) -> bool {
        self.selections[candidate].enabled && self.selections[candidate].chosen == transport
    }

    /// Whether this row is the commander. The commander is a *connection*, not a
    /// vendor, so the marker belongs on the chosen transport's row only — marking
    /// both "via CLI" and "via API" claimed two commanders and could badge a row
    /// that is unavailable.
    pub fn is_commander(&self, candidate: usize, transport: usize) -> bool {
        self.commander == Some(candidate) && self.selections[candidate].chosen == transport
    }

    /// `Some((candidate id, buffer length))` while a masked key prompt is open, so
    /// the UI can render `API key for <id>: ` followed by one `•` per typed
    /// character — the buffer's actual contents never leave this module through
    /// this accessor.
    pub fn key_entry(&self) -> Option<(&str, usize)> {
        match &self.mode {
            Mode::Browsing => None,
            Mode::EnteringKey { candidate, buffer } => {
                Some((self.candidates[*candidate].id.as_str(), buffer.len()))
            }
        }
    }

    // --- interaction -----------------------------------------------------------

    pub fn move_up(&mut self) {
        self.flash = None;
        self.cursor = self.cursor.saturating_sub(1);
    }

    pub fn move_down(&mut self) {
        self.flash = None;
        if self.cursor + 1 < self.rows.len() {
            self.cursor += 1;
        }
    }

    fn current_row(&self) -> Option<RowRef> {
        self.rows.get(self.cursor).copied()
    }

    /// Ticks or unticks the highlighted row. Enabling a row backed by an
    /// unavailable transport is a no-op that surfaces the reason instead — never
    /// a silent failure, and never a way to select something construction would
    /// later drop. Un-ticking is different: a row can arrive already enabled+
    /// chosen from saved config (e.g. a key that was removed from the keyring
    /// after `enabled = true` was written), and construction drops a disabled row
    /// regardless of its availability — so refusing the un-tick would only trap
    /// the user with a stale `[x]` they can never clear.
    pub fn toggle(&mut self) {
        // Key entry routes every keypress through the UI's dedicated match arm
        // (`push_key_char`/`backspace_key`/`cancel_key_entry`/`submit_key_entry`);
        // `toggle` should not fire underneath it even if a caller mis-routes.
        if !matches!(self.mode, Mode::Browsing) {
            return;
        }

        let Some(row) = self.current_row() else {
            return;
        };

        let already_chosen = {
            let sel = &self.selections[row.candidate];
            sel.enabled && sel.chosen == row.transport
        };

        if !already_chosen {
            let option = &self.candidates[row.candidate].transports[row.transport];
            if let Availability::Unavailable(reason) = &option.availability {
                if option.needs_key {
                    // The one unavailable reason the picker can fix itself: open the
                    // masked prompt instead of just flashing why the row can't be
                    // ticked.
                    self.mode = Mode::EnteringKey {
                        candidate: row.candidate,
                        buffer: String::new(),
                    };
                    self.flash = None;
                    return;
                }
                self.flash = Some(reason.clone());
                return;
            }
        }
        self.flash = None;

        let sel = &mut self.selections[row.candidate];
        if already_chosen {
            sel.enabled = false;
            if self.commander == Some(row.candidate) {
                self.commander = None;
            }
        } else {
            sel.enabled = true;
            sel.chosen = row.transport;
        }
    }

    // --- key entry ---------------------------------------------------------------

    /// Appends a typed character to the in-progress key. A no-op outside key-entry
    /// mode.
    pub fn push_key_char(&mut self, c: char) {
        if let Mode::EnteringKey { buffer, .. } = &mut self.mode {
            buffer.push(c);
        }
    }

    /// Deletes the last typed character. A no-op outside key-entry mode or on an
    /// empty buffer.
    pub fn backspace_key(&mut self) {
        if let Mode::EnteringKey { buffer, .. } = &mut self.mode {
            buffer.pop();
        }
    }

    /// Abandons key entry and returns to browsing. The half-typed key must not
    /// linger anywhere in picker state once the mode ends, so the buffer is
    /// zeroized rather than just dropped — an ordinary `String` drop frees its heap
    /// allocation without clearing it first.
    pub fn cancel_key_entry(&mut self) {
        if let Mode::EnteringKey { mut buffer, .. } =
            std::mem::replace(&mut self.mode, Mode::Browsing)
        {
            buffer.zeroize();
        }
    }

    /// On a non-empty buffer, leaves key-entry mode and hands the typed key to the
    /// caller as `(candidate_id, key)` — this is the only copy of the key that
    /// survives the call; the picker keeps none. On an empty buffer, cancels
    /// instead (with a flash) and returns `None`: an empty key is never something
    /// to attempt storing.
    pub fn submit_key_entry(&mut self) -> Option<(String, String)> {
        let (candidate, is_empty) = match &self.mode {
            Mode::EnteringKey { candidate, buffer } => (*candidate, buffer.is_empty()),
            Mode::Browsing => return None,
        };

        if is_empty {
            self.flash = Some("empty key — nothing stored".into());
            self.cancel_key_entry();
            return None;
        }

        let id = self.candidates[candidate].id.clone();
        match std::mem::replace(&mut self.mode, Mode::Browsing) {
            Mode::EnteringKey { buffer, .. } => Some((id, buffer)),
            Mode::Browsing => unreachable!("checked above: mode was EnteringKey"),
        }
    }

    /// Called by the UI after it has written the key to the OS keyring: flips the
    /// row to available, ticks it (mirrors the normal enabling path in `toggle`,
    /// since this row is now exactly as selectable as any other available one), and
    /// flashes confirmation.
    pub fn mark_key_stored(&mut self, candidate: usize, transport: usize) {
        let option = &mut self.candidates[candidate].transports[transport];
        option.availability = Availability::Available;
        option.needs_key = false;

        let sel = &mut self.selections[candidate];
        sel.enabled = true;
        sel.chosen = transport;

        self.flash = Some("key stored in OS keyring".into());
    }

    /// Called by the UI when the keyring write itself failed. Stays in browsing
    /// mode — key entry already ended when `submit_key_entry` returned the key — and
    /// just surfaces why nothing was stored.
    pub fn mark_key_store_failed(&mut self, error: &str) {
        self.flash = Some(error.to_string());
    }

    /// Cycles which transport the highlighted candidate would use, without changing
    /// whether it is enabled. A no-op on a single-transport candidate (Ollama).
    pub fn cycle_transport(&mut self) {
        let Some(row) = self.current_row() else {
            return;
        };
        let n = self.candidates[row.candidate].transports.len();
        if n < 2 {
            return;
        }
        self.flash = None;
        let sel = &mut self.selections[row.candidate];
        sel.chosen = (sel.chosen + 1) % n;
    }

    /// Marks the highlighted candidate as commander. Refuses (with a flash) on a
    /// candidate that isn't ticked — a commander that isn't even connected makes no
    /// sense.
    pub fn set_commander(&mut self) {
        let Some(row) = self.current_row() else {
            return;
        };
        let option = &self.candidates[row.candidate].transports[row.transport];
        if let Availability::Unavailable(reason) = &option.availability {
            self.flash = Some(reason.clone());
            return;
        }
        self.flash = None;

        // Promoting a row implies connecting it. Requiring `space` first only ever
        // produced a flash telling the user to press `space` — an extra step in front
        // of an unambiguous intent. Choosing a commander on a different transport of
        // the same connection also switches to that transport.
        let sel = &mut self.selections[row.candidate];
        sel.enabled = true;
        sel.chosen = row.transport;
        self.commander = Some(row.candidate);
    }

    /// Finalises the picker into a `connections`/`commander` pair to persist, or
    /// refuses (setting `flash`) if nothing is ticked, or if no commander has been
    /// chosen — starting a session with no providers, or with no model designated to
    /// receive prompts, is a worse outcome than asking again. The nothing-ticked
    /// check runs first: a user who hasn't ticked anything should be told that,
    /// not sent chasing a commander they can't set on an empty selection.
    pub fn submit(&mut self) -> Option<(BTreeMap<String, ConnectionSpec>, Option<String>)> {
        if !self.selections.iter().any(|s| s.enabled) {
            self.flash = Some("tick at least one connection before connecting".into());
            return None;
        }

        let Some(commander_idx) = self.commander else {
            self.flash = Some("press `c` to choose a commander before connecting".into());
            return None;
        };

        let mut connections = BTreeMap::new();
        for (i, candidate) in self.candidates.iter().enumerate() {
            let sel = &self.selections[i];
            let option = &candidate.transports[sel.chosen];
            connections.insert(
                candidate.id.clone(),
                ConnectionSpec {
                    enabled: sel.enabled,
                    transport: option.transport,
                    path: option.cli.as_ref().map(|cli| cli.path.clone()),
                    model: None,
                },
            );
        }

        let commander = self.candidates[commander_idx].id.clone();

        Some((connections, Some(commander)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Transport;
    use crate::orchestrator::CliSpec;

    fn candidate_single(id: &str) -> Candidate {
        Candidate {
            id: id.into(),
            group: id.to_uppercase(),
            model: id.into(),
            transports: vec![crate::orchestrator::TransportOption {
                transport: None,
                label: String::new(),
                detail: String::new(),
                availability: Availability::Available,
                cli: None,
                needs_key: false,
            }],
        }
    }

    /// A vendor with two transport rows: CLI (available or not) and API (always
    /// unavailable here, standing in for "no key stored" — `needs_key` set to match).
    fn candidate_dual(id: &str, cli_available: bool) -> Candidate {
        Candidate {
            id: id.into(),
            group: id.to_uppercase(),
            model: id.into(),
            transports: vec![
                crate::orchestrator::TransportOption {
                    transport: Some(Transport::Cli),
                    label: "via CLI".into(),
                    detail: "/usr/bin/x".into(),
                    availability: if cli_available {
                        Availability::Available
                    } else {
                        Availability::Unavailable("binary missing".into())
                    },
                    cli: Some(CliSpec {
                        binary_name: id.into(),
                        path: "/usr/bin/x".into(),
                        args: vec![],
                        system_arg: None,
                        dialect: None,
                    }),
                    needs_key: false,
                },
                crate::orchestrator::TransportOption {
                    transport: Some(Transport::Api),
                    label: "via API".into(),
                    detail: "(no key stored)".into(),
                    availability: Availability::Unavailable("no key stored".into()),
                    cli: None,
                    needs_key: true,
                },
            ],
        }
    }

    /// A single-row candidate unavailable for a reason the picker cannot fix by
    /// prompting (e.g. a classified-mode refusal) — `needs_key` is false, unlike
    /// `candidate_dual`'s API row.
    fn candidate_refused(id: &str, reason: &str) -> Candidate {
        Candidate {
            id: id.into(),
            group: id.to_uppercase(),
            model: id.into(),
            transports: vec![crate::orchestrator::TransportOption {
                transport: Some(Transport::Api),
                label: "via API".into(),
                detail: String::new(),
                availability: Availability::Unavailable(reason.into()),
                cli: None,
                needs_key: false,
            }],
        }
    }

    #[test]
    fn toggling_ticks_and_unticks_a_row() {
        let candidates = vec![candidate_single("ollama:llama3")];
        let mut picker = PickerState::new(candidates, &BTreeMap::new(), None, false);
        assert!(!picker.is_checked(0, 0));
        picker.toggle();
        assert!(picker.is_checked(0, 0));
        picker.toggle();
        assert!(!picker.is_checked(0, 0));
    }

    #[test]
    fn tab_cycles_transport_without_changing_enabled() {
        let candidates = vec![candidate_dual("anthropic", true)];
        let mut picker = PickerState::new(candidates, &BTreeMap::new(), None, false);
        picker.toggle(); // ticks the CLI row (row 0, transport index 0)
        assert!(picker.is_checked(0, 0));

        picker.cycle_transport();
        assert!(picker.is_checked(0, 1));
        assert!(!picker.is_checked(0, 0));
    }

    #[test]
    fn toggling_a_no_key_api_row_opens_key_entry_instead_of_flashing() {
        let candidates = vec![candidate_dual("anthropic", true)];
        let mut picker = PickerState::new(candidates, &BTreeMap::new(), None, false);
        picker.move_down(); // the API row: no key stored
        picker.toggle();

        assert!(!picker.is_checked(0, 1));
        assert!(picker.flash.is_none());
        let (id, len) = picker
            .key_entry()
            .expect("toggle on a needs_key row should open key entry");
        assert_eq!(id, "anthropic");
        assert_eq!(len, 0);
    }

    #[test]
    fn a_row_unavailable_for_other_reasons_still_flashes_not_prompts() {
        // A classified-mode refusal is unavailable for a reason the picker cannot
        // fix by prompting, so `needs_key` is false and the old flash behaviour
        // must still apply.
        let candidates = vec![candidate_refused(
            "anthropic",
            "cloud APIs are refused under --classified",
        )];
        let mut picker = PickerState::new(candidates, &BTreeMap::new(), None, false);
        picker.toggle();

        assert!(picker.key_entry().is_none());
        assert!(!picker.is_checked(0, 0));
        assert_eq!(
            picker.flash.as_deref(),
            Some("cloud APIs are refused under --classified")
        );
    }

    #[test]
    fn typed_key_chars_accumulate_and_backspace_deletes() {
        let candidates = vec![candidate_dual("anthropic", true)];
        let mut picker = PickerState::new(candidates, &BTreeMap::new(), None, false);
        picker.move_down();
        picker.toggle();

        picker.push_key_char('s');
        picker.push_key_char('k');
        picker.push_key_char('-');
        assert_eq!(picker.key_entry().unwrap().1, 3);

        picker.backspace_key();
        assert_eq!(picker.key_entry().unwrap().1, 2);
    }

    #[test]
    fn esc_cancels_key_entry_and_wipes_the_buffer() {
        let candidates = vec![candidate_dual("anthropic", true)];
        let mut picker = PickerState::new(candidates, &BTreeMap::new(), None, false);
        picker.move_down();
        picker.toggle();
        picker.push_key_char('x');

        picker.cancel_key_entry();

        assert!(picker.key_entry().is_none());
        // Cancelling leaves the row exactly as it was: unavailable and un-ticked.
        assert!(!picker.is_checked(0, 1));
    }

    #[test]
    fn submitting_an_empty_key_stores_nothing_and_flashes() {
        let candidates = vec![candidate_dual("anthropic", true)];
        let mut picker = PickerState::new(candidates, &BTreeMap::new(), None, false);
        picker.move_down();
        picker.toggle();

        let result = picker.submit_key_entry();

        assert!(result.is_none());
        assert!(picker.key_entry().is_none());
        assert_eq!(picker.flash.as_deref(), Some("empty key — nothing stored"));
    }

    #[test]
    fn a_submitted_key_is_handed_off_exactly_once() {
        let candidates = vec![candidate_dual("anthropic", true)];
        let mut picker = PickerState::new(candidates, &BTreeMap::new(), None, false);
        picker.move_down();
        picker.toggle();
        picker.push_key_char('s');
        picker.push_key_char('k');

        let (id, key) = picker
            .submit_key_entry()
            .expect("a non-empty buffer should submit");
        assert_eq!(id, "anthropic");
        assert_eq!(key, "sk");
        assert!(picker.key_entry().is_none());

        // The buffer was transferred out, not copied: a second submit in a row (the
        // mode is already back to Browsing) hands off nothing.
        assert!(picker.submit_key_entry().is_none());
    }

    #[test]
    fn mark_key_stored_ticks_the_row_and_makes_it_available() {
        let candidates = vec![candidate_dual("anthropic", true)];
        let mut picker = PickerState::new(candidates, &BTreeMap::new(), None, false);
        picker.move_down();
        picker.toggle();
        picker.push_key_char('s');
        let _ = picker.submit_key_entry();

        picker.mark_key_stored(0, 1);

        assert!(picker.is_checked(0, 1));
        assert!(
            picker.candidates()[0].transports[1]
                .availability
                .is_available()
        );
        assert!(!picker.candidates()[0].transports[1].needs_key);
        assert_eq!(picker.flash.as_deref(), Some("key stored in OS keyring"));
    }

    #[test]
    fn mark_key_store_failed_flashes_the_error_and_stays_in_browsing() {
        let candidates = vec![candidate_dual("anthropic", true)];
        let mut picker = PickerState::new(candidates, &BTreeMap::new(), None, false);
        picker.move_down();
        picker.toggle();
        picker.push_key_char('s');
        let _ = picker.submit_key_entry();

        picker.mark_key_store_failed("keyring is locked");

        assert_eq!(picker.flash.as_deref(), Some("keyring is locked"));
        assert!(picker.key_entry().is_none());
        assert!(!picker.is_checked(0, 1));
    }

    #[test]
    fn promoting_an_unticked_row_connects_it_too() {
        // `c` on an available but unticked row used to refuse and tell the user to
        // press `space` first. Choosing a commander is unambiguous, so it now ticks.
        let candidates = vec![candidate_single("ollama:llama3")];
        let mut picker = PickerState::new(candidates, &BTreeMap::new(), None, false);
        assert!(!picker.is_checked(0, 0));

        picker.set_commander();
        assert!(picker.flash.is_none());
        assert!(picker.is_commander(0, 0));
        assert!(picker.is_checked(0, 0));
    }

    #[test]
    fn an_unavailable_row_still_cannot_become_commander() {
        // The tick-on-promote shortcut must not become a way to select something
        // construction would immediately drop.
        let candidates = vec![candidate_dual("anthropic", false)];
        let mut picker = PickerState::new(candidates, &BTreeMap::new(), None, false);
        picker.move_down();

        picker.set_commander();
        assert_eq!(picker.flash.as_deref(), Some("no key stored"));
        assert!(!picker.is_commander(0, 1));
        assert!(!picker.is_checked(0, 1));
    }

    #[test]
    fn an_unavailable_row_that_is_already_ticked_can_still_be_unticked() {
        // Saved config can carry `enabled = true` for a transport that has since
        // gone unavailable (e.g. the API key was removed from the keyring after
        // the config was written). Construction drops a disabled row either way,
        // so refusing the un-tick would trap the user with a permanent `[x]`.
        let candidates = vec![candidate_dual("google", false)];
        let mut connections = BTreeMap::new();
        connections.insert(
            "google".to_string(),
            ConnectionSpec {
                enabled: true,
                transport: Some(Transport::Api),
                path: None,
                model: None,
            },
        );
        let mut picker = PickerState::new(candidates, &connections, Some("google"), false);
        assert!(picker.is_checked(0, 1));
        assert!(picker.is_commander(0, 1));

        picker.move_down(); // land on the API row
        picker.toggle();

        assert!(!picker.is_checked(0, 1));
        assert!(picker.flash.is_none());
        assert!(!picker.is_commander(0, 1));
    }

    #[test]
    fn unticking_the_commander_clears_it() {
        let candidates = vec![candidate_single("ollama:llama3")];
        let mut picker = PickerState::new(candidates, &BTreeMap::new(), None, false);
        picker.toggle();
        picker.set_commander();
        assert!(picker.is_commander(0, 0));
        picker.toggle();
        assert!(!picker.is_commander(0, 0));
    }

    #[test]
    fn unticking_the_commander_forces_choosing_one_again_before_connecting() {
        let candidates = vec![candidate_single("ollama:llama3")];
        let mut picker = PickerState::new(candidates, &BTreeMap::new(), None, false);
        picker.toggle();
        picker.set_commander();
        assert!(picker.is_commander(0, 0));

        picker.toggle(); // unticks the commander row, clearing `commander` too
        picker.toggle(); // re-ticks it, but that alone does not restore commander status
        assert!(!picker.is_commander(0, 0));

        assert!(picker.submit().is_none());
        assert_eq!(
            picker.flash.as_deref(),
            Some("press `c` to choose a commander before connecting")
        );

        picker.set_commander();
        assert!(picker.submit().is_some());
    }

    #[test]
    fn submitting_an_empty_selection_is_refused() {
        let candidates = vec![candidate_single("ollama:llama3")];
        let mut picker = PickerState::new(candidates, &BTreeMap::new(), None, false);
        assert!(picker.submit().is_none());
        assert!(picker.flash.is_some());
    }

    #[test]
    fn submitting_produces_the_ticked_connections_and_commander() {
        let candidates = vec![candidate_single("ollama:llama3")];
        let mut picker = PickerState::new(candidates, &BTreeMap::new(), None, false);
        picker.toggle();
        picker.set_commander();
        let (connections, commander) = picker.submit().unwrap();
        assert!(connections["ollama:llama3"].enabled);
        assert_eq!(commander.as_deref(), Some("ollama:llama3"));
    }

    #[test]
    fn submitting_without_a_commander_refuses_and_flashes() {
        let candidates = vec![candidate_single("ollama:llama3")];
        let mut picker = PickerState::new(candidates, &BTreeMap::new(), None, false);
        picker.toggle(); // ticked, but no commander chosen

        assert!(picker.submit().is_none());
        assert_eq!(
            picker.flash.as_deref(),
            Some("press `c` to choose a commander before connecting")
        );
    }

    #[test]
    fn submitting_with_nothing_ticked_still_reports_that_first() {
        // Pins the ordering: with nothing ticked *and* no commander chosen, the
        // nothing-ticked flash must win — telling the user about a missing
        // commander first would be solving the wrong problem.
        let candidates = vec![candidate_single("ollama:llama3")];
        let mut picker = PickerState::new(candidates, &BTreeMap::new(), None, false);

        assert!(picker.submit().is_none());
        assert_eq!(
            picker.flash.as_deref(),
            Some("tick at least one connection before connecting")
        );
    }

    #[test]
    fn first_run_pre_ticks_every_available_candidate() {
        let candidates = vec![
            candidate_single("ollama:llama3"),
            candidate_dual("anthropic", true),
        ];
        let picker = PickerState::new(candidates, &BTreeMap::new(), None, true);
        assert!(picker.is_checked(0, 0));
        // anthropic's first available transport is CLI (index 0); API (index 1) is
        // unavailable in this fixture.
        assert!(picker.is_checked(1, 0));
        // Ticking is automatic on first run; choosing a commander is not — see
        // `a_first_run_starts_with_no_commander_until_the_user_picks_one`.
        assert!(!picker.is_commander(0, 0));
        assert!(!picker.is_commander(1, 0));
    }

    #[test]
    fn a_first_run_starts_with_no_commander_until_the_user_picks_one() {
        let candidates = vec![
            candidate_single("ollama:llama3"),
            candidate_dual("anthropic", true),
        ];
        let picker = PickerState::new(candidates, &BTreeMap::new(), None, true);
        assert!(picker.is_checked(0, 0));
        assert!(picker.is_checked(1, 0));

        for row in picker.rows() {
            assert!(!picker.is_commander(row.candidate, row.transport));
        }
    }

    #[test]
    fn saved_selection_is_restored_verbatim() {
        let candidates = vec![candidate_dual("anthropic", true)];
        let mut connections = BTreeMap::new();
        connections.insert(
            "anthropic".to_string(),
            ConnectionSpec {
                enabled: true,
                transport: Some(Transport::Cli),
                path: Some("/usr/bin/x".into()),
                model: None,
            },
        );
        let picker = PickerState::new(candidates, &connections, Some("anthropic"), false);
        assert!(picker.is_checked(0, 0));
        assert!(picker.is_commander(0, 0));
    }

    #[test]
    fn a_saved_commander_is_restored_without_asking_again() {
        let candidates = vec![candidate_single("ollama:llama3")];
        let mut connections = BTreeMap::new();
        connections.insert(
            "ollama:llama3".to_string(),
            ConnectionSpec {
                enabled: true,
                transport: None,
                path: None,
                model: None,
            },
        );
        let mut picker = PickerState::new(candidates, &connections, Some("ollama:llama3"), false);
        assert!(picker.is_commander(0, 0));

        let (connections, commander) = picker.submit().expect("a restored commander should submit");
        assert!(connections["ollama:llama3"].enabled);
        assert_eq!(commander.as_deref(), Some("ollama:llama3"));
        assert!(picker.flash.is_none());
    }

    #[test]
    fn only_the_chosen_transport_row_is_badged_commander() {
        // Regression: the marker keyed on the candidate alone, so a vendor with both
        // a CLI and an API row rendered "● commander" twice — including on the row
        // that was unavailable.
        let candidates = vec![candidate_dual("anthropic", true)];
        let mut picker = PickerState::new(candidates, &BTreeMap::new(), None, false);
        picker.toggle();
        picker.set_commander();

        assert!(picker.is_commander(0, 0));
        assert!(!picker.is_commander(0, 1));
    }
}

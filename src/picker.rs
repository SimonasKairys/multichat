//! Interactive connection-picker state, kept free of I/O so it can be unit-tested,
//! exactly as `src/app.rs` does for the chat TUI.

use std::collections::BTreeMap;

use zeroize::Zeroize;

use crate::config::{ConnectionSpec, Transport};
use crate::orchestrator::{Availability, Candidate, ConnectionState, TransportOption};

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

#[derive(Debug, Clone, PartialEq, Eq)]
struct ModelChoice {
    id: String,
    name: String,
}

/// Browsing the row list, entering a masked API key, or entering a model override.
/// Kept as an explicit mode rather than independent booleans so only one text field
/// can own keyboard input at a time.
enum Mode {
    Browsing,
    EnteringKey {
        candidate: usize,
        buffer: String,
    },
    EnteringModel {
        candidate: usize,
        transport: usize,
        buffer: String,
        /// Index into the (possibly typed-filtered) known-model list — see
        /// `model_options` — that `Up`/`Down` move and `Enter` confirms. Meaningless
        /// when that list is empty, which is the free-text-only case.
        selected: usize,
        /// Set once `Up`/`Down` has moved `selected`. `submit_model_entry` needs
        /// this to tell "the user arrowed onto a specific option, with an otherwise
        /// empty buffer" apart from "the user pressed `Enter` without touching
        /// anything" — the list can open pre-highlighted on the row's *current*
        /// model (which may be an override), and an untouched `Enter` must still
        /// clear that override back to the provider default, exactly as it did
        /// before this list existed.
        touched: bool,
    },
}

/// Picker state: candidates discovered up front, plus the user's in-progress
/// choices. Nothing here touches the filesystem, the network, or a terminal — in
/// particular, key entry never calls the keyring itself; it only hands a typed key
/// back to the caller (`src/ui/mod.rs::run_picker`), which is the one place that does.
pub struct PickerState {
    candidates: Vec<Candidate>,
    rows: Vec<RowRef>,
    selections: Vec<Selection>,
    /// Per-connection model overrides restored from and written back to
    /// `ConnectionSpec::model`. Providers use `None` for their default; a value such
    /// as `anthropic/claude-sonnet-4` selects that exact OpenRouter model.
    models: Vec<Option<String>>,
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
        let models = candidates
            .iter()
            .map(|c| connections.get(&c.id).and_then(|conn| conn.model.clone()))
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
            models,
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
    /// index — i.e. whether that row should render as connected. Two rows of the
    /// same candidate (e.g. "via CLI" / "via API") can never both be connected:
    /// they share one `Selection`, so enabling one always disables the other.
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

    pub fn connection_state(&self, candidate: usize, transport: usize) -> ConnectionState {
        ConnectionState::from_availability(
            self.is_checked(candidate, transport),
            &self.candidates[candidate].transports[transport].availability,
        )
    }

    /// Model name shown for a candidate. A user-entered override takes precedence
    /// over the discovered/default model name.
    pub fn display_model(&self, candidate: usize, transport: usize) -> &str {
        if let Some(model) = self.models[candidate].as_deref() {
            return model;
        }
        self.candidates[candidate].transports[transport]
            .cli
            .as_ref()
            .map(|cli| cli.binary_name.as_str())
            .unwrap_or(self.candidates[candidate].model.as_str())
    }

    /// `Some((candidate id, buffer length))` while a masked key prompt is open, so
    /// the UI can render `API key for <id>: ` followed by one `•` per typed
    /// character — the buffer's actual contents never leave this module through
    /// this accessor.
    pub fn key_entry(&self) -> Option<(&str, usize)> {
        match &self.mode {
            Mode::EnteringKey { candidate, buffer } => {
                // `chars().count()`, not `.len()`: the caller repeats one `•` per
                // *typed character*, and this codebase's user types Lithuanian —
                // 'š', 'ą', 'č' and friends are two UTF-8 bytes each. `.len()` would
                // report byte count, so one keystroke of a non-ASCII character would
                // render as two bullets.
                Some((
                    self.candidates[*candidate].id.as_str(),
                    buffer.chars().count(),
                ))
            }
            Mode::Browsing | Mode::EnteringModel { .. } => None,
        }
    }

    /// `Some((candidate id, current model, typed replacement))` while the model
    /// editor is open. Model names are not secrets, so the UI renders the buffer
    /// directly rather than masking it like an API key.
    pub fn model_entry(&self) -> Option<(&str, &str, &str)> {
        match &self.mode {
            Mode::EnteringModel {
                candidate,
                transport,
                buffer,
                ..
            } => Some((
                self.candidates[*candidate].id.as_str(),
                self.display_model(*candidate, *transport),
                buffer.as_str(),
            )),
            Mode::Browsing | Mode::EnteringKey { .. } => None,
        }
    }

    /// The row being edited's known-model pick-list, narrowed by whatever has been
    /// typed so far, paired with whether each entry is the one `Up`/`Down` last
    /// landed on. Always empty outside model entry, and also empty within it when
    /// the row's vendor/CLI has no known list (see `known_models_for`) — the UI
    /// falls back to showing just the typed buffer in that case, exactly as the
    /// model editor behaved before this list existed.
    pub fn model_options(&self) -> Vec<(String, bool)> {
        let options = self.current_model_options();
        let selected = match &self.mode {
            Mode::EnteringModel { selected, .. } => *selected,
            _ => 0,
        };
        options
            .into_iter()
            .enumerate()
            .map(|(i, option)| (option.name, i == selected))
            .collect()
    }

    /// The known-model pick-list for the row currently being edited, filtered to
    /// whatever has been typed so far. Shared by `model_options` (rendering) and
    /// the `move_model_selection_*` methods (clamping and buffer sync), so all
    /// three can never disagree about what is currently on screen.
    ///
    fn current_model_options(&self) -> Vec<ModelChoice> {
        match &self.mode {
            Mode::EnteringModel {
                candidate,
                transport,
                buffer,
                ..
            } => {
                let option = &self.candidates[*candidate].transports[*transport];
                let known = Self::known_models_for(option, &self.candidates[*candidate].id);
                Self::filter_options(&known, buffer)
            }
            _ => Vec::new(),
        }
    }

    /// Known model identifiers for the given row: the vendor's known models for an
    /// API row, or the CLI's known models for a CLI row. Empty when nothing is known
    /// (a custom endpoint, a hand-configured `local_binaries` CLI, or a CLI like
    /// `llm` with no fixed model set), in which case the caller's list is empty and
    /// the model editor is free-text only, exactly as it was before this list
    /// existed.
    fn known_models_for(option: &TransportOption, candidate_id: &str) -> Vec<ModelChoice> {
        match option.transport {
            Some(Transport::Api) => crate::config::known_models(candidate_id)
                .iter()
                .map(|model| ModelChoice {
                    id: (*model).to_string(),
                    name: (*model).to_string(),
                })
                .collect(),
            Some(Transport::Cli) => option.cli.as_ref().map_or_else(Vec::new, |cli| {
                if cli.models.is_empty() {
                    crate::orchestrator::known_cli_models(&cli.binary_name)
                        .iter()
                        .map(|model| ModelChoice {
                            id: (*model).to_string(),
                            name: (*model).to_string(),
                        })
                        .collect()
                } else {
                    cli.models
                        .iter()
                        .map(|model| ModelChoice {
                            id: model.id.clone(),
                            name: model.name.clone(),
                        })
                        .collect()
                }
            }),
            None => Vec::new(),
        }
    }

    /// Narrows a known-model list to whatever has been typed so far, with a
    /// case-insensitive substring match so e.g. `"sonnet"` finds
    /// `"claude-sonnet-5"` without requiring an exact prefix. An empty buffer
    /// matches everything, so the list opens showing every known option rather
    /// than nothing.
    fn filter_options(known: &[ModelChoice], buffer: &str) -> Vec<ModelChoice> {
        let needle = buffer.trim().to_ascii_lowercase();
        known
            .iter()
            .filter(|model| {
                needle.is_empty()
                    || model.id.to_ascii_lowercase().contains(&needle)
                    || model.name.to_ascii_lowercase().contains(&needle)
            })
            .cloned()
            .collect()
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
    /// the user with a stale connected marker they can never clear.
    pub fn toggle(&mut self) {
        // Text entry routes every keypress through the UI's dedicated match arm;
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
            Mode::EnteringKey { candidate, buffer } => (*candidate, buffer.trim().is_empty()),
            Mode::Browsing | Mode::EnteringModel { .. } => return None,
        };

        if is_empty {
            self.flash = Some("empty key — nothing stored".into());
            self.cancel_key_entry();
            return None;
        }

        let id = self.candidates[candidate].id.clone();
        match std::mem::replace(&mut self.mode, Mode::Browsing) {
            Mode::EnteringKey { buffer, .. } => Some((id, buffer)),
            Mode::Browsing | Mode::EnteringModel { .. } => {
                unreachable!("checked above: mode was EnteringKey")
            }
        }
    }

    /// Called by the UI after it has written the key to the OS keyring: flips the
    /// row to available-unverified (the key is now stored but not yet probed),
    /// ticks it (mirrors the normal enabling path in `toggle`, since this row is
    /// now exactly as selectable as any other available one), and flashes confirmation.
    pub fn mark_key_stored(&mut self, candidate: usize, transport: usize) {
        let option = &mut self.candidates[candidate].transports[transport];
        option.availability =
            Availability::AvailableUnverified("key stored; authentication not yet checked".into());
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

    // --- model entry -------------------------------------------------------------

    /// Opens model entry for a row whose transport accepts an explicit model. The
    /// buffer starts empty so the known-model list (see `model_options`) renders
    /// unfiltered, and the highlight opens on the row's current model when that
    /// model is one of the known ones — so re-opening the editor shows what's
    /// already in effect instead of always resetting to the top of the list.
    /// Submitting an empty buffer still deliberately restores the provider's
    /// default model, exactly as before this list existed.
    pub fn start_model_entry(&mut self) {
        if !matches!(self.mode, Mode::Browsing) {
            return;
        }

        let Some(row) = self.current_row() else {
            return;
        };
        let option = &self.candidates[row.candidate].transports[row.transport];
        let unsupported = match option.transport {
            Some(Transport::Api) => None,
            Some(Transport::Cli)
                if option
                    .cli
                    .as_ref()
                    .and_then(|cli| cli.model_arg.as_ref())
                    .is_some() =>
            {
                None
            }
            Some(Transport::Cli) => Some("this CLI has no model-selection flag configured"),
            None => Some("choose a different Ollama model row"),
        };
        if let Some(reason) = unsupported {
            self.flash = Some(reason.into());
            return;
        }

        let known = Self::known_models_for(option, &self.candidates[row.candidate].id);
        let current = self.display_model(row.candidate, row.transport);
        let selected = known
            .iter()
            .position(|model| {
                model.id.eq_ignore_ascii_case(current) || model.name.eq_ignore_ascii_case(current)
            })
            .unwrap_or(0);

        self.mode = Mode::EnteringModel {
            candidate: row.candidate,
            transport: row.transport,
            buffer: String::new(),
            selected,
            touched: false,
        };
        self.flash = None;
    }

    /// Appends a typed character to the model filter and resets the highlight back
    /// to the top match — the same behaviour any filtered pick-list needs, since the
    /// previously highlighted row may no longer be part of the narrowed list at all.
    pub fn push_model_char(&mut self, c: char) {
        if let Mode::EnteringModel {
            buffer, selected, ..
        } = &mut self.mode
        {
            buffer.push(c);
            *selected = 0;
        }
    }

    pub fn backspace_model(&mut self) {
        if let Mode::EnteringModel {
            buffer, selected, ..
        } = &mut self.mode
        {
            buffer.pop();
            *selected = 0;
        }
    }

    /// Moves the model pick-list highlight up by one row. A no-op at the top, and a
    /// no-op outside model entry (the `if let` simply does not match). Deliberately
    /// leaves `buffer` untouched — writing the highlighted name into it would make
    /// the very next list computation filter on that name and collapse down to just
    /// one row, trapping further movement a single step in.
    pub fn move_model_selection_up(&mut self) {
        if let Mode::EnteringModel {
            selected, touched, ..
        } = &mut self.mode
        {
            *selected = selected.saturating_sub(1);
            *touched = true;
        }
    }

    /// Moves the model pick-list highlight down by one row, clamped to the
    /// (possibly filtered) list's current length so it can never point past the
    /// last option actually on screen. See `move_model_selection_up` for why
    /// `buffer` is left alone.
    pub fn move_model_selection_down(&mut self) {
        let len = self.current_model_options().len();
        if let Mode::EnteringModel {
            selected, touched, ..
        } = &mut self.mode
        {
            if *selected + 1 < len {
                *selected += 1;
            }
            *touched = true;
        }
    }

    pub fn cancel_model_entry(&mut self) {
        if matches!(self.mode, Mode::EnteringModel { .. }) {
            self.mode = Mode::Browsing;
        }
    }

    /// Applies the chosen model override.
    ///
    /// With typed text: an exact (case-insensitive) match against the row's
    /// known-model list always wins — so typing an id in full behaves the same
    /// regardless of what else that id happens to be a substring of — and failing
    /// that, whatever the (typed-filtered) pick-list highlight currently rests on
    /// is used. If the row has no known list at all, or the typed text matches
    /// nothing in it, the typed buffer is used verbatim, exactly like the
    /// free-text-only editor this replaced.
    ///
    /// With an empty buffer: confirms the pick-list highlight if `Up`/`Down` was
    /// used to explicitly land on it (`touched`), otherwise clears the override
    /// and returns to the endpoint default — the behaviour the empty case always
    /// had, preserved for a bare `Enter` that never touched the list at all.
    pub fn submit_model_entry(&mut self) {
        let (candidate, transport, buffer, selected, touched) =
            match std::mem::replace(&mut self.mode, Mode::Browsing) {
                Mode::EnteringModel {
                    candidate,
                    transport,
                    buffer,
                    selected,
                    touched,
                } => (candidate, transport, buffer, selected, touched),
                other => {
                    self.mode = other;
                    return;
                }
            };

        let typed = buffer.trim();
        let option = &self.candidates[candidate].transports[transport];
        let known = Self::known_models_for(option, &self.candidates[candidate].id);

        let chosen = if !typed.is_empty() {
            Some(
                known
                    .iter()
                    .find(|model| {
                        model.id.eq_ignore_ascii_case(typed)
                            || model.name.eq_ignore_ascii_case(typed)
                    })
                    .map(|model| model.id.clone())
                    .or_else(|| {
                        Self::filter_options(&known, &buffer)
                            .get(selected)
                            .map(|model| model.id.clone())
                    })
                    .unwrap_or_else(|| typed.to_string()),
            )
        } else if touched {
            known.get(selected).map(|model| model.id.clone())
        } else {
            None
        };

        match chosen {
            Some(model) => {
                self.models[candidate] = Some(model.clone());
                self.flash = Some(format!("model set to {model}"));
            }
            None => {
                self.models[candidate] = None;
                self.flash = Some("model reset to provider default".into());
            }
        }
    }

    /// Cycles which transport the highlighted candidate would use, without changing
    /// whether it is enabled. A no-op on a single-transport candidate (Ollama).
    ///
    /// This used to cycle blindly through every transport index, which meant Tab
    /// could land — and, once `enabled`, silently submit — on a transport `toggle`
    /// and `set_commander` would both have refused: a cloud API with no stored key,
    /// or (worse) any remote transport under `--classified`, the one flag this
    /// program promises never lets traffic off the machine. Skipping unavailable
    /// transports here, the same signal every other selection path already checks,
    /// is the fix: it keeps one source of truth (`Availability`) instead of adding
    /// a second "is this okay for Tab" check that could drift from the first.
    ///
    /// When every other transport is unavailable there is nothing to cycle to, so
    /// this flashes why instead of silently doing nothing — consistent with how
    /// `toggle`/`set_commander` explain a refusal rather than swallowing the
    /// keypress.
    pub fn cycle_transport(&mut self) {
        let Some(row) = self.current_row() else {
            return;
        };
        let candidate = row.candidate;
        let n = self.candidates[candidate].transports.len();
        if n < 2 {
            return;
        }

        let start = self.selections[candidate].chosen;
        let mut probe = start;
        for _ in 0..n - 1 {
            probe = (probe + 1) % n;
            if self.candidates[candidate].transports[probe]
                .availability
                .is_available()
            {
                self.flash = None;
                self.selections[candidate].chosen = probe;
                return;
            }
        }

        // Nothing else to switch to. Flash the reason attached to the very next
        // transport in the cycle — the one a single Tab press would most plausibly
        // have expected to land on — rather than a generic message.
        let next = (start + 1) % n;
        if let Availability::Unavailable(reason) =
            &self.candidates[candidate].transports[next].availability
        {
            self.flash = Some(reason.clone());
        }
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

        // Belt and braces. `toggle`, `set_commander` and `cycle_transport` all gate
        // on `Availability` before letting a row become enabled/chosen/commander,
        // so in the ordinary run of the UI nothing unavailable ever reaches here.
        // But availability can also shift out from under an *already* enabled
        // selection with no picker interaction at all — a saved connection whose
        // API key was deleted from the keyring between runs is restored straight
        // into `Selection { enabled: true, .. }` by `initial_selection`, never
        // touching any of the gated paths. Re-checking here is the one place that
        // catches that case, and it is also the last line of defence for
        // `--classified`: if any selection path upstream ever regresses (as
        // `cycle_transport` once did), this still refuses to hand back a
        // connection the availability rules forbid.
        for (i, candidate) in self.candidates.iter().enumerate() {
            let sel = &self.selections[i];
            if !sel.enabled {
                continue;
            }
            if let Some(Availability::Unavailable(reason)) = candidate
                .transports
                .get(sel.chosen)
                .map(|opt| &opt.availability)
            {
                self.flash = Some(format!("{}: {reason}", candidate.id));
                return None;
            }
        }

        let mut connections = BTreeMap::new();
        for (i, candidate) in self.candidates.iter().enumerate() {
            let sel = &self.selections[i];
            let option = candidate.transports.get(sel.chosen);
            connections.insert(
                candidate.id.clone(),
                ConnectionSpec {
                    enabled: sel.enabled,
                    transport: option.and_then(|opt| opt.transport),
                    path: option.and_then(|opt| opt.cli.as_ref().map(|cli| cli.path.clone())),
                    model: self.models[i].clone(),
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
                        model_arg: Some("--model".into()),
                        system_arg: None,
                        dialect: None,
                        workspace_arg: None,
                        models: Vec::new(),
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

    /// Like `candidate_dual`, but with both transport rows available — for
    /// exercising ordinary cycling where the landing row is actually selectable,
    /// as opposed to the refusal path `candidate_dual`'s API row is built for.
    fn candidate_dual_both_available(id: &str) -> Candidate {
        Candidate {
            id: id.into(),
            group: id.to_uppercase(),
            model: id.into(),
            transports: vec![
                crate::orchestrator::TransportOption {
                    transport: Some(Transport::Cli),
                    label: "via CLI".into(),
                    detail: "/usr/bin/x".into(),
                    availability: Availability::Available,
                    cli: Some(CliSpec {
                        binary_name: id.into(),
                        path: "/usr/bin/x".into(),
                        args: vec![],
                        model_arg: Some("--model".into()),
                        system_arg: None,
                        dialect: None,
                        workspace_arg: None,
                        models: Vec::new(),
                    }),
                    needs_key: false,
                },
                crate::orchestrator::TransportOption {
                    transport: Some(Transport::Api),
                    label: "via API".into(),
                    detail: "(key stored)".into(),
                    availability: Availability::Available,
                    cli: None,
                    needs_key: false,
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
        assert_eq!(picker.connection_state(0, 0), ConnectionState::NotConnected);
        assert!(!picker.is_checked(0, 0));
        picker.toggle();
        assert_eq!(picker.connection_state(0, 0), ConnectionState::Connected);
        assert!(picker.is_checked(0, 0));
        picker.toggle();
        assert_eq!(picker.connection_state(0, 0), ConnectionState::NotConnected);
        assert!(!picker.is_checked(0, 0));
    }

    #[test]
    fn tab_cycles_transport_without_changing_enabled() {
        // Both rows available here: `candidate_dual`'s API row would make this a
        // refusal case, which is covered separately by
        // `cycle_transport_cannot_land_on_a_cloud_transport_with_no_stored_key`.
        let candidates = vec![candidate_dual_both_available("anthropic")];
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
    fn typing_a_lithuanian_character_reports_one_typed_character_not_two_bytes() {
        // The masked prompt renders one `•` per *typed character*
        // (`src/ui/mod.rs::draw_picker`: `"•".repeat(len)`), per `key_entry`'s own
        // doc comment. This codebase's user types Lithuanian, so ordinary input
        // includes multi-byte UTF-8 scalars like 'š' (2 bytes). If `key_entry`
        // reports a byte count instead of a character count, typing one 'š' would
        // render two bullets for one keystroke.
        let candidates = vec![candidate_dual("anthropic", true)];
        let mut picker = PickerState::new(candidates, &BTreeMap::new(), None, false);
        picker.move_down();
        picker.toggle();

        picker.push_key_char('š');

        assert_eq!(
            picker.key_entry().unwrap().1,
            1,
            "one typed character must report length 1, not its UTF-8 byte count"
        );
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
    fn submitting_a_whitespace_only_key_stores_nothing_and_flashes() {
        let candidates = vec![candidate_dual("anthropic", true)];
        let mut picker = PickerState::new(candidates, &BTreeMap::new(), None, false);
        picker.move_down();
        picker.toggle();
        picker.push_key_char(' ');
        picker.push_key_char(' ');

        let result = picker.submit_key_entry();

        assert!(
            result.is_none(),
            "whitespace-only key must not be submitted"
        );
        assert!(picker.key_entry().is_none());
        assert_eq!(picker.flash.as_deref(), Some("empty key — nothing stored"));
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
        // so refusing the un-tick would trap the user with a permanent connected marker.
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
        assert_eq!(
            picker.connection_state(0, 1),
            ConnectionState::ConnectedUnavailable
        );

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
    fn api_model_override_can_be_entered_and_is_saved() {
        let candidates = vec![Candidate {
            id: "openrouter".into(),
            group: "OPENROUTER".into(),
            model: "openai/gpt-4o".into(),
            transports: vec![crate::orchestrator::TransportOption {
                transport: Some(Transport::Api),
                label: "via API".into(),
                detail: "https://openrouter.ai/api/v1".into(),
                availability: Availability::Available,
                cli: None,
                needs_key: false,
            }],
        }];
        let mut picker = PickerState::new(candidates, &BTreeMap::new(), None, false);

        picker.start_model_entry();
        for c in "anthropic/claude-sonnet-4".chars() {
            picker.push_model_char(c);
        }
        picker.submit_model_entry();
        picker.toggle();
        picker.set_commander();

        assert_eq!(picker.display_model(0, 0), "anthropic/claude-sonnet-4");
        let (connections, commander) = picker.submit().expect("configured model should submit");
        assert_eq!(commander.as_deref(), Some("openrouter"));
        assert_eq!(
            connections["openrouter"].model.as_deref(),
            Some("anthropic/claude-sonnet-4")
        );
    }

    #[test]
    fn cli_model_override_can_be_entered_and_is_saved() {
        let candidates = vec![candidate_dual_both_available("copilot")];
        let mut picker = PickerState::new(candidates, &BTreeMap::new(), None, false);

        picker.start_model_entry();
        for c in "gpt-5.4".chars() {
            picker.push_model_char(c);
        }
        picker.submit_model_entry();
        picker.toggle();
        picker.set_commander();

        assert_eq!(picker.display_model(0, 0), "gpt-5.4");
        let (connections, commander) = picker.submit().expect("configured model should submit");
        assert_eq!(commander.as_deref(), Some("copilot"));
        assert_eq!(connections["copilot"].model.as_deref(), Some("gpt-5.4"));
    }

    #[test]
    fn api_and_cli_rows_show_their_own_default_model() {
        let candidates = vec![Candidate {
            id: "anthropic".into(),
            group: "ANTHROPIC".into(),
            model: "claude-opus-5".into(),
            transports: vec![
                crate::orchestrator::TransportOption {
                    transport: Some(Transport::Cli),
                    label: "via CLI".into(),
                    detail: "/usr/bin/claude".into(),
                    availability: Availability::Available,
                    cli: Some(CliSpec {
                        binary_name: "claude".into(),
                        path: "/usr/bin/claude".into(),
                        args: vec![],
                        model_arg: Some("--model".into()),
                        system_arg: None,
                        dialect: None,
                        workspace_arg: None,
                        models: Vec::new(),
                    }),
                    needs_key: false,
                },
                crate::orchestrator::TransportOption {
                    transport: Some(Transport::Api),
                    label: "via API".into(),
                    detail: "https://api.anthropic.com".into(),
                    availability: Availability::Available,
                    cli: None,
                    needs_key: false,
                },
            ],
        }];
        let picker = PickerState::new(candidates, &BTreeMap::new(), None, false);

        assert_eq!(picker.display_model(0, 0), "claude");
        assert_eq!(picker.display_model(0, 1), "claude-opus-5");
    }

    #[test]
    fn picker_preserves_an_existing_model_override() {
        let candidates = vec![Candidate {
            id: "openrouter".into(),
            group: "OPENROUTER".into(),
            model: "openai/gpt-4o".into(),
            transports: vec![crate::orchestrator::TransportOption {
                transport: Some(Transport::Api),
                label: "via API".into(),
                detail: "https://openrouter.ai/api/v1".into(),
                availability: Availability::Available,
                cli: None,
                needs_key: false,
            }],
        }];
        let mut connections = BTreeMap::new();
        connections.insert(
            "openrouter".into(),
            ConnectionSpec {
                enabled: true,
                transport: Some(Transport::Api),
                path: None,
                model: Some("google/gemini-2.5-pro".into()),
            },
        );
        let mut picker = PickerState::new(candidates, &connections, Some("openrouter"), false);

        assert_eq!(picker.display_model(0, 0), "google/gemini-2.5-pro");
        let (saved, _) = picker.submit().expect("restored selection should submit");
        assert_eq!(
            saved["openrouter"].model.as_deref(),
            Some("google/gemini-2.5-pro")
        );
    }

    #[test]
    fn empty_model_entry_restores_the_provider_default() {
        let candidates = vec![Candidate {
            id: "openrouter".into(),
            group: "OPENROUTER".into(),
            model: "openai/gpt-4o".into(),
            transports: vec![crate::orchestrator::TransportOption {
                transport: Some(Transport::Api),
                label: "via API".into(),
                detail: "https://openrouter.ai/api/v1".into(),
                availability: Availability::Available,
                cli: None,
                needs_key: false,
            }],
        }];
        let mut connections = BTreeMap::new();
        connections.insert(
            "openrouter".into(),
            ConnectionSpec {
                enabled: true,
                transport: Some(Transport::Api),
                path: None,
                model: Some("google/gemini-2.5-pro".into()),
            },
        );
        let mut picker = PickerState::new(candidates, &connections, Some("openrouter"), false);

        picker.start_model_entry();
        picker.submit_model_entry();

        assert_eq!(picker.display_model(0, 0), "openai/gpt-4o");
        let (saved, _) = picker.submit().expect("restored selection should submit");
        assert_eq!(saved["openrouter"].model, None);
    }

    #[test]
    fn model_entry_opens_with_the_known_list_for_a_known_vendor() {
        let candidates = vec![Candidate {
            id: "anthropic".into(),
            group: "ANTHROPIC".into(),
            model: "claude-opus-5".into(),
            transports: vec![crate::orchestrator::TransportOption {
                transport: Some(Transport::Api),
                label: "via API".into(),
                detail: "https://api.anthropic.com".into(),
                availability: Availability::Available,
                cli: None,
                needs_key: false,
            }],
        }];
        let mut picker = PickerState::new(candidates, &BTreeMap::new(), None, false);

        picker.start_model_entry();
        let options = picker.model_options();

        assert!(
            !options.is_empty(),
            "a known vendor should offer a non-empty pick-list"
        );
        assert!(options.iter().any(|(name, _)| name == "claude-opus-5"));
        // The row's current model (its endpoint default here) is highlighted first,
        // so re-opening the editor shows what's already in effect rather than
        // always landing on the top of the list regardless of the current value.
        assert_eq!(
            options
                .iter()
                .find(|(_, selected)| *selected)
                .map(|(name, selected)| (name.as_str(), *selected)),
            Some(("claude-opus-5", true))
        );
    }

    #[test]
    fn model_entry_has_no_known_list_for_an_unlisted_vendor() {
        let candidates = vec![Candidate {
            id: "my-custom-gateway".into(),
            group: "MY-CUSTOM-GATEWAY".into(),
            model: "whatever-they-called-it".into(),
            transports: vec![crate::orchestrator::TransportOption {
                transport: Some(Transport::Api),
                label: "via API".into(),
                detail: "https://example.com".into(),
                availability: Availability::Available,
                cli: None,
                needs_key: false,
            }],
        }];
        let mut picker = PickerState::new(candidates, &BTreeMap::new(), None, false);

        picker.start_model_entry();

        assert!(picker.model_options().is_empty());
    }

    #[test]
    fn typing_filters_the_known_model_list() {
        let candidates = vec![candidate_refused("anthropic", "unused")];
        // `candidate_refused` builds a single API row; availability does not matter
        // for entering a model, only for connecting.
        let mut picker = PickerState::new(candidates, &BTreeMap::new(), None, false);

        picker.start_model_entry();
        for c in "sonnet".chars() {
            picker.push_model_char(c);
        }

        let options = picker.model_options();
        assert!(!options.is_empty());
        assert!(
            options
                .iter()
                .all(|(name, _)| name.to_ascii_lowercase().contains("sonnet")),
            "filtered list must only contain matches for the typed text: {options:?}"
        );
    }

    #[test]
    fn arrow_down_moves_the_highlight_without_touching_the_typed_buffer() {
        let candidates = vec![candidate_refused("anthropic", "unused")];
        let mut picker = PickerState::new(candidates, &BTreeMap::new(), None, false);

        picker.start_model_entry();
        assert!(picker.model_options()[0].1);

        picker.move_model_selection_down();

        assert!(!picker.model_options()[0].1);
        assert!(picker.model_options()[1].1);
        // Arrowing must not fill the buffer — otherwise the very next
        // recomputation of the list would filter itself down to just that one
        // name (a self-collapsing list), trapping further `Down` presses on the
        // second row forever.
        assert_eq!(picker.model_entry().unwrap().2, "");
    }

    #[test]
    fn arrow_down_can_move_through_the_entire_known_list_without_collapsing() {
        let candidates = vec![candidate_refused("anthropic", "unused")];
        let mut picker = PickerState::new(candidates, &BTreeMap::new(), None, false);

        picker.start_model_entry();
        let len = picker.model_options().len();
        assert!(
            len > 1,
            "anthropic's known list should have more than one entry"
        );

        for _ in 0..len - 1 {
            picker.move_model_selection_down();
            assert_eq!(
                picker.model_options().len(),
                len,
                "the list must not shrink while arrowing through it"
            );
        }
        assert!(picker.model_options()[len - 1].1);

        // One more `Down` past the end stays clamped on the last row.
        picker.move_model_selection_down();
        assert!(picker.model_options()[len - 1].1);
    }

    #[test]
    fn arrow_up_from_the_top_of_the_list_is_a_no_op() {
        let candidates = vec![candidate_refused("anthropic", "unused")];
        let mut picker = PickerState::new(candidates, &BTreeMap::new(), None, false);

        picker.start_model_entry();
        picker.move_model_selection_up();

        // Still on the first row. Note that `touched` is now `true` (the key was
        // pressed), so — unlike a bare `Enter` that never arrowed at all — this
        // would confirm that first row rather than reset to the provider default;
        // see `enter_after_arrowing_with_no_typing_confirms_the_highlighted_model`.
        assert!(picker.model_options()[0].1);
        assert_eq!(picker.model_entry().unwrap().2, "");
    }

    #[test]
    fn enter_after_arrowing_with_no_typing_confirms_the_highlighted_model() {
        let candidates = vec![Candidate {
            id: "openrouter".into(),
            group: "OPENROUTER".into(),
            model: "openai/gpt-4o".into(),
            transports: vec![crate::orchestrator::TransportOption {
                transport: Some(Transport::Api),
                label: "via API".into(),
                detail: "https://openrouter.ai/api/v1".into(),
                availability: Availability::Available,
                cli: None,
                needs_key: false,
            }],
        }];
        let mut picker = PickerState::new(candidates, &BTreeMap::new(), None, false);

        picker.start_model_entry();
        picker.move_model_selection_down();
        let expected = picker
            .model_options()
            .into_iter()
            .find(|(_, selected)| *selected)
            .map(|(name, _)| name.to_string())
            .expect("moving down should keep some row highlighted");
        picker.submit_model_entry();

        // Distinguishes this from `empty_model_entry_restores_the_provider_default`:
        // arrowing (even with zero typed characters) must not be read as an empty
        // submit, or the pick-list would be unusable by keyboard alone.
        assert_eq!(picker.display_model(0, 0), expected);
    }

    #[test]
    fn arrow_keys_are_a_no_op_when_the_row_has_no_known_model_list() {
        let candidates = vec![Candidate {
            id: "my-custom-gateway".into(),
            group: "MY-CUSTOM-GATEWAY".into(),
            model: "whatever-they-called-it".into(),
            transports: vec![crate::orchestrator::TransportOption {
                transport: Some(Transport::Api),
                label: "via API".into(),
                detail: "https://example.com".into(),
                availability: Availability::Available,
                cli: None,
                needs_key: false,
            }],
        }];
        let mut picker = PickerState::new(candidates, &BTreeMap::new(), None, false);

        picker.start_model_entry();
        picker.move_model_selection_down();
        picker.move_model_selection_up();

        assert!(picker.model_options().is_empty());
        assert_eq!(picker.model_entry().unwrap().2, "");
    }

    #[test]
    fn typing_a_value_outside_the_known_list_falls_back_to_the_typed_text() {
        // OpenRouter's real catalog is far larger than the curated pick-list, so an
        // id that is not one of the suggestions must still work exactly as free-text
        // entry did before the list existed.
        let candidates = vec![Candidate {
            id: "openrouter".into(),
            group: "OPENROUTER".into(),
            model: "openai/gpt-4o".into(),
            transports: vec![crate::orchestrator::TransportOption {
                transport: Some(Transport::Api),
                label: "via API".into(),
                detail: "https://openrouter.ai/api/v1".into(),
                availability: Availability::Available,
                cli: None,
                needs_key: false,
            }],
        }];
        let mut picker = PickerState::new(candidates, &BTreeMap::new(), None, false);

        picker.start_model_entry();
        for c in "mistralai/mistral-large-2411".chars() {
            picker.push_model_char(c);
        }
        picker.submit_model_entry();

        assert_eq!(picker.display_model(0, 0), "mistralai/mistral-large-2411");
    }

    #[test]
    fn a_cli_row_offers_its_own_known_model_list() {
        let candidates = vec![candidate_dual_both_available("copilot")];
        let mut picker = PickerState::new(candidates, &BTreeMap::new(), None, false);
        picker.move_down(); // land on the API row first...
        picker.move_up(); //  ...then back onto the CLI row (index 0), explicitly.

        picker.start_model_entry();

        let options = picker.model_options();
        assert!(options.iter().any(|(name, _)| name == "gpt-5.4"));
        assert!(options.iter().any(|(name, _)| name == "claude-sonnet-5"));
    }

    #[test]
    fn a_discovered_cli_model_shows_its_name_but_saves_its_id() {
        let mut candidate = candidate_dual_both_available("agy");
        let cli = candidate.transports[0].cli.as_mut().unwrap();
        cli.models = vec![
            crate::orchestrator::CliModelOption {
                id: "gemini-3.7-flash-high".into(),
                name: "Gemini 3.7 Flash (High)".into(),
            },
            crate::orchestrator::CliModelOption {
                id: "claude-sonnet-4-6".into(),
                name: "Claude Sonnet 4.6 (Thinking)".into(),
            },
        ];
        let mut picker = PickerState::new(vec![candidate], &BTreeMap::new(), None, false);

        picker.start_model_entry();
        assert_eq!(
            picker
                .model_options()
                .into_iter()
                .map(|(name, _)| name)
                .collect::<Vec<_>>(),
            ["Gemini 3.7 Flash (High)", "Claude Sonnet 4.6 (Thinking)"]
        );
        picker.move_model_selection_down();
        picker.submit_model_entry();

        assert_eq!(picker.display_model(0, 0), "claude-sonnet-4-6");
    }

    #[test]
    fn discovered_cli_models_filter_by_id_or_human_name() {
        let mut candidate = candidate_dual_both_available("agy");
        candidate.transports[0].cli.as_mut().unwrap().models = vec![
            crate::orchestrator::CliModelOption {
                id: "gemini-3.7-flash-high".into(),
                name: "Gemini 3.7 Flash (High)".into(),
            },
            crate::orchestrator::CliModelOption {
                id: "claude-sonnet-4-6".into(),
                name: "Claude Sonnet 4.6 (Thinking)".into(),
            },
        ];

        let mut by_id = PickerState::new(vec![candidate.clone()], &BTreeMap::new(), None, false);
        by_id.start_model_entry();
        for c in "sonnet-4-6".chars() {
            by_id.push_model_char(c);
        }
        assert_eq!(
            by_id.model_options(),
            vec![("Claude Sonnet 4.6 (Thinking)".into(), true)]
        );

        let mut by_name = PickerState::new(vec![candidate], &BTreeMap::new(), None, false);
        by_name.start_model_entry();
        for c in "thinking".chars() {
            by_name.push_model_char(c);
        }
        assert_eq!(
            by_name.model_options(),
            vec![("Claude Sonnet 4.6 (Thinking)".into(), true)]
        );
    }

    #[test]
    fn discovered_cli_editor_highlights_a_saved_model_id() {
        let mut candidate = candidate_dual_both_available("agy");
        candidate.transports[0].cli.as_mut().unwrap().models = vec![
            crate::orchestrator::CliModelOption {
                id: "gemini-3.7-flash-high".into(),
                name: "Gemini 3.7 Flash (High)".into(),
            },
            crate::orchestrator::CliModelOption {
                id: "claude-sonnet-4-6".into(),
                name: "Claude Sonnet 4.6 (Thinking)".into(),
            },
        ];
        let mut connections = BTreeMap::new();
        connections.insert(
            "agy".into(),
            ConnectionSpec {
                enabled: true,
                transport: Some(Transport::Cli),
                path: None,
                model: Some("claude-sonnet-4-6".into()),
            },
        );
        let mut picker = PickerState::new(vec![candidate], &connections, Some("agy"), false);

        picker.start_model_entry();

        assert_eq!(
            picker.model_options(),
            vec![
                ("Gemini 3.7 Flash (High)".into(), false),
                ("Claude Sonnet 4.6 (Thinking)".into(), true),
            ]
        );
    }

    #[test]
    fn exact_human_name_wins_over_an_earlier_partial_match() {
        let mut candidate = candidate_dual_both_available("agy");
        candidate.transports[0].cli.as_mut().unwrap().models = vec![
            crate::orchestrator::CliModelOption {
                id: "preview-id".into(),
                name: "Claude Sonnet 4.6 (Thinking) Preview".into(),
            },
            crate::orchestrator::CliModelOption {
                id: "stable-id".into(),
                name: "Claude Sonnet 4.6 (Thinking)".into(),
            },
        ];
        let mut picker = PickerState::new(vec![candidate], &BTreeMap::new(), None, false);

        picker.start_model_entry();
        for c in "Claude Sonnet 4.6 (Thinking)".chars() {
            picker.push_model_char(c);
        }
        picker.submit_model_entry();

        assert_eq!(picker.display_model(0, 0), "stable-id");
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
        assert_eq!(picker.connection_state(0, 0), ConnectionState::Connected);
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

    /// A vendor with a local CLI (always available) and a remote API refused under
    /// `--classified` — the exact shape `discover_vendors` builds when `--classified`
    /// is set (see `src/orchestrator.rs`'s `build_vendor_candidate`). `needs_key`
    /// stays false: unlike a missing key, a classified refusal is not something
    /// the picker can fix by prompting.
    fn candidate_local_and_classified_remote(id: &str) -> Candidate {
        Candidate {
            id: id.into(),
            group: id.to_uppercase(),
            model: id.into(),
            transports: vec![
                crate::orchestrator::TransportOption {
                    transport: Some(Transport::Cli),
                    label: "via CLI".into(),
                    detail: "/usr/bin/x".into(),
                    availability: Availability::Available,
                    cli: Some(CliSpec {
                        binary_name: id.into(),
                        path: "/usr/bin/x".into(),
                        args: vec![],
                        model_arg: Some("--model".into()),
                        system_arg: None,
                        dialect: None,
                        workspace_arg: None,
                        models: Vec::new(),
                    }),
                    needs_key: false,
                },
                crate::orchestrator::TransportOption {
                    transport: Some(Transport::Api),
                    label: "via API".into(),
                    detail: String::new(),
                    availability: Availability::Unavailable(
                        "cloud APIs are refused under --classified".into(),
                    ),
                    cli: None,
                    needs_key: false,
                },
            ],
        }
    }

    #[test]
    fn cycle_transport_cannot_land_on_a_cloud_transport_with_no_stored_key() {
        // Inverted from the external audit's `bug_cycle_transport_selects_
        // unavailable_transport_and_submits_it`, which asserted the *broken*
        // behaviour — Tab landing on, and submit() persisting, an API row with no
        // stored key — and passed before this fix. Same setup, opposite assertions.
        let candidate = candidate_dual("anthropic", true);
        let mut picker = PickerState::new(vec![candidate], &BTreeMap::new(), None, false);

        picker.toggle(); // ticks the CLI row (available)
        picker.set_commander();
        assert!(picker.is_commander(0, 0));
        assert!(picker.is_checked(0, 0));
        // Fixture guard: the only other transport really is unavailable, so a
        // no-op here would be meaningless.
        assert!(
            !picker.candidates()[0].transports[1]
                .availability
                .is_available()
        );

        picker.cycle_transport(); // the only other transport (API) needs a key

        // Tab must not move onto the unavailable row...
        assert!(!picker.is_checked(0, 1));
        assert!(!picker.is_commander(0, 1));
        // ...and must leave the still-valid CLI selection exactly as it was,
        // rather than e.g. clearing commander status as a side effect of refusing.
        assert!(picker.is_checked(0, 0));
        assert!(picker.is_commander(0, 0));
        assert_eq!(picker.flash.as_deref(), Some("no key stored"));

        let (connections, commander) = picker.submit().expect("the CLI selection is still valid");
        assert_eq!(commander.as_deref(), Some("anthropic"));
        let conn = &connections["anthropic"];
        assert!(conn.enabled);
        assert_eq!(conn.transport, Some(Transport::Cli));
    }

    #[test]
    fn submit_refuses_a_saved_connection_that_has_become_unavailable() {
        // Inverted from the external audit's `bug_submit_permits_submitting_
        // unavailable_saved_connection_and_commander`, which asserted submit()
        // handed back an unavailable commander and passed before this fix.
        //
        // This is also the "previously saved connection that has since become
        // unavailable" case: nothing in the picker's own interaction paths ever ran
        // — `initial_selection` restored `enabled: true` straight from config — so
        // only submit()'s own belt-and-braces check can catch it.
        let candidate = candidate_refused("anthropic", "cloud APIs are refused under --classified");
        let mut connections = BTreeMap::new();
        connections.insert(
            "anthropic".into(),
            ConnectionSpec {
                enabled: true,
                transport: Some(Transport::Api),
                path: None,
                model: None,
            },
        );

        let mut picker = PickerState::new(vec![candidate], &connections, Some("anthropic"), false);
        assert!(picker.is_checked(0, 0));
        assert!(picker.is_commander(0, 0));
        // Fixture guard: the restored row really is unavailable.
        assert!(
            !picker.candidates()[0].transports[0]
                .availability
                .is_available()
        );

        let result = picker.submit();
        assert!(
            result.is_none(),
            "submit must refuse an unavailable commander"
        );
        assert_eq!(
            picker.flash.as_deref(),
            Some("anthropic: cloud APIs are refused under --classified")
        );
        // Refusing does not silently rewrite state out from under the user: the
        // row is left exactly as ticked/commandered as it was, so they can see it
        // and fix it (e.g. by un-ticking it) rather than wondering what happened.
        assert!(picker.is_checked(0, 0));
        assert!(picker.is_commander(0, 0));
    }

    #[test]
    fn classified_blocks_tab_and_submit_on_a_remote_transport() {
        // Belt and braces for the strongest promise this program makes: under
        // `--classified`, no remote transport may ever be selected, however it got
        // there.
        let candidate = candidate_local_and_classified_remote("anthropic");
        let mut picker = PickerState::new(vec![candidate], &BTreeMap::new(), None, false);
        picker.toggle(); // ticks the local CLI row
        picker.set_commander();
        assert!(picker.is_checked(0, 0));
        // Fixture guard.
        assert!(
            !picker.candidates()[0].transports[1]
                .availability
                .is_available()
        );

        // Belt: Tab must skip straight past the classified-forbidden remote row.
        picker.cycle_transport();
        assert!(!picker.is_checked(0, 1));
        assert!(picker.is_checked(0, 0));
        assert_eq!(
            picker.flash.as_deref(),
            Some("cloud APIs are refused under --classified")
        );

        // Braces: even if a remote transport ends up selected some other way —
        // config hand-edited, or restored from a run made before --classified was
        // set — submit() must still refuse it rather than trust the stored state.
        let smuggled_candidate = candidate_local_and_classified_remote("anthropic");
        let mut connections = BTreeMap::new();
        connections.insert(
            "anthropic".into(),
            ConnectionSpec {
                enabled: true,
                transport: Some(Transport::Api),
                path: None,
                model: None,
            },
        );
        let mut smuggled = PickerState::new(
            vec![smuggled_candidate],
            &connections,
            Some("anthropic"),
            false,
        );
        assert!(smuggled.is_checked(0, 1));
        assert!(smuggled.is_commander(0, 1));

        assert!(smuggled.submit().is_none());
        assert_eq!(
            smuggled.flash.as_deref(),
            Some("anthropic: cloud APIs are refused under --classified")
        );
    }

    #[test]
    fn reproduction_test_submit_candidate_with_empty_transports_panics() {
        let candidates = vec![
            candidate_single("ollama:llama3"),
            Candidate {
                id: "empty_provider".into(),
                group: "EMPTY".into(),
                model: "empty".into(),
                transports: vec![],
            },
        ];
        let mut picker = PickerState::new(candidates, &BTreeMap::new(), None, false);
        // Select and promote ollama:llama3 (row 0)
        picker.toggle();
        picker.set_commander();
        assert!(picker.is_commander(0, 0));

        // Submitting should succeed and produce connections without panicking on empty_provider
        let (connections, commander) = picker.submit().expect("submit should succeed");
        assert_eq!(commander.as_deref(), Some("ollama:llama3"));
        assert!(connections.contains_key("empty_provider"));
        assert!(!connections["empty_provider"].enabled);
        assert_eq!(connections["empty_provider"].transport, None);
    }
}

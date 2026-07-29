//! Interactive connection-picker state, kept free of I/O so it can be unit-tested,
//! exactly as `src/app.rs` does for the chat TUI.

use std::collections::BTreeMap;

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

/// Picker state: candidates discovered up front, plus the user's in-progress
/// choices. Nothing here touches the filesystem, the network, or a terminal.
pub struct PickerState {
    candidates: Vec<Candidate>,
    rows: Vec<RowRef>,
    selections: Vec<Selection>,
    cursor: usize,
    commander: Option<usize>,
    /// Set when `space`/`enter`/`c` was a no-op, to show in the hint line.
    pub flash: Option<String>,
}

impl PickerState {
    /// Builds the initial state. On first run (`first_run` — the saved config has no
    /// `connections` at all) every available candidate starts ticked with its first
    /// available transport, and the first ticked one is commander: today's "connect
    /// everything" behaviour, so the user unticks rather than starting from nothing.
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

        let commander_idx = commander
            .and_then(|label| candidates.iter().position(|c| c.id == label))
            .filter(|&i| selections[i].enabled)
            .or_else(|| {
                first_run
                    .then(|| (0..candidates.len()).find(|&i| selections[i].enabled))
                    .flatten()
            });

        Self {
            candidates,
            rows,
            selections,
            cursor: 0,
            commander: commander_idx,
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

    /// Ticks or unticks the highlighted row. A row backed by an unavailable
    /// transport is a no-op that surfaces the reason instead — never a silent
    /// failure, and never a way to select something construction would later drop.
    pub fn toggle(&mut self) {
        let Some(row) = self.current_row() else {
            return;
        };
        let option = &self.candidates[row.candidate].transports[row.transport];
        if let Availability::Unavailable(reason) = &option.availability {
            self.flash = Some(reason.clone());
            return;
        }
        self.flash = None;

        let sel = &mut self.selections[row.candidate];
        if sel.enabled && sel.chosen == row.transport {
            sel.enabled = false;
            if self.commander == Some(row.candidate) {
                self.commander = None;
            }
        } else {
            sel.enabled = true;
            sel.chosen = row.transport;
        }
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
    /// refuses (setting `flash`) if nothing is ticked — starting a session with no
    /// providers is a worse outcome than asking again.
    pub fn submit(&mut self) -> Option<(BTreeMap<String, ConnectionSpec>, Option<String>)> {
        if !self.selections.iter().any(|s| s.enabled) {
            self.flash = Some("tick at least one connection before connecting".into());
            return None;
        }

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

        let commander = self
            .commander
            .map(|i| self.candidates[i].id.clone())
            .or_else(|| {
                self.candidates
                    .iter()
                    .enumerate()
                    .find(|(i, _)| self.selections[*i].enabled)
                    .map(|(_, c)| c.id.clone())
            });

        Some((connections, commander))
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
            }],
        }
    }

    /// A vendor with two transport rows: CLI (available or not) and API (always
    /// unavailable here, standing in for "no key stored").
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
                    }),
                },
                crate::orchestrator::TransportOption {
                    transport: Some(Transport::Api),
                    label: "via API".into(),
                    detail: "(no key stored)".into(),
                    availability: Availability::Unavailable("no key stored".into()),
                    cli: None,
                },
            ],
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
    fn no_op_toggle_on_an_unavailable_row_flashes_the_reason() {
        let candidates = vec![candidate_dual("anthropic", true)];
        let mut picker = PickerState::new(candidates, &BTreeMap::new(), None, false);
        picker.move_down(); // the API row: no key stored
        picker.toggle();
        assert!(!picker.is_checked(0, 1));
        assert_eq!(picker.flash.as_deref(), Some("no key stored"));
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
        assert!(picker.is_commander(0, 0));
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

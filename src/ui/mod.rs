//! Ratatui front end. Owns the terminal, forwards input to the orchestrator, and
//! renders events coming back.

use anyhow::{Context, Result};
use crossterm::{
    event::{
        DisableMouseCapture, EnableMouseCapture, Event as TermEvent, EventStream, KeyCode,
        KeyEventKind, KeyModifiers,
    },
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use futures::StreamExt;
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    widgets::{Block, Borders, Paragraph, Wrap},
};
use std::io::{self, Stdout};
use std::time::Duration;
use tokio::sync::mpsc;
use zeroize::Zeroize;

use crate::app::{App, CommanderCommand, parse_commander_command, parse_forget_command};
use crate::config::{Credentials, Settings};
use crate::orchestrator::{Command, Event, WriteDecision, discover_candidates};
use crate::picker::PickerState;

/// Restores the terminal on drop, so a panic or an early `?` cannot leave the user in
/// raw mode with no echo.
struct TerminalGuard {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl TerminalGuard {
    fn enter() -> Result<Self> {
        enable_raw_mode().context("failed to enable raw mode")?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;

        let terminal = Terminal::new(CrosstermBackend::new(stdout))?;
        Ok(Self { terminal })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(
            self.terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        );
        let _ = self.terminal.show_cursor();
    }
}

/// Runs the connection picker standalone, before any chat session exists — the
/// `simon chat` startup path. Returns `true` if the user connected (settings updated
/// in place; the caller must still persist them), `false` if they quit.
pub async fn pick_connections(settings: &mut Settings, classified: bool) -> Result<bool> {
    let mut guard = TerminalGuard::enter()?;
    let mut input = EventStream::new();
    run_picker(&mut guard.terminal, &mut input, settings, classified).await
}

/// Runs the TUI until the user quits or the orchestrator closes its event channel.
///
/// `settings`/`classified` are only needed to reopen the picker mid-chat (Ctrl+O or
/// `F2`); the initial picker (before this function is ever called) is handled by
/// `pick_connections`.
///
/// Returns the final `App` on a clean exit, so a caller running `--vault` can save
/// the last-seen transcript. `TerminalGuard::enter` is called inside this function
/// and its `Drop` restores the terminal when the local `guard` variable goes out of
/// scope at the `Ok`/`Err` return below — so by the time this `async fn` resolves,
/// the caller can safely prompt or print (e.g. "vault saved") without corrupting a
/// terminal that is still in raw mode / the alternate screen.
pub async fn run(
    mut app: App,
    commands: mpsc::Sender<Command>,
    decisions: mpsc::Sender<WriteDecision>,
    mut events: mpsc::Receiver<Event>,
    mut settings: Settings,
    paths: crate::config::Paths,
    classified: bool,
) -> Result<App> {
    let mut guard = TerminalGuard::enter()?;
    let mut input = EventStream::new();
    // Drives the busy status line's spinner/elapsed-seconds display. ~200ms is fast
    // enough to read as "live" without redrawing so often it fights the terminal for
    // CPU; the tick itself does nothing unless `app.activity` is set (see below), so
    // this interval firing is cheap even across a long idle session.
    let mut ticker = tokio::time::interval(Duration::from_millis(200));
    // Set by the previous iteration's `select!` outcome: `false` only when that
    // iteration was an idle tick (nothing in `app` changed), so this iteration's draw
    // is skipped. `Terminal::draw` already diffs against the previous buffer
    // internally, but rebuilding the widget tree every 200ms even while nothing
    // changed is exactly the "pointless full redraw" this avoids. Every other branch
    // leaves it at `true`.
    let mut needs_redraw = true;

    loop {
        if needs_redraw {
            guard.terminal.draw(|frame| draw(frame, &app))?;
        }
        needs_redraw = true;

        tokio::select! {
            maybe_term = input.next() => {
                match maybe_term {
                    Some(Ok(TermEvent::Key(key))) if key.kind == KeyEventKind::Press => {
                        // `app.pending_write.is_some()` is checked here, BEFORE
                        // `is_reopen_picker`, not after: while a write-approval prompt
                        // is up, the orchestrator is blocked on `decisions.recv()`
                        // waiting for the answer. If Ctrl+O/F2 were still routed to
                        // `reopen_picker` during that wait, it would send
                        // `Command::Reconfigure` and then await the orchestrator's
                        // reply — but the orchestrator can't get to that command
                        // because it's parked on `decisions.recv()`, and nothing here
                        // ever sends a decision, since the key that would have gone to
                        // `handle_key`'s pending-write guard went to the picker
                        // instead. Both sides then wait on each other forever. Routing
                        // every key to `handle_key` while a write is pending — the same
                        // guard already used for approve/deny/approve-all — means
                        // `is_reopen_picker` is simply never consulted during the
                        // prompt, so there is only one place that decides what a key
                        // does while `pending_write` is set.
                        if app.pending_write.is_none() && is_reopen_picker(key.code, key.modifiers) {
                            reopen_picker(&mut guard, &mut input, &mut app, &commands, &mut settings, &paths, classified).await;
                        } else {
                            handle_key(&mut app, key.code, key.modifiers, &commands, &decisions).await;
                        }
                    }
                    // Ignore resize/mouse/focus events; the next draw picks up the size.
                    Some(Ok(_)) => {}
                    Some(Err(e)) => {
                        app.apply(Event::Error(format!("input error: {e}")));
                    }
                    None => break,
                }
            }
            maybe_event = events.recv() => {
                match maybe_event {
                    // Persisting the new commander here, rather than in `App::apply`,
                    // is what keeps `App` free of I/O: `App::apply` only ever updates
                    // in-memory state. Mirrors `reopen_picker`'s `settings.save` below.
                    Some(Event::CommanderChanged { label, connection_id }) => {
                        app.apply(Event::CommanderChanged {
                            label,
                            connection_id: connection_id.clone(),
                        });
                        if let Some(id) = connection_id {
                            settings.commander = Some(id);
                            if let Err(e) = settings.save(&paths) {
                                app.apply(Event::Error(format!(
                                    "failed to save commander: {e}"
                                )));
                            }
                        }
                        // No backing connection id (shouldn't happen on the normal
                        // path — see `Event::CommanderChanged`'s doc comment): the
                        // switch already happened for this session, just nothing to
                        // persist, so silently skipping here is correct, not a bug.
                    }
                    Some(event) => app.apply(event),
                    // Orchestrator shut down; nothing more can arrive.
                    None => break,
                }
            }
            // Kept deliberately minimal — `tokio::select!` polls a ready branch at
            // random, so anything heavier here would be a chance to starve input or
            // orchestrator events, not just a perf concern.
            _ = ticker.tick() => {
                if app.activity.is_some() {
                    app.advance_spinner();
                } else {
                    needs_redraw = false;
                }
            }
        }

        if app.should_quit {
            break;
        }
    }

    let _ = commands.send(Command::Shutdown).await;
    Ok(app)
}

/// `Ctrl+O` reopens the picker, with `F2` as an equivalent alternative. `Ctrl+O` is
/// control code 0x0F, distinct from Enter in every terminal — unlike `Ctrl+M`, which
/// *is* 0x0D and so cannot be told apart from Enter without the kitty keyboard
/// protocol.
fn is_reopen_picker(code: KeyCode, modifiers: KeyModifiers) -> bool {
    matches!(code, KeyCode::F(2))
        || (modifiers.contains(KeyModifiers::CONTROL) && matches!(code, KeyCode::Char('o')))
}

/// Reopens the picker inside an already-running chat session. On a successful
/// connect, saves the new settings and asks the orchestrator to rebuild its
/// registry; `Event::Reconfigured` (handled in `App::apply`) updates the visible
/// commander once that finishes.
async fn reopen_picker(
    guard: &mut TerminalGuard,
    input: &mut EventStream,
    app: &mut App,
    commands: &mpsc::Sender<Command>,
    settings: &mut Settings,
    paths: &crate::config::Paths,
    classified: bool,
) {
    match run_picker(&mut guard.terminal, input, settings, classified).await {
        Ok(true) => {
            if let Err(e) = settings.save(paths) {
                app.apply(Event::Error(format!("failed to save connections: {e}")));
                return;
            }
            if commands
                .send(Command::Reconfigure(settings.clone()))
                .await
                .is_err()
            {
                app.apply(Event::Error("orchestrator is not running".into()));
            }
        }
        Ok(false) => {} // user cancelled; chat continues unchanged
        Err(e) => app.apply(Event::Error(format!("picker failed: {e}"))),
    }
}

/// Runs the picker to completion inside an already-entered terminal. Discovery runs
/// on a background task so the draw loop never blocks on it.
async fn run_picker(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    input: &mut EventStream,
    settings: &mut Settings,
    classified: bool,
) -> Result<bool> {
    let (candidates_tx, mut candidates_rx) = mpsc::channel(1);
    {
        let settings = settings.clone();
        tokio::spawn(async move {
            let candidates = discover_candidates(&settings, classified).await;
            let _ = candidates_tx.send(candidates).await;
        });
    }

    let mut picker: Option<PickerState> = None;

    loop {
        terminal.draw(|frame| draw_picker(frame, picker.as_ref()))?;

        tokio::select! {
            maybe_term = input.next() => {
                match maybe_term {
                    Some(Ok(TermEvent::Key(key))) if key.kind == KeyEventKind::Press => {
                        if let Some(state) = picker.as_mut() {
                            if state.key_entry().is_some() {
                                // While a masked key prompt is open, every other
                                // binding (toggle, cycle transport, commander, quit)
                                // is suspended — none of them make sense mid-entry,
                                // and letting `q`/`Esc` fall through would make
                                // "cancel the prompt" indistinguishable from "quit
                                // the picker".
                                match key.code {
                                    KeyCode::Char(c) => state.push_key_char(c),
                                    KeyCode::Backspace => state.backspace_key(),
                                    KeyCode::Esc => state.cancel_key_entry(),
                                    KeyCode::Enter => {
                                        if let Some((id, mut key_text)) =
                                            state.submit_key_entry()
                                        {
                                            // The only place in the picker path that
                                            // touches the keyring — `PickerState`
                                            // itself stays I/O-free.
                                            match Credentials::set(&id, key_text.trim()) {
                                                Ok(()) => {
                                                    if let Some((c, t)) =
                                                        needs_key_row(state, &id)
                                                    {
                                                        state.mark_key_stored(c, t);
                                                    }
                                                }
                                                Err(e) => state.mark_key_store_failed(&format!(
                                                    "failed to store key: {e}"
                                                )),
                                            }
                                            key_text.zeroize();
                                        }
                                    }
                                    _ => {}
                                }
                            } else {
                                match key.code {
                                    KeyCode::Up => state.move_up(),
                                    KeyCode::Down => state.move_down(),
                                    KeyCode::Char(' ') => state.toggle(),
                                    KeyCode::Tab => state.cycle_transport(),
                                    KeyCode::Char('c') => state.set_commander(),
                                    KeyCode::Enter => {
                                        if let Some((connections, commander)) = state.submit() {
                                            settings.connections = connections;
                                            settings.commander = commander;
                                            return Ok(true);
                                        }
                                    }
                                    KeyCode::Esc | KeyCode::Char('q') => return Ok(false),
                                    _ => {}
                                }
                            }
                        }
                    }
                    Some(Ok(_)) => {}
                    Some(Err(_)) | None => return Ok(false),
                }
            }
            maybe_candidates = candidates_rx.recv(), if picker.is_none() => {
                if let Some(candidates) = maybe_candidates {
                    let first_run = settings.connections.is_empty();
                    let commander = settings.commander.clone();
                    picker = Some(PickerState::new(
                        candidates,
                        &settings.connections,
                        commander.as_deref(),
                        first_run,
                    ));
                }
            }
        }
    }
}

/// Finds the `(candidate, transport)` row that a just-completed key entry belongs
/// to. `PickerState::submit_key_entry` only hands back the candidate id (its public
/// surface has no reason to expose row indices), so the caller — this function —
/// re-derives them from `needs_key`, which singles out exactly the row that could
/// have opened key entry for that candidate.
fn needs_key_row(state: &PickerState, id: &str) -> Option<(usize, usize)> {
    state.candidates().iter().enumerate().find_map(|(ci, c)| {
        if c.id != id {
            return None;
        }
        c.transports
            .iter()
            .position(|t| t.needs_key)
            .map(|ti| (ci, ti))
    })
}

async fn handle_key(
    app: &mut App,
    code: KeyCode,
    modifiers: KeyModifiers,
    commands: &mpsc::Sender<Command>,
    decisions: &mpsc::Sender<WriteDecision>,
) {
    // A pending write takes the keyboard until it is answered. Typing must not fall
    // through to the input box: the turn is blocked on this answer, and a user who
    // kept typing would be composing a message that cannot be sent while silently
    // leaving a model waiting.
    if app.pending_write.is_some() {
        let decision = match code {
            KeyCode::Char('y') | KeyCode::Char('Y') => Some(WriteDecision::Approve),
            KeyCode::Char('a') | KeyCode::Char('A') => Some(WriteDecision::ApproveAll),
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => Some(WriteDecision::Deny),
            // Anything else is ignored rather than treated as a default. Neither
            // default is safe: silently allowing is the whole thing this gate exists
            // to prevent, and silently refusing would make a stray keypress look like
            // a model failure.
            _ => None,
        };
        if let Some(decision) = decision {
            app.pending_write = None;
            if decisions.send(decision).await.is_err() {
                app.apply(Event::Error("orchestrator is not running".into()));
            }
        }
        return;
    }

    match code {
        KeyCode::Esc => app.should_quit = true,
        KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => {
            app.should_quit = true;
        }
        KeyCode::Enter => {
            if let Some(prompt) = app.submit() {
                // `submit()` already recorded the typed text as the user's line and
                // set `busy = true`, assuming a model turn — correct even for
                // `/commander` and `/forget`; only how the text is dispatched differs
                // below, and the locally-handled branch has to undo the `busy` guess.
                match parse_commander_command(&prompt) {
                    Some(CommanderCommand::List) => app.list_commander(),
                    Some(CommanderCommand::SwitchTo(name)) => {
                        if commands.send(Command::SetCommander(name)).await.is_err() {
                            app.apply(Event::Error("orchestrator is not running".into()));
                            app.busy = false;
                        }
                    }
                    None if parse_forget_command(&prompt) => {
                        if commands.send(Command::ClearLedger).await.is_err() {
                            app.apply(Event::Error("orchestrator is not running".into()));
                            app.busy = false;
                        }
                    }
                    None => {
                        // A full channel means the orchestrator is backed up; report
                        // rather than silently dropping the user's message.
                        if commands.send(Command::Prompt(prompt)).await.is_err() {
                            app.apply(Event::Error("orchestrator is not running".into()));
                            app.busy = false;
                        }
                    }
                }
            }
        }
        KeyCode::Backspace => app.backspace(),
        KeyCode::Delete => app.delete_forward(),
        KeyCode::Left => app.cursor_left(),
        KeyCode::Right => app.cursor_right(),
        KeyCode::Home => app.cursor_home(),
        KeyCode::End => app.cursor_end(),
        KeyCode::PageUp => app.scroll_up(),
        KeyCode::PageDown => app.scroll_down(),
        // Ctrl-modified characters are shortcuts, not text. This arm is the catch-all
        // for typing, and it used to take `c` whatever the modifiers were — so every
        // chord this function does not explicitly handle (Ctrl+A, Ctrl+W, Ctrl+U…)
        // silently typed its bare letter into the prompt. Alt is left alone: it is not
        // bound to anything here, and some keyboard layouts produce ordinary characters
        // with AltGr, which crossterm reports as Alt.
        KeyCode::Char(c) if !modifiers.contains(KeyModifiers::CONTROL) => app.push_char(c),
        _ => {}
    }
}

fn draw(frame: &mut ratatui::Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(3)])
        .split(frame.area());

    let history_body = app.body();
    let total_lines = history_body.lines().count();
    let history_interior_height = chunks[0].height.saturating_sub(2) as usize;
    let base_scroll = total_lines.saturating_sub(history_interior_height);
    let effective_scroll = base_scroll.saturating_sub(app.scroll as usize) as u16;

    let history = Paragraph::new(history_body)
        .wrap(Wrap { trim: false })
        .scroll((effective_scroll, 0))
        .block(Block::default().title(" simon ").borders(Borders::ALL));
    frame.render_widget(history, chunks[0]);

    let style = if app.busy {
        Style::default().fg(Color::DarkGray)
    } else {
        Style::default()
    };

    // Interior space inside the input block's borders: a border on each side eats 2
    // columns and 2 rows, so below that there is no content cell to draw text or a
    // caret on at all. The old version of this function computed `chunks[1].y + 1`
    // unconditionally, assuming the block was always at least 3 rows tall — on a
    // short terminal (`Constraint::Length(3)` is a request, not a guarantee) that
    // landed the caret past the block, sometimes past the frame itself
    // (`bug_draw_cursor_position_out_of_bounds_on_small_height`, inverted below as
    // `draw_keeps_the_caret_inside_the_frame_on_a_short_terminal`).
    let interior_width = chunks[1].width.saturating_sub(2);
    let interior_height = chunks[1].height.saturating_sub(2);

    // Caret column measured from the very start of the rendered line ("> " + input),
    // in characters — the same unit `cursor_column()` uses, which is right for this
    // project's Latin and Lithuanian text but would drift on double-width CJK, since
    // measuring that needs a grapheme-width table this crate deliberately does not
    // carry.
    let caret_in_line = 2 + app.cursor_column() as u16;
    // How far the line must scroll left so the caret's column stays inside the field
    // instead of running off the right edge. Zero (no scroll) as long as the caret
    // still fits; once it doesn't, this pins the caret to the last visible column and
    // scrolls the text out from under it instead — the previous version scrolled
    // neither, so a line wider than the field just made the caret's `x` fail the
    // bounds check and vanish instead of following the text
    // (`bug_draw_cursor_disappears_when_input_exceeds_terminal_width`, inverted below
    // as `draw_scrolls_a_long_line_so_the_caret_stays_on_the_right_character`).
    // `interior_width - 1` cannot underflow: this is only evaluated when
    // `interior_width > 0`.
    let offset = if interior_width > 0 {
        caret_in_line.saturating_sub(interior_width - 1)
    } else {
        0
    };

    let input = Paragraph::new(format!("> {}", app.input))
        .style(style)
        .scroll((0, offset))
        .block(
            Block::default()
                .title(format!(" {} ", app.status_line()))
                .borders(Borders::ALL),
        );
    frame.render_widget(input, chunks[1]);

    // Place the terminal's own caret. Without this the arrow keys move an invisible
    // position and editing mid-line is guesswork. Skipped while busy, where the input
    // is greyed out and not accepting text — a caret there would invite typing that
    // goes nowhere — and skipped when the block has no interior cell at all, where
    // there is nowhere on-screen placement could even mean.
    if !app.busy && interior_width > 0 && interior_height > 0 {
        let x = chunks[1].x + 1 + (caret_in_line - offset);
        let y = chunks[1].y + 1;
        frame.set_cursor_position((x, y));
    }
}

/// Renders the picker: a body pane listing every candidate grouped by provider, and
/// a hint line (or a flash message, when the last key press was a no-op).
fn draw_picker(frame: &mut ratatui::Frame, picker: Option<&PickerState>) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(frame.area());

    let (body, cursor_line) = match picker {
        None => ("Discovering connections…".to_string(), 0),
        Some(picker) => render_picker_body_with_cursor(picker),
    };
    let interior_height = chunks[0].height.saturating_sub(2) as usize;
    let scroll_offset = if interior_height > 0 && cursor_line >= interior_height {
        (cursor_line - interior_height + 1) as u16
    } else {
        0
    };

    let list = Paragraph::new(body)
        .wrap(Wrap { trim: false })
        .scroll((scroll_offset, 0))
        .block(
            Block::default()
                .title(" simon — choose connections ")
                .borders(Borders::ALL),
        );
    frame.render_widget(list, chunks[0]);

    // Key entry takes over the hint/flash line with a masked prompt — never the
    // typed characters themselves, only a `•` per character typed so far.
    let hint = match picker.and_then(|p| p.key_entry()) {
        Some((id, len)) => format!(
            "API key for {id} (stored in OS keyring, never in config; enter confirms, esc cancels): {}",
            "•".repeat(len)
        ),
        None => picker
            .and_then(|p| p.flash.as_deref())
            .map(str::to_string)
            .unwrap_or_else(|| {
                "space toggle · c commander · tab transport · enter connect · q quit".to_string()
            }),
    };
    frame.render_widget(Paragraph::new(hint), chunks[1]);
}

fn render_picker_body_with_cursor(picker: &PickerState) -> (String, usize) {
    let mut out = String::new();
    let mut last_group: Option<&str> = None;
    let mut current_line = 0;
    let mut cursor_line = 0;

    for (line_idx, row) in picker.rows().iter().enumerate() {
        let candidate = &picker.candidates()[row.candidate];
        if last_group != Some(candidate.group.as_str()) {
            if last_group.is_some() {
                out.push('\n');
                current_line += 1;
            }
            out.push_str(&candidate.group);
            out.push('\n');
            current_line += 1;
            last_group = Some(candidate.group.as_str());
        }

        let option = &candidate.transports[row.transport];
        let checkbox = if picker.is_checked(row.candidate, row.transport) {
            "[x]"
        } else {
            "[ ]"
        };
        let is_current = picker.cursor() == line_idx;
        let cursor = if is_current {
            cursor_line = current_line;
            ">"
        } else {
            " "
        };
        let label = if option.label.is_empty() {
            String::new()
        } else {
            format!("  {}", option.label)
        };
        let commander = if picker.is_commander(row.candidate, row.transport) {
            "  ● commander"
        } else {
            ""
        };
        let reason = match &option.availability {
            crate::orchestrator::Availability::Unavailable(reason) => format!("  ({reason})"),
            crate::orchestrator::Availability::Available => String::new(),
        };

        out.push_str(&format!(
            "{cursor}{checkbox} {}{label}   {}{commander}{reason}\n",
            candidate.model, option.detail
        ));
        current_line += 1;
    }

    if out.is_empty() {
        out.push_str("No candidate connections were found.\n");
    }
    (out, cursor_line)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;

    #[tokio::test]
    async fn handle_key_does_not_let_a_local_command_clear_busy_while_a_turn_is_in_flight() {
        let mut app = App::new(
            "ollama:llama3",
            &["ollama:llama3".to_string()],
            "/tmp".to_string(),
        );
        app.busy = true; // A model turn is currently in flight

        let (cmd_tx, _cmd_rx) = mpsc::channel(32);
        let (dec_tx, _dec_rx) = mpsc::channel(1);

        // While turn is running, user enters /commander and presses Enter
        for c in "/commander".chars() {
            handle_key(
                &mut app,
                KeyCode::Char(c),
                KeyModifiers::NONE,
                &cmd_tx,
                &dec_tx,
            )
            .await;
        }
        handle_key(
            &mut app,
            KeyCode::Enter,
            KeyModifiers::NONE,
            &cmd_tx,
            &dec_tx,
        )
        .await;

        // `submit()` (see `app.rs`) now refuses to start anything while `busy` is
        // already true, so the local command never runs and never gets a chance to
        // clear the real turn's busy flag.
        assert!(
            app.busy,
            "busy must stay true: the background turn is still in flight"
        );
        assert_eq!(
            app.input, "/commander",
            "the typed command must be preserved, not swallowed"
        );
    }

    /// Inverts `bug_draw_cursor_position_out_of_bounds_on_small_height`: on a
    /// terminal too short to fit the input block's borders plus a content row, the
    /// caret must simply not be placed rather than land on a row outside the frame.
    /// Covers both a 1-row and a 2-row terminal, per the audit's request — the old
    /// code was wrong for both, just in slightly different ways (see the table this
    /// was derived from: `Layout::split` gives the input chunk height 0 at h=1 and
    /// height 1 at h=2, neither of which has room for a content row).
    #[test]
    fn draw_shows_the_latest_transcript_lines_at_scroll_zero() {
        let mut app = App::new(
            "ollama:llama3",
            &["ollama:llama3".to_string()],
            "/tmp".to_string(),
        );
        for i in 0..20 {
            app.transcript.push(crate::app::Line {
                speaker: crate::app::Speaker::You,
                text: format!("message_{i}"),
            });
        }
        assert_eq!(app.scroll, 0);

        let backend = TestBackend::new(80, 10);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();

        let buffer = terminal.backend().buffer();
        let mut rendered = String::new();
        for y in 1..9 {
            for x in 1..79 {
                rendered.push_str(buffer.cell((x, y)).unwrap().symbol());
            }
            rendered.push('\n');
        }

        assert!(
            rendered.contains("message_19"),
            "the latest transcript line (message_19) must be visible at scroll 0, but rendered:\n{rendered}"
        );
    }

    #[test]
    fn draw_picker_scrolls_to_keep_cursor_visible_when_navigating_down() {
        use crate::orchestrator::{Availability, Candidate, TransportOption};
        let candidates: Vec<Candidate> = (0..15)
            .map(|i| Candidate {
                id: format!("model_{i}"),
                group: format!("GROUP_{i}"),
                model: format!("model_{i}"),
                transports: vec![TransportOption {
                    transport: None,
                    label: String::new(),
                    detail: String::new(),
                    availability: Availability::Available,
                    cli: None,
                    needs_key: false,
                }],
            })
            .collect();
        let mut picker =
            PickerState::new(candidates, &std::collections::BTreeMap::new(), None, false);
        for _ in 0..12 {
            picker.move_down();
        }
        assert_eq!(picker.cursor(), 12);

        let backend = TestBackend::new(80, 10);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| draw_picker(frame, Some(&picker)))
            .unwrap();

        let buffer = terminal.backend().buffer();
        let mut rendered = String::new();
        for y in 1..9 {
            for x in 1..79 {
                rendered.push_str(buffer.cell((x, y)).unwrap().symbol());
            }
            rendered.push('\n');
        }

        assert!(
            rendered.contains(">"),
            "the cursor indicator `>` must be visible in the viewport when scrolled down, but rendered:\n{rendered}"
        );
        assert!(
            rendered.contains("model_12"),
            "the selected model_12 row must be visible in the viewport, but rendered:\n{rendered}"
        );
    }

    #[test]
    fn draw_keeps_the_caret_inside_the_frame_on_a_short_terminal() {
        for height in [1u16, 2] {
            let app = App::new(
                "ollama:llama3",
                &["ollama:llama3".to_string()],
                "/tmp".to_string(),
            );
            let backend = TestBackend::new(80, height);
            let mut terminal = Terminal::new(backend).unwrap();

            terminal.draw(|frame| draw(frame, &app)).unwrap();

            // Either the caret was left un-placed (there is no content row to put it
            // on), or — if it was placed — it must land on an actual row/column of
            // this frame. The old code always placed it, at a row past the frame's
            // last valid index, which is exactly what this catches.
            if terminal.backend().cursor_visible() {
                let pos = terminal.backend().cursor_position();
                assert!(
                    pos.y < height,
                    "caret row {} is outside a {height}-row frame",
                    pos.y
                );
                assert!(pos.x < 80, "caret column {} is outside the frame", pos.x);
            }
        }
    }

    /// Inverts `bug_draw_cursor_disappears_when_input_exceeds_terminal_width`: once
    /// the line is wider than the field, the field must scroll to keep the caret
    /// visible, and the caret must land on the exact character it is editing — not
    /// merely somewhere on screen. Uses 30 distinct characters, not a repeated run,
    /// so a wrong scroll offset that happens to land on a same-looking character
    /// can't pass by accident.
    #[test]
    fn draw_scrolls_a_long_line_so_the_caret_stays_on_the_right_character() {
        let mut app = App::new(
            "ollama:llama3",
            &["ollama:llama3".to_string()],
            "/tmp".to_string(),
        );
        let text = "0123456789ABCDEFGHIJKLMNOPQRST"; // 30 distinct characters
        for c in text.chars() {
            app.push_char(c);
        }
        // Off the very end, so this also exercises "mid-line", not just "at the end".
        for _ in 0..5 {
            app.cursor_left();
        }
        assert_eq!(app.cursor_column(), 25);

        let backend = TestBackend::new(20, 10); // interior width 18 < the 30-char line
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();

        assert!(
            terminal.backend().cursor_visible(),
            "the caret must not disappear just because the line is wider than the field"
        );
        let pos = terminal.backend().cursor_position();
        assert!(
            pos.x < 20 && pos.y < 10,
            "caret must stay inside the frame: {pos:?}"
        );

        let expected_char = text.chars().nth(app.cursor_column()).unwrap();
        let cell = terminal
            .backend()
            .buffer()
            .cell((pos.x, pos.y))
            .expect("caret position must be inside the buffer");
        assert_eq!(
            cell.symbol(),
            expected_char.to_string(),
            "the caret must land on the character it is actually editing"
        );
    }

    /// This crate has shipped byte-index panics on multi-byte input before
    /// (923b934). `cursor_column()` counts characters, not bytes, so the caret
    /// arithmetic in `draw` is safe by construction — this stress-tests that across
    /// every caret position, a range of terminal sizes including degenerate ones (0,
    /// 1, and 2 rows/columns, where the offset math takes its early-out paths), and
    /// therefore every possible scroll offset for this input.
    #[test]
    fn draw_never_panics_on_multibyte_input_at_any_caret_position_or_terminal_size() {
        let text = "ąčęėįšųūž";
        for width in [0u16, 1, 2, 3, 5, 10, 30] {
            for height in [0u16, 1, 2, 3, 10] {
                let mut app = App::new(
                    "ollama:llama3",
                    &["ollama:llama3".to_string()],
                    "/tmp".to_string(),
                );
                for c in text.chars() {
                    app.push_char(c);
                }
                for _ in 0..=text.chars().count() {
                    let backend = TestBackend::new(width, height);
                    let mut terminal = Terminal::new(backend).unwrap();
                    terminal.draw(|frame| draw(frame, &app)).unwrap();
                    app.cursor_left();
                }
            }
        }
    }
}

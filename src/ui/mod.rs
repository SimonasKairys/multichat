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
///
/// This loop itself is not unit-tested: it drives a live `crossterm::EventStream`,
/// and there is no injectable event source to feed it a scripted key sequence from a
/// test. That is not a coverage gap in disguise, though — every decision this loop
/// makes about a keypress (which mode routes it, what it does, whether to submit or
/// cancel) has already been factored out into `handle_picker_key`, which is a pure
/// function and is exercised directly by the `handle_picker_key_*` tests below. What
/// stays untested here is strictly the glue: reading the next terminal event, the
/// `select!` between that and the discovery channel, and threading a submitted key
/// through to `Credentials::set`.
#[cfg_attr(test, mutants::skip)]
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
                                match handle_picker_key(state, key.code, key.modifiers) {
                                    PickerKeyOutcome::Submit => {
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
                                    PickerKeyOutcome::Cancel | PickerKeyOutcome::Continue => {}
                                }
                            } else if state.model_entry().is_some() {
                                match handle_picker_key(state, key.code, key.modifiers) {
                                    PickerKeyOutcome::Submit => state.submit_model_entry(),
                                    PickerKeyOutcome::Cancel | PickerKeyOutcome::Continue => {}
                                }
                            } else {
                                match handle_picker_key(state, key.code, key.modifiers) {
                                    PickerKeyOutcome::Submit => {
                                        if let Some((connections, commander)) = state.submit() {
                                            settings.connections = connections;
                                            settings.commander = commander;
                                            return Ok(true);
                                        }
                                    }
                                    PickerKeyOutcome::Cancel => return Ok(false),
                                    PickerKeyOutcome::Continue => {}
                                }
                            }
                        } else {
                            match key.code {
                                KeyCode::Esc => return Ok(false),
                                KeyCode::Char('q')
                                    if !key.modifiers.contains(KeyModifiers::CONTROL) =>
                                {
                                    return Ok(false);
                                }
                                KeyCode::Char('c') | KeyCode::Char('C')
                                    if key.modifiers.contains(KeyModifiers::CONTROL) =>
                                {
                                    return Ok(false);
                                }
                                _ => {}
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PickerKeyOutcome {
    Continue,
    Submit,
    Cancel,
}

pub(crate) fn handle_picker_key(
    state: &mut PickerState,
    code: KeyCode,
    modifiers: KeyModifiers,
) -> PickerKeyOutcome {
    if state.key_entry().is_some() {
        match code {
            KeyCode::Esc => {
                state.cancel_key_entry();
                PickerKeyOutcome::Continue
            }
            KeyCode::Char('c') | KeyCode::Char('C')
                if modifiers.contains(KeyModifiers::CONTROL) =>
            {
                state.cancel_key_entry();
                PickerKeyOutcome::Continue
            }
            KeyCode::Backspace => {
                state.backspace_key();
                PickerKeyOutcome::Continue
            }
            KeyCode::Enter => PickerKeyOutcome::Submit,
            KeyCode::Char(c) if !modifiers.contains(KeyModifiers::CONTROL) => {
                state.push_key_char(c);
                PickerKeyOutcome::Continue
            }
            _ => PickerKeyOutcome::Continue,
        }
    } else if state.model_entry().is_some() {
        match code {
            KeyCode::Esc => {
                state.cancel_model_entry();
                PickerKeyOutcome::Continue
            }
            KeyCode::Char('c') | KeyCode::Char('C')
                if modifiers.contains(KeyModifiers::CONTROL) =>
            {
                state.cancel_model_entry();
                PickerKeyOutcome::Continue
            }
            KeyCode::Backspace => {
                state.backspace_model();
                PickerKeyOutcome::Continue
            }
            KeyCode::Enter => PickerKeyOutcome::Submit,
            KeyCode::Char(c) if !modifiers.contains(KeyModifiers::CONTROL) => {
                state.push_model_char(c);
                PickerKeyOutcome::Continue
            }
            _ => PickerKeyOutcome::Continue,
        }
    } else {
        match code {
            KeyCode::Up => {
                state.move_up();
                PickerKeyOutcome::Continue
            }
            KeyCode::Down => {
                state.move_down();
                PickerKeyOutcome::Continue
            }
            KeyCode::Char(' ') if !modifiers.contains(KeyModifiers::CONTROL) => {
                state.toggle();
                PickerKeyOutcome::Continue
            }
            KeyCode::Tab => {
                state.cycle_transport();
                PickerKeyOutcome::Continue
            }
            KeyCode::Char('c') | KeyCode::Char('C')
                if modifiers.contains(KeyModifiers::CONTROL) =>
            {
                PickerKeyOutcome::Cancel
            }
            // No `if !modifiers.contains(CONTROL)` guard here, deliberately: the arm
            // directly above already claims every `Char('c')`/`Char('C')` carrying
            // CONTROL, so matching only reaches this arm with CONTROL absent and such a
            // guard would always be true. `cargo mutants` is what surfaced it — the
            // guard was an unkillable equivalent mutant, which is its way of saying the
            // condition is dead. Keep this arm *below* the Ctrl one; swapping them
            // would make plain `c` and Ctrl+C do the same thing.
            KeyCode::Char('c') | KeyCode::Char('C') => {
                state.set_commander();
                PickerKeyOutcome::Continue
            }
            KeyCode::Char('m') | KeyCode::Char('M')
                if !modifiers.contains(KeyModifiers::CONTROL) =>
            {
                state.start_model_entry();
                PickerKeyOutcome::Continue
            }
            KeyCode::Enter => PickerKeyOutcome::Submit,
            KeyCode::Esc => PickerKeyOutcome::Cancel,
            KeyCode::Char('q') | KeyCode::Char('Q')
                if !modifiers.contains(KeyModifiers::CONTROL) =>
            {
                PickerKeyOutcome::Cancel
            }
            _ => PickerKeyOutcome::Continue,
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
        KeyCode::Char('c') | KeyCode::Char('C') if modifiers.contains(KeyModifiers::CONTROL) => {
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
    let history_interior_height = chunks[0].height.saturating_sub(2) as usize;
    let history_interior_width = chunks[0].width.saturating_sub(2);
    let total_lines = Paragraph::new(history_body.as_str())
        .wrap(Wrap { trim: false })
        .line_count(history_interior_width);
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
    let scroll_offset = picker_scroll_offset(interior_height, cursor_line);

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
    let hint = if let Some((id, len)) = picker.and_then(|p| p.key_entry()) {
        format!(
            "API key for {id} (stored in OS keyring, never in config; enter confirms, esc cancels): {}",
            "•".repeat(len)
        )
    } else if let Some((id, current, buffer)) = picker.and_then(|p| p.model_entry()) {
        format!(
            "Model for {id} (current: {current}; type exact id, empty = default; enter confirms, esc cancels): {buffer}"
        )
    } else {
        picker
            .and_then(|p| p.flash.as_deref())
            .map(str::to_string)
            .unwrap_or_else(|| {
                "● connected · ○ not connected · × unavailable   space toggle · c commander · m model · tab transport · enter connect · q quit".to_string()
            })
    };
    frame.render_widget(Paragraph::new(hint), chunks[1]);
}

/// Rows the picker body must scroll down so the cursor's line stays inside the
/// visible interior. Split out of `draw_picker` so its two boundary conditions can be
/// pinned directly: with a zero-height interior (a terminal too short to show any
/// content row) there is nothing to scroll into view, and while the cursor is
/// already within the viewport no scroll is needed either. Both of those collapse to
/// the same on-screen result — nothing visible changes — when driven only through a
/// rendered frame, since a zero-height interior shows no rows to compare regardless
/// of the scroll value passed to it.
fn picker_scroll_offset(interior_height: usize, cursor_line: usize) -> u16 {
    if interior_height > 0 && cursor_line >= interior_height {
        (cursor_line - interior_height + 1) as u16
    } else {
        0
    }
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
        let state = picker.connection_state(row.candidate, row.transport);
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
            "  ★ commander"
        } else {
            ""
        };
        let reason = match &option.availability {
            crate::orchestrator::Availability::Unavailable(reason) => format!("  ({reason})"),
            crate::orchestrator::Availability::Available => String::new(),
        };

        out.push_str(&format!(
            "{cursor}{} {}{label}   {}{commander}{reason}\n",
            state.symbol(),
            picker.display_model(row.candidate, row.transport),
            option.detail
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
    fn draw_shows_the_tail_of_a_long_wrapped_reply_at_scroll_zero() {
        let mut app = App::new("copilot", &[], ".".to_string());
        app.transcript.push(crate::app::Line {
            speaker: crate::app::Speaker::Model("copilot".into()),
            text: format!("{} TAIL_MARKER", "long response ".repeat(24)),
        });
        assert_eq!(app.scroll, 0);

        let backend = TestBackend::new(30, 8);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();

        let buffer = terminal.backend().buffer();
        let mut rendered = String::new();
        for y in 1..4 {
            for x in 1..29 {
                rendered.push_str(buffer.cell((x, y)).unwrap().symbol());
            }
            rendered.push('\n');
        }

        assert!(
            rendered.contains("TAIL_MARKER"),
            "the final wrapped line must remain visible at scroll zero, but rendered:\n{rendered}"
        );
    }

    #[test]
    fn picker_scroll_offset_never_scrolls_when_the_interior_has_no_rows() {
        // Pins `interior_height > 0`: with zero interior rows there is nothing to
        // scroll into view, so the offset must stay 0 no matter how far down the
        // cursor sits. `interior_height >= 0` is trivially true for a `usize` and
        // would compute a nonzero offset here instead (`cursor_line + 1`).
        assert_eq!(picker_scroll_offset(0, 50), 0);
    }

    #[test]
    fn picker_scroll_offset_stays_zero_while_the_cursor_is_already_in_view() {
        // Pins `&&`: swapped for `||`, `interior_height > 0` alone would already
        // satisfy the condition here (5 > 0), and the arithmetic below would then
        // underflow subtracting a larger `interior_height` from a smaller
        // `cursor_line` — panicking rather than just returning 0.
        assert_eq!(picker_scroll_offset(5, 4), 0);
    }

    #[test]
    fn picker_scroll_offset_scrolls_exactly_enough_to_reveal_the_cursor_line() {
        assert_eq!(picker_scroll_offset(5, 5), 1);
        assert_eq!(picker_scroll_offset(5, 8), 4);
    }

    #[test]
    fn render_picker_body_marks_only_the_cursor_row() {
        use crate::orchestrator::{Availability, Candidate, TransportOption};
        let candidates: Vec<Candidate> = (0..3)
            .map(|i| Candidate {
                id: format!("model_{i}"),
                group: "GROUP".to_string(),
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
        picker.move_down(); // cursor now on the model_1 row

        let (body, cursor_line) = render_picker_body_with_cursor(&picker);
        let lines: Vec<&str> = body.lines().collect();

        // Exactly one row carries the `>` marker — the one under the cursor. `==`
        // swapped for `!=` would flip this: every row EXCEPT the current one would
        // get the marker instead of the one row that should.
        let marked: Vec<&&str> = lines.iter().filter(|l| l.starts_with('>')).collect();
        assert_eq!(
            marked.len(),
            1,
            "expected exactly one cursor row: {lines:?}"
        );
        assert!(
            marked[0].contains("model_1"),
            "wrong row marked as current: {marked:?}"
        );
        assert_eq!(lines[cursor_line], *marked[0]);
    }

    #[test]
    fn render_picker_body_shows_all_three_connection_states() {
        use crate::config::ConnectionSpec;
        use crate::orchestrator::{Availability, Candidate, TransportOption};
        let candidates = vec![
            Candidate {
                id: "ready".to_string(),
                group: "MODELS".to_string(),
                model: "ready".to_string(),
                transports: vec![TransportOption {
                    transport: None,
                    label: String::new(),
                    detail: String::new(),
                    availability: Availability::Available,
                    cli: None,
                    needs_key: false,
                }],
            },
            Candidate {
                id: "idle".to_string(),
                group: "MODELS".to_string(),
                model: "idle".to_string(),
                transports: vec![TransportOption {
                    transport: None,
                    label: String::new(),
                    detail: String::new(),
                    availability: Availability::Available,
                    cli: None,
                    needs_key: false,
                }],
            },
            Candidate {
                id: "broken".to_string(),
                group: "MODELS".to_string(),
                model: "broken".to_string(),
                transports: vec![TransportOption {
                    transport: None,
                    label: String::new(),
                    detail: String::new(),
                    availability: Availability::Unavailable("daemon is down".to_string()),
                    cli: None,
                    needs_key: false,
                }],
            },
        ];
        let connections = [
            (
                "ready".to_string(),
                ConnectionSpec {
                    enabled: true,
                    transport: None,
                    path: None,
                    model: None,
                },
            ),
            (
                "broken".to_string(),
                ConnectionSpec {
                    enabled: true,
                    transport: None,
                    path: None,
                    model: None,
                },
            ),
        ]
        .into_iter()
        .collect();
        let picker = PickerState::new(candidates, &connections, None, false);

        let (body, _) = render_picker_body_with_cursor(&picker);

        assert!(body.contains("● ready"));
        assert!(body.contains("○ idle"));
        assert!(body.contains("× broken"));
        assert!(body.contains("(daemon is down)"));
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

    #[test]
    fn reproduction_test_picker_ctrl_c_in_browsing_mode_cancels_instead_of_setting_commander() {
        use crate::orchestrator::{Availability, Candidate, TransportOption};
        let candidate = Candidate {
            id: "ollama:llama3".into(),
            group: "OLLAMA".into(),
            model: "ollama:llama3".into(),
            transports: vec![TransportOption {
                transport: None,
                label: String::new(),
                detail: String::new(),
                availability: Availability::Available,
                cli: None,
                needs_key: false,
            }],
        };
        let mut picker = PickerState::new(
            vec![candidate],
            &std::collections::BTreeMap::new(),
            None,
            false,
        );
        assert!(!picker.is_commander(0, 0));

        // When user presses Ctrl+C in browsing mode, it must cancel the picker rather than setting commander
        let outcome = handle_picker_key(&mut picker, KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert_eq!(
            outcome,
            PickerKeyOutcome::Cancel,
            "Ctrl+C in browsing mode must cancel the picker"
        );
        assert!(
            !picker.is_commander(0, 0),
            "Ctrl+C must not mark the highlighted candidate as commander"
        );
    }

    #[test]
    fn reproduction_test_picker_ctrl_chords_in_key_entry_do_not_type_characters() {
        use crate::orchestrator::{Availability, Candidate, TransportOption};
        let candidate = Candidate {
            id: "anthropic".into(),
            group: "ANTHROPIC".into(),
            model: "claude".into(),
            transports: vec![TransportOption {
                transport: None,
                label: String::new(),
                detail: String::new(),
                availability: Availability::Unavailable("no key".into()),
                cli: None,
                needs_key: true,
            }],
        };
        let mut picker = PickerState::new(
            vec![candidate],
            &std::collections::BTreeMap::new(),
            None,
            false,
        );
        picker.toggle(); // opens key entry
        assert!(picker.key_entry().is_some());

        // Pressing Ctrl+V or Ctrl+A should not append 'v' or 'a' to the secret key buffer
        let outcome = handle_picker_key(&mut picker, KeyCode::Char('v'), KeyModifiers::CONTROL);
        assert_eq!(outcome, PickerKeyOutcome::Continue);
        assert_eq!(
            picker.key_entry().unwrap().1,
            0,
            "Ctrl+V must not insert 'v' into the key buffer"
        );

        // Pressing Ctrl+C in key entry mode should cancel key entry
        let outcome = handle_picker_key(&mut picker, KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert_eq!(outcome, PickerKeyOutcome::Continue);
        assert!(
            picker.key_entry().is_none(),
            "Ctrl+C must cancel key entry mode"
        );
    }

    // --- handle_picker_key: browsing mode ---------------------------------------

    /// `n` single-transport, always-available candidates, one row each — enough to
    /// exercise cursor movement, toggling, and commander selection without any
    /// transport-cycling or key-entry complications.
    fn browsing_picker(ids: &[&str]) -> PickerState {
        use crate::orchestrator::{Availability, Candidate, TransportOption};
        let candidates: Vec<Candidate> = ids
            .iter()
            .map(|id| Candidate {
                id: (*id).to_string(),
                group: "GROUP".into(),
                model: (*id).to_string(),
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
        PickerState::new(candidates, &std::collections::BTreeMap::new(), None, false)
    }

    /// A candidate with two always-available transport rows, for exercising Tab's
    /// cycle without hitting the "nothing else to switch to" refusal path.
    fn dual_available_picker(id: &str) -> PickerState {
        use crate::orchestrator::{Availability, Candidate, TransportOption};
        let candidate = Candidate {
            id: id.into(),
            group: "GROUP".into(),
            model: id.into(),
            transports: vec![
                TransportOption {
                    transport: None,
                    label: "first".into(),
                    detail: String::new(),
                    availability: Availability::Available,
                    cli: None,
                    needs_key: false,
                },
                TransportOption {
                    transport: None,
                    label: "second".into(),
                    detail: String::new(),
                    availability: Availability::Available,
                    cli: None,
                    needs_key: false,
                },
            ],
        };
        PickerState::new(
            vec![candidate],
            &std::collections::BTreeMap::new(),
            None,
            false,
        )
    }

    #[test]
    fn handle_picker_key_down_moves_cursor_to_the_next_row() {
        let mut picker = browsing_picker(&["a", "b"]);
        assert_eq!(picker.cursor(), 0);

        let outcome = handle_picker_key(&mut picker, KeyCode::Down, KeyModifiers::NONE);

        assert_eq!(outcome, PickerKeyOutcome::Continue);
        assert_eq!(
            picker.cursor(),
            1,
            "Down must move the cursor to the next row"
        );
    }

    #[test]
    fn handle_picker_key_up_moves_cursor_to_the_previous_row() {
        let mut picker = browsing_picker(&["a", "b"]);
        picker.move_down();
        assert_eq!(picker.cursor(), 1);

        let outcome = handle_picker_key(&mut picker, KeyCode::Up, KeyModifiers::NONE);

        assert_eq!(outcome, PickerKeyOutcome::Continue);
        assert_eq!(
            picker.cursor(),
            0,
            "Up must move the cursor to the previous row"
        );
    }

    #[test]
    fn handle_picker_key_space_toggles_only_without_control() {
        let mut picker = browsing_picker(&["a"]);
        assert!(!picker.is_checked(0, 0));

        // Ctrl+Space must be a no-op for the checkbox — it must not toggle.
        let outcome = handle_picker_key(&mut picker, KeyCode::Char(' '), KeyModifiers::CONTROL);
        assert_eq!(outcome, PickerKeyOutcome::Continue);
        assert!(
            !picker.is_checked(0, 0),
            "Ctrl+Space must not toggle the highlighted row"
        );

        // Plain space must toggle it on.
        let outcome = handle_picker_key(&mut picker, KeyCode::Char(' '), KeyModifiers::NONE);
        assert_eq!(outcome, PickerKeyOutcome::Continue);
        assert!(
            picker.is_checked(0, 0),
            "plain space must toggle the highlighted row"
        );
    }

    #[test]
    fn handle_picker_key_tab_cycles_the_transport() {
        let mut picker = dual_available_picker("dual");
        // Enable the row on its first transport so the cycle is observable through
        // `is_checked` (an un-enabled row reports not-checked for every transport
        // regardless of which one is "chosen").
        handle_picker_key(&mut picker, KeyCode::Char(' '), KeyModifiers::NONE);
        assert!(picker.is_checked(0, 0));

        let outcome = handle_picker_key(&mut picker, KeyCode::Tab, KeyModifiers::NONE);

        assert_eq!(outcome, PickerKeyOutcome::Continue);
        assert!(
            picker.is_checked(0, 1),
            "Tab must cycle the enabled row onto the second transport"
        );
        assert!(
            !picker.is_checked(0, 0),
            "the first transport must no longer be the chosen one after Tab"
        );
    }

    #[test]
    fn handle_picker_key_plain_c_sets_commander_and_does_not_cancel() {
        let mut picker = browsing_picker(&["a"]);
        // `set_commander` refuses a row that isn't ticked, so tick it first.
        picker.toggle();
        assert!(!picker.is_commander(0, 0));

        let outcome = handle_picker_key(&mut picker, KeyCode::Char('c'), KeyModifiers::NONE);

        assert_eq!(
            outcome,
            PickerKeyOutcome::Continue,
            "plain 'c' must not cancel the picker"
        );
        assert!(
            picker.is_commander(0, 0),
            "plain 'c' must set the highlighted row as commander"
        );
    }

    #[test]
    fn handle_picker_key_m_edits_an_api_model() {
        use crate::config::Transport;
        use crate::orchestrator::{Availability, Candidate, TransportOption};

        let candidate = Candidate {
            id: "openrouter".into(),
            group: "OPENROUTER".into(),
            model: "openai/gpt-4o".into(),
            transports: vec![TransportOption {
                transport: Some(Transport::Api),
                label: "via API".into(),
                detail: "https://openrouter.ai/api/v1".into(),
                availability: Availability::Available,
                cli: None,
                needs_key: false,
            }],
        };
        let mut picker = PickerState::new(
            vec![candidate],
            &std::collections::BTreeMap::new(),
            None,
            false,
        );

        let outcome = handle_picker_key(&mut picker, KeyCode::Char('m'), KeyModifiers::NONE);
        assert_eq!(outcome, PickerKeyOutcome::Continue);
        assert!(picker.model_entry().is_some());

        for c in "anthropic/claude-sonnet-4".chars() {
            let outcome = handle_picker_key(&mut picker, KeyCode::Char(c), KeyModifiers::NONE);
            assert_eq!(outcome, PickerKeyOutcome::Continue);
        }
        let outcome = handle_picker_key(&mut picker, KeyCode::Enter, KeyModifiers::NONE);
        assert_eq!(outcome, PickerKeyOutcome::Submit);
        picker.submit_model_entry();

        assert_eq!(picker.display_model(0, 0), "anthropic/claude-sonnet-4");
    }

    #[test]
    fn handle_picker_key_enter_submits_in_browsing_mode() {
        let mut picker = browsing_picker(&["a"]);

        let outcome = handle_picker_key(&mut picker, KeyCode::Enter, KeyModifiers::NONE);

        assert_eq!(outcome, PickerKeyOutcome::Submit);
    }

    #[test]
    fn handle_picker_key_esc_cancels_in_browsing_mode() {
        let mut picker = browsing_picker(&["a"]);

        let outcome = handle_picker_key(&mut picker, KeyCode::Esc, KeyModifiers::NONE);

        assert_eq!(outcome, PickerKeyOutcome::Cancel);
    }

    #[test]
    fn handle_picker_key_q_cancels_only_without_control() {
        let mut picker = browsing_picker(&["a"]);

        // Ctrl+Q must not cancel — it must fall through as a no-op.
        let outcome = handle_picker_key(&mut picker, KeyCode::Char('q'), KeyModifiers::CONTROL);
        assert_eq!(
            outcome,
            PickerKeyOutcome::Continue,
            "Ctrl+Q must not cancel the picker"
        );

        // Plain 'q' must cancel.
        let outcome = handle_picker_key(&mut picker, KeyCode::Char('q'), KeyModifiers::NONE);
        assert_eq!(
            outcome,
            PickerKeyOutcome::Cancel,
            "plain 'q' must cancel the picker"
        );
    }

    // --- handle_picker_key: key-entry mode ---------------------------------------

    /// A single candidate whose only transport needs a key, already ticked into key
    /// entry — everything below routes keys through `handle_picker_key` while
    /// `state.key_entry().is_some()`.
    fn key_entry_picker() -> PickerState {
        use crate::orchestrator::{Availability, Candidate, TransportOption};
        let candidate = Candidate {
            id: "needs-key".into(),
            group: "GROUP".into(),
            model: "needs-key".into(),
            transports: vec![TransportOption {
                transport: None,
                label: String::new(),
                detail: String::new(),
                availability: Availability::Unavailable("no key".into()),
                cli: None,
                needs_key: true,
            }],
        };
        let mut picker = PickerState::new(
            vec![candidate],
            &std::collections::BTreeMap::new(),
            None,
            false,
        );
        picker.toggle(); // opens key entry
        assert!(picker.key_entry().is_some());
        picker
    }

    #[test]
    fn handle_picker_key_esc_cancels_key_entry() {
        let mut picker = key_entry_picker();

        let outcome = handle_picker_key(&mut picker, KeyCode::Esc, KeyModifiers::NONE);

        assert_eq!(outcome, PickerKeyOutcome::Continue);
        assert!(
            picker.key_entry().is_none(),
            "Esc must cancel key entry and return to browsing"
        );
    }

    #[test]
    fn handle_picker_key_ctrl_c_cancels_key_entry_but_plain_c_types() {
        let mut picker = key_entry_picker();

        // Plain 'c' (no modifiers) must be typed into the key buffer, not treated as
        // a cancel chord.
        let outcome = handle_picker_key(&mut picker, KeyCode::Char('c'), KeyModifiers::NONE);
        assert_eq!(outcome, PickerKeyOutcome::Continue);
        assert_eq!(
            picker.key_entry().unwrap().1,
            1,
            "plain 'c' must be appended to the key buffer, not cancel key entry"
        );

        // Ctrl+C must cancel key entry.
        let outcome = handle_picker_key(&mut picker, KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert_eq!(outcome, PickerKeyOutcome::Continue);
        assert!(picker.key_entry().is_none(), "Ctrl+C must cancel key entry");
    }

    #[test]
    fn handle_picker_key_backspace_deletes_the_last_typed_character() {
        let mut picker = key_entry_picker();
        handle_picker_key(&mut picker, KeyCode::Char('x'), KeyModifiers::NONE);
        handle_picker_key(&mut picker, KeyCode::Char('y'), KeyModifiers::NONE);
        assert_eq!(picker.key_entry().unwrap().1, 2);

        let outcome = handle_picker_key(&mut picker, KeyCode::Backspace, KeyModifiers::NONE);

        assert_eq!(outcome, PickerKeyOutcome::Continue);
        assert_eq!(
            picker.key_entry().unwrap().1,
            1,
            "Backspace must delete exactly one character from the key buffer"
        );
    }

    #[test]
    fn handle_picker_key_enter_submits_key_entry() {
        let mut picker = key_entry_picker();
        handle_picker_key(&mut picker, KeyCode::Char('s'), KeyModifiers::NONE);
        handle_picker_key(&mut picker, KeyCode::Char('k'), KeyModifiers::NONE);

        let outcome = handle_picker_key(&mut picker, KeyCode::Enter, KeyModifiers::NONE);

        assert_eq!(outcome, PickerKeyOutcome::Submit);
    }

    #[test]
    fn handle_picker_key_plain_characters_type_but_control_chords_do_not() {
        let mut picker = key_entry_picker();
        assert_eq!(picker.key_entry().unwrap().1, 0);

        // A plain character must be appended.
        let outcome = handle_picker_key(&mut picker, KeyCode::Char('x'), KeyModifiers::NONE);
        assert_eq!(outcome, PickerKeyOutcome::Continue);
        assert_eq!(
            picker.key_entry().unwrap().1,
            1,
            "a plain character must be appended to the key buffer"
        );

        // A non-'c' Ctrl chord must not be appended (and must not cancel either).
        let outcome = handle_picker_key(&mut picker, KeyCode::Char('a'), KeyModifiers::CONTROL);
        assert_eq!(outcome, PickerKeyOutcome::Continue);
        assert_eq!(
            picker.key_entry().unwrap().1,
            1,
            "Ctrl+A must not be appended to the key buffer"
        );
        assert!(
            picker.key_entry().is_some(),
            "Ctrl+A must not cancel key entry"
        );
    }

    #[tokio::test]
    async fn reproduction_test_handle_key_ctrl_c_with_shift_or_caps_exits() {
        let mut app = App::new(
            "ollama:llama3",
            &["ollama:llama3".to_string()],
            "/tmp".to_string(),
        );
        let (cmd_tx, _cmd_rx) = mpsc::channel(32);
        let (dec_tx, _dec_rx) = mpsc::channel(1);

        handle_key(
            &mut app,
            KeyCode::Char('C'),
            KeyModifiers::CONTROL,
            &cmd_tx,
            &dec_tx,
        )
        .await;

        assert!(app.should_quit);
    }

    // Pins the `KeyCode::Esc` arm at the top of the main `match code` block: Esc is
    // the primary way out of the TUI, and with no pending write to intercept it first
    // the key has to reach that arm and set `should_quit` directly, not just be
    // absorbed by the trailing `_ => {}` catch-all as an ordinary unbound key.
    #[tokio::test]
    async fn esc_quits_the_app_from_the_main_key_handler() {
        let mut app = App::new(
            "ollama:llama3",
            &["ollama:llama3".to_string()],
            "/tmp".to_string(),
        );
        let (cmd_tx, _cmd_rx) = mpsc::channel(32);
        let (dec_tx, _dec_rx) = mpsc::channel(1);

        handle_key(&mut app, KeyCode::Esc, KeyModifiers::NONE, &cmd_tx, &dec_tx).await;

        assert!(app.should_quit);
    }

    #[test]
    fn reproduction_test_picker_uppercase_c_sets_commander() {
        let mut picker = browsing_picker(&["a"]);
        assert!(!picker.is_commander(0, 0));

        handle_picker_key(&mut picker, KeyCode::Char('C'), KeyModifiers::NONE);

        assert!(picker.is_commander(0, 0));
    }
}

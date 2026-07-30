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
use tokio::sync::mpsc;

use crate::app::App;
use crate::config::Settings;
use crate::orchestrator::{Command, Event, discover_candidates};
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
    mut events: mpsc::Receiver<Event>,
    mut settings: Settings,
    paths: crate::config::Paths,
    classified: bool,
) -> Result<App> {
    let mut guard = TerminalGuard::enter()?;
    let mut input = EventStream::new();

    loop {
        guard.terminal.draw(|frame| draw(frame, &app))?;

        tokio::select! {
            maybe_term = input.next() => {
                match maybe_term {
                    Some(Ok(TermEvent::Key(key))) if key.kind == KeyEventKind::Press => {
                        if is_reopen_picker(key.code, key.modifiers) {
                            reopen_picker(&mut guard, &mut input, &mut app, &commands, &mut settings, &paths, classified).await;
                        } else {
                            handle_key(&mut app, key.code, key.modifiers, &commands).await;
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
                    Some(event) => app.apply(event),
                    // Orchestrator shut down; nothing more can arrive.
                    None => break,
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

async fn handle_key(
    app: &mut App,
    code: KeyCode,
    modifiers: KeyModifiers,
    commands: &mpsc::Sender<Command>,
) {
    match code {
        KeyCode::Esc => app.should_quit = true,
        KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => {
            app.should_quit = true;
        }
        KeyCode::Enter => {
            if let Some(prompt) = app.submit() {
                // A full channel means the orchestrator is backed up; report rather
                // than silently dropping the user's message.
                if commands.send(Command::Prompt(prompt)).await.is_err() {
                    app.apply(Event::Error("orchestrator is not running".into()));
                    app.busy = false;
                }
            }
        }
        KeyCode::Backspace => app.backspace(),
        KeyCode::PageUp => app.scroll_up(),
        KeyCode::PageDown => app.scroll_down(),
        KeyCode::Char(c) => app.push_char(c),
        _ => {}
    }
}

fn draw(frame: &mut ratatui::Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(3)])
        .split(frame.area());

    let history = Paragraph::new(app.body())
        .wrap(Wrap { trim: false })
        .scroll((app.scroll, 0))
        .block(Block::default().title(" simon ").borders(Borders::ALL));
    frame.render_widget(history, chunks[0]);

    let style = if app.busy {
        Style::default().fg(Color::DarkGray)
    } else {
        Style::default()
    };
    let input = Paragraph::new(format!("> {}", app.input))
        .style(style)
        .block(
            Block::default()
                .title(format!(" {} ", app.status_line()))
                .borders(Borders::ALL),
        );
    frame.render_widget(input, chunks[1]);
}

/// Renders the picker: a body pane listing every candidate grouped by provider, and
/// a hint line (or a flash message, when the last key press was a no-op).
fn draw_picker(frame: &mut ratatui::Frame, picker: Option<&PickerState>) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(frame.area());

    let body = match picker {
        None => "Discovering connections…".to_string(),
        Some(picker) => render_picker_body(picker),
    };
    let list = Paragraph::new(body).wrap(Wrap { trim: false }).block(
        Block::default()
            .title(" simon — choose connections ")
            .borders(Borders::ALL),
    );
    frame.render_widget(list, chunks[0]);

    let hint = picker
        .and_then(|p| p.flash.as_deref())
        .map(str::to_string)
        .unwrap_or_else(|| {
            "space toggle · c commander · tab transport · enter connect · q quit".to_string()
        });
    frame.render_widget(Paragraph::new(hint), chunks[1]);
}

fn render_picker_body(picker: &PickerState) -> String {
    let mut out = String::new();
    let mut last_group: Option<&str> = None;

    for (line_idx, row) in picker.rows().iter().enumerate() {
        let candidate = &picker.candidates()[row.candidate];
        if last_group != Some(candidate.group.as_str()) {
            if last_group.is_some() {
                out.push('\n');
            }
            out.push_str(&candidate.group);
            out.push('\n');
            last_group = Some(candidate.group.as_str());
        }

        let option = &candidate.transports[row.transport];
        let checkbox = if picker.is_checked(row.candidate, row.transport) {
            "[x]"
        } else {
            "[ ]"
        };
        let cursor = if picker.cursor() == line_idx {
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
    }

    if out.is_empty() {
        out.push_str("No candidate connections were found.\n");
    }
    out
}

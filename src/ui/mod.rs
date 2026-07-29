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
use crate::orchestrator::{Command, Event};

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

/// Runs the TUI until the user quits or the orchestrator closes its event channel.
pub async fn run(
    mut app: App,
    commands: mpsc::Sender<Command>,
    mut events: mpsc::Receiver<Event>,
) -> Result<()> {
    let mut guard = TerminalGuard::enter()?;
    let mut input = EventStream::new();

    loop {
        guard.terminal.draw(|frame| draw(frame, &app))?;

        tokio::select! {
            maybe_term = input.next() => {
                match maybe_term {
                    Some(Ok(TermEvent::Key(key))) if key.kind == KeyEventKind::Press => {
                        handle_key(&mut app, key.code, key.modifiers, &commands).await;
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
    Ok(())
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

use crate::app::{App, AppEvent};
use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use futures::{FutureExt, StreamExt};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    widgets::{Block, Borders, Paragraph},
    Terminal,
};
use std::io;

pub async fn run_tui() -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();
    let mut reader = crossterm::event::EventStream::new();

    loop {
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(1), Constraint::Length(3)].as_ref())
                .split(f.size());

            let history_text = app.messages.join("\n");
            let history_block = Paragraph::new(history_text)
                .block(Block::default().title("Multichat History").borders(Borders::ALL));
            f.render_widget(history_block, chunks[0]);

            let input_text = format!("> {}", app.input);
            let input_block = Paragraph::new(input_text)
                .block(Block::default().title("Input (Press Enter to send, Esc to quit)").borders(Borders::ALL));
            f.render_widget(input_block, chunks[1]);
        })?;

        tokio::select! {
            Some(Ok(evt)) = reader.next().fuse() => {
                if let Event::Key(key) = evt {
                    if key.kind == KeyEventKind::Press {
                        match key.code {
                            KeyCode::Esc => {
                                break;
                            }
                            KeyCode::Char(c) => {
                                app.handle_key_char(c);
                            }
                            KeyCode::Backspace => {
                                app.handle_backspace();
                            }
                            KeyCode::Enter => {
                                if let Some(msg) = app.submit_input() {
                                    // Send to background swarm orchestrator (mocked here for now)
                                    // Normally we would tx.send(AppEvent::UiInput(msg)) and await it.
                                    app.add_agent_response(&format!("Acknowledged: {}", msg));
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            Some(app_event) = app.ui_rx.recv() => {
                match app_event {
                    AppEvent::AgentResponse(msg) => app.add_agent_response(&msg),
                    AppEvent::Quit => break,
                    _ => {}
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}

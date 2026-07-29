//! TUI state, kept free of I/O so it can be unit-tested.

use crate::orchestrator::Event;

/// Who produced a line in the transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Speaker {
    You,
    Model(String),
    System,
    Error,
}

#[derive(Debug, Clone)]
pub struct Line {
    pub speaker: Speaker,
    pub text: String,
}

impl Line {
    pub fn render(&self) -> String {
        match &self.speaker {
            Speaker::You => format!("you › {}", self.text),
            Speaker::Model(label) => format!("{label} › {}", self.text),
            Speaker::System => format!("· {}", self.text),
            Speaker::Error => format!("! {}", self.text),
        }
    }
}

pub struct App {
    pub input: String,
    pub transcript: Vec<Line>,
    /// Lines scrolled off the top of the history pane.
    pub scroll: u16,
    /// True while the orchestrator is working on a turn.
    pub busy: bool,
    pub primary: String,
    pub should_quit: bool,
}

impl App {
    pub fn new(primary: impl Into<String>, roster: &[String]) -> Self {
        let primary = primary.into();
        let mut transcript = vec![Line {
            speaker: Speaker::System,
            text: format!("commander: {primary}"),
        }];
        if !roster.is_empty() {
            transcript.push(Line {
                speaker: Speaker::System,
                text: format!("swarm: {}", roster.join(", ")),
            });
        }
        Self {
            input: String::new(),
            transcript,
            scroll: 0,
            busy: false,
            primary,
            should_quit: false,
        }
    }

    pub fn push_char(&mut self, c: char) {
        self.input.push(c);
    }

    pub fn backspace(&mut self) {
        self.input.pop();
    }

    /// Takes the pending input if there is any, recording it in the transcript.
    pub fn submit(&mut self) -> Option<String> {
        let text = self.input.trim().to_string();
        if text.is_empty() {
            return None;
        }
        self.input.clear();
        self.transcript.push(Line {
            speaker: Speaker::You,
            text: text.clone(),
        });
        self.busy = true;
        Some(text)
    }

    /// Folds an orchestrator event into the transcript.
    pub fn apply(&mut self, event: Event) {
        match event {
            Event::Reply { label, text } => self.transcript.push(Line {
                speaker: Speaker::Model(label),
                text,
            }),
            Event::Delegated { from, to } => self.transcript.push(Line {
                speaker: Speaker::System,
                text: format!("{from} delegated to {to}"),
            }),
            Event::Status(text) => self.transcript.push(Line {
                speaker: Speaker::System,
                text,
            }),
            Event::Error(text) => self.transcript.push(Line {
                speaker: Speaker::Error,
                text,
            }),
            Event::TurnComplete => self.busy = false,
            Event::Reconfigured { primary, roster } => {
                self.primary = primary.clone();
                self.transcript.push(Line {
                    speaker: Speaker::System,
                    text: format!("connections updated — commander: {primary}"),
                });
                if !roster.is_empty() {
                    self.transcript.push(Line {
                        speaker: Speaker::System,
                        text: format!("swarm: {}", roster.join(", ")),
                    });
                }
            }
        }
    }

    pub fn scroll_up(&mut self) {
        self.scroll = self.scroll.saturating_sub(1);
    }

    pub fn scroll_down(&mut self) {
        self.scroll = self.scroll.saturating_add(1);
    }

    pub fn body(&self) -> String {
        self.transcript
            .iter()
            .map(Line::render)
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The chat input's title bar. It names the commander and, crucially, advertises
    /// `Ctrl+O`: without it there is nothing on the chat screen to suggest the
    /// connection set or the commander can be changed without restarting.
    pub fn status_line(&self) -> String {
        if self.busy {
            format!("{} · working… (Esc to quit)", self.primary)
        } else {
            format!(
                "{} · Enter send · Ctrl+O connections · Esc quit",
                self.primary
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> App {
        App::new("ollama:llama3", &["ollama:llama3".to_string()])
    }

    #[test]
    fn typing_and_submitting_moves_text_into_the_transcript() {
        let mut app = app();
        for c in "hello".chars() {
            app.push_char(c);
        }
        assert_eq!(app.submit().as_deref(), Some("hello"));
        assert!(app.input.is_empty());
        assert!(app.busy);
        assert!(app.body().contains("you › hello"));
    }

    #[test]
    fn blank_input_is_not_submitted() {
        let mut app = app();
        assert!(app.submit().is_none());
        app.push_char(' ');
        assert!(
            app.submit().is_none(),
            "whitespace-only input must be ignored"
        );
        assert!(!app.busy);
    }

    #[test]
    fn backspace_removes_the_last_character() {
        let mut app = app();
        app.push_char('a');
        app.push_char('b');
        app.backspace();
        assert_eq!(app.input, "a");
        // Backspacing an empty buffer must not panic.
        app.backspace();
        app.backspace();
        assert!(app.input.is_empty());
    }

    #[test]
    fn replies_are_attributed_to_their_model() {
        let mut app = app();
        app.apply(Event::Reply {
            label: "anthropic:claude-opus-5".into(),
            text: "hi".into(),
        });
        assert!(app.body().contains("anthropic:claude-opus-5 › hi"));
    }

    #[test]
    fn turn_complete_clears_the_busy_flag() {
        let mut app = app();
        app.push_char('x');
        app.submit();
        assert!(app.busy);
        app.apply(Event::TurnComplete);
        assert!(!app.busy);
        assert!(app.status_line().contains("Ctrl+O"));
    }

    #[test]
    fn errors_are_shown_without_ending_the_session() {
        let mut app = app();
        app.apply(Event::Error("rate limited".into()));
        assert!(app.body().contains("! rate limited"));
        assert!(!app.should_quit);
    }

    #[test]
    fn reconfigured_updates_the_primary_and_status_line() {
        let mut app = app();
        app.apply(Event::Reconfigured {
            primary: "anthropic:claude-opus-5".into(),
            roster: vec!["anthropic:claude-opus-5".into(), "ollama:llama3".into()],
        });
        assert_eq!(app.primary, "anthropic:claude-opus-5");
        assert!(app.status_line().contains("anthropic:claude-opus-5"));
        assert!(app.body().contains("commander: anthropic:claude-opus-5"));
        assert!(
            app.body()
                .contains("swarm: anthropic:claude-opus-5, ollama:llama3")
        );
    }

    #[test]
    fn scrolling_saturates_instead_of_wrapping() {
        let mut app = app();
        app.scroll_up();
        assert_eq!(app.scroll, 0);
        app.scroll_down();
        assert_eq!(app.scroll, 1);
    }
}

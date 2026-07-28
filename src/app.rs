use tokio::sync::mpsc;

pub enum AppEvent {
    UiInput(String),
    AgentResponse(String),
    Quit,
}

pub struct App {
    pub input: String,
    pub messages: Vec<String>,
    pub ui_tx: mpsc::Sender<AppEvent>,
    pub ui_rx: mpsc::Receiver<AppEvent>,
}

impl App {
    pub fn new() -> Self {
        let (ui_tx, ui_rx) = mpsc::channel(100);
        Self {
            input: String::new(),
            messages: Vec::new(),
            ui_tx,
            ui_rx,
        }
    }

    pub fn handle_key_char(&mut self, c: char) {
        self.input.push(c);
    }

    pub fn handle_backspace(&mut self) {
        self.input.pop();
    }

    pub fn submit_input(&mut self) -> Option<String> {
        if self.input.is_empty() {
            return None;
        }
        let msg = self.input.clone();
        self.messages.push(format!("You: {}", msg));
        self.input.clear();
        Some(msg)
    }

    pub fn add_agent_response(&mut self, response: &str) {
        self.messages.push(format!("Agent: {}", response));
    }
}

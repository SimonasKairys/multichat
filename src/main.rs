#![deny(unsafe_code)] // Forbid unsafe code globally (except in security.rs where it is explicitly allowed)

pub mod config;
pub mod providers;
pub mod security;
pub mod vault;
pub mod swarm;
pub mod audit;
pub mod app;
pub mod ui;

use clap::{Parser, Subcommand};
use anyhow::Result;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Enforce strictly classified mode (air-gap, local models only)
    #[arg(long, default_value_t = false)]
    classified: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the chat TUI (default)
    Chat {
        /// The primary commander model to use (e.g. 'claude-3-5-sonnet-20240620' or 'ollama:llama3')
        #[arg(short, long)]
        model: Option<String>,
    },
    /// Store an API key securely (e.g. auth set openai <key>)
    Auth {
        #[arg(short, long)]
        service: String,
        #[arg(short, long)]
        key: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Enforce Zero-Trust Security Foundation immediately on startup
    security::enforce_memory_protection()?;
    security::enforce_seccomp_sandbox()?;

    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Auth { service, key }) => {
            config::Config::set_api_key(service, "default", key)?;
            println!("Successfully securely saved API key for {}", service);
        }
        Some(Commands::Chat { model }) => {
            let selected_model = model.as_deref().unwrap_or("auto-discovery");
            println!("Starting Simon Swarm Environment... (Commander: {})", selected_model);
            ui::run_tui().await?;
        }
        None => {
            println!("Starting Simon Swarm Environment... (Commander: auto-discovery)");
            ui::run_tui().await?;
        }
    }

    Ok(())
}

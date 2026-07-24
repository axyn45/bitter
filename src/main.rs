mod agent;
mod api;
mod cli;
mod commands;
mod config;
mod crypto;
mod daemon;
mod storage;
mod tui;


use clap::Parser;
use cli::{Cli, Commands};
use config::Config;

fn main() {
    let max_level = if std::env::var("RUST_LOG").unwrap_or_default().to_lowercase() == "debug" {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };

    tracing_subscriber::fmt()
        .with_max_level(max_level)
        .with_target(false)
        .init();

    let cli = Cli::parse();

    // Check if it's the start command
    if let Commands::Start(ref start_args) = cli.command {
        if let Err(e) = daemon::start_agent(start_args.background, start_args.socket.clone()) {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
        return;
    }

    let mut config = match Config::load() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Error loading config: {}", e);
            std::process::exit(1);
        }
    };

    // Route commands
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to build Tokio runtime");

    if let Err(e) = rt.block_on(commands::run_command(cli.command, &mut config)) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

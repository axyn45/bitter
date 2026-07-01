mod cli;
mod config;

use clap::Parser;
use cli::{Cli, Commands, KeysCommands};
use config::{Config, TimeoutAction};
use std::str::FromStr;

fn main() {
    // Parse CLI arguments
    let cli = Cli::parse();

    // Load configuration (loads default if file doesn't exist)
    let mut config = match Config::load() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Error loading config: {}", e);
            std::process::exit(1);
        }
    };

    // Route commands
    match cli.command {
        Commands::Login(args) => {
            println!("Subcommand: Login");
            if let Some(srv) = args.server {
                config.server_url = srv;
            }
            if let Some(email) = args.email {
                config.email = Some(email);
            }
            if let Some(cid) = args.client_id {
                config.client_id = Some(cid);
            }
            if let Some(csec) = args.client_secret {
                config.client_secret = Some(csec);
            }

            // Save updated config
            if let Err(e) = config.save() {
                eprintln!("Error saving configuration: {}", e);
                std::process::exit(1);
            }
            println!("Configuration updated. Server: {}", config.server_url);
            if let Some(ref email) = config.email {
                println!("Email: {}", email);
            }
            if config.client_id.is_some() {
                println!("API Credentials provided.");
            }
            println!("Proceeding to authentication (Phase 2)...");
        }
        Commands::Logout => {
            println!("Subcommand: Logout");
            // Clear credentials
            config.email = None;
            config.client_id = None;
            config.client_secret = None;
            if let Err(e) = config.save() {
                eprintln!("Error saving configuration: {}", e);
                std::process::exit(1);
            }
            println!("Logged out successfully. Configuration cleared.");
        }
        Commands::Sync => {
            println!("Subcommand: Sync");
            println!("Syncing vault items from server {}...", config.server_url);
        }
        Commands::Settings(args) => {
            println!("Subcommand: Settings");
            let mut updated = false;

            if let Some(t) = args.timeout {
                config.timeout = t.clone();
                println!("Timeout updated to: {}", t);
                updated = true;
            }

            if let Some(act_str) = args.timeout_action {
                match TimeoutAction::from_str(&act_str) {
                    Ok(action) => {
                        config.timeout_action = action;
                        println!("Timeout action updated to: {:?}", action);
                        updated = true;
                    }
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                }
            }

            if updated {
                if let Err(e) = config.save() {
                    eprintln!("Error saving configuration: {}", e);
                    std::process::exit(1);
                }
                println!("Settings saved.");
            } else {
                // Just display settings
                println!("Current settings:");
                println!("  Server URL:     {}", config.server_url);
                println!(
                    "  Email:          {}",
                    config.email.as_deref().unwrap_or("<not logged in>")
                );
                println!("  Session Timeout: {}", config.timeout);
                println!("  Timeout Action:  {:?}", config.timeout_action);
            }
        }
        Commands::Keys(args) => match args.command {
            KeysCommands::List => {
                println!("Subcommand: Keys List");
                println!("Listing available SSH keys...");
            }
            KeysCommands::Add => {
                println!("Subcommand: Keys Add");
                println!("Interactive SSH key creation/addition...");
            }
            KeysCommands::Edit { id } => {
                println!("Subcommand: Keys Edit");
                println!("Editing SSH key with ID: {}", id);
            }
            KeysCommands::Delete { id } => {
                println!("Subcommand: Keys Delete");
                println!("Deleting SSH key with ID: {}", id);
            }
        },
        Commands::Daemon(args) => {
            println!("Subcommand: Daemon");
            println!("Starting agent socket daemon...");
            if args.foreground {
                println!("Running in foreground...");
            } else {
                println!("Daemonizing process...");
            }
            let sock_path = args.socket.or(config.socket_path.clone());
            println!(
                "Socket path: {:?}",
                sock_path.unwrap_or_else(|| "/tmp/sshwarden.sock".into())
            );
        }
        Commands::Unlock => {
            println!("Subcommand: Unlock");
            println!("Unlocking agent memory cache...");
        }
    }
}

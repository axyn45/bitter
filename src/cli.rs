use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "bitter",
    about = "Bitwarden Terminal Client & SSH Agent",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Log in to Bitwarden server
    Login(LoginArgs),

    /// Log out from Bitwarden, clearing cache and credentials
    Logout,

    /// Synchronize ciphers from Bitwarden server to local cache
    Sync,

    /// View or update settings
    Settings(SettingsArgs),

    /// Manage SSH keys
    Keys(KeysArgs),

    /// Start the background daemon process
    Start(DaemonArgs),

    /// Stop the running background daemon process
    Stop,

    /// Start the SSH agent listener loop inside the running daemon
    StartSsh,

    /// Stop the SSH agent listener loop inside the running daemon
    StopSsh,

    /// Unlock the agent by supplying the master password
    Unlock,

    /// View global status of bitter
    Status,

    /// Open the interactive Terminal User Interface (TUI)
    Tui,

    /// Reset bitter's local configuration or database
    Reset(ResetArgs),
}

#[derive(Debug, Args)]
pub struct LoginArgs {
    /// Account email address
    #[arg(short, long)]
    pub email: Option<String>,

    /// Master password (will prompt securely if not provided)
    #[arg(short, long)]
    pub password: Option<String>,

    /// Personal API Key client ID
    #[arg(long)]
    pub client_id: Option<String>,

    /// Personal API Key client secret
    #[arg(long)]
    pub client_secret: Option<String>,

    /// Custom Bitwarden server URL (e.g. self-hosted Vaultwarden)
    #[arg(short, long)]
    pub server: Option<String>,

    /// Log in using SSO (Single Sign-On)
    #[arg(long)]
    pub sso: bool,

    /// Organization identifier (required for SSO login)
    #[arg(long)]
    pub org_id: Option<String>,
}

#[derive(Debug, Args)]
pub struct SettingsArgs {
    /// Set session timeout (e.g., 'immediately', '1m', '15m', 'never', 'unlocked', 'custom 300')
    #[arg(short, long)]
    pub timeout: Option<String>,

    /// Set timeout action: 'lock' (requires master password) or 'logout' (wipes vault)
    #[arg(short = 'a', long)]
    pub timeout_action: Option<String>,

    /// Set custom Bitwarden server URL (e.g. self-hosted Vaultwarden)
    #[arg(short, long)]
    pub server_url: Option<String>,

    /// Enable or disable SSH agent auto-start with the daemon ('true' or 'false')
    #[arg(long)]
    pub ssh_agent_auto_start: Option<String>,
}

#[derive(Debug, Args)]
pub struct KeysArgs {
    #[command(subcommand)]
    pub command: KeysCommands,
}

#[derive(Debug, Subcommand)]
pub enum KeysCommands {
    /// List all synced SSH keys
    List,

    /// Add/Create a new SSH key item in Bitwarden
    Add,

    /// Edit an existing SSH key item in Bitwarden
    Edit {
        /// The Bitwarden cipher ID of the key to edit
        id: String,
    },

    /// Delete an SSH key item from Bitwarden
    Delete {
        /// The Bitwarden cipher ID of the key to delete
        id: String,
    },
}

#[derive(Debug, Args)]
pub struct DaemonArgs {
    /// Run the agent in the background (daemonize)
    #[arg(short, long)]
    pub background: bool,

    /// Path to the Unix domain socket for the SSH agent listener
    #[arg(short, long)]
    pub socket: Option<PathBuf>,
}

#[derive(Debug, Args, Clone)]
pub struct ResetArgs {
    /// Reset configuration file (removes it)
    #[arg(long)]
    pub config: bool,

    /// Reset database file (removes it)
    #[arg(long)]
    pub db: bool,
}

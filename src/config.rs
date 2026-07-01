use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::str::FromStr;

const APP_NAME: &str = "sshwarden";
const CONFIG_FILE_NAME: &str = "config.toml";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TimeoutAction {
    Lock,
    Logout,
}

impl FromStr for TimeoutAction {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "lock" => Ok(TimeoutAction::Lock),
            "logout" => Ok(TimeoutAction::Logout),
            _ => Err(format!(
                "Invalid timeout action '{}'. Expected 'lock' or 'logout'",
                s
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub server_url: String,
    pub email: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub timeout: String,
    pub timeout_action: TimeoutAction,
    pub socket_path: Option<PathBuf>,
    pub vault_cache_path: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            server_url: "https://api.bitwarden.com".to_string(),
            email: None,
            client_id: None,
            client_secret: None,
            timeout: "15m".to_string(),
            timeout_action: TimeoutAction::Lock,
            socket_path: None,
            vault_cache_path: None,
        }
    }
}

impl Config {
    /// Gets the standard configuration directory for sshwarden
    pub fn config_dir() -> Option<PathBuf> {
        ProjectDirs::from("com", "", APP_NAME).map(|proj| proj.config_dir().to_path_buf())
    }

    /// Gets the path to the config.toml file
    pub fn config_path() -> Option<PathBuf> {
        Self::config_dir().map(|dir| dir.join(CONFIG_FILE_NAME))
    }

    /// Loads the configuration from disk, returning default if file doesn't exist
    pub fn load() -> io::Result<Self> {
        let path = match Self::config_path() {
            Some(p) => p,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "Could not determine config path",
                ));
            }
        };

        if !path.exists() {
            return Ok(Config::default());
        }

        let content = fs::read_to_string(&path)?;
        let config: Config = toml::from_str(&content).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to parse config: {}", e),
            )
        })?;

        Ok(config)
    }

    /// Saves the configuration to disk, ensuring directory exists and permissions are secure (0600)
    pub fn save(&self) -> io::Result<()> {
        let dir = match Self::config_dir() {
            Some(d) => d,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "Could not determine config path",
                ));
            }
        };

        // Ensure directory exists
        fs::create_dir_all(&dir)?;

        let path = dir.join(CONFIG_FILE_NAME);
        let content = toml::to_string_pretty(self).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to serialize config: {}", e),
            )
        })?;

        // Create file with owner read/write permissions only (0600)
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);

        let mut file = options.open(&path)?;

        // Apply UNIX file permissions (0600)
        let mut perms = file.metadata()?.permissions();
        perms.set_mode(0o600);
        file.set_permissions(perms)?;

        file.write_all(content.as_bytes())?;
        file.flush()?;

        Ok(())
    }
}

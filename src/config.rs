use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use directories::ProjectDirs;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::str::FromStr;
use crate::api::ApiClient;
use tracing;

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
    #[serde(default = "generate_device_id")]
    pub device_id: String,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub cache_salt: Option<String>,
    pub last_sync_time: Option<String>,
    pub local_key_count: Option<usize>,
    #[serde(default = "default_ssh_agent_auto_start")]
    pub ssh_agent_auto_start: bool,
}

fn default_ssh_agent_auto_start() -> bool {
    false
}

fn generate_device_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn generate_cache_salt() -> String {
    let mut salt = [0u8; 16];
    let sr = SystemRandom::new();
    if sr.fill(&mut salt).is_ok() {
        BASE64_STANDARD.encode(salt)
    } else {
        BASE64_STANDARD.encode(uuid::Uuid::new_v4().as_bytes())
    }
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
            device_id: generate_device_id(),
            access_token: None,
            refresh_token: None,
            cache_salt: Some(generate_cache_salt()),
            last_sync_time: None,
            local_key_count: None,
            ssh_agent_auto_start: false,
        }
    }
}

impl Config {
    /// Parses the timeout string into a Duration, or None if set to 'never'
    pub fn parse_timeout_duration(&self) -> Result<Option<std::time::Duration>, String> {
        let s = self.timeout.trim().to_lowercase();
        if s == "never" {
            return Ok(None);
        }
        if s == "immediately" {
            return Ok(Some(std::time::Duration::ZERO));
        }
        if s.starts_with("custom ") {
            let secs_str = s.strip_prefix("custom ").unwrap();
            let secs: u64 = secs_str
                .parse()
                .map_err(|e| format!("Invalid custom seconds '{}': {}", secs_str, e))?;
            return Ok(Some(std::time::Duration::from_secs(secs)));
        }
        // Check for suffixes: s, m, h, d
        let (val_str, multiplier) = if s.ends_with('s') {
            (s.strip_suffix('s').unwrap(), 1)
        } else if s.ends_with('m') {
            (s.strip_suffix('m').unwrap(), 60)
        } else if s.ends_with('h') {
            (s.strip_suffix('h').unwrap(), 3600)
        } else if s.ends_with('d') {
            (s.strip_suffix('d').unwrap(), 86400)
        } else {
            // Assume minutes if no suffix
            (s.as_str(), 60)
        };

        let val: u64 = val_str
            .parse()
            .map_err(|e| format!("Invalid timeout duration value '{}': {}", val_str, e))?;
        Ok(Some(std::time::Duration::from_secs(val * multiplier)))
    }
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
        let mut config: Config = toml::from_str(&content).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to parse config: {}", e),
            )
        })?;

        if config.cache_salt.is_none() {
            config.cache_salt = Some(generate_cache_salt());
            config.save()?;
        }

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

    /// Checks if the stored access token is expired or close to expiring
    pub fn is_token_expired(&self) -> bool {
        let token = match &self.access_token {
            Some(t) => t,
            None => return true,
        };
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() < 2 {
            return true;
        }
        let payload_b64 = parts[1];
        let mut pad = payload_b64.to_string();
        while pad.len() % 4 != 0 {
            pad.push('=');
        }
        let pad = pad.replace('-', "+").replace('_', "/");
        if let Ok(decoded) = BASE64_STANDARD.decode(pad) {
            if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&decoded) {
                if let Some(exp) = val.get("exp").and_then(|e| e.as_i64()) {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;
                    // Expired if current time is past (exp - 60s buffer)
                    return now >= (exp - 60);
                }
            }
        }
        true
    }

    /// Returns a valid access token, refreshing it if expired and refresh token is available
    pub async fn get_valid_token(&mut self) -> Result<String, String> {
        let access_token = self.access_token.as_ref().ok_or_else(|| "Not logged in".to_string())?;

        if self.is_token_expired() {
            if let Some(ref refresh_token) = self.refresh_token {
                tracing::info!("Access token is expired. Refreshing token...");
                let client = ApiClient::new(&self.server_url);
                match client.refresh_token(refresh_token).await {
                    Ok(token_resp) => {
                        self.access_token = Some(token_resp.access_token.clone());
                        if let Some(ref rt) = token_resp.refresh_token {
                            self.refresh_token = Some(rt.clone());
                        }
                        self.save().map_err(|e| format!("Failed to save refreshed token: {}", e))?;
                        tracing::info!("Token refreshed successfully.");
                        return Ok(token_resp.access_token);
                    }
                    Err(e) => {
                        return Err(format!("Failed to refresh token: {}", e));
                    }
                }
            } else {
                return Err("Access token is expired and no refresh token is available.".to_string());
            }
        }

        Ok(access_token.clone())
    }
}

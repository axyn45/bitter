use daemonize::Daemonize;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use ssh_key::private::PrivateKey;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::RwLock;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use tracing::{debug, error, info};

use crate::agent;
use crate::api::ApiClient;
use crate::storage;

#[derive(Clone)]
pub struct KeysContext {
    pub enc_key: [u8; 32],
    pub mac_key: [u8; 32],
    pub db_key: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ControlRequest {
    Unlock {
        keys: Vec<SshKeyData>,
        enc_key: String,
        mac_key: String,
        db_key: String,
    },
    Lock,
    Status,
    Reload,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SshKeyData {
    pub name: String,
    pub private_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unlocked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_count: Option<usize>,
}

type KeyRing = Arc<RwLock<Vec<PrivateKey>>>;
type SharedKeysContext = Arc<RwLock<Option<KeysContext>>>;

/// Starts the agent background process
pub async fn start_agent(foreground: bool, custom_socket_path: Option<PathBuf>) -> Result<(), String> {
    let cache_dir =
        storage::cache_dir().ok_or_else(|| "Could not determine cache directory".to_string())?;
    fs::create_dir_all(&cache_dir)
        .map_err(|e| format!("Failed to create cache directory: {}", e))?;

    let pid_path = cache_dir.join("agent.pid");
    let socket_path = custom_socket_path.unwrap_or_else(|| cache_dir.join("ssh-agent.sock"));
    let control_socket_path = PathBuf::from(format!("{}.control", socket_path.display()));

    // Check if already running
    if is_agent_running() {
        return Err("Agent is already running.".to_string());
    }

    // Clean up stale socket files if they exist
    let _ = fs::remove_file(&socket_path);
    let _ = fs::remove_file(&control_socket_path);

    info!("Starting sshwarden agent...");
    info!("SSH_AUTH_SOCK={}", socket_path.display());

    if foreground {
        let pid = std::process::id();
        fs::write(&pid_path, pid.to_string())
            .map_err(|e| format!("Failed to write pid file: {}", e))?;

        if let Err(e) = run_daemon_loops(socket_path, control_socket_path, pid_path).await {
            error!("Agent error: {}", e);
        }
        Ok(())
    } else {
        let daemonize = Daemonize::new()
            .pid_file(&pid_path)
            .working_directory(&cache_dir);

        match daemonize.start() {
            Ok(_) => {
                // Inside the daemon process
                let rt = tokio::runtime::Runtime::new()
                    .map_err(|e| format!("Failed to start Tokio runtime: {}", e))?;

                rt.block_on(async {
                    if let Err(e) =
                        run_daemon_loops(socket_path, control_socket_path, pid_path).await
                    {
                        error!("Daemon error: {}", e);
                    }
                });
                std::process::exit(0);
            }
            Err(e) => Err(format!("Daemonize failed: {}", e)),
        }
    }
}

/// Stops the running agent background process
pub fn stop_agent() -> Result<(), String> {
    let cache_dir =
        storage::cache_dir().ok_or_else(|| "Could not determine cache directory".to_string())?;
    let pid_path = cache_dir.join("agent.pid");

    if !pid_path.exists() {
        return Err("Agent pid file not found. Is the agent running?".to_string());
    }

    let mut pid_str = String::new();
    File::open(&pid_path)
        .map_err(|e| format!("Failed to open pid file: {}", e))?
        .read_to_string(&mut pid_str)
        .map_err(|e| format!("Failed to read pid file: {}", e))?;

    let pid: i32 = pid_str
        .trim()
        .parse()
        .map_err(|e| format!("Invalid pid format: {}", e))?;

    info!("Stopping agent with PID {}...", pid);

    // Send SIGTERM
    unsafe {
        if libc::kill(pid, libc::SIGTERM) != 0 {
            let err = std::io::Error::last_os_error();
            return Err(format!("Failed to kill process: {}", err));
        }
    }

    // Wait up to 5 seconds for shutdown and cleanup
    for _ in 0..50 {
        if !pid_path.exists() {
            info!("Agent stopped successfully.");
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    Err(
        "Agent did not shut down within timeout. You may need to manually terminate it."
            .to_string(),
    )
}

/// Checks the status of the background agent process
pub async fn print_status() -> Result<(), String> {
    let cache_dir =
        storage::cache_dir().ok_or_else(|| "Could not determine cache directory".to_string())?;
    let socket_path = cache_dir.join("ssh-agent.sock");
    let control_socket_path = cache_dir.join("ssh-agent.sock.control");

    if is_agent_running() {
        info!("sshwarden agent: running");
        info!("SSH_AUTH_SOCK:   {}", socket_path.display());

        // Connect to control socket to fetch key statistics
        match query_agent_status(&control_socket_path).await {
            Ok(resp) => {
                let status_str = if resp.unlocked.unwrap_or(false) {
                    "Unlocked"
                } else {
                    "Locked"
                };
                info!("Vault Status:    {}", status_str);
                info!("Keys Loaded:     {}", resp.key_count.unwrap_or(0));
            }
            Err(e) => {
                info!("Vault Status:    Error contacting control socket ({})", e);
            }
        }
    } else {
        info!("sshwarden agent: stopped");
    }
    Ok(())
}

/// Helper to check if the agent process is alive
pub fn is_agent_running() -> bool {
    let cache_dir = match storage::cache_dir() {
        Some(dir) => dir,
        None => return false,
    };
    let pid_path = cache_dir.join("agent.pid");
    if !pid_path.exists() {
        return false;
    }

    let mut pid_str = String::new();
    if let Ok(mut f) = File::open(&pid_path) {
        if f.read_to_string(&mut pid_str).is_err() {
            return false;
        }
    } else {
        return false;
    }

    if let Ok(pid) = pid_str.trim().parse::<i32>() {
        // libc::kill with signal 0 checks if the pid exists and can receive signals
        unsafe {
            return libc::kill(pid, 0) == 0;
        }
    }
    false
}

async fn query_agent_status(control_socket: &Path) -> Result<ControlResponse, String> {
    let mut stream = UnixStream::connect(control_socket)
        .await
        .map_err(|e| format!("Failed to connect to control socket: {}", e))?;

    let req = ControlRequest::Status;
    let req_bytes = serde_json::to_vec(&req).unwrap();
    stream
        .write_all(&req_bytes)
        .await
        .map_err(|e| e.to_string())?;
    stream.shutdown().await.map_err(|e| e.to_string())?;

    let mut resp_bytes = Vec::new();
    stream
        .read_to_end(&mut resp_bytes)
        .await
        .map_err(|e| e.to_string())?;

    let resp: ControlResponse = serde_json::from_slice(&resp_bytes)
        .map_err(|e| format!("Invalid control response: {}", e))?;

    Ok(resp)
}

/// Sends control command to unlock/lock agent
pub async fn send_control_request(req: ControlRequest) -> Result<ControlResponse, String> {
    let cache_dir =
        storage::cache_dir().ok_or_else(|| "Could not determine cache directory".to_string())?;
    let control_socket_path = cache_dir.join("ssh-agent.sock.control");

    if !is_agent_running() {
        return Err(
            "Agent is not running. Start it first with 'sshwarden agent start'".to_string(),
        );
    }

    let mut stream = UnixStream::connect(&control_socket_path)
        .await
        .map_err(|e| format!("Failed to connect to agent control socket: {}", e))?;

    let req_bytes = serde_json::to_vec(&req).map_err(|e| e.to_string())?;
    stream
        .write_all(&req_bytes)
        .await
        .map_err(|e| e.to_string())?;
    stream.shutdown().await.map_err(|e| e.to_string())?;

    let mut resp_bytes = Vec::new();
    stream
        .read_to_end(&mut resp_bytes)
        .await
        .map_err(|e| e.to_string())?;

    let resp: ControlResponse = serde_json::from_slice(&resp_bytes)
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    Ok(resp)
}

/// Runs the background loops for agent socket and control socket
async fn run_daemon_loops(
    socket_path: PathBuf,
    control_socket_path: PathBuf,
    pid_path: PathBuf,
) -> Result<(), String> {
    let keyring: KeyRing = Arc::new(RwLock::new(Vec::new()));
    let last_activity = Arc::new(RwLock::new(Instant::now()));
    let keys_context: SharedKeysContext = Arc::new(RwLock::new(None));

    // Load configuration to initialize timeout settings
    let config = crate::config::Config::load().unwrap_or_default();
    let timeout = config.parse_timeout_duration().unwrap_or(None);
    let timeout_action = config.timeout_action;

    let shared_timeout = Arc::new(RwLock::new(timeout));
    let shared_timeout_action = Arc::new(RwLock::new(timeout_action));

    let agent_listener = UnixListener::bind(&socket_path)
        .map_err(|e| format!("Failed to bind SSH agent socket: {}", e))?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("Failed to set socket permissions: {}", e))?;

    let control_listener = UnixListener::bind(&control_socket_path)
        .map_err(|e| format!("Failed to bind control socket: {}", e))?;
    fs::set_permissions(&control_socket_path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("Failed to set control socket permissions: {}", e))?;

    let mut sigterm = signal(SignalKind::terminate()).unwrap();
    let mut sigint = signal(SignalKind::interrupt()).unwrap();

    // Spawn the inactivity watchdog task
    let kr = keyring.clone();
    let la = last_activity.clone();
    let st = shared_timeout.clone();
    let sta = shared_timeout_action.clone();
    let kc = keys_context.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            let timeout_dur_opt = *st.read().await;
            if let Some(timeout_dur) = timeout_dur_opt {
                let last_act = *la.read().await;
                if !kr.read().await.is_empty() && last_act.elapsed() >= timeout_dur {
                    let action = *sta.read().await;
                    info!("Session timeout reached. Triggering action: {:?}", action);
                    match action {
                        crate::config::TimeoutAction::Lock => {
                            kr.write().await.clear();
                            *kc.write().await = None;
                            info!("Agent locked due to inactivity.");
                        }
                        crate::config::TimeoutAction::Logout => {
                            kr.write().await.clear();
                            *kc.write().await = None;
                            let _ = storage::wipe_db();
                            if let Ok(mut config) = crate::config::Config::load() {
                                config.access_token = None;
                                let _ = config.save();
                            }
                            info!("Logged out due to inactivity.");
                        }
                    }
                }
            }
        }
    });

    // Spawn the background WebSocket live-sync listener
    let kc_ws = keys_context.clone();
    let kr_ws = keyring.clone();
    tokio::spawn(async move {
        let mut backoff = 10;
        loop {
            let has_context = kc_ws.read().await.is_some();
            if !has_context {
                backoff = 10;
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                continue;
            }

            if let Err(e) = run_websocket_sync_loop(kc_ws.clone(), kr_ws.clone()).await {
                error!(
                    "WebSocket live sync loop error: {}. Reconnecting in {} seconds...",
                    e, backoff
                );
                tokio::time::sleep(tokio::time::Duration::from_secs(backoff)).await;
                backoff = std::cmp::min(backoff * 2, 300); // Max backoff 5 minutes
            } else {
                backoff = 10;
            }
        }
    });

    info!("Listeners bound successfully. Running daemon listeners.");

    loop {
        tokio::select! {
            // OS Signal termination
            _ = sigterm.recv() => {
                break;
            }
            _ = sigint.recv() => {
                break;
            }
            // SSH Agent protocol connection
            Ok((stream, _)) = agent_listener.accept() => {
                let kr = keyring.clone();
                let la = last_activity.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_ssh_agent_connection(stream, kr, la).await {
                        error!("SSH Agent connection error: {}", e);
                    }
                });
            }
            // Control socket connection
            Ok((stream, _)) = control_listener.accept() => {
                let kr = keyring.clone();
                let la = last_activity.clone();
                let st = shared_timeout.clone();
                let sta = shared_timeout_action.clone();
                let kc = keys_context.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_control_connection(stream, kr, la, st, sta, kc).await {
                        error!("Control connection error: {}", e);
                    }
                });
            }
        }
    }

    // Graceful cleanup
    let _ = fs::remove_file(&socket_path);
    let _ = fs::remove_file(&control_socket_path);
    let _ = fs::remove_file(&pid_path);

    Ok(())
}

async fn handle_ssh_agent_connection(
    mut stream: UnixStream,
    keyring: KeyRing,
    last_activity: Arc<RwLock<Instant>>,
) -> Result<(), std::io::Error> {
    debug!("New SSH Agent connection accepted.");
    loop {
        // Read 4-byte length prefix
        let mut len_bytes = [0u8; 4];
        if stream.read_exact(&mut len_bytes).await.is_err() {
            debug!("SSH Agent connection closed by client.");
            return Ok(());
        }
        let len = u32::from_be_bytes(len_bytes) as usize;
        debug!("Received SSH Agent request length: {} bytes.", len);

        // Read message payload
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload).await?;

        // Update inactivity timer
        *last_activity.write().await = Instant::now();

        // Process request
        let keys = keyring.read().await;
        let response = match agent::handle_agent_request(&payload, &keys) {
            Ok(resp) => resp,
            Err(e) => {
                error!("Error handling agent request: {}", e);
                // Fail message type 5
                vec![5]
            }
        };

        // Write response length prefix
        let resp_len = response.len() as u32;
        debug!("Sending SSH Agent response length: {} bytes.", resp_len);
        stream.write_all(&resp_len.to_be_bytes()).await?;
        // Write response payload
        stream.write_all(&response).await?;
    }
}

async fn handle_control_connection(
    mut stream: UnixStream,
    keyring: KeyRing,
    last_activity: Arc<RwLock<Instant>>,
    shared_timeout: Arc<RwLock<Option<std::time::Duration>>>,
    shared_timeout_action: Arc<RwLock<crate::config::TimeoutAction>>,
    keys_context: SharedKeysContext,
) -> Result<(), std::io::Error> {
    let mut request_bytes = Vec::new();
    stream.read_to_end(&mut request_bytes).await?;

    // Update inactivity timer
    *last_activity.write().await = Instant::now();

    let req: ControlRequest = match serde_json::from_slice(&request_bytes) {
        Ok(r) => r,
        Err(e) => {
            let resp = ControlResponse {
                status: "error".to_string(),
                error: Some(format!("JSON parsing error: {}", e)),
                unlocked: None,
                key_count: None,
            };
            let resp_bytes = serde_json::to_vec(&resp).unwrap();
            stream.write_all(&resp_bytes).await?;
            return Ok(());
        }
    };

    let response = match req {
        ControlRequest::Unlock {
            keys,
            enc_key,
            mac_key,
            db_key,
        } => {
            let mut parsed_keys = Vec::new();
            let mut parse_err = None;

            for key_data in keys {
                match PrivateKey::from_openssh(&key_data.private_key) {
                    Ok(mut pkey) => {
                        pkey.set_comment(&key_data.name);
                        parsed_keys.push(pkey);
                    }
                    Err(e) => {
                        parse_err = Some(format!(
                            "Failed to parse private key '{}': {}",
                            key_data.name, e
                        ));
                        break;
                    }
                }
            }

            if let Some(err_msg) = parse_err {
                ControlResponse {
                    status: "error".to_string(),
                    error: Some(err_msg),
                    unlocked: Some(!keyring.read().await.is_empty()),
                    key_count: Some(keyring.read().await.len()),
                }
            } else {
                // Decode hex keys
                let enc_dec = hex::decode(&enc_key);
                let mac_dec = hex::decode(&mac_key);
                let db_dec = hex::decode(&db_key);

                if let (Ok(enc_val), Ok(mac_val), Ok(db_val)) = (enc_dec, mac_dec, db_dec) {
                    let mut enc_bytes = [0u8; 32];
                    let mut mac_bytes = [0u8; 32];
                    let mut db_bytes = [0u8; 32];

                    if enc_val.len() == 32 && mac_val.len() == 32 && db_val.len() == 32 {
                        enc_bytes.copy_from_slice(&enc_val);
                        mac_bytes.copy_from_slice(&mac_val);
                        db_bytes.copy_from_slice(&db_val);

                        // Store keys context in memory for WebSocket sync
                        *keys_context.write().await = Some(KeysContext {
                            enc_key: enc_bytes,
                            mac_key: mac_bytes,
                            db_key: db_bytes,
                        });

                        let count = parsed_keys.len();
                        let mut kr = keyring.write().await;
                        *kr = parsed_keys;

                        ControlResponse {
                            status: "ok".to_string(),
                            error: None,
                            unlocked: Some(true),
                            key_count: Some(count),
                        }
                    } else {
                        ControlResponse {
                            status: "error".to_string(),
                            error: Some("Security keys must be exactly 32 bytes".to_string()),
                            unlocked: Some(!keyring.read().await.is_empty()),
                            key_count: Some(keyring.read().await.len()),
                        }
                    }
                } else {
                    ControlResponse {
                        status: "error".to_string(),
                        error: Some("Invalid hex format for security keys".to_string()),
                        unlocked: Some(!keyring.read().await.is_empty()),
                        key_count: Some(keyring.read().await.len()),
                    }
                }
            }
        }
        ControlRequest::Lock => {
            let mut kr = keyring.write().await;
            kr.clear();
            *keys_context.write().await = None;
            ControlResponse {
                status: "ok".to_string(),
                error: None,
                unlocked: Some(false),
                key_count: Some(0),
            }
        }
        ControlRequest::Status => {
            let kr = keyring.read().await;
            ControlResponse {
                status: "ok".to_string(),
                error: None,
                unlocked: Some(!kr.is_empty()),
                key_count: Some(kr.len()),
            }
        }
        ControlRequest::Reload => {
            let config_res = crate::config::Config::load();
            match config_res {
                Ok(config) => {
                    let t = config.parse_timeout_duration().unwrap_or(None);
                    *shared_timeout.write().await = t;
                    *shared_timeout_action.write().await = config.timeout_action;
                    ControlResponse {
                        status: "ok".to_string(),
                        error: None,
                        unlocked: Some(!keyring.read().await.is_empty()),
                        key_count: Some(keyring.read().await.len()),
                    }
                }
                Err(e) => ControlResponse {
                    status: "error".to_string(),
                    error: Some(format!("Failed to reload config: {}", e)),
                    unlocked: Some(!keyring.read().await.is_empty()),
                    key_count: Some(keyring.read().await.len()),
                },
            }
        }
    };

    let resp_bytes = serde_json::to_vec(&response).unwrap();
    stream.write_all(&resp_bytes).await?;
    Ok(())
}

async fn run_websocket_sync_loop(
    keys_context: SharedKeysContext,
    keyring: KeyRing,
) -> Result<(), String> {
    let config =
        crate::config::Config::load().map_err(|e| format!("Failed to load config: {}", e))?;

    let token = config
        .access_token
        .as_ref()
        .ok_or_else(|| "No session token in configuration".to_string())?;

    let notifications_url = crate::api::get_notifications_endpoints(&config.server_url);
    let client = ApiClient::new(&config.server_url);

    let mut ws_url = format!(
        "{}/notifications/hub?access_token={}",
        notifications_url.trim_end_matches('/'),
        token
    );
    if ws_url.starts_with("https://") {
        ws_url = ws_url.replace("https://", "wss://");
    } else if ws_url.starts_with("http://") {
        ws_url = ws_url.replace("http://", "ws://");
    }

    info!("WebSocket: Connecting to {}", ws_url);
    let (mut ws_stream, _) = connect_async(&ws_url)
        .await
        .map_err(|e| format!("WebSocket connection failed: {}", e))?;

    info!("WebSocket: Connected. Sending handshake...");
    let handshake = "{\"protocol\":\"json\",\"version\":1}\u{1E}";
    ws_stream
        .send(Message::Text(handshake.to_string().into()))
        .await
        .map_err(|e| format!("Failed to send handshake: {}", e))?;

    while let Some(msg_res) = ws_stream.next().await {
        let msg = msg_res.map_err(|e| format!("WebSocket read error: {}", e))?;
        debug!("WebSocket received frame: {:?}", msg);

        if keys_context.read().await.is_none() {
            info!("WebSocket: Agent locked. Closing connection...");
            let _ = ws_stream.close(None).await;
            break;
        }

        match msg {
            Message::Text(text) => {
                debug!("WebSocket text payload: {}", text);
                for part in text.split('\u{1E}') {
                    if part.is_empty() {
                        continue;
                    }

                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(part) {
                        if val.get("type").and_then(|t| t.as_i64()) == Some(6) {
                            debug!("WebSocket received Ping (type 6).");
                            continue;
                        }

                        let is_receive_msg = val.get("type").and_then(|t| t.as_i64()) == Some(1)
                            && val.get("target").and_then(|t| t.as_str()) == Some("ReceiveMessage");

                        if let Some(args) = is_receive_msg.then(|| val.get("arguments").and_then(|a| a.as_array())).flatten() {
                            for arg in args {
                                let update_type = arg.get("Type").and_then(|t| t.as_i64());
                                if let Some(ut) = update_type.filter(|&ut| ut == 0 || ut == 1 || ut == 4 || ut == 5) {
                                    info!(
                                        "WebSocket: Received vault update event (Type {}). Syncing...",
                                        ut
                                    );

                                    match client.sync(token).await {
                                        Ok(sync_data) => {
                                            let ctx_opt = keys_context.read().await;
                                            if let Some(ref ctx) = *ctx_opt {
                                                let new_items =
                                                    storage::parse_and_extract_ssh_keys(
                                                        &sync_data,
                                                        &ctx.enc_key,
                                                        &ctx.mac_key,
                                                    );

                                                let mut parsed_keys = Vec::new();
                                                for item in &new_items {
                                                    if let Ok(mut pkey) =
                                                        PrivateKey::from_openssh(
                                                            &item.private_key,
                                                        )
                                                    {
                                                        pkey.set_comment(&item.name);
                                                        parsed_keys.push(pkey);
                                                    }
                                                }

                                                let count = parsed_keys.len();
                                                let mut kr = keyring.write().await;
                                                *kr = parsed_keys;

                                                if let Err(err) = storage::save_db(
                                                    &new_items,
                                                    &ctx.db_key,
                                                ) {
                                                    error!(
                                                        "WebSocket background sync failed to save db: {}",
                                                        err
                                                    );
                                                } else {
                                                    info!(
                                                        "WebSocket: Background sync completed. Synced and reloaded {} keys.",
                                                        count
                                                    );
                                                }
                                            }
                                        }
                                        Err(err) => {
                                            error!(
                                                "WebSocket background sync failed: {}",
                                                err
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Message::Ping(ping) => {
                let _ = ws_stream.send(Message::Pong(ping)).await;
            }
            Message::Close(_) => {
                info!("WebSocket: Connection closed by server.");
                break;
            }
            _ => {}
        }
    }

    Ok(())
}

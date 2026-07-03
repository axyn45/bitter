use daemonize::Daemonize;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use ssh_key::private::PrivateKey;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::RwLock;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use rmpv::Value;
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
    StartSshAgent,
    StopSshAgent,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_to_lock: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_agent_active: Option<bool>,
}

type KeyRing = Arc<RwLock<Vec<PrivateKey>>>;
type SharedKeysContext = Arc<RwLock<Option<KeysContext>>>;

/// Starts the agent background process
pub fn start_agent(background: bool, custom_socket_path: Option<PathBuf>) -> Result<(), String> {
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

    if !background {
        let pid = std::process::id();
        fs::write(&pid_path, pid.to_string())
            .map_err(|e| format!("Failed to write pid file: {}", e))?;

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("Failed to start Tokio runtime: {}", e))?;

        rt.block_on(async {
            if let Err(e) = run_daemon_loops(socket_path, control_socket_path, pid_path).await {
                error!("Agent error: {}", e);
            }
        });
        Ok(())
    } else {
        let daemonize = Daemonize::new()
            .pid_file(&pid_path)
            .working_directory(&cache_dir);

        match daemonize.start() {
            Ok(_) => {
                // Inside the daemon process
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .expect("Failed to start Tokio runtime");

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

    // SAFETY: `libc::kill` is a standard Unix system call. We pass `pid` (parsed from the local
    // pid file) and a standard signal constant `libc::SIGTERM`. This call is memory safe as it only
    // interacts with the OS scheduler and process control and does not perform memory dereferences.
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
        // SAFETY: `libc::kill` with signal `0` is a standard, memory-safe POSIX system call
        // used to check for the existence of the process with the given PID. It does not send
        // a terminating signal or dereference memory.
        unsafe {
            return libc::kill(pid, 0) == 0;
        }
    }
    false
}

/// Sends control command to unlock/lock agent
pub async fn send_control_request(req: ControlRequest) -> Result<ControlResponse, String> {
    let cache_dir =
        storage::cache_dir().ok_or_else(|| "Could not determine cache directory".to_string())?;
    let control_socket_path = cache_dir.join("ssh-agent.sock.control");

    if !is_agent_running() {
        return Err(
            "Agent is not running. Start it first with 'sshwarden start'".to_string(),
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

async fn start_ssh_agent_task(
    socket_path: PathBuf,
    keyring: KeyRing,
    last_activity: Arc<RwLock<Instant>>,
    keys_context: SharedKeysContext,
    mut shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) -> Result<(), String> {
    let _ = fs::remove_file(&socket_path);

    let listener = UnixListener::bind(&socket_path)
        .map_err(|e| format!("Failed to bind SSH agent socket: {}", e))?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("Failed to set socket permissions: {}", e))?;

    info!("SSH Agent listener started at {}", socket_path.display());

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => {
                break;
            }
            accept_res = listener.accept() => {
                match accept_res {
                    Ok((stream, _)) => {
                        let kr = keyring.clone();
                        let la = last_activity.clone();
                        let kc = keys_context.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_ssh_agent_connection(stream, kr, la, kc).await {
                                error!("SSH Agent connection error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("SSH Agent accept error: {}", e);
                    }
                }
            }
        }
    }

    let _ = fs::remove_file(&socket_path);
    info!("SSH Agent listener stopped.");
    Ok(())
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

    // If timeout is "never", try to load unencrypted keys and decryption keys automatically
    if config.timeout.trim().to_lowercase() == "never" {
        if let Some(raw_keys) = storage::load_unencrypted_db() {
            let count = raw_keys.len();
            *keyring.write().await = raw_keys;

            let mut enc_bytes = [0u8; 32];
            let mut mac_bytes = [0u8; 32];
            let mut db_bytes = [0u8; 32];
            if let Some((enc, mac, db)) = storage::load_saved_keys() {
                enc_bytes = enc;
                mac_bytes = mac;
                db_bytes = db;
                info!("Agent started: loaded decryption keys from secure cache.");
            } else {
                info!("Agent started: decryption keys missing, running in read-only cache mode until unlocked.");
            }

            *keys_context.write().await = Some(KeysContext {
                enc_key: enc_bytes,
                mac_key: mac_bytes,
                db_key: db_bytes,
            });
            info!("Agent started: automatically unlocked and loaded {} keys from unencrypted cache.", count);
        }
    }

    let shared_timeout = Arc::new(RwLock::new(timeout));
    let shared_timeout_action = Arc::new(RwLock::new(timeout_action));
    let active_ssh_agent: Arc<RwLock<Option<tokio::sync::oneshot::Sender<()>>>> = Arc::new(RwLock::new(None));

    if config.ssh_agent_auto_start {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let sp = socket_path.clone();
        let kr = keyring.clone();
        let la = last_activity.clone();
        let kc = keys_context.clone();
        tokio::spawn(async move {
            if let Err(e) = start_ssh_agent_task(sp, kr, la, kc, rx).await {
                error!("SSH Agent task error: {}", e);
            }
        });
        *active_ssh_agent.write().await = Some(tx);
    }

    let control_listener = UnixListener::bind(&control_socket_path)
        .map_err(|e| format!("Failed to bind control socket: {}", e))?;
    fs::set_permissions(&control_socket_path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("Failed to set control socket permissions: {}", e))?;

    let mut sigterm = signal(SignalKind::terminate()).unwrap();
    let mut sigint = signal(SignalKind::interrupt()).unwrap();

    // Spawn the inactivity watchdog and user session watcher task
    let kr = keyring.clone();
    let la = last_activity.clone();
    let st = shared_timeout.clone();
    let sta = shared_timeout_action.clone();
    let kc = keys_context.clone();
    let sp_clone = socket_path.clone();
    let cp_clone = control_socket_path.clone();
    let pp_clone = pid_path.clone();
    tokio::spawn(async move {
        let username = get_current_username();

        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;

            if !username.is_empty() {
                let active_sessions = count_active_user_sessions(&username);
                if active_sessions == 0 {
                    info!("No active login sessions found for user '{}'. Stopping agent daemon.", username);
                    let _ = fs::remove_file(&sp_clone);
                    let _ = fs::remove_file(&cp_clone);
                    let _ = fs::remove_file(&pp_clone);
                    std::process::exit(0);
                }
            }

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
                            let session = crate::config::Session::default();
                            let _ = session.save();
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
            // Control socket connection
            Ok((stream, _)) = control_listener.accept() => {
                let kr = keyring.clone();
                let la = last_activity.clone();
                let st = shared_timeout.clone();
                let sta = shared_timeout_action.clone();
                let kc = keys_context.clone();
                let active_agent = active_ssh_agent.clone();
                let sp = socket_path.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_control_connection(stream, kr, la, st, sta, kc, active_agent, sp).await {
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
    keys_context: SharedKeysContext,
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

        // Check if vault is locked (keyring empty) and it's a request that needs keys
        let msg_type = payload.first().copied().unwrap_or(0);
        if keyring.read().await.is_empty() && (msg_type == 11 || msg_type == 13) {
            if let Some(peer_pid) = stream.peer_cred().ok().and_then(|cred| cred.pid()) {
                if let Err(err) = prompt_tty_for_unlock(peer_pid, &keyring, &keys_context).await {
                    error!("TTY unlock failed: {}", err);
                }
            }
        }

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
    active_ssh_agent: Arc<RwLock<Option<tokio::sync::oneshot::Sender<()>>>>,
    socket_path: PathBuf,
) -> Result<(), std::io::Error> {
    let mut request_bytes = Vec::new();
    stream.read_to_end(&mut request_bytes).await?;

    let req: ControlRequest = match serde_json::from_slice(&request_bytes) {
        Ok(r) => r,
        Err(e) => {
            let resp = ControlResponse {
                status: "error".to_string(),
                error: Some(format!("JSON parsing error: {}", e)),
                unlocked: None,
                key_count: None,
                time_to_lock: None,
                ssh_agent_active: None,
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
                    time_to_lock: None,
                    ssh_agent_active: Some(active_ssh_agent.read().await.is_some()),
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

                        // Reset inactivity timer on successful unlock!
                        *last_activity.write().await = Instant::now();

                         ControlResponse {
                            status: "ok".to_string(),
                            error: None,
                            unlocked: Some(true),
                            key_count: Some(count),
                            time_to_lock: None,
                            ssh_agent_active: Some(active_ssh_agent.read().await.is_some()),
                        }
                    } else {
                        ControlResponse {
                            status: "error".to_string(),
                            error: Some("Security keys must be exactly 32 bytes".to_string()),
                            unlocked: Some(!keyring.read().await.is_empty()),
                            key_count: Some(keyring.read().await.len()),
                            time_to_lock: None,
                            ssh_agent_active: Some(active_ssh_agent.read().await.is_some()),
                        }
                    }
                } else {
                    ControlResponse {
                        status: "error".to_string(),
                        error: Some("Invalid hex format for security keys".to_string()),
                        unlocked: Some(!keyring.read().await.is_empty()),
                        key_count: Some(keyring.read().await.len()),
                        time_to_lock: None,
                        ssh_agent_active: Some(active_ssh_agent.read().await.is_some()),
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
                time_to_lock: None,
                ssh_agent_active: Some(active_ssh_agent.read().await.is_some()),
            }
        }
        ControlRequest::Status => {
            let kr = keyring.read().await;
            let timeout_dur_opt = *shared_timeout.read().await;
            let time_to_lock = if let Some(timeout_dur) = timeout_dur_opt {
                if !kr.is_empty() {
                    let last_act = *last_activity.read().await;
                    Some(timeout_dur.saturating_sub(last_act.elapsed()).as_secs())
                } else {
                    None
                }
            } else {
                None
            };
            ControlResponse {
                status: "ok".to_string(),
                error: None,
                unlocked: Some(!kr.is_empty()),
                key_count: Some(kr.len()),
                time_to_lock,
                ssh_agent_active: Some(active_ssh_agent.read().await.is_some()),
            }
        }
        ControlRequest::Reload => {
            let config_res = crate::config::Config::load();
            match config_res {
                Ok(config) => {
                    let t = config.parse_timeout_duration().unwrap_or(None);
                    *shared_timeout.write().await = t;
                    *shared_timeout_action.write().await = config.timeout_action;

                    // If timeout is not "never", remove unencrypted DB and keys if they exist
                    if config.timeout.trim().to_lowercase() != "never" {
                        if let Some(raw_path) = storage::unencrypted_db_path() {
                            if raw_path.exists() {
                                let _ = fs::remove_file(raw_path);
                            }
                        }
                        if let Some(keys_path) = storage::keys_path() {
                            if keys_path.exists() {
                                let _ = fs::remove_file(keys_path);
                            }
                        }
                    }

                    ControlResponse {
                        status: "ok".to_string(),
                        error: None,
                        unlocked: Some(!keyring.read().await.is_empty()),
                        key_count: Some(keyring.read().await.len()),
                        time_to_lock: None,
                        ssh_agent_active: Some(active_ssh_agent.read().await.is_some()),
                    }
                }
                Err(e) => ControlResponse {
                    status: "error".to_string(),
                    error: Some(format!("Failed to reload config: {}", e)),
                    unlocked: Some(!keyring.read().await.is_empty()),
                    key_count: Some(keyring.read().await.len()),
                    time_to_lock: None,
                    ssh_agent_active: Some(active_ssh_agent.read().await.is_some()),
                },
            }
        }
        ControlRequest::StartSshAgent => {
            let mut active = active_ssh_agent.write().await;
            if active.is_some() {
                ControlResponse {
                    status: "error".to_string(),
                    error: Some("SSH agent is already running".to_string()),
                    unlocked: Some(!keyring.read().await.is_empty()),
                    key_count: Some(keyring.read().await.len()),
                    time_to_lock: None,
                    ssh_agent_active: Some(true),
                }
            } else {
                let (tx, rx) = tokio::sync::oneshot::channel();
                let sp = socket_path.clone();
                let kr = keyring.clone();
                let la = last_activity.clone();
                let kc = keys_context.clone();
                tokio::spawn(async move {
                    if let Err(e) = start_ssh_agent_task(sp, kr, la, kc, rx).await {
                        error!("SSH Agent task error: {}", e);
                    }
                });
                *active = Some(tx);
                ControlResponse {
                    status: "ok".to_string(),
                    error: None,
                    unlocked: Some(!keyring.read().await.is_empty()),
                    key_count: Some(keyring.read().await.len()),
                    time_to_lock: None,
                    ssh_agent_active: Some(true),
                }
            }
        }
        ControlRequest::StopSshAgent => {
            let mut active = active_ssh_agent.write().await;
            if let Some(tx) = active.take() {
                let _ = tx.send(());
                ControlResponse {
                    status: "ok".to_string(),
                    error: None,
                    unlocked: Some(!keyring.read().await.is_empty()),
                    key_count: Some(keyring.read().await.len()),
                    time_to_lock: None,
                    ssh_agent_active: Some(false),
                }
            } else {
                ControlResponse {
                    status: "error".to_string(),
                    error: Some("SSH agent is not running".to_string()),
                    unlocked: Some(!keyring.read().await.is_empty()),
                    key_count: Some(keyring.read().await.len()),
                    time_to_lock: None,
                    ssh_agent_active: Some(false),
                }
            }
        }
    };

    let resp_bytes = serde_json::to_vec(&response).unwrap();
    stream.write_all(&resp_bytes).await?;
    Ok(())
}

async fn handle_surgical_cipher_update(
    client: &ApiClient,
    token: &str,
    cipher_id: &str,
    keys_context: &SharedKeysContext,
    keyring: &KeyRing,
) -> Result<(), String> {
    let ctx_opt = keys_context.read().await;
    let ctx = match &*ctx_opt {
        Some(c) => c,
        None => return Err("Agent locked".to_string()),
    };
    if ctx.enc_key == [0u8; 32] {
        return Err("Decryption keys missing (agent was auto-unlocked from cache)".to_string());
    }
    // Fetch individual cipher details from server first
    let fetch_result = client.get_cipher_details(token, cipher_id).await;

    let mut is_deleted = false;
    let mut fetched_cipher = None;

    match fetch_result {
        Ok(cipher) => {
            if cipher.deleted_date.is_some() {
                is_deleted = true;
            } else {
                fetched_cipher = Some(cipher);
            }
        }
        Err(e) => {
            info!("Failed to fetch cipher details for {}: {}. Assuming deleted.", cipher_id, e);
            is_deleted = true;
        }
    }

    // Load existing SyncResponse from cache database
    let mut sync_resp = match storage::load_db(&ctx.db_key) {
        Ok(resp) => resp,
        Err(e) => {
            info!("Failed to load cache database: {}. Initializing empty database.", e);
            storage::SyncResponse {
                profile: storage::ProfileSync {
                    id: String::new(),
                    email: String::new(),
                    key: String::new(),
                    extra: std::collections::HashMap::new(),
                },
                ciphers: Vec::new(),
                user_decryption: None,
                extra: std::collections::HashMap::new(),
            }
        }
    };

    let existed = sync_resp.ciphers.iter().any(|c| c.id == cipher_id);
    if is_deleted {
        if !existed {
            return Ok(());
        }
        // Remove from list
        sync_resp.ciphers.retain(|c| c.id != cipher_id);
    } else if let Some(cipher) = fetched_cipher {
        // Upsert item
        if let Some(pos) = sync_resp.ciphers.iter().position(|x| x.id == cipher_id) {
            sync_resp.ciphers[pos] = cipher;
        } else {
            sync_resp.ciphers.push(cipher);
        }
    }

    // Save updated SyncResponse back to database cache
    storage::save_db(&sync_resp, &ctx.db_key, Some(&ctx.enc_key), Some(&ctx.mac_key))?;

    // Decrypt all ciphers
    let decrypted_items = storage::parse_and_decrypt_all_ciphers(&sync_resp, &ctx.enc_key, &ctx.mac_key);

    // Reload keyring memory
    let ssh_items = storage::extract_ssh_keys_from_ciphers(&decrypted_items);
    let mut parsed_keys = Vec::new();
    for item in &ssh_items {
        if let Ok(mut pkey) = PrivateKey::from_openssh(&item.private_key) {
            pkey.set_comment(&item.name);
            parsed_keys.push(pkey);
        }
    }

    let count = parsed_keys.len();
    let mut kr = keyring.write().await;
    *kr = parsed_keys;

    info!(
        "WebSocket: Surgically updated cipher {}. Keyring now has {} keys.",
        cipher_id, count
    );

    Ok(())
}

async fn run_websocket_sync_loop(
    keys_context: SharedKeysContext,
    keyring: KeyRing,
) -> Result<(), String> {
    let config =
        crate::config::Config::load().map_err(|e| format!("Failed to load config: {}", e))?;
    let mut session =
        crate::config::Session::load().map_err(|e| format!("Failed to load session: {}", e))?;

    let token = session.get_valid_token(&config.server_url).await?;

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
                                if let Some(ut) = arg.get("Type").and_then(|t| t.as_i64()) {
                                    if ut == 1 {
                                        // Surgical cipher update (Type 1 is SyncCipher)
                                        let cipher_id = arg.get("Payload")
                                            .and_then(|p| p.get("Id").or_else(|| p.get("id")))
                                            .and_then(|id| id.as_str())
                                            .or_else(|| arg.get("Id").or_else(|| arg.get("id")).and_then(|id| id.as_str()));

                                        if let Some(cipher_id) = cipher_id {
                                            info!("WebSocket: Received cipher update event for ID: {}. Processing surgically...", cipher_id);
                                            let client_clone = client.clone();
                                            let kc_clone = keys_context.clone();
                                            let kr_clone = keyring.clone();
                                            let cipher_id_str = cipher_id.to_string();
                                            tokio::spawn(async move {
                                                let current_token = if let (Ok(cfg), Ok(mut sess)) = (crate::config::Config::load(), crate::config::Session::load()) {
                                                    sess.get_valid_token(&cfg.server_url).await.unwrap_or_default()
                                                } else {
                                                    String::new()
                                                };
                                                if let Err(e) = handle_surgical_cipher_update(
                                                    &client_clone,
                                                    &current_token,
                                                    &cipher_id_str,
                                                    &kc_clone,
                                                    &kr_clone,
                                                )
                                                .await
                                                {
                                                    error!("Surgical cipher update failed for {}: {}", cipher_id_str, e);
                                                }
                                            });
                                        }
                                    } else if ut == 0 || ut == 4 || ut == 5 {
                                        // Full Sync
                                        info!(
                                            "WebSocket: Received vault update event (Type {}). Syncing...",
                                            ut
                                        );

                                        let current_token = if let (Ok(cfg), Ok(mut sess)) = (crate::config::Config::load(), crate::config::Session::load()) {
                                            sess.get_valid_token(&cfg.server_url).await.unwrap_or_else(|_| token.clone())
                                        } else {
                                            token.clone()
                                        };
                                        match client.sync(&current_token).await {
                                            Ok(sync_data) => {
                                                let ctx_opt = keys_context.read().await;
                                                if let Some(ref ctx) = *ctx_opt {
                                                    if ctx.enc_key == [0u8; 32] {
                                                        info!("WebSocket: Agent was auto-unlocked from cache; skipping real-time full sync decryption since decryption keys are missing.");
                                                        continue;
                                                    }
                                                                                    let decrypted_ciphers =
                                                        storage::parse_and_decrypt_all_ciphers(
                                                            &sync_data,
                                                            &ctx.enc_key,
                                                            &ctx.mac_key,
                                                        );
                                                    let new_items =
                                                        storage::extract_ssh_keys_from_ciphers(&decrypted_ciphers);

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
                                                        &sync_data,
                                                        &ctx.db_key,
                                                        Some(&ctx.enc_key),
                                                        Some(&ctx.mac_key),
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
            }
            Message::Binary(bytes) => {
                debug!("WebSocket received Binary payload length: {}", bytes.len());
                let mut current_slice = &bytes[..];
                while !current_slice.is_empty() {
                    let (msg_len, remaining) = match read_varint(current_slice) {
                        Some(val) => val,
                        None => {
                            error!("WebSocket: Failed to parse varint message length prefix");
                            break;
                        }
                    };
                    if remaining.len() < msg_len {
                        error!("WebSocket: Binary message truncated (expected {} bytes, got {})", msg_len, remaining.len());
                        break;
                    }
                    let (msg_bytes, next_slice) = remaining.split_at(msg_len);
                    current_slice = next_slice;

                    let mut read_cursor = msg_bytes;
                    match rmpv::decode::read_value(&mut read_cursor) {
                        Ok(Value::Array(arr)) => {
                            if arr.len() >= 5 {
                                let msg_type = arr[0].as_i64();
                                let target = arr[3].as_str();

                                if msg_type == Some(1) && target == Some("ReceiveMessage") {
                                    if let Value::Array(ref args) = arr[4] {
                                        for arg in args {
                                            if let Value::Map(map) = arg {
                                                let ut = get_map_val(map, "Type").and_then(|v| v.as_i64());
                                                if let Some(ut_val) = ut {
                                                    if ut_val == 1 {
                                                        // Surgical cipher update
                                                        let payload_val = get_map_val(map, "Payload");
                                                        let cipher_id = if let Some(Value::Map(p_map)) = payload_val {
                                                            get_map_val(p_map, "Id").and_then(|v| v.as_str())
                                                        } else {
                                                            get_map_val(map, "Id").and_then(|v| v.as_str())
                                                        };

                                                        if let Some(cipher_id) = cipher_id {
                                                            info!("WebSocket (binary): Received cipher update event for ID: {}. Processing surgically...", cipher_id);
                                                            let client_clone = client.clone();
                                                            let kc_clone = keys_context.clone();
                                                            let kr_clone = keyring.clone();
                                                            let cipher_id_str = cipher_id.to_string();
                                                            tokio::spawn(async move {
                                                                let current_token = if let (Ok(cfg), Ok(mut sess)) = (crate::config::Config::load(), crate::config::Session::load()) {
                                                                    sess.get_valid_token(&cfg.server_url).await.unwrap_or_default()
                                                                } else {
                                                                    String::new()
                                                                };
                                                                if let Err(e) = handle_surgical_cipher_update(
                                                                    &client_clone,
                                                                    &current_token,
                                                                    &cipher_id_str,
                                                                    &kc_clone,
                                                                    &kr_clone,
                                                                )
                                                                .await
                                                                {
                                                                    error!("Surgical cipher update failed for {}: {}", cipher_id_str, e);
                                                                }
                                                            });
                                                        }
                                                    } else if ut_val == 0 || ut_val == 4 || ut_val == 5 {
                                                        // Full Sync
                                                        info!("WebSocket (binary): Received vault update event (Type {}). Syncing...", ut_val);
                                                        let current_token = if let (Ok(cfg), Ok(mut sess)) = (crate::config::Config::load(), crate::config::Session::load()) {
                                                            sess.get_valid_token(&cfg.server_url).await.unwrap_or_else(|_| token.clone())
                                                        } else {
                                                            token.clone()
                                                        };
                                                        match client.sync(&current_token).await {
                                                            Ok(sync_data) => {
                                                                let ctx_opt = keys_context.read().await;
                                                                if let Some(ref ctx) = *ctx_opt {
                                                                    if ctx.enc_key == [0u8; 32] {
                                                                        info!("WebSocket: Agent was auto-unlocked from cache; skipping real-time full sync decryption since decryption keys are missing.");
                                                                        continue;
                                                                    }
                                                                    let decrypted_ciphers = storage::parse_and_decrypt_all_ciphers(
                                                                        &sync_data,
                                                                        &ctx.enc_key,
                                                                        &ctx.mac_key,
                                                                    );
                                                                    let new_items = storage::extract_ssh_keys_from_ciphers(&decrypted_ciphers);
                                                                    let mut parsed_keys = Vec::new();
                                                                    for item in &new_items {
                                                                        if let Ok(mut pkey) = PrivateKey::from_openssh(&item.private_key) {
                                                                            pkey.set_comment(&item.name);
                                                                            parsed_keys.push(pkey);
                                                                        }
                                                                    }
                                                                    let count = parsed_keys.len();
                                                                    *keyring.write().await = parsed_keys;
                                                                    if let Err(err) = storage::save_db(&sync_data, &ctx.db_key, Some(&ctx.enc_key), Some(&ctx.mac_key)) {
                                                                        error!("WebSocket background sync failed to save db: {}", err);
                                                                    } else {
                                                                        info!("WebSocket (binary): Background sync completed. Synced and reloaded {} keys.", count);
                                                                    }
                                                                }
                                                            }
                                                            Err(err) => {
                                                                error!("WebSocket background sync failed: {}", err);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Ok(other) => {
                            debug!("WebSocket parsed non-array message: {:?}", other);
                        }
                        Err(e) => {
                            error!("WebSocket: Failed to parse MessagePack payload: {}", e);
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

fn read_varint(bytes: &[u8]) -> Option<(usize, &[u8])> {
    let mut value = 0usize;
    let mut shift = 0usize;
    let mut bytes_read = 0;
    
    for &b in bytes {
        bytes_read += 1;
        value |= ((b & 0x7f) as usize) << shift;
        if (b & 0x80) == 0 {
            return Some((value, &bytes[bytes_read..]));
        }
        shift += 7;
        if shift >= 32 {
            return None;
        }
    }
    None
}

fn get_map_val<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    for (k, v) in map {
        if let Some(k_str) = k.as_str() {
            if k_str == key {
                return Some(v);
            }
        }
    }
    None
}

fn get_tty_path_for_pid(pid: i32) -> Option<PathBuf> {
    for fd in &[2, 0, 1] {
        let fd_path = format!("/proc/{}/fd/{}", pid, fd);
        if let Ok(target) = std::fs::read_link(&fd_path) {
            let target_str = target.to_string_lossy();
            if target_str.starts_with("/dev/pts/") || target_str == "/dev/tty" {
                return Some(target);
            }
        }
    }
    None
}

async fn prompt_tty_for_unlock(
    peer_pid: i32,
    keyring: &KeyRing,
    keys_context: &SharedKeysContext,
) -> Result<(), String> {
    use std::io::{BufRead, BufReader, Write};
    use std::fs::OpenOptions;
    use std::os::unix::io::AsRawFd;

    static UNLOCK_MUTEX: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    let mutex = UNLOCK_MUTEX.get_or_init(|| tokio::sync::Mutex::new(()));
    let _guard = mutex.lock().await;

    if !keyring.read().await.is_empty() {
        return Ok(());
    }

    // Load session to check if logged in
    let session = crate::config::Session::load()
        .map_err(|e| format!("Failed to load session: {}", e))?;

    if session.email.is_none() {
        return Err("Not logged in".to_string());
    }

    let db_exists = crate::storage::db_path()
        .map(|p| p.exists())
        .unwrap_or(false);

    if !db_exists {
        return Err("Local database cache is empty".to_string());
    }

    let tty_path = get_tty_path_for_pid(peer_pid)
        .ok_or_else(|| "Could not resolve client TTY path".to_string())?;

    let mut tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&tty_path)
        .map_err(|e| format!("Failed to open TTY: {}", e))?;

    let fd = tty.as_raw_fd();
    // SAFETY: `libc::termios` is a Plain Old Data (POD) struct containing only primitive fields.
    // Zero-initializing it is safe and it is immediately fully populated by `tcgetattr`.
    let mut termios = unsafe { std::mem::zeroed() };
    
    // SAFETY: `fd` is a valid open file descriptor for the user's controlling TTY,
    // and `&mut termios` points to a valid local stack allocation.
    let has_termios = unsafe { libc::tcgetattr(fd, &mut termios) == 0 };
    if has_termios {
        let mut no_echo = termios;
        no_echo.c_lflag &= !libc::ECHO;
        no_echo.c_lflag &= !libc::ECHONL;
        // SAFETY: `fd` is a valid open file descriptor, and `&no_echo` points to a valid
        // termios struct configured to temporarily disable screen echo.
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &no_echo) };
    }

    tty.write_all(b"\r\n[sshwarden] SSH Agent request received, but vault is locked.\r\nMaster Password: ")
        .map_err(|e| e.to_string())?;
    let _ = tty.flush();

    let mut reader = BufReader::new(&mut tty);
    let mut password = String::new();
    let read_res = reader.read_line(&mut password);

    // Restore echo immediately
    if has_termios {
        // SAFETY: `fd` is a valid open file descriptor, and `&termios` points to the
        // original termios settings we read on function entry, restoring user terminal state.
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &termios) };
    }
    tty.write_all(b"\n").map_err(|e| e.to_string())?;

    read_res.map_err(|e| format!("Failed to read password from TTY: {}", e))?;
    let password = password.trim().to_string();

    if password.is_empty() {
        return Err("Empty password".to_string());
    }



    let salt = session.cache_salt.as_ref()
        .ok_or_else(|| "No cache salt found in session".to_string())?;

    // Derive DB key
    tty.write_all(b"[sshwarden] Deriving encryption key (Argon2)... ").map_err(|e| e.to_string())?;
    let _ = tty.flush();
    let db_key = crate::storage::derive_db_key(&password, salt)
        .map_err(|e| format!("KDF failed: {}", e))?;
    tty.write_all(b"Done.\r\n").map_err(|e| e.to_string())?;

    // Load local database
    let sync_resp = crate::storage::load_db(&db_key)
        .map_err(|e| format!("Password incorrect or local database decryption failed: {}", e))?;

    // Decrypt ciphers offline using master password
    let (items, enc_key, mac_key) = crate::storage::decrypt_sync_response_offline(&sync_resp, &password)
        .map_err(|e| format!("Failed to decrypt local database offline: {}", e))?;

    // Parse SSH keys
    let ssh_items = crate::storage::extract_ssh_keys_from_ciphers(&items);
    let mut parsed_keys = Vec::new();
    for item in &ssh_items {
        if let Ok(mut pkey) = ssh_key::private::PrivateKey::from_openssh(&item.private_key) {
            pkey.set_comment(&item.name);
            parsed_keys.push(pkey);
        }
    }

    let count = parsed_keys.len();
    *keyring.write().await = parsed_keys;
    *keys_context.write().await = Some(KeysContext {
        enc_key,
        mac_key,
        db_key,
    });

    tty.write_all(format!("[sshwarden] Vault unlocked successfully. Loaded {} keys.\r\n\n", count).as_bytes())
        .map_err(|e| e.to_string())?;
    let _ = tty.flush();

    Ok(())
}

fn get_current_username() -> String {
    if let Ok(user) = std::env::var("USER") {
        if !user.is_empty() {
            return user;
        }
    }
    if let Ok(user) = std::env::var("LOGNAME") {
        if !user.is_empty() {
            return user;
        }
    }
    if let Ok(output) = std::process::Command::new("id").args(&["-un"]).output() {
        let user = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !user.is_empty() {
            return user;
        }
    }
    String::new()
}

fn count_active_user_sessions(username: &str) -> usize {
    let output = match std::process::Command::new("who").output() {
        Ok(out) => out,
        Err(_) => return 1,
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut count = 0;
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(&user) = parts.first() {
            if user == username {
                count += 1;
            }
        }
    }
    count
}

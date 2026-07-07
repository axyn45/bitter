use daemonize::Daemonize;
use futures_util::{SinkExt, StreamExt};
use rmpv::Value;
use serde::{Deserialize, Serialize};
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
use tracing::{debug, error, info, warn};

use crate::agent;
use crate::api::ApiClient;
use crate::storage;

#[derive(Clone)]
pub struct KeysContext {
    pub user_id: String,
    pub enc_key: [u8; 32],
    pub mac_key: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ControlRequest {
    Unlock { user_id: String, enc_key: String, mac_key: String },
    Lock,
    Status { user_id: Option<String> },
    Reload,
    StartSshAgent,
    StopSshAgent,
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

type SharedKeysContext = Arc<RwLock<Option<KeysContext>>>;
type SharedDb = Arc<tokio::sync::Mutex<storage::VaultRepository>>;

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

    info!("Starting bitter daemon...");
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

    info!("Stopping daemon with PID {}...", pid);

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
        return Err("Agent is not running. Start it first with 'bitter start'".to_string());
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
    last_activity: Arc<RwLock<Instant>>,
    keys_context: SharedKeysContext,
    shared_db: SharedDb,
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
                        let la = last_activity.clone();
                        let kc = keys_context.clone();
                        let db_clone = shared_db.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_ssh_agent_connection(stream, la, kc, db_clone).await {
                                if e.kind() == std::io::ErrorKind::BrokenPipe || e.kind() == std::io::ErrorKind::ConnectionReset {
                                    debug!("SSH Agent connection terminated gracefully: {}", e);
                                } else {
                                    error!("SSH Agent connection error: {}", e);
                                }
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
    let last_activity = Arc::new(RwLock::new(Instant::now()));
    let keys_context: SharedKeysContext = Arc::new(RwLock::new(None));

    // Load configuration and session to initialize timeout settings
    let config = crate::config::Config::load().unwrap_or_default();
    let db_path =
        storage::db_path().ok_or_else(|| "Could not determine cache database path".to_string())?;
    let repo = storage::VaultRepository::open(&db_path)?;
    let session = repo.load_session()?.unwrap_or_else(|| {
        let mut s = crate::config::Session::default();
        if let Some(ref d_id) = config.device_id {
            s.device_id = d_id.clone();
        }
        s
    });

    let timeout = session.parse_timeout_duration().unwrap_or(None);
    let timeout_action = session.timeout_action;

    let saved_keys_opt = repo.load_saved_keys().ok().flatten();

    // Persist and wrap the VaultRepository in a SharedDb (Arc<Mutex<VaultRepository>>)
    let shared_db: SharedDb = Arc::new(tokio::sync::Mutex::new(repo));

    // If timeout is "unlocked", try to load decryption keys automatically
    if session.timeout.trim().to_lowercase() == "unlocked" {
        if let Some((enc, mac)) = saved_keys_opt {
            *keys_context.write().await = Some(KeysContext {
                user_id: session.user_id.clone().unwrap_or_default(),
                enc_key: enc,
                mac_key: mac,
            });
            info!("Agent started: loaded decryption keys from secure cache.");
        } else {
            info!("Agent started: decryption keys missing, running in locked state.");
        }
    }

    let shared_timeout = Arc::new(RwLock::new(timeout));
    let shared_timeout_action = Arc::new(RwLock::new(timeout_action));
    let active_ssh_agent: Arc<RwLock<Option<tokio::sync::oneshot::Sender<()>>>> =
        Arc::new(RwLock::new(None));

    if config.ssh_agent_auto_start {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let sp = socket_path.clone();
        let la = last_activity.clone();
        let kc = keys_context.clone();
        let db_clone = shared_db.clone();
        tokio::spawn(async move {
            if let Err(e) = start_ssh_agent_task(sp, la, kc, db_clone, rx).await {
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
    let la = last_activity.clone();
    let st = shared_timeout.clone();
    let sta = shared_timeout_action.clone();
    let kc = keys_context.clone();
    let sp_clone = socket_path.clone();
    let cp_clone = control_socket_path.clone();
    let pp_clone = pid_path.clone();
    let db_clone = shared_db.clone();
    tokio::spawn(async move {
        let username = get_current_username();

        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;

            if !username.is_empty() {
                let active_sessions = count_active_user_sessions(&username);
                if active_sessions == 0 {
                    info!(
                        "No active login sessions found for user '{}'. Stopping agent daemon.",
                        username
                    );
                    let _ = fs::remove_file(&sp_clone);
                    let _ = fs::remove_file(&cp_clone);
                    let _ = fs::remove_file(&pp_clone);
                    std::process::exit(0);
                }
            }

            let timeout_dur_opt = *st.read().await;
            if let Some(timeout_dur) = timeout_dur_opt {
                let last_act = *la.read().await;
                if kc.read().await.is_some() && last_act.elapsed() >= timeout_dur {
                    let action = *sta.read().await;
                    info!("Session timeout reached. Triggering action: {:?}", action);
                    match action {
                        crate::config::TimeoutAction::Lock => {
                            *kc.write().await = None;
                            info!("Agent locked due to inactivity.");
                        }
                        crate::config::TimeoutAction::Logout => {
                            *kc.write().await = None;
                            let mut repo_guard = db_clone.lock().await;
                            let _ = repo_guard.logout_active_user();
                            info!("Logged out due to inactivity.");
                        }
                    }
                }
            }
        }
    });

    // Spawn the background WebSocket live-sync listener
    let kc_ws = keys_context.clone();
    let db_clone = shared_db.clone();
    tokio::spawn(async move {
        let mut backoff = 10;
        loop {
            let has_context = kc_ws.read().await.is_some();
            if !has_context {
                backoff = 10;
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                continue;
            }

            if let Err(e) = run_websocket_sync_loop(kc_ws.clone(), db_clone.clone()).await {
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
                let la = last_activity.clone();
                let st = shared_timeout.clone();
                let sta = shared_timeout_action.clone();
                let kc = keys_context.clone();
                let active_agent = active_ssh_agent.clone();
                let sp = socket_path.clone();
                let db_clone = shared_db.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_control_connection(stream, la, st, sta, kc, active_agent, sp, db_clone).await {
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
    last_activity: Arc<RwLock<Instant>>,
    keys_context: SharedKeysContext,
    shared_db: SharedDb,
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

        // Check if vault is locked (keys_context is None) and it's a request that needs keys
        let msg_type = payload.first().copied().unwrap_or(0);
        let is_locked = keys_context.read().await.is_none();
        if is_locked && (msg_type == 11 || msg_type == 13) {
            if let Some(peer_pid) = stream.peer_cred().ok().and_then(|cred| cred.pid()) {
                if let Err(err) = prompt_tty_for_unlock(peer_pid, &keys_context, &mut stream, shared_db.clone()).await {
                    warn!("TTY unlock failed: {}", err);
                }
            }
        }

        // Process request
        let keys_opt = keys_context.read().await.clone();
        let response = if let Some(keys) = keys_opt {
            let mut decrypt_err = None;
            let mut parsed_keys = Vec::new();
            
            let repo_guard = shared_db.lock().await;
            match storage::decrypt_ssh_keys_from_db(
                &repo_guard,
                Some(&keys.user_id),
                &keys.enc_key,
                &keys.mac_key,
            ) {
                Ok(ssh_items) => {
                    for item in ssh_items {
                        if let Ok(mut pkey) = ssh_key::private::PrivateKey::from_openssh(
                            &item.private_key,
                        ) {
                            pkey.set_comment(&item.name);
                            parsed_keys.push(pkey);
                        }
                    }
                }
                Err(e) => {
                    decrypt_err = Some(format!(
                        "Failed to decrypt SSH keys from database: {}",
                        e
                    ));
                }
            }
            drop(repo_guard);

            if let Some(err) = decrypt_err {
                error!("Decryption error during agent request: {}", err);
                vec![5] // failure
            } else {
                let resp = agent::handle_agent_request(&payload, &parsed_keys);
                drop(parsed_keys);
                match resp {
                    Ok(r) => r,
                    Err(e) => {
                        error!("Error handling agent request: {}", e);
                        vec![5]
                    }
                }
            }
        } else {
            // Locked: return empty list or fail
            if msg_type == 11 {
                // SSH_AGENT_IDENTITIES_ANSWER: message type 12, count 0
                vec![12, 0, 0, 0, 0]
            } else {
                vec![5] // failure
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

async fn count_keys_in_db(keys_context: &SharedKeysContext, shared_db: &SharedDb) -> usize {
    let keys_opt = keys_context.read().await.clone();
    if let Some(keys) = keys_opt {
        let repo_guard = shared_db.lock().await;
        match repo_guard.count_non_deleted_ciphers(&keys.user_id) {
            Ok(count) => {
                debug!("Successfully counted {} non-deleted items in database", count);
                return count;
            }
            Err(e) => {
                error!("count_non_deleted_ciphers failed: {}", e);
            }
        }
    } else {
        debug!("keys_context is None (vault is locked)");
    }
    0
}


async fn handle_control_connection(
    mut stream: UnixStream,
    last_activity: Arc<RwLock<Instant>>,
    shared_timeout: Arc<RwLock<Option<std::time::Duration>>>,
    shared_timeout_action: Arc<RwLock<crate::config::TimeoutAction>>,
    keys_context: SharedKeysContext,
    active_ssh_agent: Arc<RwLock<Option<tokio::sync::oneshot::Sender<()>>>>,
    socket_path: PathBuf,
    shared_db: SharedDb,
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
        ControlRequest::Unlock { user_id, enc_key, mac_key } => {
            let enc_dec = hex::decode(&enc_key);
            let mac_dec = hex::decode(&mac_key);

            if let (Ok(enc_val), Ok(mac_val)) = (enc_dec, mac_dec) {
                let mut enc_bytes = [0u8; 32];
                let mut mac_bytes = [0u8; 32];

                if enc_val.len() == 32 && mac_val.len() == 32 {
                    enc_bytes.copy_from_slice(&enc_val);
                    mac_bytes.copy_from_slice(&mac_val);

                    // Store keys context in memory
                    *keys_context.write().await = Some(KeysContext {
                        user_id,
                        enc_key: enc_bytes,
                        mac_key: mac_bytes,
                    });

                    // Reset inactivity timer on successful unlock!
                    *last_activity.write().await = Instant::now();

                    let count = count_keys_in_db(&keys_context, &shared_db).await;

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
                        unlocked: Some(keys_context.read().await.is_some()),
                        key_count: Some(count_keys_in_db(&keys_context, &shared_db).await),
                        time_to_lock: None,
                        ssh_agent_active: Some(active_ssh_agent.read().await.is_some()),
                    }
                }
            } else {
                ControlResponse {
                    status: "error".to_string(),
                    error: Some("Failed to decode hex security keys".to_string()),
                    unlocked: Some(keys_context.read().await.is_some()),
                    key_count: Some(count_keys_in_db(&keys_context, &shared_db).await),
                    time_to_lock: None,
                    ssh_agent_active: Some(active_ssh_agent.read().await.is_some()),
                }
            }
        }
        ControlRequest::Lock => {
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
        ControlRequest::Status { user_id } => {
            let unlocked = {
                let keys_guard = keys_context.read().await;
                match (&*keys_guard, &user_id) {
                    (Some(keys), Some(uid)) => keys.user_id == *uid,
                    (Some(_), None) => true,
                    (None, _) => false,
                }
            };
            let key_count = if unlocked {
                count_keys_in_db(&keys_context, &shared_db).await
            } else {
                0
            };
            let timeout_dur_opt = *shared_timeout.read().await;
            let time_to_lock = if let Some(timeout_dur) = timeout_dur_opt {
                if unlocked {
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
                unlocked: Some(unlocked),
                key_count: Some(key_count),
                time_to_lock,
                ssh_agent_active: Some(active_ssh_agent.read().await.is_some()),
            }
        }
        ControlRequest::Reload => {
            // Re-load session from DB for timeout settings
            let session_res = {
                let repo_guard = shared_db.lock().await;
                repo_guard.load_session().ok().flatten()
            };

            if let Some(session) = session_res {
                let t = session.parse_timeout_duration().unwrap_or(None);
                *shared_timeout.write().await = t;
                *shared_timeout_action.write().await = session.timeout_action;
                *last_activity.write().await = Instant::now();

                let is_unlocked = {
                    let mut keys = keys_context.write().await;
                    let user_id_mismatch = if let Some(ref k) = *keys {
                        Some(&k.user_id) != session.user_id.as_ref()
                    } else {
                        false
                    };

                    if user_id_mismatch {
                        *keys = None;
                    }
                    keys.is_some()
                };

                // If timeout is not "unlocked", clear saved keys if they exist
                if session.timeout.trim().to_lowercase() != "unlocked" {
                    let repo_guard = shared_db.lock().await;
                    let _ = repo_guard.clear_saved_keys();
                }

                ControlResponse {
                    status: "ok".to_string(),
                    error: None,
                    unlocked: Some(is_unlocked),
                    key_count: Some(count_keys_in_db(&keys_context, &shared_db).await),
                    time_to_lock: None,
                    ssh_agent_active: Some(active_ssh_agent.read().await.is_some()),
                }
            } else {
                // No session left in database (e.g., after logout). Lock the vault.
                *keys_context.write().await = None;
                *shared_timeout.write().await = None;

                ControlResponse {
                    status: "ok".to_string(),
                    error: None,
                    unlocked: Some(false),
                    key_count: Some(0),
                    time_to_lock: None,
                    ssh_agent_active: Some(active_ssh_agent.read().await.is_some()),
                }
            }
        }
        ControlRequest::StartSshAgent => {
            let mut active = active_ssh_agent.write().await;
            if active.is_some() {
                ControlResponse {
                    status: "error".to_string(),
                    error: Some("SSH agent is already running".to_string()),
                    unlocked: Some(keys_context.read().await.is_some()),
                    key_count: Some(count_keys_in_db(&keys_context, &shared_db).await),
                    time_to_lock: None,
                    ssh_agent_active: Some(true),
                }
            } else {
                let (tx, rx) = tokio::sync::oneshot::channel();
                let sp = socket_path.clone();
                let la = last_activity.clone();
                let kc = keys_context.clone();
                let db_clone = shared_db.clone();
                tokio::spawn(async move {
                    if let Err(e) = start_ssh_agent_task(sp, la, kc, db_clone, rx).await {
                        error!("SSH Agent task error: {}", e);
                    }
                });
                *active = Some(tx);
                ControlResponse {
                    status: "ok".to_string(),
                    error: None,
                    unlocked: Some(keys_context.read().await.is_some()),
                    key_count: Some(count_keys_in_db(&keys_context, &shared_db).await),
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
                    unlocked: Some(keys_context.read().await.is_some()),
                    key_count: Some(count_keys_in_db(&keys_context, &shared_db).await),
                    time_to_lock: None,
                    ssh_agent_active: Some(false),
                }
            } else {
                ControlResponse {
                    status: "error".to_string(),
                    error: Some("SSH agent is not running".to_string()),
                    unlocked: Some(keys_context.read().await.is_some()),
                    key_count: Some(count_keys_in_db(&keys_context, &shared_db).await),
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
    shared_db: &SharedDb,
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
            info!(
                "Failed to fetch cipher details for {}: {}. Assuming deleted.",
                cipher_id, e
            );
            is_deleted = true;
        }
    }

    // Get current active user ID to update
    let mut repo = shared_db.lock().await;
    let user_id = repo
        .get_active_user_id()?
        .ok_or_else(|| "No active user logged in".to_string())?;

    if is_deleted {
        repo.delete_cipher(&cipher_id)?;
    } else if let Some(cipher) = fetched_cipher {
        repo.save_cipher(&cipher, &user_id)?;
    }

    info!(
        "WebSocket: Surgically updated cipher {} in SQLite cache.",
        cipher_id
    );

    Ok(())
}

async fn run_websocket_sync_loop(keys_context: SharedKeysContext, shared_db: SharedDb) -> Result<(), String> {
    let config =
        crate::config::Config::load().map_err(|e| format!("Failed to load config: {}", e))?;
    let mut session = {
        let db = shared_db.lock().await;
        db.load_session()?.unwrap_or_else(|| {
            let mut s = crate::config::Session::default();
            if let Some(ref d_id) = config.device_id {
                s.device_id = d_id.clone();
            }
            s
        })
    };

    let token = session.get_valid_token(&config.server_url).await?;

    {
        let db = shared_db.lock().await;
        db.save_session(&session)?;
    }

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

                        if let Some(args) = is_receive_msg
                            .then(|| val.get("arguments").and_then(|a| a.as_array()))
                            .flatten()
                        {
                            for arg in args {
                                if let Some(ut) = arg.get("Type").and_then(|t| t.as_i64()) {
                                    if ut == 1 {
                                        // Surgical cipher update (Type 1 is SyncCipher)
                                        let cipher_id = arg
                                            .get("Payload")
                                            .and_then(|p| p.get("Id").or_else(|| p.get("id")))
                                            .and_then(|id| id.as_str())
                                            .or_else(|| {
                                                arg.get("Id")
                                                    .or_else(|| arg.get("id"))
                                                    .and_then(|id| id.as_str())
                                            });

                                        if let Some(cipher_id) = cipher_id {
                                            info!(
                                                "WebSocket: Received cipher update event for ID: {}. Processing surgically...",
                                                cipher_id
                                            );
                                            let client_clone = client.clone();
                                            let kc_clone = keys_context.clone();
                                            let cipher_id_str = cipher_id.to_string();
                                            let db_clone = shared_db.clone();
                                            tokio::spawn(async move {
                                                let current_token =
                                                    get_valid_token_from_db(&db_clone, "").await;
                                                if let Err(e) = handle_surgical_cipher_update(
                                                    &client_clone,
                                                    &current_token,
                                                    &cipher_id_str,
                                                    &kc_clone,
                                                    &db_clone,
                                                )
                                                .await
                                                {
                                                    error!(
                                                        "Surgical cipher update failed for {}: {}",
                                                        cipher_id_str, e
                                                    );
                                                }
                                            });
                                        }
                                    } else if ut == 0 || ut == 4 || ut == 5 {
                                        // Full Sync
                                        info!(
                                            "WebSocket: Received vault update event (Type {}). Syncing...",
                                            ut
                                        );

                                        let current_token = get_valid_token_from_db(&shared_db, &token).await;
                                        match client.sync(&current_token).await {
                                            Ok(sync_data) => {
                                                let repo_res = {
                                                    let mut db = shared_db.lock().await;
                                                    db.save_sync_response(&sync_data)
                                                };

                                                if let Err(err) = repo_res {
                                                    error!(
                                                        "WebSocket background sync failed to save db: {}",
                                                        err
                                                    );
                                                } else {
                                                    info!(
                                                        "WebSocket: Background sync completed. Synced and updated database."
                                                    );
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
                        error!(
                            "WebSocket: Binary message truncated (expected {} bytes, got {})",
                            msg_len,
                            remaining.len()
                        );
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
                                                let ut = get_map_val(map, "Type")
                                                    .and_then(|v| v.as_i64());
                                                if let Some(ut_val) = ut {
                                                    if ut_val == 1 {
                                                        // Surgical cipher update
                                                        let payload_val =
                                                            get_map_val(map, "Payload");
                                                        let cipher_id =
                                                            if let Some(Value::Map(p_map)) =
                                                                payload_val
                                                            {
                                                                get_map_val(p_map, "Id")
                                                                    .and_then(|v| v.as_str())
                                                            } else {
                                                                get_map_val(map, "Id")
                                                                    .and_then(|v| v.as_str())
                                                            };

                                                        if let Some(cipher_id) = cipher_id {
                                                            info!(
                                                                "WebSocket (binary): Received cipher update event for ID: {}. Processing surgically...",
                                                                cipher_id
                                                            );
                                                            let client_clone = client.clone();
                                                            let kc_clone = keys_context.clone();
                                                            let cipher_id_str =
                                                                cipher_id.to_string();
                                                            let db_clone = shared_db.clone();
                                                            tokio::spawn(async move {
                                                                let current_token =
                                                                    get_valid_token_from_db(&db_clone, "")
                                                                        .await;
                                                                if let Err(e) =
                                                                    handle_surgical_cipher_update(
                                                                        &client_clone,
                                                                        &current_token,
                                                                        &cipher_id_str,
                                                                        &kc_clone,
                                                                        &db_clone,
                                                                    )
                                                                    .await
                                                                {
                                                                    error!(
                                                                        "Surgical cipher update failed for {}: {}",
                                                                        cipher_id_str, e
                                                                    );
                                                                }
                                                            });
                                                        }
                                                    } else if ut_val == 0
                                                        || ut_val == 4
                                                        || ut_val == 5
                                                    {
                                                        // Full Sync
                                                        info!(
                                                            "WebSocket (binary): Received vault update event (Type {}). Syncing...",
                                                            ut_val
                                                        );
                                                        let current_token =
                                                            get_valid_token_from_db(&shared_db, &token).await;
                                                        match client.sync(&current_token).await {
                                                            Ok(sync_data) => {
                                                                let repo_res = {
                                                                    let mut db = shared_db.lock().await;
                                                                    db.save_sync_response(&sync_data)
                                                                };
                                                                if let Err(err) = repo_res {
                                                                    error!(
                                                                        "WebSocket background sync failed to save db: {}",
                                                                        err
                                                                    );
                                                                } else {
                                                                    info!(
                                                                        "WebSocket (binary): Background sync completed. Synced and updated database."
                                                                    );
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

struct TtyResetGuard {
    file: std::fs::File,
    original_termios: Option<libc::termios>,
    original_flags: libc::c_int,
}

impl Drop for TtyResetGuard {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        let fd = self.file.as_raw_fd();
        if let Some(termios) = self.original_termios {
            // SAFETY: `fd` is a valid open file descriptor for the user's TTY,
            // and `termios` points to the original settings read on entry.
            unsafe {
                libc::tcsetattr(fd, libc::TCSANOW, &termios);
            }
        }
        // SAFETY: `fd` is a valid open file descriptor, restoring the original fcntl flags.
        unsafe {
            libc::fcntl(fd, libc::F_SETFL, self.original_flags);
        }
    }
}

async fn prompt_tty_for_unlock(
    peer_pid: i32,
    keys_context: &SharedKeysContext,
    stream: &mut tokio::net::UnixStream,
    shared_db: SharedDb,
) -> Result<(), String> {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::io::AsRawFd;
    use tokio::io::AsyncReadExt;
    use tokio::io::unix::AsyncFd;

    static UNLOCK_MUTEX: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    let mutex = UNLOCK_MUTEX.get_or_init(|| tokio::sync::Mutex::new(()));
    let _guard = mutex.lock().await;

    if keys_context.read().await.is_some() {
        return Ok(());
    }

    // Load session to check if logged in
    let session = {
        let db = shared_db.lock().await;
        db.load_session()?.unwrap_or_default()
    };

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

    let tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&tty_path)
        .map_err(|e| format!("Failed to open TTY: {}", e))?;

    let fd = tty.as_raw_fd();

    // Check if the client process is in the foreground of the TTY.
    // This prevents background automated queries (like git prompts) from popping up TTY prompts
    // or stealing keyboard input when the user is actively typing in their shell.
    let pgid = unsafe { libc::getpgid(peer_pid) };
    let tpgrp = unsafe { libc::tcgetpgrp(fd) };
    if pgid >= 0 && tpgrp >= 0 && pgid != tpgrp {
        return Err("Client is not in the foreground process group of the TTY".to_string());
    }

    // SAFETY: `libc::termios` is a Plain Old Data (POD) struct containing only primitive fields.
    // Zero-initializing it is safe and it is immediately fully populated by `tcgetattr`.
    let mut termios = unsafe { std::mem::zeroed() };

    // SAFETY: `fd` is a valid open file descriptor for the user's controlling TTY,
    // and `&mut termios` points to a valid local stack allocation.
    let has_termios = unsafe { libc::tcgetattr(fd, &mut termios) == 0 };

    // Retrieve original fcntl flags to restore on exit
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err("Failed to retrieve TTY fcntl flags".to_string());
    }

    // Clone the TTY to create a guard that will automatically restore original termios and flags on drop.
    let guard_file = tty.try_clone().map_err(|e| format!("Failed to clone TTY for guard: {}", e))?;
    let _reset_guard = TtyResetGuard {
        file: guard_file,
        original_termios: if has_termios { Some(termios) } else { None },
        original_flags: flags,
    };

    if has_termios {
        let mut no_echo = termios;
        no_echo.c_lflag &= !libc::ECHO;
        no_echo.c_lflag &= !libc::ECHONL;
        // SAFETY: `fd` is a valid open file descriptor, and `&no_echo` points to a valid
        // termios struct configured to temporarily disable screen echo.
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &no_echo) };
    }

    // Set O_NONBLOCK so we can read from it asynchronously with AsyncFd
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err("Failed to set TTY O_NONBLOCK fcntl flag".to_string());
    }

    let mut tty_write = tty.try_clone().map_err(|e| format!("Failed to clone TTY: {}", e))?;

    tty_write.write_all(
        b"\r\n[bitter] SSH Agent request received, but vault is locked.\r\nMaster Password: ",
    )
    .map_err(|e| e.to_string())?;
    let _ = tty_write.flush();

    let async_tty = AsyncFd::new(tty).map_err(|e| format!("Failed to create AsyncFd for TTY: {}", e))?;

    let disconnect_mon = async {
        let mut buf = [0u8; 1];
        match stream.read(&mut buf).await {
            Ok(0) => {
                // Connection closed (EOF)
                Ok::<(), String>(())
            }
            Ok(_) => {
                // Should not happen, but if they send data, we treat it as disconnect/cancel
                Ok::<(), String>(())
            }
            Err(e) => {
                Err::<(), String>(e.to_string())
            }
        }
    };

    let password_future = async {
        let mut password = String::new();
        let mut buf = [0u8; 1024];
        loop {
            let mut guard = async_tty.readable().await.map_err(|e| e.to_string())?;
            match guard.try_io(|inner| {
                use std::io::Read;
                let mut file_ref = inner.get_ref();
                file_ref.read(&mut buf)
            }) {
                Ok(Ok(0)) => {
                    break;
                }
                Ok(Ok(n)) => {
                    let chunk = String::from_utf8_lossy(&buf[..n]);
                    password.push_str(&chunk);
                    if password.contains('\n') || password.contains('\r') {
                        break;
                    }
                }
                Ok(Err(ref e)) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    continue;
                }
                Ok(Err(e)) => {
                    return Err(format!("TTY read error: {}", e));
                }
                Err(_) => {
                    continue;
                }
            }
        }
        Ok::<String, String>(password)
    };

    let password = tokio::select! {
        res = password_future => {
            res?
        }
        _ = disconnect_mon => {
            let _ = tty_write.write_all(b"\n[bitter] Connection closed by client. Cancelling unlock.\r\n");
            let _ = tty_write.flush();
            return Err("Client disconnected during password prompt".to_string());
        }
    };

    tty_write.write_all(b"\n").map_err(|e| e.to_string())?;

    let password = password.trim().to_string();

    if password.is_empty() {
        return Err("Empty password".to_string());
    }

    // Load local database
    let sync_resp = {
        let db = shared_db.lock().await;
        db.load_sync_response()
            .map_err(|e| format!("Password incorrect or local database load failed: {}", e))?
    };

    // Decrypt symmetric keys offline using master password
    let (_items, enc_key, mac_key) =
        crate::storage::decrypt_sync_response_offline(&sync_resp, &password)
            .map_err(|e| format!("Failed to decrypt local database offline: {}", e))?;

    *keys_context.write().await = Some(KeysContext {
        user_id: sync_resp.profile.id.clone(),
        enc_key,
        mac_key,
    });

    tty_write.write_all(b"[bitter] Vault unlocked successfully.\r\n\n")
        .map_err(|e| e.to_string())?;
    let _ = tty_write.flush();

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

async fn get_valid_token_from_db(shared_db: &SharedDb, fallback: &str) -> String {
    if let Ok(cfg) = crate::config::Config::load() {
        let db = shared_db.lock().await;
        if let Ok(Some(mut sess)) = db.load_session() {
            match sess.get_valid_token(&cfg.server_url).await {
                Ok(t) => {
                    let _ = db.save_session(&sess);
                    return t;
                }
                Err(e) => {
                    error!("Failed to get valid token: {}", e);
                }
            }
        }
    }
    fallback.to_string()
}

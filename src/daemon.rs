use daemonize::Daemonize;
use serde::{Deserialize, Serialize};
use ssh_key::private::PrivateKey;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::RwLock;

use crate::agent;
use crate::storage;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ControlRequest {
    Unlock { keys: Vec<SshKeyData> },
    Lock,
    Status,
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

/// Starts the agent background process
pub fn start_agent(foreground: bool, custom_socket_path: Option<PathBuf>) -> Result<(), String> {
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

    println!("Starting sshwarden agent...");
    println!("SSH_AUTH_SOCK={}", socket_path.display());

    if foreground {
        let pid = std::process::id();
        fs::write(&pid_path, pid.to_string())
            .map_err(|e| format!("Failed to write pid file: {}", e))?;

        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| format!("Failed to start Tokio runtime: {}", e))?;

        rt.block_on(async {
            if let Err(e) = run_daemon_loops(socket_path, control_socket_path, pid_path).await {
                eprintln!("Agent error: {}", e);
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
                let rt = tokio::runtime::Runtime::new()
                    .map_err(|e| format!("Failed to start Tokio runtime: {}", e))?;

                rt.block_on(async {
                    if let Err(e) =
                        run_daemon_loops(socket_path, control_socket_path, pid_path).await
                    {
                        eprintln!("Daemon error: {}", e);
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

    println!("Stopping agent with PID {}...", pid);

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
            println!("Agent stopped successfully.");
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
pub fn print_status() -> Result<(), String> {
    let cache_dir =
        storage::cache_dir().ok_or_else(|| "Could not determine cache directory".to_string())?;
    let socket_path = cache_dir.join("ssh-agent.sock");
    let control_socket_path = cache_dir.join("ssh-agent.sock.control");

    if is_agent_running() {
        println!("sshwarden agent: running");
        println!("SSH_AUTH_SOCK:   {}", socket_path.display());

        // Connect to control socket to fetch key statistics
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            match query_agent_status(&control_socket_path).await {
                Ok(resp) => {
                    let status_str = if resp.unlocked.unwrap_or(false) {
                        "Unlocked"
                    } else {
                        "Locked"
                    };
                    println!("Vault Status:    {}", status_str);
                    println!("Keys Loaded:     {}", resp.key_count.unwrap_or(0));
                }
                Err(e) => {
                    println!("Vault Status:    Error contacting control socket ({})", e);
                }
            }
        });
    } else {
        println!("sshwarden agent: stopped");
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

    let agent_listener = UnixListener::bind(&socket_path)
        .map_err(|e| format!("Failed to bind SSH agent socket: {}", e))?;
    // Set socket permissions to 0600 so only the owner can connect
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("Failed to set socket permissions: {}", e))?;

    let control_listener = UnixListener::bind(&control_socket_path)
        .map_err(|e| format!("Failed to bind control socket: {}", e))?;
    fs::set_permissions(&control_socket_path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("Failed to set control socket permissions: {}", e))?;

    let mut sigterm = signal(SignalKind::terminate()).unwrap();
    let mut sigint = signal(SignalKind::interrupt()).unwrap();

    println!("Listeners bound successfully. Running daemon listeners.");

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
                tokio::spawn(async move {
                    if let Err(e) = handle_ssh_agent_connection(stream, kr).await {
                        eprintln!("SSH Agent connection error: {}", e);
                    }
                });
            }
            // Control socket connection
            Ok((stream, _)) = control_listener.accept() => {
                let kr = keyring.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_control_connection(stream, kr).await {
                        eprintln!("Control connection error: {}", e);
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
) -> Result<(), std::io::Error> {
    loop {
        // Read 4-byte length prefix
        let mut len_bytes = [0u8; 4];
        if stream.read_exact(&mut len_bytes).await.is_err() {
            // Connection closed by client
            return Ok(());
        }
        let len = u32::from_be_bytes(len_bytes) as usize;

        // Read message payload
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload).await?;

        // Process request
        let keys = keyring.read().await;
        let response = match agent::handle_agent_request(&payload, &keys) {
            Ok(resp) => resp,
            Err(e) => {
                eprintln!("Error handling agent request: {}", e);
                // Fail message type 5
                vec![5]
            }
        };

        // Write response length prefix
        let resp_len = response.len() as u32;
        stream.write_all(&resp_len.to_be_bytes()).await?;
        // Write response payload
        stream.write_all(&response).await?;
    }
}

async fn handle_control_connection(
    mut stream: UnixStream,
    keyring: KeyRing,
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
            };
            let resp_bytes = serde_json::to_vec(&resp).unwrap();
            stream.write_all(&resp_bytes).await?;
            return Ok(());
        }
    };

    let response = match req {
        ControlRequest::Unlock { keys } => {
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
                let count = parsed_keys.len();
                let mut kr = keyring.write().await;
                *kr = parsed_keys;
                ControlResponse {
                    status: "ok".to_string(),
                    error: None,
                    unlocked: Some(true),
                    key_count: Some(count),
                }
            }
        }
        ControlRequest::Lock => {
            let mut kr = keyring.write().await;
            kr.clear();
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
    };

    let resp_bytes = serde_json::to_vec(&response).unwrap();
    stream.write_all(&resp_bytes).await?;
    Ok(())
}

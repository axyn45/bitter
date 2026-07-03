mod agent;
mod api;
mod cli;
mod config;
mod crypto;
mod daemon;
mod storage;

use api::ApiClient;
use clap::Parser;
use cli::{Cli, Commands, KeysCommands};
use config::{Config, TimeoutAction, Session};
use std::io::{self, Write};
use std::str::FromStr;

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

    if let Err(e) = rt.block_on(run_command(cli.command, &mut config)) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

async fn run_command(command: Commands, config: &mut Config) -> Result<(), String> {
    let mut session = Session::load().map_err(|e| format!("Failed to load session: {}", e))?;
    match command {
        Commands::Login(args) => {
            let server_url = args
                .server
                .clone()
                .unwrap_or_else(|| config.server_url.clone());
            let api_client = ApiClient::new(&server_url);

            // Determine if using API Key or Password Login
            let client_id = args.client_id.or_else(|| config.client_id.clone());
            let client_secret = args.client_secret.or_else(|| config.client_secret.clone());

            let (token_resp, _master_key, (enc_key, mac_key), password, email) = if let (Some(cid), Some(csec)) = (client_id, client_secret) {
                println!("Logging in using Personal API Key client credentials...");

                let resp = api_client
                    .login_api_key(&cid, &csec, &session.device_id, "sshwarden_client")
                    .await?;

                // Save credentials in config
                config.client_id = Some(cid.clone());
                config.client_secret = Some(csec.clone());

                let email = match args.email.clone().or_else(|| session.email.clone()) {
                    Some(e) => e,
                    None => {
                        print!("Email Address: ");
                        io::stdout().flush().unwrap();
                        let mut input = String::new();
                        io::stdin().read_line(&mut input).map_err(|e| format!("Failed to read email: {}", e))?;
                        input.trim().to_string()
                    }
                };

                // Prompt for master password to verify we can derive the Master Key and decrypt the symmetric key
                let password = match args.password.clone() {
                    Some(pass) => pass,
                    None => rpassword::prompt_password("Master Password (to decrypt vault keys): ")
                        .map_err(|e| format!("Password prompt failed: {}", e))?,
                };

                // Extract KDF parameters from the login response (under UserDecryptionOptions)
                let decrypt_opts = resp.user_decryption_options.as_ref()
                    .ok_or_else(|| "UserDecryptionOptions missing from API Key login response. Ensure your account is fully set up.".to_string())?;

                let unlock_data =
                    decrypt_opts
                        .master_password_unlock
                        .as_ref()
                        .ok_or_else(|| {
                            "MasterPasswordUnlock data missing from response.".to_string()
                        })?;

                let kdf_type = unlock_data.kdf.kdf_type;
                let iterations = unlock_data.kdf.iterations;
                let memory = unlock_data.kdf.memory;
                let parallelism = unlock_data.kdf.parallelism;
                let salt_email = &unlock_data.salt;

                println!("Deriving master key to verify password...");
                let master_key = match kdf_type {
                    0 => crypto::derive_master_key_pbkdf2(&password, salt_email, iterations)?,
                    1 => {
                        let mem = memory.ok_or_else(|| {
                            "Argon2 memory parameter missing from KDF settings".to_string()
                        })?;
                        let para = parallelism.ok_or_else(|| {
                            "Argon2 parallelism parameter missing from KDF settings".to_string()
                        })?;
                        crypto::derive_master_key_argon2(
                            &password, salt_email, iterations, mem, para,
                        )?
                    }
                    t => return Err(format!("Unsupported KDF type: {}", t)),
                };

                println!("Decrypting vault symmetric keys...");
                let sym_keys = crypto::decrypt_symmetric_key(&master_key, &resp.key)?;
                println!("Vault keys decrypted and verified successfully.");

                (resp, master_key, sym_keys, password, email)
            } else {
                // Password Login
                let email = match args.email.or_else(|| session.email.clone()) {
                    Some(email) => email,
                    None => {
                        print!("Email: ");
                        io::stdout().flush().unwrap();
                        let mut input = String::new();
                        io::stdin()
                            .read_line(&mut input)
                            .map_err(|e| format!("Failed to read email input: {}", e))?;
                        input.trim().to_string()
                    }
                };

                let password = match args.password {
                    Some(pass) => pass,
                    None => rpassword::prompt_password("Master Password: ")
                        .map_err(|e| format!("Password prompt failed: {}", e))?,
                };

                println!("Fetching KDF settings for {}...", email);
                let prelogin = api_client.prelogin(&email).await?;

                println!("Deriving master key locally...");
                let master_key = match prelogin.kdf {
                    0 => crypto::derive_master_key_pbkdf2(
                        &password,
                        &email,
                        prelogin.kdf_iterations,
                    )?,
                    1 => {
                        let mem = prelogin.kdf_memory.ok_or_else(|| {
                            "Argon2 memory parameter missing from prelogin settings".to_string()
                        })?;
                        let para = prelogin.kdf_parallelism.ok_or_else(|| {
                            "Argon2 parallelism parameter missing from prelogin settings"
                                .to_string()
                        })?;
                        crypto::derive_master_key_argon2(
                            &password,
                            &email,
                            prelogin.kdf_iterations,
                            mem,
                            para,
                        )?
                    }
                    t => return Err(format!("Unsupported KDF type: {}", t)),
                };

                let login_hash = crypto::derive_login_hash(&master_key, &password);
                println!("Authenticating with server...");

                let resp = api_client
                    .login_password(&email, &login_hash, &session.device_id, "sshwarden_client")
                    .await?;

                println!("Decrypting vault symmetric keys...");
                let sym_keys = crypto::decrypt_symmetric_key(&master_key, &resp.key)?;
                println!("Vault keys decrypted and verified successfully.");

                (resp, master_key, sym_keys, password, email)
            };

            // Store token and configurations
            config.server_url = server_url;
            config
                .save()
                .map_err(|e| format!("Failed to save configuration: {}", e))?;

            session.access_token = Some(token_resp.access_token.clone());
            session.refresh_token = token_resp.refresh_token.clone();
            session.email = Some(email);
            session
                .save()
                .map_err(|e| format!("Failed to save session: {}", e))?;

            println!("Logged in successfully. Session token stored locally.");

            // Automatically perform synchronization
            println!("Automatically syncing ciphers from server...");
            match api_client.sync(&token_resp.access_token).await {
                Ok(sync_data) => {
                    let salt = session
                        .cache_salt
                        .as_ref()
                        .ok_or_else(|| "Local database salt missing from session.".to_string())?;
                    let db_key = storage::derive_db_key(&password, salt)?;

                    let decrypted_ciphers = storage::parse_and_decrypt_all_ciphers(&sync_data, &enc_key, &mac_key);
                    let ssh_keys = storage::extract_ssh_keys_from_ciphers(&decrypted_ciphers);
                    if let Err(e) = storage::save_db(&decrypted_ciphers, &db_key, Some(&enc_key), Some(&mac_key)) {
                        eprintln!("Warning: Failed to save synced keys to database cache: {}", e);
                    } else {
                        config.last_sync_time = Some(get_current_time_string());
                        config.local_key_count = Some(ssh_keys.len());
                        let _ = config.save();
                        println!("Sync completed. Synced {} SSH keys.", ssh_keys.len());
                        for key in &ssh_keys {
                            println!("  - {}", key.name);
                        }

                        // Automatically unlock active background agent if it is running
                        if daemon::is_agent_running() {
                            println!("Agent daemon is running. Automatically unlocking and loading keys...");
                            let enc_hex = hex::encode(enc_key);
                            let mac_hex = hex::encode(mac_key);
                            let db_hex = hex::encode(db_key);
                            let daemon_keys: Vec<daemon::SshKeyData> = ssh_keys
                                .into_iter()
                                .map(|k| daemon::SshKeyData {
                                    name: k.name,
                                    private_key: k.private_key,
                                })
                                .collect();

                            match daemon::send_control_request(daemon::ControlRequest::Unlock {
                                keys: daemon_keys,
                                enc_key: enc_hex,
                                mac_key: mac_hex,
                                db_key: db_hex,
                            })
                            .await
                            {
                                Ok(resp) => {
                                    if resp.status == "ok" {
                                        println!(
                                            "Agent unlocked successfully. Synced {} keys to memory.",
                                            resp.key_count.unwrap_or(0)
                                        );
                                    } else {
                                        eprintln!("Warning: Failed to unlock agent: {}", resp.error.unwrap_or_default());
                                    }
                                }
                                Err(e) => {
                                    eprintln!("Warning: Failed to communicate with running agent to unlock: {}", e);
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Warning: Automatic sync failed: {}", e);
                }
            }
        }
        Commands::Logout => {
            println!("Logging out...");
            if daemon::is_agent_running() {
                println!("Locking and clearing background agent memory...");
                if let Err(e) = daemon::send_control_request(daemon::ControlRequest::Lock).await {
                    eprintln!("Warning: Failed to notify agent to lock/clear keys: {}", e);
                }
            }
            if let Err(e) = storage::wipe_db() {
                eprintln!("Warning: Failed to delete local database cache: {}", e);
            }
            config.client_id = None;
            config.client_secret = None;
            config
                .save()
                .map_err(|e| format!("Failed to save configuration: {}", e))?;

            let session = Session::default();
            session
                .save()
                .map_err(|e| format!("Failed to save session: {}", e))?;
            println!("Logged out successfully. Configuration, session, and local cache cleared.");
        }
        Commands::Sync => {
            let token = session.get_valid_token(&config.server_url).await?;

            let api_client = ApiClient::new(&config.server_url);
            println!("Syncing ciphers from server {}...", config.server_url);

            let sync_data = api_client.sync(&token).await?;

            let mut cached_keys = None;
            if config.timeout.trim().to_lowercase() == "never" {
                if let Some((enc, mac, db)) = storage::load_saved_keys() {
                    println!("Using cached decryption keys for passwordless sync...");
                    cached_keys = Some((enc, mac, db));
                }
            }

            let (enc_key, mac_key, db_key) = match cached_keys {
                Some(keys) => keys,
                None => {
                    let password = rpassword::prompt_password("Master Password (to decrypt vault keys): ")
                        .map_err(|e| format!("Password prompt failed: {}", e))?;

                    let email = session.email.as_ref().ok_or_else(|| {
                        "Email address missing from session. Please log in again.".to_string()
                    })?;

                    println!("Fetching KDF settings...");
                    let prelogin = api_client.prelogin(email).await?;

                    println!("Deriving keys...");
                    let master_key = match prelogin.kdf {
                        0 => crypto::derive_master_key_pbkdf2(&password, email, prelogin.kdf_iterations)?,
                        1 => {
                            let mem = prelogin
                                .kdf_memory
                                .ok_or_else(|| "Argon2 memory parameter missing".to_string())?;
                            let para = prelogin
                                .kdf_parallelism
                                .ok_or_else(|| "Argon2 parallelism parameter missing".to_string())?;
                            crypto::derive_master_key_argon2(
                                &password,
                                email,
                                prelogin.kdf_iterations,
                                mem,
                                para,
                            )?
                        }
                        t => return Err(format!("Unsupported KDF type: {}", t)),
                    };

                    let salt = session
                        .cache_salt
                        .as_ref()
                        .ok_or_else(|| "Local database salt missing from session.".to_string())?;
                    let db_key = storage::derive_db_key(&password, salt)?;

                    let (enc, mac) =
                        crypto::decrypt_symmetric_key(&master_key, &sync_data.profile.key)?;
                    (enc, mac, db_key)
                }
            };

            println!("Decrypting and parsing vault items...");
            let decrypted_ciphers = storage::parse_and_decrypt_all_ciphers(&sync_data, &enc_key, &mac_key);
            let ssh_keys = storage::extract_ssh_keys_from_ciphers(&decrypted_ciphers);

            println!("Saving cache to disk...");
            storage::save_db(&decrypted_ciphers, &db_key, Some(&enc_key), Some(&mac_key))?;

            config.last_sync_time = Some(get_current_time_string());
            config.local_key_count = Some(ssh_keys.len());
            let _ = config.save();

            println!(
                "Sync completed successfully. Synced {} SSH keys:",
                ssh_keys.len()
            );
            for key in &ssh_keys {
                println!("  - {}", key.name);
            }

            // Automatically unlock active background agent if it is running
            if daemon::is_agent_running() {
                println!("Agent daemon is running. Automatically updating keys in agent memory...");
                let enc_hex = hex::encode(enc_key);
                let mac_hex = hex::encode(mac_key);
                let db_hex = hex::encode(db_key);
                let daemon_keys: Vec<daemon::SshKeyData> = ssh_keys
                    .into_iter()
                    .map(|k| daemon::SshKeyData {
                        name: k.name,
                        private_key: k.private_key,
                    })
                    .collect();

                match daemon::send_control_request(daemon::ControlRequest::Unlock {
                    keys: daemon_keys,
                    enc_key: enc_hex,
                    mac_key: mac_hex,
                    db_key: db_hex,
                })
                .await
                {
                    Ok(resp) => {
                        if resp.status == "ok" {
                            println!(
                                "Agent keys updated successfully. Synced {} keys to memory.",
                                resp.key_count.unwrap_or(0)
                            );
                        } else {
                            eprintln!("Warning: Failed to update keys in agent: {}", resp.error.unwrap_or_default());
                        }
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to communicate with running agent to update keys: {}", e);
                    }
                }
            }
        }
        Commands::Settings(args) => {
            let mut updated = false;

            if let Some(t) = args.timeout {
                if t.trim().to_lowercase() == "never" {
                    if let Some(ref email) = session.email {
                        let token = session
                            .access_token
                            .as_ref()
                            .ok_or_else(|| "Access token missing from session".to_string())?;

                        let password = rpassword::prompt_password("Enter Master Password to verify and enable 'never' timeout: ")
                            .map_err(|e| format!("Password prompt failed: {}", e))?;

                        let salt = session
                            .cache_salt
                            .as_ref()
                            .ok_or_else(|| "Local database salt missing from session.".to_string())?;
                        let db_key = storage::derive_db_key(&password, salt)?;

                        // Try verifying with local cache first
                        let path = storage::db_path().ok_or_else(|| "Invalid cache path".to_string())?;
                        let mut verified = false;
                        let mut loaded_keys = Vec::new();
                        let mut enc_opt = None;
                        let mut mac_opt = None;

                        if path.exists() {
                            if let Ok(keys) = storage::load_db(&db_key) {
                                verified = true;
                                loaded_keys = keys;
                            }
                        }

                        // If not verified locally, verify with server
                        if !verified {
                            println!("Verifying master password with server...");
                            let api_client = ApiClient::new(&config.server_url);
                            let prelogin = api_client.prelogin(email).await?;
                            let master_key_res = match prelogin.kdf {
                                0 => crypto::derive_master_key_pbkdf2(&password, email, prelogin.kdf_iterations),
                                1 => {
                                    if let (Some(mem), Some(para)) = (prelogin.kdf_memory, prelogin.kdf_parallelism) {
                                        crypto::derive_master_key_argon2(&password, email, prelogin.kdf_iterations, mem, para)
                                    } else {
                                        Err("Argon2 parameters missing".to_string())
                                    }
                                }
                                t => Err(format!("Unsupported KDF type: {}", t)),
                            };

                            match master_key_res {
                                Ok(master_key) => {
                                    match api_client.sync(token).await {
                                        Ok(sync_data) => {
                                            match crypto::decrypt_symmetric_key(&master_key, &sync_data.profile.key) {
                                                Ok((enc_key, mac_key)) => {
                                                    verified = true;
                                                    loaded_keys = storage::parse_and_decrypt_all_ciphers(&sync_data, &enc_key, &mac_key);
                                                    enc_opt = Some(enc_key);
                                                    mac_opt = Some(mac_key);
                                                }
                                                Err(_) => {}
                                            }
                                        }
                                        Err(_) => {}
                                    }
                                }
                                Err(_) => {}
                            }
                        }

                        if !verified {
                            return Err("Incorrect Master Password. Timeout setting remains unchanged.".to_string());
                        }

                        config.timeout = t.clone();
                        println!("Timeout updated to: {}", t);
                        updated = true;

                        // Save configuration first so that save_db reads timeout as "never"
                        config
                            .save()
                            .map_err(|e| format!("Failed to save configuration: {}", e))?;
                        
                        if !loaded_keys.is_empty() {
                            println!("Generating unencrypted cache database...");
                            if let Err(e) = storage::save_db(&loaded_keys, &db_key, enc_opt.as_ref(), mac_opt.as_ref()) {
                                eprintln!("Warning: Failed to generate unencrypted cache: {}", e);
                            }
                        }
                    } else {
                        // Not logged in, allow setting timeout to "never"
                        config.timeout = t.clone();
                        println!("Timeout updated to: {}", t);
                        updated = true;
                    }
                } else {
                    config.timeout = t.clone();
                    println!("Timeout updated to: {}", t);
                    updated = true;
                }
            }

            if let Some(act_str) = args.timeout_action {
                let action = TimeoutAction::from_str(&act_str)?;
                config.timeout_action = action;
                println!("Timeout action updated to: {:?}", action);
                updated = true;
            }

            if let Some(url) = args.server_url {
                config.server_url = url.clone();
                println!("Server URL updated to: {}", url);
                updated = true;
            }

            if let Some(ref auto_start_str) = args.ssh_agent_auto_start {
                let val = match auto_start_str.trim().to_lowercase().as_str() {
                    "true" | "yes" | "1" => true,
                    "false" | "no" | "0" => false,
                    _ => return Err("Invalid value for ssh_agent_auto_start. Use 'true' or 'false'.".to_string()),
                };
                config.ssh_agent_auto_start = val;
                println!("SSH Agent auto-start updated to: {}", val);
                updated = true;
            }

            if updated {
                config
                    .save()
                    .map_err(|e| format!("Failed to save configuration: {}", e))?;
                println!("Settings saved.");

                if daemon::is_agent_running() {
                    println!("Notifying active agent daemon to reload settings...");
                    if let Err(e) =
                        daemon::send_control_request(daemon::ControlRequest::Reload).await
                    {
                        eprintln!("Warning: Failed to notify running agent: {}", e);
                    }
                }
            } else {
                println!("Current settings:");
                println!("  Server URL:     {}", config.server_url);
                println!(
                    "  Email:          {}",
                    session.email.as_deref().unwrap_or("<not logged in>")
                );
                println!("  Session Timeout: {}", config.timeout);
                println!("  Timeout Action:  {:?}", config.timeout_action);
                println!("  SSH Agent Auto-Start: {}", config.ssh_agent_auto_start);
            }
        }
        Commands::Keys(args) => match args.command {
            KeysCommands::List => {
                let password = rpassword::prompt_password("Master Password: ")
                    .map_err(|e| format!("Password prompt failed: {}", e))?;

                let salt = session
                    .cache_salt
                    .as_ref()
                    .ok_or_else(|| "Local database salt missing from session.".to_string())?;
                let db_key = storage::derive_db_key(&password, salt)?;

                let ciphers = storage::load_db(&db_key)?;
                let keys = storage::extract_ssh_keys_from_ciphers(&ciphers);
                if keys.is_empty() {
                    println!(
                        "No SSH keys found in local cache. Run 'sshwarden sync' to fetch them."
                    );
                } else {
                    println!("Available SSH Keys ({}):", keys.len());
                    for (i, key) in keys.iter().enumerate() {
                        println!("{}. {} [ID: {}]", i + 1, key.name, key.id);
                        if let Some(ref note) = key.note {
                            println!("   Note: {}", note);
                        }
                    }
                }
            }
            KeysCommands::Add => {
                println!("Adding new key... (Will be implemented in Phase 3)");
            }
            KeysCommands::Edit { id } => {
                println!("Editing key {}... (Will be implemented in Phase 3)", id);
            }
            KeysCommands::Delete { id } => {
                println!("Deleting key {}... (Will be implemented in Phase 3)", id);
            }
        },
        Commands::Start(_) => {
            unreachable!("Start command handled synchronously in main()");
        }
        Commands::Stop => {
            daemon::stop_agent()?;
        }
        Commands::StartSsh => {
            if !daemon::is_agent_running() {
                return Err("Agent daemon is not running. Please start the daemon first using 'sshwarden start'.".to_string());
            }
            println!("Requesting running daemon to start SSH agent loop...");
            let resp = daemon::send_control_request(daemon::ControlRequest::StartSshAgent).await?;
            if resp.status == "ok" {
                println!("SSH agent loop started successfully.");
            } else {
                return Err(format!("Failed to start SSH agent: {}", resp.error.unwrap_or_default()));
            }
        }
        Commands::StopSsh => {
            if !daemon::is_agent_running() {
                return Err("Agent daemon is not running.".to_string());
            }
            println!("Requesting running daemon to stop SSH agent loop...");
            let resp = daemon::send_control_request(daemon::ControlRequest::StopSshAgent).await?;
            if resp.status == "ok" {
                println!("SSH agent loop stopped successfully.");
            } else {
                return Err(format!("Failed to stop SSH agent: {}", resp.error.unwrap_or_default()));
            }
        }
        Commands::Unlock => {
            let email = session.email.as_ref().ok_or_else(|| {
                "Email address missing from session. Please log in first.".to_string()
            })?;
            let token = session
                .access_token
                .as_ref()
                .ok_or_else(|| "Not logged in. Please run 'sshwarden login' first.".to_string())?;

            let password = rpassword::prompt_password("Master Password: ")
                .map_err(|e| format!("Password prompt failed: {}", e))?;

            let salt = session
                .cache_salt
                .as_ref()
                .ok_or_else(|| "Local database salt missing from session.".to_string())?;
            let db_key = storage::derive_db_key(&password, salt)?;

            let api_client = ApiClient::new(&config.server_url);

            // Attempt online sync first
            println!("Syncing ciphers and decrypting keys from server...");
            let mut keys_to_load = Vec::new();
            let mut enc_hex = String::new();
            let mut mac_hex = String::new();
            let mut synced_successfully = false;

            match api_client.prelogin(email).await {
                Ok(prelogin) => {
                    let master_key_res = match prelogin.kdf {
                        0 => crypto::derive_master_key_pbkdf2(&password, email, prelogin.kdf_iterations),
                        1 => {
                            if let (Some(mem), Some(para)) = (prelogin.kdf_memory, prelogin.kdf_parallelism) {
                                crypto::derive_master_key_argon2(&password, email, prelogin.kdf_iterations, mem, para)
                            } else {
                                Err("Argon2 parameters missing from prelogin response".to_string())
                            }
                        }
                        t => Err(format!("Unsupported KDF type: {}", t)),
                    };

                    match master_key_res {
                        Ok(master_key) => {
                            match api_client.sync(token).await {
                                Ok(sync_data) => {
                                    match crypto::decrypt_symmetric_key(&master_key, &sync_data.profile.key) {
                                        Ok((enc_key, mac_key)) => {
                                            let decrypted_ciphers = storage::parse_and_decrypt_all_ciphers(&sync_data, &enc_key, &mac_key);
                                            let ssh_keys = storage::extract_ssh_keys_from_ciphers(&decrypted_ciphers);
                                            println!("Sync successful. Saving encrypted cache to disk...");
                                             if let Err(e) = storage::save_db(&decrypted_ciphers, &db_key, Some(&enc_key), Some(&mac_key)) {
                                                 eprintln!("Warning: Failed to save synced keys to database cache: {}", e);
                                             } else {
                                                 config.last_sync_time = Some(get_current_time_string());
                                                 config.local_key_count = Some(ssh_keys.len());
                                                 let _ = config.save();
                                             }
                                            enc_hex = hex::encode(enc_key);
                                            mac_hex = hex::encode(mac_key);
                                            keys_to_load = ssh_keys;
                                            synced_successfully = true;
                                        }
                                        Err(e) => {
                                            eprintln!("Warning: Failed to decrypt profile keys: {}", e);
                                        }
                                    }
                                }
                                Err(e) => {
                                    eprintln!("Warning: Failed to sync vault: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Warning: Key derivation failed: {}", e);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("Warning: Prelogin failed: {}", e);
                }
            }

            if !synced_successfully {
                println!("Falling back to decrypting local cache database...");
                let ciphers = storage::load_db(&db_key)?;
                let cache_keys = storage::extract_ssh_keys_from_ciphers(&ciphers);
                if cache_keys.is_empty() {
                    return Err(
                        "No keys found in local cache database. Please check your network and try again."
                            .to_string(),
                    );
                }
                keys_to_load = cache_keys;
                println!("Warning: Running in offline mode. Live background sync will be unavailable.");
            }

            let db_hex = hex::encode(db_key);
            let daemon_keys: Vec<daemon::SshKeyData> = keys_to_load
                .into_iter()
                .map(|k| daemon::SshKeyData {
                    name: k.name,
                    private_key: k.private_key,
                })
                .collect();

            println!("Sending keys to background agent daemon...");
            let resp = daemon::send_control_request(daemon::ControlRequest::Unlock {
                keys: daemon_keys,
                enc_key: enc_hex,
                mac_key: mac_hex,
                db_key: db_hex,
            })
            .await?;

            if resp.status == "ok" {
                println!(
                    "Agent unlocked successfully. Synced {} keys to memory.",
                    resp.key_count.unwrap_or(0)
                );
            } else {
                return Err(format!(
                    "Failed to unlock agent: {}",
                    resp.error.unwrap_or_default()
                ));
            }
        }
        Commands::Status => {
            println!("sshwarden Status:");
            println!("  Server URL:     {}", config.server_url);
            
            if let Some(ref email) = session.email {
                println!("  Login Status:   Logged In");
                println!("  Logged in User: {}", email);
                
                let method = if config.client_id.is_some() {
                    "API Key"
                } else {
                    "Master Password"
                };
                println!("  Login Method:   {}", method);
            } else {
                println!("  Login Status:   Not Logged In");
            }

            let agent_running = daemon::is_agent_running();
            println!("  Agent Status:   {}", if agent_running { "Running" } else { "Not Running" });

            if agent_running {
                match daemon::send_control_request(daemon::ControlRequest::Status).await {
                    Ok(resp) => {
                        let unlocked = resp.unlocked.unwrap_or(false);
                        println!("  Agent Vault:    {}", if unlocked { "Unlocked" } else { "Locked" });
                        println!("  Keys in Memory: {}", resp.key_count.unwrap_or(0));
                        if let Some(ttl) = resp.time_to_lock {
                            let mins = ttl / 60;
                            let secs = ttl % 60;
                            if mins > 0 {
                                println!("  Time to Auto-Lock: {}m {}s", mins, secs);
                            } else {
                                println!("  Time to Auto-Lock: {}s", secs);
                            }
                        }
                    }
                    Err(e) => {
                        println!("  Agent Details:  Could not query (Error: {})", e);
                    }
                }
            }

            println!("  Timeout Setting: {}", config.timeout);
            println!("  Timeout Action:  {:?}", config.timeout_action);
            println!("  SSH Agent Auto-Start: {}", config.ssh_agent_auto_start);

            if let Some(ref sync_time) = config.last_sync_time {
                println!("  Last Synced:    {}", sync_time);
            } else {
                println!("  Last Synced:    Never");
            }

            let local_keys = config.local_key_count.unwrap_or(0);
            println!("  Total Keys (stored locally): {}", local_keys);
        }
    }
    Ok(())
}

fn get_current_time_string() -> String {
    // SAFETY: We use thread-safe libc calls `localtime_r` and `strftime` with local stack allocations.
    // Zero-initializing `tm` is safe as it is a Plain Old Data (POD) struct and is written to by `localtime_r`.
    unsafe {
        let t = libc::time(std::ptr::null_mut());
        let mut tm = std::mem::zeroed();
        libc::localtime_r(&t, &mut tm);
        let mut buf = [0u8; 64];
        let len = libc::strftime(
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            b"%Y-%m-%d %H:%M:%S\0".as_ptr() as *const libc::c_char,
            &tm,
        );
        if len > 0 {
            String::from_utf8_lossy(&buf[..len]).into_owned()
        } else {
            "Unknown".to_string()
        }
    }
}

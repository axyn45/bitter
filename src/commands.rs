use crate::api::ApiClient;
use crate::cli::{Commands, KeysCommands};
use crate::config::{Config, Session, TimeoutAction};
use crate::{crypto, daemon, storage};
use std::io::{self, Write};
use std::str::FromStr;

pub enum KeySource {
    MasterKey([u8; 32]),
    DecryptedKeys {
        enc_key: [u8; 32],
        mac_key: [u8; 32],
    },
}

pub async fn perform_sync_and_reload(
    api_client: &ApiClient,
    token: &str,
    key_source: KeySource,
    session: &mut Session,
) -> Result<Vec<storage::CipherItem>, String> {
    // 1. Fetch sync data
    let sync_data = api_client
        .sync(token)
        .await
        .map_err(|e| format!("Failed to sync vault from server: {}", e))?;

    // 2. Obtain symmetric keys
    let (enc_key, mac_key) = match key_source {
        KeySource::MasterKey(master_key) => {
            crypto::decrypt_symmetric_key(&master_key, &sync_data.profile.key)
                .map_err(|e| format!("Failed to decrypt symmetric keys: {}", e))?
        }
        KeySource::DecryptedKeys { enc_key, mac_key } => (enc_key, mac_key),
    };

    // 3. Decrypt all ciphers
    let decrypted_ciphers = storage::parse_and_decrypt_all_ciphers(&sync_data, &enc_key, &mac_key);

    // 4. Update session fields and save
    session.last_sync_time = Some(get_current_time_string());
    let db_path = storage::db_path().ok_or_else(|| "Could not determine cache database path".to_string())?;
    let mut repo = storage::VaultRepository::open(&db_path)?;
    repo.save_session(session)
        .map_err(|e| format!("Failed to save session: {}", e))?;

    // 5. Save sync response to database cache
    repo.save_sync_response(&sync_data)
        .map_err(|e| format!("Failed to save cache database: {}", e))?;
    storage::handle_post_sync(&sync_data, &repo, &enc_key, &mac_key)?;

    // 6. Automatically unlock running agent daemon if it is running
    if daemon::is_agent_running() {
        let ssh_keys = storage::extract_ssh_keys_from_ciphers(&decrypted_ciphers);
        let enc_hex = hex::encode(&enc_key);
        let mac_hex = hex::encode(&mac_key);
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
        })
        .await
        {
            Ok(resp) => {
                if resp.status == "ok" {
                    println!(
                        "Agent unlocked/updated successfully. Loaded {} keys to memory.",
                        resp.key_count.unwrap_or(0)
                    );
                } else {
                    eprintln!(
                        "Warning: Failed to unlock agent: {}",
                        resp.error.unwrap_or_default()
                    );
                }
            }
            Err(e) => {
                eprintln!(
                    "Warning: Failed to communicate with running agent to unlock: {}",
                    e
                );
            }
        }
    }

    Ok(decrypted_ciphers)
}

pub async fn run_command(command: Commands, config: &mut Config) -> Result<(), String> {
    let db_path = storage::db_path().ok_or_else(|| "Could not determine cache database path".to_string())?;
    let repo = storage::VaultRepository::open(&db_path)?;
    let mut session = repo.load_session()?.unwrap_or_default();

    let is_logout = matches!(command, Commands::Logout);

    match command {
        Commands::Login(args) => handle_login(args, config, &mut session).await?,
        Commands::Logout => handle_logout(config).await?,
        Commands::Sync => handle_sync(config, &mut session).await?,
        Commands::Settings(args) => handle_settings(args, config, &mut session).await?,
        Commands::Keys(args) => handle_keys(args.command, &session).await?,
        Commands::Unlock => handle_unlock(config, &mut session).await?,
        Commands::Status => handle_status(config, &session).await?,
        Commands::Start(_) => {
            unreachable!("Start command handled synchronously in main()");
        }
        Commands::Stop => {
            daemon::stop_agent()?;
        }
        Commands::StartSsh => {
            if !daemon::is_agent_running() {
                return Err("Agent daemon is not running. Please start the daemon first using 'bitter start'.".to_string());
            }
            println!("Requesting running daemon to start SSH agent loop...");
            let resp = daemon::send_control_request(daemon::ControlRequest::StartSshAgent).await?;
            if resp.status == "ok" {
                println!("SSH agent loop started successfully.");
            } else {
                return Err(format!(
                    "Failed to start SSH agent: {}",
                    resp.error.unwrap_or_default()
                ));
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
                return Err(format!(
                    "Failed to stop SSH agent: {}",
                    resp.error.unwrap_or_default()
                ));
            }
        }
    }

    if !is_logout {
        repo.save_session(&session)?;
    }
    Ok(())
}

fn parse_auth_code(input: &str) -> Result<String, String> {
    if input.contains("code=") {
        // It's a full URL or query string, parse it
        let url_parts: Vec<&str> = input.split('?').collect();
        let query = url_parts.last().ok_or_else(|| "Invalid URL format".to_string())?;
        for pair in query.split('&') {
            let key_val: Vec<&str> = pair.split('=').collect();
            if key_val.len() == 2 && key_val[0] == "code" {
                return Ok(urlencoding::decode(key_val[1])
                    .map_err(|e| e.to_string())?
                    .into_owned());
            }
        }
        Err("Authorization code not found in URL".to_string())
    } else {
        // It's already the raw code
        Ok(input.to_string())
    }
}

async fn handle_login(
    args: crate::cli::LoginArgs,
    config: &mut Config,
    session: &mut Session,
) -> Result<(), String> {
    let server_url = args
        .server
        .clone()
        .unwrap_or_else(|| config.server_url.clone());
    let api_client = ApiClient::new(&server_url);

    // Determine if using API Key or Password Login
    let client_id = args.client_id.or_else(|| config.client_id.clone());
    let client_secret = args.client_secret.or_else(|| config.client_secret.clone());

    let (token_resp, master_key, email) = if args.sso {
        println!("Logging in using Single Sign-On (SSO)...");
        
        let org_id = match args.org_id.clone() {
            Some(o) => o,
            None => {
                print!("Organization Identifier: ");
                io::stdout().flush().unwrap();
                let mut input = String::new();
                io::stdin()
                    .read_line(&mut input)
                    .map_err(|e| format!("Failed to read organization ID: {}", e))?;
                input.trim().to_string()
            }
        };

        if org_id.is_empty() {
            return Err("Organization Identifier is required for SSO login.".to_string());
        }

        // 1. Generate PKCE Verifier and Challenge and State
        let (code_verifier, code_challenge) = crypto::generate_pkce_pair();
        let state = uuid::Uuid::new_v4().to_string();

        // Try to fetch Vaultwarden SSO prevalidate token if available
        println!("Retrieving SSO pre-validation token...");
        let sso_token = api_client.fetch_sso_prevalidate_token().await.unwrap_or(None);

        let (client_id, redirect_uri) = match sso_token {
            Some(_) => (
                "web",
                format!("{}/sso-connector.html", server_url.trim_end_matches('/')),
            ),
            None => (
                "cli",
                "http://localhost:8081/sso-callback".to_string(),
            ),
        };

        // 2. Build the authorization URL
        let auth_url = match sso_token {
            Some(ref token) => {
                // Vaultwarden OIDC SSO flow
                format!(
                    "{}/identity/connect/authorize?response_type=code&scope=api%20offline_access\
                     &client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256\
                     &response_mode=query&state={}&_identifier={}&ssoToken={}",
                    server_url.trim_end_matches('/'),
                    client_id,
                    urlencoding::encode(&redirect_uri),
                    code_challenge,
                    urlencoding::encode(&state),
                    org_id,
                    urlencoding::encode(token)
                )
            }
            None => {
                // Official Bitwarden SSO flow
                format!(
                    "{}/identity/connect/authorize?response_type=code&scope=api%20offline_access\
                     &client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256\
                     &state={}&acr_values=idp:sso&organizationId={}",
                    server_url.trim_end_matches('/'),
                    client_id,
                    urlencoding::encode(&redirect_uri),
                    code_challenge,
                    urlencoding::encode(&state),
                    org_id
                )
            }
        };

        println!("\nPlease open the following URL in a browser on your local device to authenticate:\n");
        println!("{}\n", auth_url);

        // 3. Prompt the user for the redirect URL or auth code
        println!("Once logged in, your browser will redirect to a page starting with '{}'.", redirect_uri);
        print!("Paste the redirected URL (or the 'code' parameter value): ");
        io::stdout().flush().unwrap();
        let mut callback_input = String::new();
        io::stdin()
            .read_line(&mut callback_input)
            .map_err(|e| format!("Failed to read redirect input: {}", e))?;
        
        let code = parse_auth_code(callback_input.trim())?;

        // 4. Exchange authorization code for token
        println!("Exchanging authorization code for access token...");
        let resp = api_client.exchange_sso_code(client_id, &code, &code_verifier, &redirect_uri, &session.device_id).await?;

        // 5. Prompt for Master Password to verify master key and decrypt vault keys
        let password = match args.password.clone() {
            Some(pass) => pass,
            None => crypto::prompt_master_password(Some("Master Password (to decrypt vault keys): "))?,
        };

        // Extract KDF parameters from the login response
        let decrypt_opts = resp.user_decryption_options.as_ref()
            .ok_or_else(|| "UserDecryptionOptions missing from SSO response. Ensure your account is fully set up.".to_string())?;

        let unlock_data = decrypt_opts
            .master_password_unlock
            .as_ref()
            .ok_or_else(|| "MasterPasswordUnlock data missing from response.".to_string())?;

        let email = args.email.clone()
            .or_else(|| session.email.clone())
            .unwrap_or_else(|| unlock_data.salt.clone());

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
                crypto::derive_master_key_argon2(&password, salt_email, iterations, mem, para)?
            }
            t => return Err(format!("Unsupported KDF type: {}", t)),
        };

        println!("Decrypting vault symmetric keys...");
        let _sym_keys = crypto::decrypt_symmetric_key(&master_key, &resp.key)?;
        println!("Vault keys decrypted and verified successfully.");

        (resp, master_key, email)
    } else if let (Some(cid), Some(csec)) = (client_id, client_secret) {
        println!("Logging in using Personal API Key client credentials...");

        let resp = api_client
            .login_api_key(&cid, &csec, &session.device_id, "bitter_client")
            .await?;

        // Save credentials in config
        config.client_id = Some(cid.clone());
        config.client_secret = Some(csec.clone());

        // Prompt for master password to verify we can derive the Master Key and decrypt the symmetric key
        let password = match args.password.clone() {
            Some(pass) => pass,
            None => crypto::prompt_master_password(Some("Master Password (to decrypt vault keys): "))?,
        };

        // Extract KDF parameters from the login response (under UserDecryptionOptions)
        let decrypt_opts = resp.user_decryption_options.as_ref()
            .ok_or_else(|| "UserDecryptionOptions missing from API Key login response. Ensure your account is fully set up.".to_string())?;

        let unlock_data = decrypt_opts
            .master_password_unlock
            .as_ref()
            .ok_or_else(|| "MasterPasswordUnlock data missing from response.".to_string())?;

        let email = args.email.clone()
            .or_else(|| session.email.clone())
            .unwrap_or_else(|| unlock_data.salt.clone());

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
                crypto::derive_master_key_argon2(&password, salt_email, iterations, mem, para)?
            }
            t => return Err(format!("Unsupported KDF type: {}", t)),
        };

        println!("Decrypting vault symmetric keys...");
        let _sym_keys = crypto::decrypt_symmetric_key(&master_key, &resp.key)?;
        println!("Vault keys decrypted and verified successfully.");

        (resp, master_key, email)
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
            None => crypto::prompt_master_password(None)?,
        };

        println!("Fetching KDF settings for {}...", email);
        let prelogin = api_client.prelogin(&email).await?;

        println!("Deriving master key locally...");
        let master_key = match prelogin.kdf {
            0 => crypto::derive_master_key_pbkdf2(&password, &email, prelogin.kdf_iterations)?,
            1 => {
                let mem = prelogin.kdf_memory.ok_or_else(|| {
                    "Argon2 memory parameter missing from prelogin settings".to_string()
                })?;
                let para = prelogin.kdf_parallelism.ok_or_else(|| {
                    "Argon2 parallelism parameter missing from prelogin settings".to_string()
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
            .login_password(&email, &login_hash, &session.device_id, "bitter_client")
            .await?;

        println!("Decrypting vault symmetric keys...");
        let _sym_keys = crypto::decrypt_symmetric_key(&master_key, &resp.key)?;
        println!("Vault keys decrypted and verified successfully.");

        (resp, master_key, email)
    };

    // Store token and configurations
    config.server_url = server_url.clone();
    config
        .save()
        .map_err(|e| format!("Failed to save configuration: {}", e))?;

    session.access_token = Some(token_resp.access_token.clone());
    session.refresh_token = token_resp.refresh_token.clone();
    session.email = Some(email);
    session.server_url = Some(server_url);
    println!("Logged in successfully. Session token stored locally.");

    // Automatically perform synchronization
    println!("Automatically syncing ciphers from server...");

    match perform_sync_and_reload(
        &api_client,
        &token_resp.access_token,
        KeySource::MasterKey(master_key),
        session,
    )
    .await
    {
        Ok(ciphers) => {
            println!("Synced {} items.", ciphers.len());
        }
        Err(e) => {
            eprintln!("Warning: Automatic sync failed: {}", e);
        }
    }

    Ok(())
}

async fn handle_logout(config: &mut Config) -> Result<(), String> {
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

    println!("Logged out successfully. Configuration and local cache cleared.");
    Ok(())
}

async fn handle_sync(config: &mut Config, session: &mut Session) -> Result<(), String> {
    let token = session.get_valid_token(&config.server_url).await?;

    let api_client = ApiClient::new(&config.server_url);
    println!("Syncing ciphers from server {}...", config.server_url);

    let db_path = storage::db_path().ok_or_else(|| "Could not determine cache database path".to_string())?;
    let repo = storage::VaultRepository::open(&db_path)?;

    let mut cached_keys = None;
    if config.timeout.trim().to_lowercase() == "never" {
        if let Some((enc, mac)) = repo.load_saved_keys()? {
            println!("Using cached decryption keys for passwordless sync...");
            cached_keys = Some((enc, mac));
        }
    }

    let key_source = match cached_keys {
        Some((enc, mac)) => KeySource::DecryptedKeys {
            enc_key: enc,
            mac_key: mac,
        },
        None => {
            let password = crypto::prompt_master_password(Some("Master Password (to decrypt vault keys): "))?;

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

            KeySource::MasterKey(master_key)
        }
    };

    match perform_sync_and_reload(&api_client, &token, key_source, session).await {
        Ok(ciphers) => {
            println!("Synced {} items.", ciphers.len());
        }
        Err(e) => return Err(e),
    }

    Ok(())
}

async fn handle_settings(
    args: crate::cli::SettingsArgs,
    config: &mut Config,
    session: &mut Session,
) -> Result<(), String> {
    let mut updated = false;

    if let Some(t) = args.timeout {
        if t.trim().to_lowercase() == "never" {
            if let Some(ref email) = session.email {
                let token = session
                    .access_token
                    .clone()
                    .ok_or_else(|| "Access token missing from session".to_string())?;

                let password = crypto::prompt_master_password(Some("Enter Master Password to verify and enable 'never' timeout: "))?;

                let path = storage::db_path().ok_or_else(|| "Invalid cache path".to_string())?;
                let mut verified = false;
                let mut verified_locally = false;
                let mut loaded_sync_resp = None;
                let mut decrypted_keys = None;
                let repo = storage::VaultRepository::open(&path)?;

                if path.exists() {
                    if let Ok(sync_resp) = repo.load_sync_response() {
                        if let Ok((_ciphers, enc, mac)) = storage::decrypt_sync_response_offline(&sync_resp, &password) {
                            verified = true;
                            verified_locally = true;
                            loaded_sync_resp = Some(sync_resp);
                            decrypted_keys = Some((enc, mac));
                        }
                    }
                }

                // If not verified locally, verify with server
                if !verified {
                    println!("Verifying master password with server...");
                    let api_client = ApiClient::new(&config.server_url);
                    let prelogin = api_client.prelogin(email).await?;
                    let master_key_res = match prelogin.kdf {
                        0 => crypto::derive_master_key_pbkdf2(
                            &password,
                            email,
                            prelogin.kdf_iterations,
                        ),
                        1 => {
                            if let (Some(mem), Some(para)) =
                                (prelogin.kdf_memory, prelogin.kdf_parallelism)
                            {
                                crypto::derive_master_key_argon2(
                                    &password,
                                    email,
                                    prelogin.kdf_iterations,
                                    mem,
                                    para,
                                )
                            } else {
                                Err("Argon2 parameters missing".to_string())
                            }
                        }
                        t => Err(format!("Unsupported KDF type: {}", t)),
                    };

                    match master_key_res {
                        Ok(master_key) => {
                            let old_timeout = config.timeout.clone();
                            config.timeout = t.clone();
                            match perform_sync_and_reload(
                                &api_client,
                                &token,
                                KeySource::MasterKey(master_key),
                                session,
                             )
                            .await
                            {
                                Ok(_) => {
                                    verified = true;
                                    println!("Timeout updated to: {}", t);
                                }
                                Err(_) => {
                                    config.timeout = old_timeout;
                                }
                            }
                        }
                        Err(_) => {}
                    }
                }

                if !verified {
                    return Err(
                        "Incorrect Master Password. Timeout setting remains unchanged.".to_string(),
                    );
                }

                if verified_locally {
                    // Verified locally. Save config and save decryption keys.
                    config.timeout = t.clone();
                    println!("Timeout updated to: {}", t);
                    config
                        .save()
                        .map_err(|e| format!("Failed to save configuration: {}", e))?;

                    if let (Some(sync_resp), Some((enc, mac))) = (loaded_sync_resp, decrypted_keys) {
                        println!("Saving decryption keys to database...");
                        if let Err(e) = storage::handle_post_sync(&sync_resp, &repo, &enc, &mac) {
                            eprintln!("Warning: Failed to save decryption keys: {}", e);
                        }
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
            if let Some(path) = storage::db_path() {
                if let Ok(repo) = storage::VaultRepository::open(&path) {
                    if let Err(e) = repo.clear_saved_keys() {
                        eprintln!("Warning: Failed to clear saved keys: {}", e);
                    }
                }
            }
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
            _ => {
                return Err(
                    "Invalid value for ssh_agent_auto_start. Use 'true' or 'false'.".to_string(),
                );
            }
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
            if let Err(e) = daemon::send_control_request(daemon::ControlRequest::Reload).await {
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

    Ok(())
}

// Deprecated: This function is a placeholder for future key management features. Refactoration may be needed.
async fn handle_keys(command: KeysCommands, _session: &Session) -> Result<(), String> {
    match command {
        KeysCommands::List => {
            println!("Listing keys... (Will be implemented in Phase 3)");
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
    }
    Ok(())
}

async fn handle_unlock(config: &mut Config, session: &mut Session) -> Result<(), String> {
    let email = session
        .email
        .clone()
        .ok_or_else(|| "Email address missing from session. Please log in first.".to_string())?;
    let token = session
        .access_token
        .clone()
        .ok_or_else(|| "Not logged in. Please run 'bitter login' first.".to_string())?;

    let password = crypto::prompt_master_password(None)?;

    let api_client = ApiClient::new(&config.server_url);

    // Attempt online sync first
    println!("Syncing ciphers and decrypting keys from server...");
    let mut synced_successfully = false;

    match api_client.prelogin(&email).await {
        Ok(prelogin) => {
            let master_key_res = match prelogin.kdf {
                0 => crypto::derive_master_key_pbkdf2(&password, &email, prelogin.kdf_iterations),
                1 => {
                    if let (Some(mem), Some(para)) = (prelogin.kdf_memory, prelogin.kdf_parallelism)
                    {
                        crypto::derive_master_key_argon2(
                            &password,
                            &email,
                            prelogin.kdf_iterations,
                            mem,
                            para,
                        )
                    } else {
                        Err("Argon2 parameters missing from prelogin response".to_string())
                    }
                }
                t => Err(format!("Unsupported KDF type: {}", t)),
            };

            match master_key_res {
                Ok(master_key) => {
                    match perform_sync_and_reload(
                        &api_client,
                        &token,
                        KeySource::MasterKey(master_key),
                        session,
                    )
                    .await
                    {
                        Ok(_) => {
                            synced_successfully = true;
                            println!("Unlock and sync completed successfully.");
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
        let db_path = storage::db_path().ok_or_else(|| "Could not determine cache database path".to_string())?;
        let repo = storage::VaultRepository::open(&db_path)?;
        let sync_resp = repo.load_sync_response()?;
        let (ciphers, enc_key, mac_key) = storage::decrypt_sync_response_offline(&sync_resp, &password)?;
        if config.timeout.trim().to_lowercase() == "never" {
            repo.save_saved_keys(&enc_key, &mac_key)?;
        }
        let cache_keys = storage::extract_ssh_keys_from_ciphers(&ciphers);
        if cache_keys.is_empty() {
            return Err(
                "No keys found in local cache database. Please check your network and try again."
                    .to_string(),
            );
        }
        println!("Warning: Running in offline mode. Live background sync will be unavailable.");

        let enc_hex = hex::encode(enc_key);
        let mac_hex = hex::encode(mac_key);
        let daemon_keys: Vec<daemon::SshKeyData> = cache_keys
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

    Ok(())
}

async fn handle_status(config: &Config, session: &Session) -> Result<(), String> {
    println!("bitter Status:");
    let active_url = session.server_url.as_deref().unwrap_or(&config.server_url);
    println!("  Server URL:     {}", active_url);

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
    println!(
        "  Agent Status:   {}",
        if agent_running {
            "Running"
        } else {
            "Not Running"
        }
    );

    if agent_running {
        match daemon::send_control_request(daemon::ControlRequest::Status).await {
            Ok(resp) => {
                let unlocked = resp.unlocked.unwrap_or(false);
                println!(
                    "  Agent Vault:    {}",
                    if unlocked { "Unlocked" } else { "Locked" }
                );
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

    if let Some(ref sync_time) = session.last_sync_time {
        println!("  Last Synced:    {}", sync_time);
    } else {
        println!("  Last Synced:    Never");
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

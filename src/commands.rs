use crate::api::ApiClient;
use crate::cli::{Commands, KeysCommands, ResetArgs};
use crate::config::{Config, Session, TimeoutAction};
use crate::{crypto, daemon, storage};
use std::io::{self, Write};
use std::str::FromStr;

pub async fn perform_sync(
    api_client: &ApiClient,
    token: &str,
    session: &mut Session,
) -> Result<(), String> {
    // 1. Fetch sync data from server
    let sync_data = api_client
        .sync(token)
        .await
        .map_err(|e| format!("Failed to sync vault from server: {}", e))?;

    // 2. Update session fields and save
    session.user_id = Some(sync_data.profile.id.clone());
    session.email = Some(sync_data.profile.email.clone());
    session.last_sync_time = Some(get_current_time_string());
    let db_path =
        storage::db_path().ok_or_else(|| "Could not determine cache database path".to_string())?;
    let mut repo = storage::VaultRepository::open(&db_path)?;
    repo.save_session(session)
        .map_err(|e| format!("Failed to save session: {}", e))?;

    // 3. Save sync response to database cache
    repo.save_sync_response(&sync_data)
        .map_err(|e| format!("Failed to save cache database: {}", e))?;

    // 4. Send Reload signal to background agent daemon if it is running
    if daemon::is_agent_running() {
        match daemon::send_control_request(daemon::ControlRequest::Reload).await {
            Ok(resp) => {
                if resp.status == "ok" {
                    println!("Agent notified of sync reload.");
                } else {
                    eprintln!(
                        "Warning: Agent failed to reload: {}",
                        resp.error.unwrap_or_default()
                    );
                }
            }
            Err(e) => {
                eprintln!("Warning: Failed to communicate reload to agent: {}", e);
            }
        }
    }

    Ok(())
}

pub async fn run_command(command: Commands, config: &mut Config) -> Result<(), String> {
    match command {
        Commands::Reset(args) => {
            handle_reset(args).await?;
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
        other => {
            let db_path = storage::db_path()
                .ok_or_else(|| "Could not determine cache database path".to_string())?;
            let mut repo = storage::VaultRepository::open(&db_path)?;
            let mut session = repo.load_session()?.unwrap_or_else(|| {
                let mut s = Session::default();
                if let Some(ref d_id) = config.device_id {
                    s.device_id = d_id.clone();
                }
                s
            });

            let is_logout = matches!(other, Commands::Logout);

            match other {
                Commands::Login(args) => handle_login(args, config, &mut session).await?,
                Commands::Logout => handle_logout(config, &mut session, &mut repo).await?,
                Commands::Sync => handle_sync(config, &mut session, &repo).await?,
                Commands::Settings(args) => handle_settings(args, config, &mut session).await?,
                Commands::Keys(args) => handle_keys(args.command, &session).await?,
                Commands::Unlock => handle_unlock(config, &mut session).await?,
                Commands::Status => handle_status(config, &session).await?,
                Commands::Start(_) => {
                    unreachable!("Start command handled synchronously in main()");
                }
                Commands::Reset(_) => unreachable!(),
                _ => {}
            }

            if !is_logout {
                repo.save_session(&session)?;
            }
        }
    }
    Ok(())
}

fn parse_auth_code(input: &str) -> Result<String, String> {
    if input.contains("code=") {
        // It's a full URL or query string, parse it
        let url_parts: Vec<&str> = input.split('?').collect();
        let query = url_parts
            .last()
            .ok_or_else(|| "Invalid URL format".to_string())?;
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

fn derive_and_verify_keys_from_response(
    resp: &crate::api::TokenResponse,
    password_arg: Option<String>,
    email_arg: Option<String>,
    session_email: Option<String>,
    error_context: &str,
) -> Result<([u8; 32], String), String> {
    let decrypt_opts = resp.user_decryption_options.as_ref().ok_or_else(|| {
        format!(
            "UserDecryptionOptions missing from {}. Ensure your account is fully set up.",
            error_context
        )
    })?;

    let unlock_data = decrypt_opts
        .master_password_unlock
        .as_ref()
        .ok_or_else(|| "MasterPasswordUnlock data missing from response.".to_string())?;

    let email = email_arg
        .or(session_email)
        .unwrap_or_else(|| unlock_data.salt.clone());

    let kdf_type = unlock_data.kdf.kdf_type;
    let iterations = unlock_data.kdf.iterations;
    let memory = unlock_data.kdf.memory;
    let parallelism = unlock_data.kdf.parallelism;
    let salt_email = &unlock_data.salt;

    println!("Deriving master key to verify password...");
    let master_key = crypto::prompt_and_derive_master_key(
        password_arg,
        salt_email,
        kdf_type,
        iterations,
        memory,
        parallelism,
        Some("Master Password (to decrypt vault keys): "),
    )?;

    println!("Decrypting vault symmetric keys...");
    let _sym_keys = crypto::decrypt_symmetric_key(&master_key, &resp.key)?;
    println!("Vault keys decrypted and verified successfully.");

    Ok((master_key, email))
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
        let sso_token = api_client
            .fetch_sso_prevalidate_token()
            .await
            .unwrap_or(None);

        let (client_id, redirect_uri) = match sso_token {
            Some(_) => (
                "web",
                format!("{}/sso-connector.html", server_url.trim_end_matches('/')),
            ),
            None => ("cli", "http://localhost:8081/sso-callback".to_string()),
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

        println!(
            "\nPlease open the following URL in a browser on your local device to authenticate:\n"
        );
        println!("{}\n", auth_url);

        // 3. Prompt the user for the redirect URL or auth code
        println!(
            "Once logged in, your browser will redirect to a page starting with '{}'.",
            redirect_uri
        );
        print!("Paste the redirected URL (or the 'code' parameter value): ");
        io::stdout().flush().unwrap();
        let mut callback_input = String::new();
        io::stdin()
            .read_line(&mut callback_input)
            .map_err(|e| format!("Failed to read redirect input: {}", e))?;

        let code = parse_auth_code(callback_input.trim())?;

        // 4. Exchange authorization code for token
        println!("Exchanging authorization code for access token...");
        let resp = api_client
            .exchange_sso_code(
                client_id,
                &code,
                &code_verifier,
                &redirect_uri,
                &session.device_id,
            )
            .await?;

        // 5. Prompt for Master Password, derive keys, and verify
        let (master_key, email) = derive_and_verify_keys_from_response(
            &resp,
            args.password.clone(),
            args.email.clone(),
            session.email.clone(),
            "SSO response",
        )?;

        (resp, master_key, email)
    } else if let (Some(cid), Some(csec)) = (client_id, client_secret) {
        println!("Logging in using Personal API Key client credentials...");

        let resp = api_client
            .login_api_key(&cid, &csec, &session.device_id, "bitter_client")
            .await?;

        // Save credentials in config
        config.client_id = Some(cid.clone());
        config.client_secret = Some(csec.clone());

        // Prompt for Master Password, derive keys, and verify
        let (master_key, email) = derive_and_verify_keys_from_response(
            &resp,
            args.password.clone(),
            args.email.clone(),
            session.email.clone(),
            "API Key response",
        )?;

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
        let master_key = crypto::prompt_and_derive_master_key(
            Some(password.clone()),
            &email,
            prelogin.kdf,
            prelogin.kdf_iterations,
            prelogin.kdf_memory,
            prelogin.kdf_parallelism,
            None,
        )?;

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

    let (enc_key, mac_key) = crypto::decrypt_symmetric_key(&master_key, &token_resp.key)
        .map_err(|e| format!("Failed to decrypt symmetric keys: {}", e))?;

    perform_sync(&api_client, &token_resp.access_token, session).await?;

    // Save keys to SQLite if timeout is unlocked
    if session.timeout.trim().to_lowercase() == "unlocked" {
        let db_path = storage::db_path()
            .ok_or_else(|| "Could not determine cache database path".to_string())?;
        let repo = storage::VaultRepository::open(&db_path)?;
        if let Err(e) = repo.save_saved_keys(&enc_key, &mac_key) {
            eprintln!("Warning: Failed to save decryption keys: {}", e);
        }
    }

    // Send keys to agent if running
    if daemon::is_agent_running() {
        let enc_hex = hex::encode(enc_key);
        let mac_hex = hex::encode(mac_key);
        match daemon::send_control_request(daemon::ControlRequest::Unlock {
            user_id: session.user_id.clone().unwrap_or_default(),
            enc_key: enc_hex,
            mac_key: mac_hex,
        })
        .await
        {
            Ok(resp) => {
                if resp.status == "ok" {
                    println!("Agent unlocked successfully.");
                } else {
                    eprintln!(
                        "Warning: Failed to unlock agent: {}",
                        resp.error.unwrap_or_default()
                    );
                }
            }
            Err(e) => {
                eprintln!("Warning: Failed to communicate with running agent: {}", e);
            }
        }
    }

    Ok(())
}

async fn handle_logout(
    config: &mut Config,
    _session: &mut Session,
    repo: &mut storage::VaultRepository,
) -> Result<(), String> {
    println!("Logging out...");
    if let Err(e) = repo.logout_active_user() {
        eprintln!("Warning: Failed to wipe local database cache: {}", e);
    }
    config.client_id = None;
    config.client_secret = None;
    config
        .save()
        .map_err(|e| format!("Failed to save configuration: {}", e))?;

    if daemon::is_agent_running() {
        println!("Locking and clearing background agent memory...");
        if let Err(e) = daemon::send_control_request(daemon::ControlRequest::Reload).await {
            eprintln!("Warning: Failed to notify agent to lock/clear keys: {}", e);
        }
    }

    println!("Logged out successfully. Configuration and local cache cleared.");
    Ok(())
}

async fn handle_reset(args: ResetArgs) -> Result<(), String> {
    if args.config {
        if let Some(path) = Config::config_path() {
            if path.exists() {
                std::fs::remove_file(&path)
                    .map_err(|e| format!("Failed to remove config file: {}", e))?;
                println!("Configuration file reset successfully.");
            } else {
                println!("Configuration file does not exist.");
            }
        } else {
            return Err("Could not determine config path".to_string());
        }
    }
    if args.db {
        if let Err(e) = storage::nuclear_db() {
            eprintln!("Failed to reset database file: {}", e);
        } else {
            println!("Database file reset successfully.");
        }
    }
    if !args.config && !args.db {
        println!(
            "Nothing to reset. Use --config to reset configuration, and/or --db to reset database."
        );
    }
    Ok(())
}

async fn handle_sync(config: &mut Config, session: &mut Session, repo: &storage::VaultRepository) -> Result<(), String> {
    let token = repo.get_valid_token().await?;

    // Reload the updated session from database
    if let Some(updated) = repo.load_session()? {
        *session = updated;
    }

    let api_client = ApiClient::new(&config.server_url);
    println!("Syncing ciphers from server {}...", config.server_url);

    perform_sync(&api_client, &token, session).await?;
    println!("Sync completed successfully.");

    Ok(())
}

async fn handle_settings(
    args: crate::cli::SettingsArgs,
    config: &mut Config,
    session: &mut Session,
) -> Result<(), String> {
    let mut updated = false;

    if let Some(t) = args.timeout {
        if t.trim().to_lowercase() == "unlocked" {
            if let Some(ref email) = session.email {
                let password = crypto::prompt_master_password(Some(
                    "Enter Master Password to verify and enable 'unlocked' mode: ",
                ))?;

                let path = storage::db_path().ok_or_else(|| "Invalid cache path".to_string())?;
                let mut verified = false;
                let mut enc_key_opt = None;
                let mut mac_key_opt = None;
                let repo = storage::VaultRepository::open(&path)?;

                if path.exists() {
                    if let Ok(sync_resp) = repo.load_sync_response() {
                        if let Ok((_ciphers, enc, mac)) =
                            storage::decrypt_sync_response_offline(&sync_resp, &password)
                        {
                            verified = true;
                            enc_key_opt = Some(enc);
                            mac_key_opt = Some(mac);
                        }
                    }
                }

                // If not verified locally, verify with server using KDF settings
                if !verified {
                    println!("Verifying master password with server...");
                    let api_client = ApiClient::new(&config.server_url);
                    let prelogin = api_client.prelogin(email).await?;
                    let master_key_res = crypto::prompt_and_derive_master_key(
                        Some(password.clone()),
                        email,
                        prelogin.kdf,
                        prelogin.kdf_iterations,
                        prelogin.kdf_memory,
                        prelogin.kdf_parallelism,
                        None,
                    );

                    if let Ok(master_key) = master_key_res {
                        if let Ok(sync_resp) = repo.load_sync_response() {
                            if let Ok((enc, mac)) =
                                crypto::decrypt_symmetric_key(&master_key, &sync_resp.profile.key)
                            {
                                verified = true;
                                enc_key_opt = Some(enc);
                                mac_key_opt = Some(mac);
                            }
                        }
                    }
                }

                if !verified {
                    return Err(
                        "Incorrect Master Password. Timeout setting remains unchanged.".to_string(),
                    );
                }

                // Save config and save decryption keys
                session.timeout = t.clone();
                println!("Timeout updated to: {}", t);
                updated = true;

                if let (Some(enc), Some(mac)) = (enc_key_opt, mac_key_opt) {
                    println!("Saving decryption keys to database...");
                    if let Err(e) = repo.save_saved_keys(&enc, &mac) {
                        eprintln!("Warning: Failed to save decryption keys: {}", e);
                    }

                    // Send keys to daemon if running
                    if daemon::is_agent_running() {
                        let _ = daemon::send_control_request(daemon::ControlRequest::Unlock {
                            user_id: session.user_id.clone().unwrap_or_default(),
                            enc_key: hex::encode(enc),
                            mac_key: hex::encode(mac),
                        })
                        .await;
                    }
                }
            } else {
                // Not logged in, allow setting timeout to "unlocked" (keys will be saved on next login)
                session.timeout = t.clone();
                println!("Timeout updated to: {}", t);
                updated = true;
            }
        } else {
            session.timeout = t.clone();
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
        session.timeout_action = action;
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
        println!("  Session Timeout: {}", session.timeout);
        println!("  Timeout Action:  {:?}", session.timeout_action);
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

    let password = crypto::prompt_master_password(None)?;

    let db_path =
        storage::db_path().ok_or_else(|| "Could not determine cache database path".to_string())?;
    let repo = storage::VaultRepository::open(&db_path)?;

    // Attempt online sync of KDF settings first
    let api_client = ApiClient::new(&config.server_url);
    let mut derived_key = None;

    println!("Deriving master key...");
    match api_client.prelogin(&email).await {
        Ok(prelogin) => {
            if let Ok(master_key) = crypto::prompt_and_derive_master_key(
                Some(password.clone()),
                &email,
                prelogin.kdf,
                prelogin.kdf_iterations,
                prelogin.kdf_memory,
                prelogin.kdf_parallelism,
                None,
            ) {
                derived_key = Some(master_key);
            }
        }
        Err(e) => {
            eprintln!(
                "Warning: Failed to fetch online KDF settings: {}. Falling back to offline derivation.",
                e
            );
        }
    }

    let (enc_key, mac_key) = match derived_key {
        Some(master_key) => {
            // Decrypt symmetric keys from the local database
            let sync_resp = repo.load_sync_response()?;
            crypto::decrypt_symmetric_key(&master_key, &sync_resp.profile.key)
                .map_err(|e| format!("Failed to decrypt symmetric keys: {}", e))?
        }
        None => {
            // Fallback: use offline KDF settings from SQLite sync response
            let sync_resp = repo.load_sync_response()?;
            let (_ciphers, enc, mac) =
                storage::decrypt_sync_response_offline(&sync_resp, &password)?;
            (enc, mac)
        }
    };

    // If timeout is "unlocked", save keys to SQLite
    if session.timeout.trim().to_lowercase() == "unlocked" {
        repo.save_saved_keys(&enc_key, &mac_key)?;
    }

    // Send keys to daemon if running
    if daemon::is_agent_running() {
        println!("Sending decryption keys to background agent daemon...");
        let enc_hex = hex::encode(enc_key);
        let mac_hex = hex::encode(mac_key);
        let resp = daemon::send_control_request(daemon::ControlRequest::Unlock {
            user_id: session.user_id.clone().unwrap_or_default(),
            enc_key: enc_hex,
            mac_key: mac_hex,
        })
        .await?;

        if resp.status == "ok" {
            println!("Agent unlocked successfully.");
        } else {
            return Err(format!(
                "Failed to unlock agent: {}",
                resp.error.unwrap_or_default()
            ));
        }
    } else {
        println!(
            "Keys derived successfully. (Agent daemon is not running, so keys were not sent.)"
        );
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
        "  Daemon Status:   {}",
        if agent_running {
            "Running"
        } else {
            "Not Running"
        }
    );

    if agent_running {
        match daemon::send_control_request(daemon::ControlRequest::Status {
            user_id: session.user_id.clone(),
        }).await {
            Ok(resp) => {
                let unlocked = resp.unlocked.unwrap_or(false);
                println!(
                    "  Daemon Vault:    {}",
                    if unlocked { "Unlocked" } else { "Locked" }
                );
                println!("  Keys in vault: {}", resp.key_count.unwrap_or(0));
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

    println!("  Timeout Setting: {}", session.timeout);
    println!("  Timeout Action:  {:?}", session.timeout_action);
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

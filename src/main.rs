mod agent;
mod api;
mod cli;
mod config;
mod crypto;
mod daemon;
mod storage;

use api::ApiClient;
use clap::Parser;
use cli::{AgentCommands, Cli, Commands, KeysCommands};
use config::{Config, TimeoutAction};
use std::io::{self, Write};
use std::str::FromStr;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let mut config = match Config::load() {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Error loading config: {}", e);
            std::process::exit(1);
        }
    };

    // Route commands
    if let Err(e) = run_command(cli.command, &mut config).await {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

async fn run_command(command: Commands, config: &mut Config) -> Result<(), String> {
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

            let token_resp = if let (Some(cid), Some(csec)) = (client_id, client_secret) {
                println!("Logging in using Personal API Key client credentials...");

                let resp = api_client
                    .login_api_key(&cid, &csec, &config.device_id, "sshwarden_client")
                    .await?;

                // Save credentials in config
                config.client_id = Some(cid.clone());
                config.client_secret = Some(csec.clone());

                // Prompt for master password to verify we can derive the Master Key and decrypt the symmetric key
                let password = match args.password {
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
                let _sym_keys = crypto::decrypt_symmetric_key(&master_key, &resp.key)?;
                println!("Vault keys decrypted and verified successfully.");

                resp
            } else {
                // Password Login
                let email = match args.email.or_else(|| config.email.clone()) {
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
                    .login_password(&email, &login_hash, &config.device_id, "sshwarden_client")
                    .await?;

                println!("Decrypting vault symmetric keys...");
                let _sym_keys = crypto::decrypt_symmetric_key(&master_key, &resp.key)?;
                println!("Vault keys decrypted and verified successfully.");

                config.email = Some(email);
                resp
            };

            // Store token and configurations
            config.server_url = server_url;
            config.access_token = Some(token_resp.access_token);
            config
                .save()
                .map_err(|e| format!("Failed to save configuration: {}", e))?;

            println!("Logged in successfully. Session token stored locally.");
        }
        Commands::Logout => {
            println!("Logging out...");
            if let Err(e) = storage::wipe_db() {
                eprintln!("Warning: Failed to delete local database cache: {}", e);
            }
            config.email = None;
            config.client_id = None;
            config.client_secret = None;
            config.access_token = None;
            config
                .save()
                .map_err(|e| format!("Failed to save configuration: {}", e))?;
            println!("Logged out successfully. Configuration, session, and local cache cleared.");
        }
        Commands::Sync => {
            let token = config
                .access_token
                .as_ref()
                .ok_or_else(|| "Not logged in. Please run 'sshwarden login' first.".to_string())?;

            let api_client = ApiClient::new(&config.server_url);
            println!("Syncing ciphers from server {}...", config.server_url);

            let password = rpassword::prompt_password("Master Password (to decrypt vault keys): ")
                .map_err(|e| format!("Password prompt failed: {}", e))?;

            let email = config.email.as_ref().ok_or_else(|| {
                "Email address missing from config. Please log in again.".to_string()
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

            let salt = config
                .cache_salt
                .as_ref()
                .ok_or_else(|| "Local database salt missing from config.".to_string())?;
            let db_key = storage::derive_db_key(&password, salt)?;

            let sync_data = api_client.sync(token).await?;

            let (enc_key, mac_key) =
                crypto::decrypt_symmetric_key(&master_key, &sync_data.profile.key)?;

            println!("Decrypting and filtering SSH keys...");
            let ssh_keys = storage::parse_and_extract_ssh_keys(&sync_data, &enc_key, &mac_key);

            println!("Saving encrypted cache to disk...");
            storage::save_db(&ssh_keys, &db_key)?;

            println!(
                "Sync completed successfully. Synced {} SSH keys.",
                ssh_keys.len()
            );
        }
        Commands::Settings(args) => {
            let mut updated = false;

            if let Some(t) = args.timeout {
                config.timeout = t.clone();
                println!("Timeout updated to: {}", t);
                updated = true;
            }

            if let Some(act_str) = args.timeout_action {
                let action = TimeoutAction::from_str(&act_str)?;
                config.timeout_action = action;
                println!("Timeout action updated to: {:?}", action);
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
                    config.email.as_deref().unwrap_or("<not logged in>")
                );
                println!("  Session Timeout: {}", config.timeout);
                println!("  Timeout Action:  {:?}", config.timeout_action);
            }
        }
        Commands::Keys(args) => match args.command {
            KeysCommands::List => {
                let password = rpassword::prompt_password("Master Password: ")
                    .map_err(|e| format!("Password prompt failed: {}", e))?;

                let salt = config
                    .cache_salt
                    .as_ref()
                    .ok_or_else(|| "Local database salt missing from config.".to_string())?;
                let db_key = storage::derive_db_key(&password, salt)?;

                let keys = storage::load_db(&db_key)?;
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
        Commands::Agent(args) => match args.command {
            AgentCommands::Start(start_args) => {
                daemon::start_agent(start_args.foreground, start_args.socket)?;
            }
            AgentCommands::Stop => {
                daemon::stop_agent()?;
            }
            AgentCommands::Status => {
                daemon::print_status()?;
            }
        },
        Commands::Unlock => {
            let email = config.email.as_ref().ok_or_else(|| {
                "Email address missing from config. Please log in first.".to_string()
            })?;
            let token = config
                .access_token
                .as_ref()
                .ok_or_else(|| "Not logged in. Please run 'sshwarden login' first.".to_string())?;

            let password = rpassword::prompt_password("Master Password: ")
                .map_err(|e| format!("Password prompt failed: {}", e))?;

            let salt = config
                .cache_salt
                .as_ref()
                .ok_or_else(|| "Local database salt missing from config.".to_string())?;
            let db_key = storage::derive_db_key(&password, salt)?;

            println!("Decrypting local cache database...");
            let cache_keys = storage::load_db(&db_key)?;
            if cache_keys.is_empty() {
                return Err(
                    "No keys found in local cache database. Run 'sshwarden sync' first."
                        .to_string(),
                );
            }

            let api_client = ApiClient::new(&config.server_url);

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

            // Retrieve symmetric key from sync response
            println!("Fetching active profile keys from server...");
            let sync_data = api_client.sync(token).await?;
            let (enc_key, mac_key) =
                crypto::decrypt_symmetric_key(&master_key, &sync_data.profile.key)?;

            let enc_hex = hex::encode(enc_key);
            let mac_hex = hex::encode(mac_key);
            let db_hex = hex::encode(db_key);

            println!("Sending keys and context to background agent daemon...");
            let daemon_keys: Vec<daemon::SshKeyData> = cache_keys
                .into_iter()
                .map(|k| daemon::SshKeyData {
                    name: k.name,
                    private_key: k.private_key,
                })
                .collect();

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
    }
    Ok(())
}

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use directories::ProjectDirs;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use crate::api::{CipherSync, SyncResponse};
use crate::crypto;

const APP_NAME: &str = "sshwarden";
const DB_FILE_NAME: &str = "vault.db.enc";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKeyItem {
    pub id: String,          // Bitwarden cipher ID
    pub name: String,        // Decrypted name
    pub private_key: String, // Decrypted private key (PEM/OpenSSH format)
    pub public_key: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptedField {
    pub name: String,
    pub value: Option<String>,
    pub r#type: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptedLogin {
    pub username: Option<String>,
    pub password: Option<String>,
    pub uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptedSshKey {
    pub private_key: Option<String>,
    pub public_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherItem {
    pub id: String,
    pub r#type: i32,
    pub name: String,
    pub notes: Option<String>,
    pub login: Option<DecryptedLogin>,
    pub fields: Option<Vec<DecryptedField>>,
    pub ssh_key: Option<DecryptedSshKey>,
}

/// Gets the standard cache directory for sshwarden
pub fn cache_dir() -> Option<PathBuf> {
    ProjectDirs::from("com", "", APP_NAME).map(|proj| proj.cache_dir().to_path_buf())
}

/// Gets the path to the vault.db.enc file
pub fn db_path() -> Option<PathBuf> {
    cache_dir().map(|dir| dir.join(DB_FILE_NAME))
}

const RAW_DB_FILE_NAME: &str = "vault.db.raw";

/// Gets the path to the vault.db.raw file (unencrypted cache)
pub fn unencrypted_db_path() -> Option<PathBuf> {
    cache_dir().map(|dir| dir.join(RAW_DB_FILE_NAME))
}

const KEYS_FILE_NAME: &str = "vault.db.keys";

/// Gets the path to the vault.db.keys file (cached keys)
pub fn keys_path() -> Option<PathBuf> {
    cache_dir().map(|dir| dir.join(KEYS_FILE_NAME))
}

/// Derive the local cache encryption key from master password and local salt
pub fn derive_db_key(password: &str, salt_b64: &str) -> Result<[u8; 32], String> {
    let salt = BASE64_STANDARD
        .decode(salt_b64)
        .map_err(|e| format!("Invalid base64 salt: {}", e))?;

    let params = argon2::Params::new(
        65536,    // 64 MB
        3,        // 3 iterations
        4,        // 4 parallelism/lanes
        Some(32), // 32-byte key
    )
    .map_err(|e| format!("Argon2 params creation failed: {}", e))?;

    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut db_key = [0u8; 32];

    argon2
        .hash_password_into(password.as_bytes(), &salt, &mut db_key)
        .map_err(|e| format!("Argon2 database key derivation failed: {}", e))?;

    Ok(db_key)
}

/// Load and decrypt the local cache database from disk
pub fn load_db(db_key: &[u8; 32]) -> Result<Vec<CipherItem>, String> {
    let path = db_path().ok_or_else(|| "Could not determine cache database path".to_string())?;

    if !path.exists() {
        return Ok(Vec::new());
    }

    let mut file =
        File::open(&path).map_err(|e| format!("Failed to open cache database: {}", e))?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)
        .map_err(|e| format!("Failed to read cache database: {}", e))?;

    if data.len() < 12 {
        return Err("Cache database file is corrupted (too short)".to_string());
    }

    // Split nonce and ciphertext
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::try_from(nonce_bytes).map_err(|e| format!("Invalid nonce: {}", e))?;

    let cipher = Aes256Gcm::new_from_slice(db_key)
        .map_err(|e| format!("Failed to initialize AES-GCM: {}", e))?;

    let plaintext = cipher.decrypt(&nonce, ciphertext).map_err(|_| {
        "Failed to decrypt local database cache. Did your master password change?".to_string()
    })?;

    let items: Vec<CipherItem> = serde_json::from_slice(&plaintext)
        .map_err(|e| format!("Failed to parse decrypted database JSON: {}", e))?;

    Ok(items)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedKeys {
    pub enc_key: String,
    pub mac_key: String,
    pub db_key: String,
}

/// Save derived keys to keys cache on disk if timeout is "never"
pub fn save_keys(enc: &[u8; 32], mac: &[u8; 32], db: &[u8; 32]) -> Result<(), String> {
    if let Some(path) = keys_path() {
        let saved = SavedKeys {
            enc_key: hex::encode(enc),
            mac_key: hex::encode(mac),
            db_key: hex::encode(db),
        };
        let content = serde_json::to_string_pretty(&saved)
            .map_err(|e| format!("Failed to serialize keys: {}", e))?;
        fs::write(&path, content)
            .map_err(|e| format!("Failed to write keys file: {}", e))?;
        
        let file = File::open(&path)
            .map_err(|e| format!("Failed to open keys file to set permissions: {}", e))?;
        let mut perms = file.metadata().map_err(|e| e.to_string())?.permissions();
        perms.set_mode(0o600);
        file.set_permissions(perms)
            .map_err(|e| format!("Failed to set permissions on keys file: {}", e))?;
    }
    Ok(())
}

/// Load saved keys from disk
pub fn load_saved_keys() -> Option<([u8; 32], [u8; 32], [u8; 32])> {
    let path = keys_path()?;
    if !path.exists() {
        return None;
    }
    let content = fs::read_to_string(&path).ok()?;
    let saved: SavedKeys = serde_json::from_str(&content).ok()?;
    
    let enc_vec = hex::decode(&saved.enc_key).ok()?;
    let mac_vec = hex::decode(&saved.mac_key).ok()?;
    let db_vec = hex::decode(&saved.db_key).ok()?;
    
    if enc_vec.len() == 32 && mac_vec.len() == 32 && db_vec.len() == 32 {
        let mut enc = [0u8; 32];
        let mut mac = [0u8; 32];
        let mut db = [0u8; 32];
        enc.copy_from_slice(&enc_vec);
        mac.copy_from_slice(&mac_vec);
        db.copy_from_slice(&db_vec);
        Some((enc, mac, db))
    } else {
        None
    }
}

/// Encrypt and save the local cache database to disk with 0600 permissions
pub fn save_db(
    items: &[CipherItem],
    db_key: &[u8; 32],
    enc_key: Option<&[u8; 32]>,
    mac_key: Option<&[u8; 32]>,
) -> Result<(), String> {
    let path = db_path().ok_or_else(|| "Could not determine cache database path".to_string())?;

    // Ensure parent cache directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create cache directory: {}", e))?;
    }

    let plaintext = serde_json::to_vec(items)
        .map_err(|e| format!("Failed to serialize database to JSON: {}", e))?;

    // Generate random 12-byte nonce
    let mut nonce_bytes = [0u8; 12];
    let sr = SystemRandom::new();
    sr.fill(&mut nonce_bytes)
        .map_err(|e| format!("Failed to generate random database nonce: {}", e))?;
    let nonce = Nonce::from(nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(db_key)
        .map_err(|e| format!("Failed to initialize AES-GCM: {}", e))?;

    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_slice())
        .map_err(|e| format!("AES-GCM encryption failed: {}", e))?;

    // Concatenate nonce + ciphertext
    let mut output = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    fs::write(&path, &output).map_err(|e| format!("Failed to write cache database: {}", e))?;

    // Set owner read/write only permissions (0600)
    let file = File::open(&path)
        .map_err(|e| format!("Failed to open database file to set permissions: {}", e))?;
    let mut perms = file.metadata().map_err(|e| e.to_string())?.permissions();
    perms.set_mode(0o600);
    file.set_permissions(perms)
        .map_err(|e| format!("Failed to set permissions on cache database: {}", e))?;

    // Save unencrypted backup if timeout is "never", otherwise remove it
    if let Ok(config) = crate::config::Config::load() {
        if config.timeout.trim().to_lowercase() == "never" {
            if let Some(raw_path) = unencrypted_db_path() {
                let pretty_json = serde_json::to_vec_pretty(items)
                    .map_err(|e| format!("Failed to serialize unencrypted database: {}", e))?;
                fs::write(&raw_path, &pretty_json)
                    .map_err(|e| format!("Failed to write unencrypted cache: {}", e))?;
                
                let file = File::open(&raw_path)
                    .map_err(|e| format!("Failed to open unencrypted cache file to set permissions: {}", e))?;
                let mut perms = file.metadata().map_err(|e| e.to_string())?.permissions();
                perms.set_mode(0o600);
                file.set_permissions(perms)
                    .map_err(|e| format!("Failed to set permissions on unencrypted cache: {}", e))?;
            }

            // Save encryption keys if provided
            if let (Some(enc), Some(mac)) = (enc_key, mac_key) {
                let _ = save_keys(enc, mac, db_key);
            }
        } else {
            if let Some(raw_path) = unencrypted_db_path() {
                if raw_path.exists() {
                    let _ = fs::remove_file(raw_path);
                }
            }
            if let Some(k_path) = keys_path() {
                if k_path.exists() {
                    let _ = fs::remove_file(k_path);
                }
            }
        }
    }

    Ok(())
}

/// Delete the local cache database from disk (used on logout)
pub fn wipe_db() -> Result<(), String> {
    let path = db_path().ok_or_else(|| "Could not determine cache database path".to_string())?;
    if path.exists() {
        fs::remove_file(&path)
            .map_err(|e| format!("Failed to delete cache database file: {}", e))?;
    }
    if let Some(raw_path) = unencrypted_db_path() {
        if raw_path.exists() {
            fs::remove_file(&raw_path)
                .map_err(|e| format!("Failed to delete unencrypted cache database file: {}", e))?;
        }
    }
    if let Some(k_path) = keys_path() {
        if k_path.exists() {
            fs::remove_file(&k_path)
                .map_err(|e| format!("Failed to delete keys cache file: {}", e))?;
        }
    }
    Ok(())
}

/// Delete only the unencrypted raw cache database and cached key files (used when timeout changes from "never")
pub fn wipe_unencrypted_cache() -> Result<(), String> {
    if let Some(raw_path) = unencrypted_db_path() {
        if raw_path.exists() {
            fs::remove_file(&raw_path)
                .map_err(|e| format!("Failed to delete unencrypted cache database file: {}", e))?;
        }
    }
    if let Some(k_path) = keys_path() {
        if k_path.exists() {
            fs::remove_file(&k_path)
                .map_err(|e| format!("Failed to delete keys cache file: {}", e))?;
        }
    }
    Ok(())
}

/// Load unencrypted SSH keys from raw cache database if timeout is "never"
pub fn load_unencrypted_db() -> Option<Vec<ssh_key::private::PrivateKey>> {
    let raw_path = unencrypted_db_path()?;
    if !raw_path.exists() {
        return None;
    }

    let mut file = File::open(&raw_path).ok()?;
    let mut data = Vec::new();
    file.read_to_end(&mut data).ok()?;

    let items: Vec<CipherItem> = serde_json::from_slice(&data).ok()?;
    let ssh_items = extract_ssh_keys_from_ciphers(&items);

    let mut parsed_keys = Vec::new();
    for item in ssh_items {
        if let Ok(mut pkey) = ssh_key::private::PrivateKey::from_openssh(&item.private_key) {
            pkey.set_comment(&item.name);
            parsed_keys.push(pkey);
        }
    }
    Some(parsed_keys)
}

/// Extracts SSH keys from generic decrypted ciphers list
pub fn extract_ssh_keys_from_ciphers(ciphers: &[CipherItem]) -> Vec<SshKeyItem> {
    let mut ssh_keys = Vec::new();
    let is_ssh_private_key = |text: &str| -> bool { text.contains("-----BEGIN") && text.contains("PRIVATE KEY-----") };

    for cipher in ciphers {
        // Scenario 1: Native SSH Key Item (type 100)
        if let Some(ref ssh_key) = cipher.ssh_key {
            if let Some(ref priv_key) = ssh_key.private_key {
                if is_ssh_private_key(priv_key) {
                    ssh_keys.push(SshKeyItem {
                        id: cipher.id.clone(),
                        name: cipher.name.clone(),
                        private_key: priv_key.clone(),
                        public_key: ssh_key.public_key.clone(),
                        note: cipher.notes.clone(),
                    });
                    continue;
                }
            }
        }

        // Scenario 2: Custom fields (e.g. login or note items containing custom fields for SSH keys)
        if let Some(ref fields) = cipher.fields {
            for field in fields {
                let field_name = field.name.to_lowercase();
                if field_name == "ssh_private_key"
                    || field_name == "ssh-private-key"
                    || field_name.contains("ssh_key")
                {
                    if let Some(ref val) = field.value {
                        if is_ssh_private_key(val) {
                            ssh_keys.push(SshKeyItem {
                                id: cipher.id.clone(),
                                name: format!("{} ({})", cipher.name, field.name),
                                private_key: val.clone(),
                                public_key: None,
                                note: cipher.notes.clone(),
                            });
                            continue;
                        }
                    }
                }
            }
        }

        // Scenario 3: Secure Note containing OpenSSH / PEM private key in notes body
        if cipher.r#type == 2 {
            if let Some(ref notes) = cipher.notes {
                if is_ssh_private_key(notes) {
                    ssh_keys.push(SshKeyItem {
                        id: cipher.id.clone(),
                        name: cipher.name.clone(),
                        private_key: notes.clone(),
                        public_key: None,
                        note: Some("Extracted from secure note text body".to_string()),
                    });
                }
            }
        }
    }
    ssh_keys
}

/// Parses the full sync response and decrypts all ciphers without filtering out non-SSH keys.
pub fn parse_and_decrypt_all_ciphers(
    sync_response: &SyncResponse,
    enc_key: &[u8; 32],
    mac_key: &[u8; 32],
) -> Vec<CipherItem> {
    let mut ciphers = Vec::new();

    for cipher in &sync_response.ciphers {
        if let Err(e) = decrypt_single_cipher(cipher, enc_key, mac_key, &mut ciphers) {
            eprintln!(
                "Warning: Skipping cipher ID {} due to error: {}",
                cipher.id, e
            );
        }
    }

    ciphers
}

fn decrypt_single_cipher(
    cipher: &CipherSync,
    user_enc_key: &[u8; 32],
    user_mac_key: &[u8; 32],
    ciphers: &mut Vec<CipherItem>,
) -> Result<(), String> {
    if cipher.deleted_date.is_some() {
        return Ok(());
    }

    let (ck_enc, ck_mac) = if let Some(ref cipher_key_str) = cipher.key {
        let decrypted = crypto::decrypt_cipher_string(cipher_key_str, user_enc_key, user_mac_key)?;
        if decrypted.len() != 64 {
            return Err(format!(
                "Decrypted cipher key has invalid length: {} (expected 64)",
                decrypted.len()
            ));
        }
        let mut ck_enc = [0u8; 32];
        let mut ck_mac = [0u8; 32];
        ck_enc.copy_from_slice(&decrypted[0..32]);
        ck_mac.copy_from_slice(&decrypted[32..64]);
        (ck_enc, ck_mac)
    } else {
        (*user_enc_key, *user_mac_key)
    };

    let enc_key = &ck_enc;
    let mac_key = &ck_mac;

    // Decrypt cipher name
    let plain_name = match &cipher.name {
        Some(enc_name) => {
            let name_bytes = crypto::decrypt_cipher_string(enc_name, enc_key, mac_key)?;
            String::from_utf8(name_bytes)
                .map_err(|e| format!("Decrypted name is not valid UTF-8: {}", e))?
        }
        None => "Unnamed Vault Item".to_string(),
    };

    // Decrypt notes if present
    let plain_notes = match &cipher.notes {
        Some(enc_notes) => {
            let note_bytes = crypto::decrypt_cipher_string(enc_notes, enc_key, mac_key)?;
            let text = String::from_utf8(note_bytes)
                .map_err(|e| format!("Decrypted notes not valid UTF-8: {}", e))?;
            Some(text)
        }
        None => None,
    };

    // Decrypt fields
    let decrypted_fields = if let Some(ref fields) = cipher.fields {
        let mut dfs = Vec::new();
        for field in fields {
            let field_name_bytes = crypto::decrypt_cipher_string(&field.name, enc_key, mac_key)?;
            let field_name = String::from_utf8(field_name_bytes)
                .map_err(|e| format!("Decrypted field name is not valid UTF-8: {}", e))?;

            let field_value = if let Some(ref enc_val) = field.value {
                let val_bytes = crypto::decrypt_cipher_string(enc_val, enc_key, mac_key)?;
                Some(String::from_utf8(val_bytes)
                    .map_err(|e| format!("Decrypted field value is not valid UTF-8: {}", e))?)
            } else {
                None
            };
            dfs.push(DecryptedField {
                name: field_name,
                value: field_value,
                r#type: field.r#type,
            });
        }
        Some(dfs)
    } else {
        None
    };

    // Decrypt login
    let decrypted_login = if let Some(ref login) = cipher.login {
        let username = if let Some(ref enc_user) = login.username {
            let user_bytes = crypto::decrypt_cipher_string(enc_user, enc_key, mac_key)?;
            Some(String::from_utf8(user_bytes)
                .map_err(|e| format!("Decrypted username is not valid UTF-8: {}", e))?)
        } else {
            None
        };
        let password = if let Some(ref enc_pass) = login.password {
            let pass_bytes = crypto::decrypt_cipher_string(enc_pass, enc_key, mac_key)?;
            Some(String::from_utf8(pass_bytes)
                .map_err(|e| format!("Decrypted password is not valid UTF-8: {}", e))?)
        } else {
            None
        };
        Some(DecryptedLogin {
            username,
            password,
            uri: login.uri.clone(),
        })
    } else {
        None
    };

    // Decrypt ssh key
    let decrypted_ssh_key = if let Some(ref ssh_key) = cipher.ssh_key {
        let private_key = if let Some(ref enc_priv) = ssh_key.private_key {
            let priv_bytes = crypto::decrypt_cipher_string(enc_priv, enc_key, mac_key)?;
            Some(String::from_utf8(priv_bytes)
                .map_err(|e| format!("Decrypted private key is not valid UTF-8: {}", e))?)
        } else {
            None
        };
        let public_key = if let Some(ref enc_pub) = ssh_key.public_key {
            let pub_bytes = crypto::decrypt_cipher_string(enc_pub, enc_key, mac_key)?;
            Some(String::from_utf8(pub_bytes)
                .map_err(|e| format!("Decrypted public key is not valid UTF-8: {}", e))?)
        } else {
            None
        };
        Some(DecryptedSshKey {
            private_key,
            public_key,
        })
    } else {
        None
    };

    ciphers.push(CipherItem {
        id: cipher.id.clone(),
        r#type: cipher.r#type,
        name: plain_name,
        notes: plain_notes,
        login: decrypted_login,
        fields: decrypted_fields,
        ssh_key: decrypted_ssh_key,
    });

    Ok(())
}

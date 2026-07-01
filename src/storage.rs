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

/// Gets the standard cache directory for sshwarden
pub fn cache_dir() -> Option<PathBuf> {
    ProjectDirs::from("com", "", APP_NAME).map(|proj| proj.cache_dir().to_path_buf())
}

/// Gets the path to the vault.db.enc file
pub fn db_path() -> Option<PathBuf> {
    cache_dir().map(|dir| dir.join(DB_FILE_NAME))
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
pub fn load_db(db_key: &[u8; 32]) -> Result<Vec<SshKeyItem>, String> {
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

    let items: Vec<SshKeyItem> = serde_json::from_slice(&plaintext)
        .map_err(|e| format!("Failed to parse decrypted database JSON: {}", e))?;

    Ok(items)
}

/// Encrypt and save the local cache database to disk with 0600 permissions
pub fn save_db(items: &[SshKeyItem], db_key: &[u8; 32]) -> Result<(), String> {
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

    Ok(())
}

/// Delete the local cache database from disk (used on logout)
pub fn wipe_db() -> Result<(), String> {
    let path = db_path().ok_or_else(|| "Could not determine cache database path".to_string())?;
    if path.exists() {
        fs::remove_file(&path)
            .map_err(|e| format!("Failed to delete cache database file: {}", e))?;
    }
    Ok(())
}

/// Parses the full sync response, decrypts ciphers, filters out non-SSH keys, and returns a list of SSH keys.
pub fn parse_and_extract_ssh_keys(
    sync_response: &SyncResponse,
    enc_key: &[u8; 32],
    mac_key: &[u8; 32],
) -> Vec<SshKeyItem> {
    let mut ssh_keys = Vec::new();

    for cipher in &sync_response.ciphers {
        if let Err(e) = process_cipher(cipher, enc_key, mac_key, &mut ssh_keys) {
            // Log decryption errors or parse errors, but continue processing other ciphers
            eprintln!(
                "Warning: Skipping cipher ID {} due to error: {}",
                cipher.id, e
            );
        }
    }

    ssh_keys
}

fn process_cipher(
    cipher: &CipherSync,
    enc_key: &[u8; 32],
    mac_key: &[u8; 32],
    ssh_keys: &mut Vec<SshKeyItem>,
) -> Result<(), String> {
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

    // Helper to check if a decrypted string looks like an SSH private key
    let is_ssh_private_key =
        |text: &str| -> bool { text.contains("-----BEGIN") && text.contains("PRIVATE KEY-----") };

    // Scenario 1: Native SSH Key Item (has ssh_key and private_key populated)
    if let Some(enc_priv_key) = cipher.ssh_key.as_ref().and_then(|k| k.private_key.as_ref()) {
        let priv_key_bytes = crypto::decrypt_cipher_string(enc_priv_key, enc_key, mac_key)?;
        let plain_priv_key = String::from_utf8(priv_key_bytes)
            .map_err(|e| format!("Decrypted private key not valid UTF-8: {}", e))?;

        if is_ssh_private_key(&plain_priv_key) {
            let plain_pub_key = match cipher.ssh_key.as_ref().and_then(|k| k.public_key.as_ref()) {
                Some(enc_pub_key) => {
                    let pub_key_bytes =
                        crypto::decrypt_cipher_string(enc_pub_key, enc_key, mac_key)?;
                    String::from_utf8(pub_key_bytes).ok()
                }
                None => None,
            };

            ssh_keys.push(SshKeyItem {
                id: cipher.id.clone(),
                name: plain_name,
                private_key: plain_priv_key,
                public_key: plain_pub_key,
                note: plain_notes,
            });
            return Ok(());
        }
    }

    // Scenario 2: Custom fields (e.g. login or note items containing custom fields for SSH keys)
    if let Some(ref fields) = cipher.fields {
        for field in fields {
            // Decrypt field name
            let field_name_bytes = crypto::decrypt_cipher_string(&field.name, enc_key, mac_key)?;
            let field_name = String::from_utf8(field_name_bytes)
                .unwrap_or_default()
                .to_lowercase();

            let enc_field_val = field.value.as_ref().filter(|_| {
                field_name == "ssh_private_key"
                    || field_name == "ssh-private-key"
                    || field_name.contains("ssh_key")
            });

            if let Some(enc_val) = enc_field_val {
                let field_val_bytes = crypto::decrypt_cipher_string(enc_val, enc_key, mac_key)?;
                let field_val = String::from_utf8(field_val_bytes)
                    .map_err(|e| format!("Decrypted field value is not valid UTF-8: {}", e))?;

                if is_ssh_private_key(&field_val) {
                    ssh_keys.push(SshKeyItem {
                        id: cipher.id.clone(),
                        name: format!("{} ({})", plain_name, field_name),
                        private_key: field_val,
                        public_key: None,
                        note: plain_notes.clone(),
                    });
                    return Ok(());
                }
            }
        }
    }

    // Scenario 3: Secure Note containing OpenSSH / PEM private key in notes body
    let secure_note_key = if cipher.r#type == 2 {
        plain_notes.as_ref().filter(|n| is_ssh_private_key(n))
    } else {
        None
    };

    if let Some(notes) = secure_note_key {
        ssh_keys.push(SshKeyItem {
            id: cipher.id.clone(),
            name: plain_name,
            private_key: notes.clone(),
            public_key: None,
            note: Some("Extracted from secure note text body".to_string()),
        });
        return Ok(());
    }

    Ok(())
}

use base64::Engine;
use base64::prelude::BASE64_STANDARD;
#[cfg(not(test))]
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

pub use crate::api::{CipherSync, SyncResponse, ProfileSync, FolderSync, OrganizationSync};
use crate::config::Session;
use crate::crypto;

#[cfg(not(test))]
const APP_NAME: &str = "bitter";
const DB_FILE_NAME: &str = "vault.db";

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

pub fn cache_dir() -> Option<PathBuf> {
    #[cfg(test)]
    {
        Some(std::env::temp_dir().join("bitter_test"))
    }
    #[cfg(not(test))]
    {
        ProjectDirs::from("com", "", APP_NAME).map(|proj| proj.cache_dir().to_path_buf())
    }
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


/// Load and decrypt the local cache database from disk
fn init_tables(conn: &rusqlite::Connection) -> Result<(), String> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL,
            email_verified INTEGER NOT NULL,
            name TEXT,
            premium INTEGER NOT NULL,
            premium_from_organization INTEGER NOT NULL,
            private_key TEXT,
            public_key TEXT,
            security_stamp TEXT,
            two_factor_enabled INTEGER NOT NULL,
            uses_key_connector INTEGER NOT NULL,
            culture TEXT,
            creation_date TEXT,
            avatar_color TEXT,
            force_password_reset INTEGER NOT NULL,
            key TEXT NOT NULL,
            _status INTEGER,
            extra TEXT
        );

        CREATE TABLE IF NOT EXISTS organizations (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            key TEXT NOT NULL,
            object TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS folders (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            object TEXT NOT NULL,
            revision_date TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS ciphers (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            organization_id TEXT,
            type INTEGER NOT NULL,
            name TEXT,
            notes TEXT,
            favorite INTEGER NOT NULL,
            reprompt INTEGER NOT NULL,
            organization_use_totp INTEGER NOT NULL,
            edit INTEGER NOT NULL,
            view_password INTEGER NOT NULL,
            creation_date TEXT NOT NULL,
            revision_date TEXT NOT NULL,
            deleted_date TEXT,
            archived_date TEXT,
            key TEXT,
            object TEXT NOT NULL,
            extra TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(organization_id) REFERENCES organizations(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS cipher_logins (
            cipher_id TEXT PRIMARY KEY,
            username TEXT,
            password TEXT,
            uri TEXT,
            FOREIGN KEY(cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS cipher_ssh_keys (
            cipher_id TEXT PRIMARY KEY,
            private_key TEXT,
            public_key TEXT,
            FOREIGN KEY(cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS cipher_fields (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cipher_id TEXT NOT NULL,
            name TEXT NOT NULL,
            value TEXT,
            type INTEGER NOT NULL,
            FOREIGN KEY(cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS attachments (
            id TEXT PRIMARY KEY,
            cipher_id TEXT NOT NULL,
            file_name TEXT,
            size INTEGER,
            FOREIGN KEY(cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS folders_ciphers (
            cipher_id TEXT,
            folder_id TEXT,
            PRIMARY KEY(cipher_id, folder_id),
            FOREIGN KEY(cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE,
            FOREIGN KEY(folder_id) REFERENCES folders(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS sync_metadata (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            domains TEXT,
            policies TEXT,
            sends TEXT,
            object TEXT NOT NULL,
            masterPasswordUnlock TEXT,
            extra TEXT
        );

        CREATE TABLE IF NOT EXISTS session_metadata (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            email TEXT,
            device_id TEXT NOT NULL,
            access_token TEXT,
            refresh_token TEXT,
            last_sync_time TEXT,
            server_url TEXT,
            enc_key TEXT,
            mac_key TEXT
        );
        "#
    ).map_err(|e| format!("Failed to initialize database tables: {}", e))?;

    conn.execute(
        "INSERT OR IGNORE INTO session_metadata (id, device_id) VALUES (1, ?1)",
        (uuid::Uuid::new_v4().to_string(),),
    ).map_err(|e| format!("Failed to initialize session_metadata default row: {}", e))?;

    Ok(())
}

pub struct VaultRepository {
    conn: rusqlite::Connection,
}

fn save_cipher_conn(conn: &rusqlite::Connection, cipher: &CipherSync, user_id: &str) -> Result<(), String> {
    
    let extra_json = serde_json::to_string(&cipher.extra).unwrap_or_default();
    conn.execute(
        "INSERT OR REPLACE INTO ciphers (id, user_id, organization_id, type, name, notes, favorite, reprompt, organization_use_totp, edit, view_password, creation_date, revision_date, deleted_date, archived_date, key, object, extra) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
        rusqlite::params![
            &cipher.id,
            user_id,
            &cipher.organization_id,
            cipher.r#type,
            &cipher.name,
            &cipher.notes,
            cipher.favorite as i32,
            cipher.reprompt,
            cipher.organization_use_totp as i32,
            cipher.edit as i32,
            cipher.view_password as i32,
            &cipher.creation_date,
            &cipher.revision_date,
            &cipher.deleted_date,
            &cipher.archived_date,
            &cipher.key,
            &cipher.object,
            &extra_json,
        ],
    ).map_err(|e| format!("Failed to save core cipher: {}", e))?;

    // 2. Clear old child rows
    conn.execute("DELETE FROM cipher_logins WHERE cipher_id = ?1", (&cipher.id,))
        .map_err(|e| e.to_string())?;
    conn.execute("DELETE FROM cipher_ssh_keys WHERE cipher_id = ?1", (&cipher.id,))
        .map_err(|e| e.to_string())?;
    conn.execute("DELETE FROM cipher_fields WHERE cipher_id = ?1", (&cipher.id,))
        .map_err(|e| e.to_string())?;
    conn.execute("DELETE FROM attachments WHERE cipher_id = ?1", (&cipher.id,))
        .map_err(|e| e.to_string())?;
    conn.execute("DELETE FROM folders_ciphers WHERE cipher_id = ?1", (&cipher.id,))
        .map_err(|e| e.to_string())?;

    // 3. Save nested login
    if let Some(ref login) = cipher.login {
        conn.execute(
            "INSERT INTO cipher_logins (cipher_id, username, password, uri) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![&cipher.id, &login.username, &login.password, &login.uri],
        ).map_err(|e| format!("Failed to save cipher login: {}", e))?;
    }

    // 4. Save nested SSH key
    if let Some(ref ssh_key) = cipher.ssh_key {
        conn.execute(
            "INSERT INTO cipher_ssh_keys (cipher_id, private_key, public_key) VALUES (?1, ?2, ?3)",
            rusqlite::params![&cipher.id, &ssh_key.private_key, &ssh_key.public_key],
        ).map_err(|e| format!("Failed to save cipher SSH key: {}", e))?;
    }

    // 5. Save custom fields
    if let Some(ref fields) = cipher.fields {
        for field in fields {
            conn.execute(
                "INSERT INTO cipher_fields (cipher_id, name, value, type) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![&cipher.id, &field.name, &field.value, field.r#type],
            ).map_err(|e| format!("Failed to save cipher field: {}", e))?;
        }
    }

    // 6. Save attachments
    if let Some(ref attachments) = cipher.attachments {
        for att in attachments {
            conn.execute(
                "INSERT INTO attachments (id, cipher_id, file_name, size) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![&att.id, &cipher.id, &att.file_name, &att.size],
            ).map_err(|e| format!("Failed to save cipher attachment: {}", e))?;
        }
    }

    // 7. Save folder mapping
    if let Some(ref folder_id) = cipher.folder_id {
        conn.execute(
            "INSERT OR REPLACE INTO folders_ciphers (cipher_id, folder_id) VALUES (?1, ?2)",
            rusqlite::params![&cipher.id, folder_id],
        ).map_err(|e| format!("Failed to save folder cipher relationship: {}", e))?;
    }

    Ok(())
}

impl VaultRepository {
    pub fn open(path: &std::path::Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let conn = rusqlite::Connection::open(path)
            .map_err(|e| format!("Failed to open cache database: {}", e))?;
        
        conn.execute("PRAGMA foreign_keys = ON;", ())
            .map_err(|e| format!("Failed to enable foreign keys: {}", e))?;
            
        init_tables(&conn)?;
        Ok(Self { conn })
    }

    pub fn clear(&mut self) -> Result<(), String> {
        self.conn.execute("DELETE FROM users", ()).map_err(|e| e.to_string())?;
        self.conn.execute("DELETE FROM organizations", ()).map_err(|e| e.to_string())?;
        self.conn.execute("DELETE FROM folders", ()).map_err(|e| e.to_string())?;
        self.conn.execute("DELETE FROM ciphers", ()).map_err(|e| e.to_string())?;
        self.conn.execute("DELETE FROM sync_metadata", ()).map_err(|e| e.to_string())?;
        self.conn.execute("UPDATE session_metadata SET email = NULL, access_token = NULL, refresh_token = NULL, last_sync_time = NULL, enc_key = NULL, mac_key = NULL WHERE id = 1", ()).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn save_session(&self, session: &Session) -> Result<(), String> {
        self.conn.execute(
            "INSERT OR REPLACE INTO session_metadata (id, email, device_id, access_token, refresh_token, last_sync_time, server_url) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                &session.email,
                &session.device_id,
                &session.access_token,
                &session.refresh_token,
                &session.last_sync_time,
                &session.server_url,
            ],
        ).map_err(|e| format!("Failed to save session: {}", e))?;
        Ok(())
    }

    pub fn load_session(&self) -> Result<Option<Session>, String> {
        let mut stmt = self.conn.prepare(
            "SELECT email, device_id, access_token, refresh_token, last_sync_time, server_url FROM session_metadata WHERE id = 1"
        ).map_err(|e| e.to_string())?;

        let res = stmt.query_row((), |row| {
            Ok(Session {
                email: row.get("email")?,
                device_id: row.get("device_id")?,
                access_token: row.get("access_token")?,
                refresh_token: row.get("refresh_token")?,
                last_sync_time: row.get("last_sync_time")?,
                server_url: row.get("server_url")?,
            })
        });

        match res {
            Ok(s) => Ok(Some(s)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(format!("Failed to load session: {}", e)),
        }
    }

    pub fn save_saved_keys(&self, enc: &[u8; 32], mac: &[u8; 32]) -> Result<(), String> {
        let enc_hex = hex::encode(enc);
        let mac_hex = hex::encode(mac);
        self.conn.execute(
            "UPDATE session_metadata SET enc_key = ?1, mac_key = ?2 WHERE id = 1",
            rusqlite::params![&enc_hex, &mac_hex],
        ).map_err(|e| format!("Failed to save keys: {}", e))?;
        Ok(())
    }

    pub fn load_saved_keys(&self) -> Result<Option<([u8; 32], [u8; 32])>, String> {
        let mut stmt = self.conn.prepare(
            "SELECT enc_key, mac_key FROM session_metadata WHERE id = 1"
        ).map_err(|e| e.to_string())?;

        let res = stmt.query_row((), |row| {
            let enc: Option<String> = row.get("enc_key")?;
            let mac: Option<String> = row.get("mac_key")?;
            Ok((enc, mac))
        });

        let (enc, mac) = match res {
            Ok(val) => val,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(e) => return Err(format!("Failed to query saved keys: {}", e)),
        };

        if let (Some(enc_hex), Some(mac_hex)) = (enc, mac) {
            let enc_bytes = hex::decode(&enc_hex).map_err(|e| e.to_string())?;
            let mac_bytes = hex::decode(&mac_hex).map_err(|e| e.to_string())?;
            if enc_bytes.len() == 32 && mac_bytes.len() == 32 {
                let mut enc_arr = [0u8; 32];
                let mut mac_arr = [0u8; 32];
                enc_arr.copy_from_slice(&enc_bytes);
                mac_arr.copy_from_slice(&mac_bytes);
                Ok(Some((enc_arr, mac_arr)))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    pub fn clear_saved_keys(&self) -> Result<(), String> {
        self.conn.execute(
            "UPDATE session_metadata SET enc_key = NULL, mac_key = NULL WHERE id = 1",
            (),
        ).map_err(|e| format!("Failed to clear keys: {}", e))?;
        Ok(())
    }

    pub fn save_cipher(&mut self, cipher: &CipherSync, user_id: &str) -> Result<(), String> {
        save_cipher_conn(&self.conn, cipher, user_id)
    }

    pub fn delete_cipher(&mut self, id: &str) -> Result<(), String> {
        self.conn.execute("DELETE FROM ciphers WHERE id = ?1", (id,))
            .map_err(|e| format!("Failed to delete cipher: {}", e))?;
        Ok(())
    }

    pub fn save_folder(&mut self, folder: &FolderSync, user_id: &str) -> Result<(), String> {
        self.conn.execute(
            "INSERT OR REPLACE INTO folders (id, user_id, name, object, revision_date) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![&folder.id, user_id, &folder.name, &folder.object, &folder.revision_date],
        ).map_err(|e| format!("Failed to save folder: {}", e))?;
        Ok(())
    }

    pub fn delete_folder(&mut self, id: &str) -> Result<(), String> {
        self.conn.execute("DELETE FROM folders WHERE id = ?1", (id,))
            .map_err(|e| format!("Failed to delete folder: {}", e))?;
        Ok(())
    }

    pub fn save_organization(&mut self, org: &OrganizationSync) -> Result<(), String> {
        self.conn.execute(
            "INSERT OR REPLACE INTO organizations (id, name, key, object) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![&org.id, &org.name, &org.key, &org.object],
        ).map_err(|e| format!("Failed to save organization: {}", e))?;
        Ok(())
    }

    pub fn get_cipher(&self, id: &str) -> Result<Option<CipherSync>, String> {
        use crate::api::{LoginSync, SshKeySync, FieldSync, AttachmentSync};
        
        let mut stmt = self.conn.prepare(
            "SELECT id, organization_id, folder_id, type, name, notes, favorite, reprompt, organization_use_totp, edit, view_password, creation_date, revision_date, deleted_date, archived_date, key, object, extra FROM ciphers WHERE id = ?1"
        ).map_err(|e| e.to_string())?;

        let res = stmt.query_row(rusqlite::params![id], |row| {
            let id: String = row.get("id")?;
            let org_id: Option<String> = row.get("organization_id")?;
            let folder_id: Option<String> = row.get("folder_id")?;
            let r#type: i32 = row.get("type")?;
            let name: Option<String> = row.get("name")?;
            let notes: Option<String> = row.get("notes")?;
            let favorite = row.get::<_, i32>("favorite")? != 0;
            let reprompt: i32 = row.get("reprompt")?;
            let organization_use_totp = row.get::<_, i32>("organization_use_totp")? != 0;
            let edit = row.get::<_, i32>("edit")? != 0;
            let view_password = row.get::<_, i32>("view_password")? != 0;
            let creation_date: String = row.get("creation_date")?;
            let revision_date: String = row.get("revision_date")?;
            let deleted_date: Option<String> = row.get("deleted_date")?;
            let archived_date: Option<String> = row.get("archived_date")?;
            let key: Option<String> = row.get("key")?;
            let object: String = row.get("object")?;
            let extra_json: String = row.get("extra")?;
            let extra: std::collections::HashMap<String, serde_json::Value> = serde_json::from_str(&extra_json).unwrap_or_default();

            Ok((id, org_id, folder_id, r#type, name, notes, favorite, reprompt, organization_use_totp, edit, view_password, creation_date, revision_date, deleted_date, archived_date, key, object, extra))
        });

        let (id, org_id, folder_id, r#type, name, notes, favorite, reprompt, organization_use_totp, edit, view_password, creation_date, revision_date, deleted_date, archived_date, key, object, extra) = match res {
            Ok(val) => val,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(e) => return Err(e.to_string()),
        };

        // Query login
        let mut login_stmt = self.conn.prepare("SELECT username, password, uri FROM cipher_logins WHERE cipher_id = ?1").map_err(|e| e.to_string())?;
        let login = match login_stmt.query_row(rusqlite::params![id], |row| {
            Ok(LoginSync {
                username: row.get("username")?,
                password: row.get("password")?,
                uri: row.get("uri")?,
            })
        }) {
            Ok(l) => Some(l),
            Err(_) => None,
        };

        // Query SSH Key
        let mut ssh_stmt = self.conn.prepare("SELECT private_key, public_key FROM cipher_ssh_keys WHERE cipher_id = ?1").map_err(|e| e.to_string())?;
        let ssh_key = match ssh_stmt.query_row(rusqlite::params![id], |row| {
            Ok(SshKeySync {
                private_key: row.get("private_key")?,
                public_key: row.get("public_key")?,
            })
        }) {
            Ok(s) => Some(s),
            Err(_) => None,
        };

        // Query fields
        let mut field_stmt = self.conn.prepare("SELECT name, value, type FROM cipher_fields WHERE cipher_id = ?1").map_err(|e| e.to_string())?;
        let field_iter = field_stmt.query_map(rusqlite::params![id], |row| {
            Ok(FieldSync {
                name: row.get("name")?,
                value: row.get("value")?,
                r#type: row.get("type")?,
            })
        }).map_err(|e| e.to_string())?;
        let mut fields = Vec::new();
        for f in field_iter {
            fields.push(f.map_err(|e| e.to_string())?);
        }
        let fields_opt = if fields.is_empty() { None } else { Some(fields) };

        // Query attachments
        let mut att_stmt = self.conn.prepare("SELECT id, file_name, size FROM attachments WHERE cipher_id = ?1").map_err(|e| e.to_string())?;
        let att_iter = att_stmt.query_map(rusqlite::params![id], |row| {
            Ok(AttachmentSync {
                id: row.get("id")?,
                file_name: row.get("file_name")?,
                size: row.get("size")?,
            })
        }).map_err(|e| e.to_string())?;
        let mut attachments = Vec::new();
        for a in att_iter {
            attachments.push(a.map_err(|e| e.to_string())?);
        }
        let attachments_opt = if attachments.is_empty() { None } else { Some(attachments) };

        Ok(Some(CipherSync {
            id,
            organization_id: org_id,
            folder_id,
            r#type,
            name,
            notes,
            favorite,
            reprompt,
            organization_use_totp,
            edit,
            view_password,
            creation_date,
            revision_date,
            deleted_date,
            archived_date,
            key,
            login,
            card: None,
            identity: None,
            secure_note: None,
            ssh_key,
            fields: fields_opt,
            attachments: attachments_opt,
            collection_ids: None,
            password_history: None,
            permissions: None,
            object,
            extra,
        }))
    }

    pub fn list_ciphers(&self) -> Result<Vec<CipherSync>, String> {
        use crate::api::{LoginSync, SshKeySync, FieldSync, AttachmentSync};

        // Query base ciphers
        let mut stmt = self.conn.prepare(
            "SELECT id, organization_id, type, name, notes, favorite, reprompt, organization_use_totp, edit, view_password, creation_date, revision_date, deleted_date, archived_date, key, object, extra FROM ciphers"
        ).map_err(|e| e.to_string())?;

        // Batch load all logins
        let mut login_stmt = self.conn.prepare("SELECT cipher_id, username, password, uri FROM cipher_logins").map_err(|e| e.to_string())?;
        let mut logins_map = std::collections::HashMap::new();
        let login_iter = login_stmt.query_map((), |row| {
            let cid: String = row.get("cipher_id")?;
            Ok((cid, LoginSync {
                username: row.get("username")?,
                password: row.get("password")?,
                uri: row.get("uri")?,
            }))
        }).map_err(|e| e.to_string())?;
        for item in login_iter {
            let (cid, login) = item.map_err(|e| e.to_string())?;
            logins_map.insert(cid, login);
        }

        // Batch load all SSH Keys
        let mut ssh_stmt = self.conn.prepare("SELECT cipher_id, private_key, public_key FROM cipher_ssh_keys").map_err(|e| e.to_string())?;
        let mut ssh_map = std::collections::HashMap::new();
        let ssh_iter = ssh_stmt.query_map((), |row| {
            let cid: String = row.get("cipher_id")?;
            Ok((cid, SshKeySync {
                private_key: row.get("private_key")?,
                public_key: row.get("public_key")?,
            }))
        }).map_err(|e| e.to_string())?;
        for item in ssh_iter {
            let (cid, ssh) = item.map_err(|e| e.to_string())?;
            ssh_map.insert(cid, ssh);
        }

        // Batch load all fields
        let mut field_stmt = self.conn.prepare("SELECT cipher_id, name, value, type FROM cipher_fields").map_err(|e| e.to_string())?;
        let mut fields_map: std::collections::HashMap<String, Vec<FieldSync>> = std::collections::HashMap::new();
        let field_iter = field_stmt.query_map((), |row| {
            let cid: String = row.get("cipher_id")?;
            Ok((cid, FieldSync {
                name: row.get("name")?,
                value: row.get("value")?,
                r#type: row.get("type")?,
            }))
        }).map_err(|e| e.to_string())?;
        for item in field_iter {
            let (cid, field) = item.map_err(|e| e.to_string())?;
            fields_map.entry(cid).or_default().push(field);
        }

        // Batch load all attachments
        let mut att_stmt = self.conn.prepare("SELECT id, cipher_id, file_name, size FROM attachments").map_err(|e| e.to_string())?;
        let mut att_map: std::collections::HashMap<String, Vec<AttachmentSync>> = std::collections::HashMap::new();
        let att_iter = att_stmt.query_map((), |row| {
            let id: String = row.get("id")?;
            let cid: String = row.get("cipher_id")?;
            Ok((cid, AttachmentSync {
                id,
                file_name: row.get("file_name")?,
                size: row.get("size")?,
            }))
        }).map_err(|e| e.to_string())?;
        for item in att_iter {
            let (cid, att) = item.map_err(|e| e.to_string())?;
            att_map.entry(cid).or_default().push(att);
        }

        // Batch load folder mappings
        let mut folder_stmt = self.conn.prepare("SELECT cipher_id, folder_id FROM folders_ciphers").map_err(|e| e.to_string())?;
        let mut folders_map = std::collections::HashMap::new();
        let folder_iter = folder_stmt.query_map((), |row| {
            let cid: String = row.get("cipher_id")?;
            let fid: String = row.get("folder_id")?;
            Ok((cid, fid))
        }).map_err(|e| e.to_string())?;
        for item in folder_iter {
            let (cid, fid) = item.map_err(|e| e.to_string())?;
            folders_map.insert(cid, fid);
        }

        // Query base ciphers and build the final list
        let cipher_iter = stmt.query_map((), |row| {
            let id: String = row.get("id")?;
            let org_id: Option<String> = row.get("organization_id")?;
            let r#type: i32 = row.get("type")?;
            let name: Option<String> = row.get("name")?;
            let notes: Option<String> = row.get("notes")?;
            let favorite = row.get::<_, i32>("favorite")? != 0;
            let reprompt: i32 = row.get("reprompt")?;
            let organization_use_totp = row.get::<_, i32>("organization_use_totp")? != 0;
            let edit = row.get::<_, i32>("edit")? != 0;
            let view_password = row.get::<_, i32>("view_password")? != 0;
            let creation_date: String = row.get("creation_date")?;
            let revision_date: String = row.get("revision_date")?;
            let deleted_date: Option<String> = row.get("deleted_date")?;
            let archived_date: Option<String> = row.get("archived_date")?;
            let key: Option<String> = row.get("key")?;
            let object: String = row.get("object")?;
            let extra_json: String = row.get("extra")?;

            Ok((id, org_id, r#type, name, notes, favorite, reprompt, organization_use_totp, edit, view_password, creation_date, revision_date, deleted_date, archived_date, key, object, extra_json))
        }).map_err(|e| e.to_string())?;

        let mut ciphers = Vec::new();
        for cipher_row in cipher_iter {
            let (id, org_id, r#type, name, notes, favorite, reprompt, organization_use_totp, edit, view_password, creation_date, revision_date, deleted_date, archived_date, key, object, extra_json) = cipher_row.map_err(|e| e.to_string())?;
            let extra = serde_json::from_str(&extra_json).unwrap_or_default();
            
            let login = logins_map.get(&id).cloned();
            let ssh_key = ssh_map.get(&id).cloned();
            let fields = fields_map.get(&id).cloned();
            let attachments = att_map.get(&id).cloned();
            let folder_id = folders_map.get(&id).cloned();

            ciphers.push(CipherSync {
                id,
                organization_id: org_id,
                folder_id,
                r#type,
                name,
                notes,
                favorite,
                reprompt,
                organization_use_totp,
                edit,
                view_password,
                creation_date,
                revision_date,
                deleted_date,
                archived_date,
                key,
                login,
                card: None,
                identity: None,
                secure_note: None,
                ssh_key,
                fields,
                attachments,
                collection_ids: None,
                password_history: None,
                permissions: None,
                object,
                extra,
            });
        }

        Ok(ciphers)
    }

    pub fn save_sync_response(&mut self, sync: &SyncResponse) -> Result<(), String> {
        let tx = self.conn.transaction().map_err(|e| e.to_string())?;

        // Clear existing data
        tx.execute("DELETE FROM users", ()).map_err(|e| e.to_string())?;
        tx.execute("DELETE FROM organizations", ()).map_err(|e| e.to_string())?;
        tx.execute("DELETE FROM folders", ()).map_err(|e| e.to_string())?;
        tx.execute("DELETE FROM ciphers", ()).map_err(|e| e.to_string())?;
        tx.execute("DELETE FROM sync_metadata", ()).map_err(|e| e.to_string())?;

        // 1. Save profile
        let profile = &sync.profile;
        let extra_profile_json = serde_json::to_string(&profile.extra).unwrap_or_default();
        tx.execute(
            "INSERT INTO users (id, email, email_verified, name, premium, premium_from_organization, private_key, public_key, security_stamp, two_factor_enabled, uses_key_connector, culture, creation_date, avatar_color, force_password_reset, key, _status, extra) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
            rusqlite::params![
                &profile.id,
                &profile.email,
                profile.email_verified as i32,
                &profile.name,
                profile.premium as i32,
                profile.premium_from_organization as i32,
                &profile.private_key,
                &profile.public_key,
                &profile.security_stamp,
                profile.two_factor_enabled as i32,
                profile.uses_key_connector as i32,
                &profile.culture,
                &profile.creation_date,
                &profile.avatar_color,
                profile.force_password_reset as i32,
                &profile.key,
                profile._status,
                &extra_profile_json,
            ],
        ).map_err(|e| format!("Failed to save user profile: {}", e))?;

        // 2. Save organizations
        if let Some(ref orgs) = profile.organizations {
            for org in orgs {
                tx.execute(
                    "INSERT INTO organizations (id, name, key, object) VALUES (?1, ?2, ?3, ?4)",
                    rusqlite::params![&org.id, &org.name, &org.key, &org.object],
                ).map_err(|e| format!("Failed to save organization: {}", e))?;
            }
        }

        // 3. Save folders
        if let Some(ref folders) = sync.folders {
            for folder in folders {
                tx.execute(
                    "INSERT INTO folders (id, user_id, name, object, revision_date) VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![&folder.id, &profile.id, &folder.name, &folder.object, &folder.revision_date],
                ).map_err(|e| format!("Failed to save folder: {}", e))?;
            }
        }

        // 4. Save metadata & KDF parameters
        let domains_json = serde_json::to_string(&sync.domains).unwrap_or_default();
        let policies_json = serde_json::to_string(&sync.policies).unwrap_or_default();
        let sends_json = serde_json::to_string(&sync.sends).unwrap_or_default();
        let extra_sync_json = serde_json::to_string(&sync.extra).unwrap_or_default();
        let mpu_json = if let Some(ref ud) = sync.user_decryption {
            serde_json::to_string(&ud.master_password_unlock).unwrap_or_default()
        } else {
            String::new()
        };

        tx.execute(
            "INSERT OR REPLACE INTO sync_metadata (id, domains, policies, sends, object, masterPasswordUnlock, extra) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![&domains_json, &policies_json, &sends_json, &sync.object, &mpu_json, &extra_sync_json],
        ).map_err(|e| format!("Failed to save sync metadata: {}", e))?;

        // 5. Save ciphers
        for cipher in &sync.ciphers {
            save_cipher_conn(&tx, cipher, &profile.id)?;
        }

        tx.commit().map_err(|e| format!("Failed to commit transaction: {}", e))?;
        Ok(())
    }

    pub fn load_sync_response(&self) -> Result<SyncResponse, String> {
        use crate::api::{OrganizationSync, FolderSync, MasterPasswordUnlockSync, UserDecryptionSync};

        // 1. Load Profile
        let mut stmt = self.conn.prepare(
            "SELECT id, email, email_verified, name, premium, premium_from_organization, private_key, public_key, security_stamp, two_factor_enabled, uses_key_connector, culture, creation_date, avatar_color, force_password_reset, key, _status, extra FROM users LIMIT 1"
        ).map_err(|e| e.to_string())?;

        let res = stmt.query_row((), |row| {
            let id: String = row.get("id")?;
            let email: String = row.get("email")?;
            let email_verified = row.get::<_, i32>("email_verified")? != 0;
            let name: Option<String> = row.get("name")?;
            let premium = row.get::<_, i32>("premium")? != 0;
            let premium_from_organization = row.get::<_, i32>("premium_from_organization")? != 0;
            let private_key: Option<String> = row.get("private_key")?;
            let public_key: Option<String> = row.get("public_key")?;
            let security_stamp: Option<String> = row.get("security_stamp")?;
            let two_factor_enabled = row.get::<_, i32>("two_factor_enabled")? != 0;
            let uses_key_connector = row.get::<_, i32>("uses_key_connector")? != 0;
            let culture: String = row.get("culture")?;
            let creation_date: String = row.get("creation_date")?;
            let avatar_color: Option<String> = row.get("avatar_color")?;
            let force_password_reset = row.get::<_, i32>("force_password_reset")? != 0;
            let key: String = row.get("key")?;
            let _status: Option<i32> = row.get("_status")?;
            let extra_json: String = row.get("extra")?;

            Ok((id, email, email_verified, name, premium, premium_from_organization, private_key, public_key, security_stamp, two_factor_enabled, uses_key_connector, culture, creation_date, avatar_color, force_password_reset, key, _status, extra_json))
        });

        let (id, email, email_verified, name, premium, premium_from_organization, private_key, public_key, security_stamp, two_factor_enabled, uses_key_connector, culture, creation_date, avatar_color, force_password_reset, key, _status, extra_json) = match res {
            Ok(val) => val,
            Err(e) => return Err(format!("Failed to load user profile: {}", e)),
        };
        let extra_profile: std::collections::HashMap<String, serde_json::Value> = serde_json::from_str(&extra_json).unwrap_or_default();

        // Load organizations
        let mut org_stmt = self.conn.prepare("SELECT id, name, key, object FROM organizations").map_err(|e| e.to_string())?;
        let org_iter = org_stmt.query_map((), |row| {
            Ok(OrganizationSync {
                id: row.get("id")?,
                name: row.get("name")?,
                key: row.get("key")?,
                object: row.get("object")?,
                extra: std::collections::HashMap::new(),
            })
        }).map_err(|e| e.to_string())?;
        let mut organizations = Vec::new();
        for org in org_iter {
            organizations.push(org.map_err(|e| e.to_string())?);
        }
        let organizations_opt = if organizations.is_empty() { None } else { Some(organizations) };

        let profile = ProfileSync {
            id,
            email,
            email_verified,
            name,
            premium,
            premium_from_organization,
            private_key,
            public_key,
            security_stamp,
            two_factor_enabled,
            uses_key_connector,
            culture,
            creation_date,
            avatar_color,
            force_password_reset,
            key,
            organizations: organizations_opt,
            provider_organizations: None,
            providers: None,
            _status,
            object: "profile".to_string(),
            extra: extra_profile,
        };

        // 2. Load folders
        let mut fold_stmt = self.conn.prepare("SELECT id, name, object, revision_date FROM folders").map_err(|e| e.to_string())?;
        let fold_iter = fold_stmt.query_map((), |row| {
            Ok(FolderSync {
                id: row.get("id")?,
                name: row.get("name")?,
                object: row.get("object")?,
                revision_date: row.get("revision_date")?,
            })
        }).map_err(|e| e.to_string())?;
        let mut folders = Vec::new();
        for f in fold_iter {
            folders.push(f.map_err(|e| e.to_string())?);
        }
        let folders_opt = if folders.is_empty() { None } else { Some(folders) };

        // 3. Load ciphers
        let ciphers = self.list_ciphers()?;

        // 4. Load metadata & KDF parameters
        let mut meta_stmt = self.conn.prepare("SELECT domains, policies, sends, object, masterPasswordUnlock, extra FROM sync_metadata LIMIT 1").map_err(|e| e.to_string())?;
        let meta_res = meta_stmt.query_row((), |row| {
            let domains_json: String = row.get("domains")?;
            let policies_json: String = row.get("policies")?;
            let sends_json: String = row.get("sends")?;
            let object: String = row.get("object")?;
            let mpu_json: String = row.get("masterPasswordUnlock")?;
            let extra_json: String = row.get("extra")?;

            let domains: Option<serde_json::Value> = serde_json::from_str(&domains_json).ok();
            let policies: Option<Vec<serde_json::Value>> = serde_json::from_str(&policies_json).ok();
            let sends: Option<Vec<serde_json::Value>> = serde_json::from_str(&sends_json).ok();
            let master_password_unlock: Option<MasterPasswordUnlockSync> = serde_json::from_str(&mpu_json).ok();
            let extra: std::collections::HashMap<String, serde_json::Value> = serde_json::from_str(&extra_json).unwrap_or_default();

            Ok((domains, policies, sends, object, master_password_unlock, extra))
        });

        let (domains, policies, sends, object, master_password_unlock, extra_sync) = match meta_res {
            Ok(val) => val,
            Err(_) => (None, None, None, "sync".to_string(), None, std::collections::HashMap::new()),
        };

        let user_decryption = if master_password_unlock.is_some() {
            Some(UserDecryptionSync { master_password_unlock })
        } else {
            None
        };

        Ok(SyncResponse {
            profile,
            ciphers,
            folders: folders_opt,
            domains,
            policies,
            sends,
            object,
            user_decryption,
            extra: extra_sync,
        })
    }
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
    Ok(())
}

/// Delete only the unencrypted raw cache database (used when timeout changes from "never")
pub fn wipe_unencrypted_cache() -> Result<(), String> {
    if let Some(raw_path) = unencrypted_db_path() {
        if raw_path.exists() {
            fs::remove_file(&raw_path)
                .map_err(|e| format!("Failed to delete unencrypted cache database file: {}", e))?;
        }
    }
    Ok(())
}

pub fn handle_post_sync(
    sync_response: &SyncResponse,
    repo: &VaultRepository,
    enc_key: &[u8; 32],
    mac_key: &[u8; 32],
) -> Result<(), String> {
    if let Ok(config) = crate::config::Config::load() {
        if config.timeout.trim().to_lowercase() == "never" {
            if let Some(raw_path) = unencrypted_db_path() {
                let decrypted_items = parse_and_decrypt_all_ciphers(sync_response, enc_key, mac_key);
                let pretty_json = serde_json::to_vec_pretty(&decrypted_items)
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
            repo.save_saved_keys(enc_key, mac_key)?;
        } else {
            let _ = wipe_unencrypted_cache();
            repo.clear_saved_keys()?;
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

fn decrypt_org_key(org_key_str: &str, priv_key_der: &[u8]) -> Result<([u8; 32], [u8; 32]), String> {
    let parts: Vec<&str> = org_key_str.split('.').collect();
    if parts.len() < 2 {
        return Err("Invalid organization key format".to_string());
    }
    let enc_type: u32 = parts[0].parse().map_err(|_| "Invalid enc_type".to_string())?;
    let data_parts: Vec<&str> = parts[1].split('|').collect();
    let ciphertext = BASE64_STANDARD.decode(data_parts[0])
        .map_err(|e| format!("Failed to base64 decode organization key ciphertext: {}", e))?;

    let decrypted = match enc_type {
        3 | 5 => crypto::decrypt_rsa_oaep_sha256(priv_key_der, &ciphertext)?,
        4 | 6 => crypto::decrypt_rsa_oaep_sha1(priv_key_der, &ciphertext)?,
        t => return Err(format!("Unsupported organization key encryption type: {}", t)),
    };

    if decrypted.len() != 64 {
        return Err(format!("Decrypted organization key has invalid length: {} (expected 64)", decrypted.len()));
    }

    let mut enc = [0u8; 32];
    let mut mac = [0u8; 32];
    enc.copy_from_slice(&decrypted[0..32]);
    mac.copy_from_slice(&decrypted[32..64]);
    Ok((enc, mac))
}

/// Parses the full sync response and decrypts all ciphers without filtering out non-SSH keys.
pub fn parse_and_decrypt_all_ciphers(
    sync_response: &SyncResponse,
    enc_key: &[u8; 32],
    mac_key: &[u8; 32],
) -> Vec<CipherItem> {
    // 1. Decrypt RSA private key if present
    let rsa_priv_key_der = if let Some(ref enc_private_key) = sync_response.profile.private_key {
        match crypto::decrypt_cipher_string(enc_private_key, enc_key, mac_key) {
            Ok(der) => Some(der),
            Err(e) => {
                eprintln!("Warning: Failed to decrypt user RSA private key: {}", e);
                None
            }
        }
    } else {
        None
    };

    // 2. Decrypt all organization keys
    let mut org_keys = std::collections::HashMap::new();
    if let (Some(organizations), Some(priv_key_der)) = (&sync_response.profile.organizations, &rsa_priv_key_der) {
        for org in organizations {
            match decrypt_org_key(&org.key, priv_key_der) {
                Ok((org_enc, org_mac)) => {
                    org_keys.insert(org.id.clone(), (org_enc, org_mac));
                }
                Err(e) => {
                    eprintln!("Warning: Failed to decrypt organization key for {}: {}", org.id, e);
                }
            }
        }
    }

    let mut ciphers = Vec::new();

    for cipher in &sync_response.ciphers {
        if let Err(e) = decrypt_single_cipher(cipher, enc_key, mac_key, &org_keys, &mut ciphers) {
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
    org_keys: &std::collections::HashMap<String, ([u8; 32], [u8; 32])>,
    ciphers: &mut Vec<CipherItem>,
) -> Result<(), String> {
    if cipher.deleted_date.is_some() {
        return Ok(());
    }

    let (ck_enc, ck_mac) = if let Some(ref cipher_key_str) = cipher.key {
        let (active_enc, active_mac) = if let Some(ref org_id) = cipher.organization_id {
            if let Some(keys) = org_keys.get(org_id) {
                *keys
            } else {
                (*user_enc_key, *user_mac_key)
            }
        } else {
            (*user_enc_key, *user_mac_key)
        };

        let decrypted = crypto::decrypt_cipher_string(cipher_key_str, &active_enc, &active_mac)?;
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
        if let Some(ref org_id) = cipher.organization_id {
            if let Some(keys) = org_keys.get(org_id) {
                *keys
            } else {
                (*user_enc_key, *user_mac_key)
            }
        } else {
            (*user_enc_key, *user_mac_key)
        }
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
        let uri = if let Some(ref enc_uri) = login.uri {
            let uri_bytes = crypto::decrypt_cipher_string(enc_uri, enc_key, mac_key)?;
            Some(String::from_utf8(uri_bytes)
                .map_err(|e| format!("Decrypted URI is not valid UTF-8: {}", e))?)
        } else {
            None
        };
        Some(DecryptedLogin {
            username,
            password,
            uri,
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

/// Offline decryption helper to extract encryption keys and decrypt all ciphers using master password
pub fn decrypt_sync_response_offline(
    sync_resp: &SyncResponse,
    password: &str,
) -> Result<(Vec<CipherItem>, [u8; 32], [u8; 32]), String> {
    // 1. Get KDF parameters from user_decryption
    let (kdf_type, iterations, memory, parallelism, salt_email) = if let Some(ref ud) = sync_resp.user_decryption {
        if let Some(ref mpu) = ud.master_password_unlock {
            (
                mpu.kdf.kdf_type,
                mpu.kdf.iterations,
                mpu.kdf.memory,
                mpu.kdf.parallelism,
                mpu.salt.clone(),
            )
        } else {
            return Err("Offline KDF data missing from local cache".to_string());
        }
    } else {
        return Err("Offline decryption settings missing from local cache. Please sync online first.".to_string());
    };

    // 2. Derive master key
    let master_key = match kdf_type {
        0 => crate::crypto::derive_master_key_pbkdf2(password, &salt_email, iterations)?,
        1 => {
            let mem = memory.ok_or_else(|| "Argon2 memory parameter missing".to_string())?;
            let para = parallelism.ok_or_else(|| "Argon2 parallelism parameter missing".to_string())?;
            crate::crypto::derive_master_key_argon2(password, &salt_email, iterations, mem, para)?
        }
        t => return Err(format!("Unsupported KDF type: {}", t)),
    };

    // 3. Decrypt user symmetric keys
    let (enc_key, mac_key) = crate::crypto::decrypt_symmetric_key(&master_key, &sync_resp.profile.key)?;

    // 4. Decrypt ciphers
    let ciphers = parse_and_decrypt_all_ciphers(sync_resp, &enc_key, &mac_key);

    Ok((ciphers, enc_key, mac_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serde_sync_response_integration() {
        // Load the actual example sync response capture
        let path = std::path::Path::new("docs/example-sync.json");
        if !path.exists() {
            // Skip the test if example-sync.json is missing in CI
            return;
        }

        let content = std::fs::read_to_string(path).expect("Failed to read docs/example-sync.json");
        let sync_resp: SyncResponse = serde_json::from_str(&content).expect("Failed to deserialize SyncResponse");

        // Verify key fields
        assert_eq!(sync_resp.profile.email, "alex@okkk.cc");
        assert!(!sync_resp.ciphers.is_empty());
        assert_eq!(sync_resp.ciphers[0].id, "0075d6b8-7e7c-4a93-8131-39102849d2ca");

        // Verify user decryption KDF data
        let ud = sync_resp.user_decryption.as_ref().expect("Missing user_decryption");
        let mpu = ud.master_password_unlock.as_ref().expect("Missing master_password_unlock");
        assert_eq!(mpu.kdf.kdf_type, 1);
        assert_eq!(mpu.kdf.iterations, 2);
        assert_eq!(mpu.kdf.memory, Some(32));
        assert_eq!(mpu.kdf.parallelism, Some(2));
        assert_eq!(mpu.salt, "alex@okkk.cc");

        // Verify that fields are parsed
        assert!(sync_resp.folders.is_some());
        assert_eq!(sync_resp.object, "sync");
        assert_eq!(sync_resp.profile.name.as_deref(), Some("Alex Yuan"));
        assert_eq!(sync_resp.ciphers[0].favorite, false);

        // Round-trip serialization
        let serialized = serde_json::to_string(&sync_resp).expect("Failed to serialize");
        let sync_resp_2: SyncResponse = serde_json::from_str(&serialized).expect("Failed to deserialize second time");

        // Verify round-tripped fields
        assert!(sync_resp_2.folders.is_some());
        assert_eq!(sync_resp_2.object, "sync");
        assert_eq!(sync_resp_2.profile.email, "alex@okkk.cc");
    }

    #[test]
    fn test_save_load_db_roundtrip() {
        // Clean up any existing test cache directory first
        let cache_d = cache_dir().expect("Missing cache dir");
        let _ = std::fs::remove_dir_all(&cache_d);

        let mut extra_profile = std::collections::HashMap::new();
        extra_profile.insert("customField".to_string(), serde_json::json!("Custom Value"));

        let mut extra_sync = std::collections::HashMap::new();
        extra_sync.insert("customSyncField".to_string(), serde_json::json!("Custom Sync Value"));

        let sync_resp = SyncResponse {
            profile: ProfileSync {
                id: "user-123".to_string(),
                email: "test@example.com".to_string(),
                email_verified: false,
                name: Some("Test User".to_string()),
                premium: false,
                premium_from_organization: false,
                private_key: None,
                public_key: None,
                security_stamp: None,
                two_factor_enabled: false,
                uses_key_connector: false,
                culture: "en-US".to_string(),
                creation_date: String::new(),
                avatar_color: None,
                force_password_reset: false,
                key: "wrapped-key".to_string(),
                organizations: None,
                provider_organizations: None,
                providers: None,
                _status: None,
                object: "profile".to_string(),
                extra: extra_profile,
            },
            ciphers: Vec::new(),
            folders: None,
            domains: None,
            policies: None,
            sends: None,
            object: "sync".to_string(),
            user_decryption: None,
            extra: extra_sync,
        };

        // Save it using VaultRepository
        let path = cache_d.join(DB_FILE_NAME);
        let mut repo = VaultRepository::open(&path).expect("VaultRepository::open failed");
        repo.save_sync_response(&sync_resp).expect("save_sync_response failed");

        // Load it back
        let loaded = repo.load_sync_response().expect("load_sync_response failed");

        assert_eq!(loaded.profile.id, "user-123");
        assert_eq!(loaded.profile.email, "test@example.com");
        assert_eq!(loaded.profile.key, "wrapped-key");
        assert_eq!(loaded.profile.name.as_deref(), Some("Test User"));
        assert_eq!(loaded.profile.extra.get("customField").unwrap(), "Custom Value");
        assert_eq!(loaded.extra.get("customSyncField").unwrap(), "Custom Sync Value");

        // Clean up
        let _ = std::fs::remove_dir_all(&cache_d);
    }
}

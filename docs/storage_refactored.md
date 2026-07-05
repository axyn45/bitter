# Storage Refactoring Plan: SQLite Migration, Normalization & Active Repository CRUD

This document outlines the detailed architecture and implementation plan to migrate `sshwarden`'s local cache storage from JSON to a fully normalized SQLite database, utilizing the **Repository Pattern** for active, granular CRUD operations.

---

## 1. Architectural Goals

1. **Vaultwarden DB Parity:** Replicate Vaultwarden's table naming (`users`, `organizations`, `folders`, `ciphers`, `attachments`, `folders_ciphers`).
2. **Semantic Columns:** Replace all Diesel-style `uuid` columns with `id` to align with the client-side API payload.
3. **Strict Normalization (Zero JSON Blobs):** Extract all nested JSON data types (`login`, `fields`, `sshKey`) into separate SQLite tables. No column will store raw JSON string blobs.
4. **Active Repository CRUD:** Instead of loading/saving the entire vault in bulk, implement granular methods to insert, update, or delete single items.
5. **Cascaded Deletions:** Use database-level `ON DELETE CASCADE` foreign keys so deleting a cipher automatically purges all nested components (logins, fields, attachments).

---

## 2. SQLite Database Schema

```sql
-- 1. Cache user profile & KDF settings (replicates 'users')
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    email_verified INTEGER NOT NULL,
    name TEXT,
    premium INTEGER NOT NULL,
    premium_from_organization INTEGER NOT NULL,
    private_key TEXT, -- Encrypted PKCS#8 DER private key
    public_key TEXT,  -- Public key (plaintext)
    security_stamp TEXT,
    two_factor_enabled INTEGER NOT NULL,
    uses_key_connector INTEGER NOT NULL,
    culture TEXT,
    creation_date TEXT,
    avatar_color TEXT,
    force_password_reset INTEGER NOT NULL,
    key TEXT NOT NULL, -- MasterKeyWrappedUserKey
    _status INTEGER
);

-- 2. Organizations mapping (replicates 'organizations')
CREATE TABLE IF NOT EXISTS organizations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    key TEXT NOT NULL, -- Encrypted organization key
    object TEXT NOT NULL
);

-- 3. Folders metadata (replicates 'folders')
CREATE TABLE IF NOT EXISTS folders (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name TEXT NOT NULL,
    object TEXT NOT NULL,
    revision_date TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- 4. Vault items (replicates 'ciphers')
CREATE TABLE IF NOT EXISTS ciphers (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    organization_id TEXT,
    type INTEGER NOT NULL, -- 1: Login, 2: SecureNote, 5: SshKey
    name TEXT,             -- Encrypted
    notes TEXT,            -- Encrypted
    favorite INTEGER NOT NULL,
    reprompt INTEGER NOT NULL,
    organization_use_totp INTEGER NOT NULL,
    edit INTEGER NOT NULL,
    view_password INTEGER NOT NULL,
    creation_date TEXT NOT NULL,
    revision_date TEXT NOT NULL,
    deleted_date TEXT,
    archived_date TEXT,
    key TEXT,              -- Cipher-specific key (nullable)
    object TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(organization_id) REFERENCES organizations(id) ON DELETE SET NULL
);

-- 5. Cipher Logins (1-to-1 normalized component of ciphers)
CREATE TABLE IF NOT EXISTS cipher_logins (
    cipher_id TEXT PRIMARY KEY,
    username TEXT, -- Encrypted
    password TEXT, -- Encrypted
    uri TEXT,      -- Encrypted
    FOREIGN KEY(cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE
);

-- 6. Cipher SSH Keys (1-to-1 normalized component of ciphers)
CREATE TABLE IF NOT EXISTS cipher_ssh_keys (
    cipher_id TEXT PRIMARY KEY,
    private_key TEXT, -- Encrypted
    public_key TEXT,  -- Encrypted
    FOREIGN KEY(cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE
);

-- 7. Cipher Custom Fields (1-to-many normalized component of ciphers)
CREATE TABLE IF NOT EXISTS cipher_fields (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cipher_id TEXT NOT NULL,
    name TEXT NOT NULL,  -- Encrypted
    value TEXT,          -- Encrypted
    type INTEGER NOT NULL,
    FOREIGN KEY(cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE
);

-- 8. Cipher Attachments (1-to-many normalized component; replicates 'attachments')
CREATE TABLE IF NOT EXISTS attachments (
    id TEXT PRIMARY KEY,
    cipher_id TEXT NOT NULL,
    file_name TEXT,
    size INTEGER,
    FOREIGN KEY(cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE
);

-- 9. Folders-Ciphers mapping (replicates 'folders_ciphers')
CREATE TABLE IF NOT EXISTS folders_ciphers (
    cipher_id TEXT,
    folder_id TEXT,
    PRIMARY KEY(cipher_id, folder_id),
    FOREIGN KEY(cipher_id) REFERENCES ciphers(id) ON DELETE CASCADE,
    FOREIGN KEY(folder_id) REFERENCES folders(id) ON DELETE CASCADE
);

-- 10. Sync Metadata (singleton helper table for root sync response data)
CREATE TABLE IF NOT EXISTS sync_metadata (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    domains TEXT,  -- JSON representation
    policies TEXT, -- JSON representation
    sends TEXT,    -- JSON representation
    object TEXT NOT NULL,
    masterPasswordUnlock TEXT -- JSON representation of KDF parameters
);

-- 11. Session Metadata (consolidates session.json and eliminates vault.db.keys)
CREATE TABLE IF NOT EXISTS session_metadata (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    email TEXT,
    device_id TEXT NOT NULL,
    access_token TEXT,
    refresh_token TEXT,
    last_sync_time TEXT,
    server_url TEXT,
    enc_key TEXT, -- hex encoded symmetric decryption key, present only when timeout is 'never'
    mac_key TEXT  -- hex encoded MAC verification key, present only when timeout is 'never'
);
```

---

## 3. Active Repository implementation (`VaultRepository`)

A new struct `VaultRepository` will encapsulate all storage transactions in [src/storage.rs](file:///home/alex/coding/sshwarden/src/storage.rs):

```rust
pub struct VaultRepository {
    conn: rusqlite::Connection,
}
```

### Methods Implementation Plan

#### 1. Lifecycle and Management
* `open(path: &Path) -> Result<Self, String>`: Opens connection, executes `PRAGMA foreign_keys = ON;`, and initializes the tables.
* `clear(&self) -> Result<(), String>`: Deletes all entries from parent tables (`users`, `organizations`, `ciphers`, `sync_metadata`). Child tables will be purged automatically via database-level cascade deletes.

#### 2. Granular Cipher CRUD
* `save_cipher(&self, cipher: &CipherSync, user_id: &str) -> Result<(), String>`:
  - Starts a SQL transaction.
  - Inserts/replaces the core row in `ciphers`.
  - Clears pre-existing records for this cipher in `cipher_logins`, `cipher_ssh_keys`, `cipher_fields`, `attachments`, and `folders_ciphers`.
  - Inserts into `cipher_logins`, `cipher_ssh_keys`, `cipher_fields`, or `attachments` as appropriate depending on the presence of nested objects in `cipher`.
  - Inserts folder mapping into `folders_ciphers` if `cipher.folder_id` is present.
  - Commits the transaction.
* `get_cipher(&self, id: &str) -> Result<Option<CipherSync>, String>`:
  - Queries `ciphers` by `id`.
  - Performs secondary queries or left joins to load login details, SSH keys, custom fields, and attachments matching the `id`.
  - Populates child structures and returns the `CipherSync` object.
* `delete_cipher(&self, id: &str) -> Result<(), String>`:
  - Deletes row from `ciphers` where `id = ?`. Databases cascade triggers cleanup all associated tables.
* `list_ciphers(&self) -> Result<Vec<CipherSync>, String>`:
  - Queries all ciphers, batch loads child properties, matches them in memory, and returns the collection.

#### 3. Folders & Organizations CRUD
* `save_folder(&self, folder: &FolderSync, user_id: &str) -> Result<(), String>`: Inserts or replaces a folder record.
* `delete_folder(&self, id: &str) -> Result<(), String>`: Deletes a folder record (cascading deletes any relationship mappings).
* `save_organization(&self, org: &OrganizationSync) -> Result<(), String>`: Inserts or replaces an organization record.

#### 4. Bulk Synchronization (API /api/sync Support)
* `save_sync_response(&self, sync: &SyncResponse) -> Result<(), String>`:
  - Starts a single transaction.
  - Wipes database tables.
  - Writes profile (`users`).
  - Writes KDF settings and domains (`sync_metadata`).
  - Iterates and saves folders.
  - Iterates and saves organizations.
  - Iterates and saves ciphers using `save_cipher`.
  - Commits the transaction.
* `load_sync_response(&self) -> Result<SyncResponse, String>`:
  - Aggregates all tables in memory to reconstruct the full unified `SyncResponse` struct.

#### 5. Session & Keys Management
* `save_session(&self, session: &Session) -> Result<(), String>`: Saves the active user session details to `session_metadata`.
* `load_session(&self) -> Result<Option<Session>, String>`: Loads the active user session details from `session_metadata`.
* `save_saved_keys(&self, enc: &[u8; 32], mac: &[u8; 32]) -> Result<(), String>`: Stores the plaintext vault keys inside `session_metadata` when timeout is `'never'`.
* `load_saved_keys(&self) -> Result<Option<([u8; 32], [u8; 32])>, String>`: Loads the plaintext vault keys from `session_metadata` when timeout is `'never'`.
* `clear_saved_keys(&self) -> Result<(), String>`: Clears the plaintext keys by setting `enc_key` and `mac_key` to `NULL` in `session_metadata`.

---

## 5. Direct Dependents Update Plan

We will completely remove the old bulk `save_db` and `load_db` functions from `src/storage.rs`. Additionally, **`session.json` and `vault.db.keys` files are completely eliminated**. All session and key persistence operations are migrated to SQLite.

### Call-Sites to Update

#### A. In `src/commands.rs`:
* **Vault Login/Sync (`sync` & `login` command flow):**
  - Instantiates `VaultRepository::open(&db_path)`
  - Calls `repo.save_sync_response(&sync_data)` to write the updated database cache.
  - Saves the updated session tokens to `repo.save_session(&session)`.
  - The backup of unencrypted credentials (`vault.db.raw` for timeout=never settings) is written directly using `storage::parse_and_decrypt_all_ciphers`.
* **Vault Decryption/Unlock (`unlock` / offline lookup):**
  - Instantiates `VaultRepository::open(&db_path)`
  - Loads session metadata from `repo.load_session()`.
  - Calls `repo.load_sync_response()` to load the data for offline key derivation and cipher decryption.

#### B. In `src/daemon.rs`:
* **Agent Daemon Setup & Refresh:**
  - Instantiates `VaultRepository::open(&db_path)`
  - Loads session from `repo.load_session()`.
  - Checks if timeout is `"never"` and loads cached keys via `repo.load_saved_keys()`.
  - Calls `repo.load_sync_response()` to rebuild the keys and ciphers in-memory.
* **WebSocket Cipher Sync Events:**
  - Instead of downloading and writing the entire database, the background WebSocket sync will directly invoke single-item CRUD operations:
    - **Cipher Created/Updated (`cipherCreated` / `cipherUpdated` events):** Calls `repo.save_cipher(&cipher, &user_id)`.
    - **Cipher Deleted (`cipherDeleted` event):** Calls `repo.delete_cipher(&id)`.
    - **Folder/Organization updates:** Invoke `repo.save_folder` / `repo.delete_folder`.

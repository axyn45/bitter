# sshwarden: Development Roadmap & Checklist

This document tracks the step-by-step progress of the `sshwarden` project, including the new feature expansion roadmap.

---

## Phase 1: Project Setup & CLI Skeleton
- [x] Initialize Cargo binary project in workspace
- [x] Add base dependencies to `Cargo.toml` (`clap`, `serde`, `toml`, `directories`)
- [x] Implement configuration file manager in `src/config.rs` (XDG config directories, strict `0600` owner permissions)
- [x] Implement CLI subcommand parsing in `src/cli.rs` using `clap`
- [x] Integrate CLI parser and config loading in `src/main.rs`
- [x] Verify compilation and test skeleton CLI commands

## Phase 2: Cryptography & Bitwarden API Client
- [x] Implement cryptographic primitives (`crypto` module)
  - [x] Client-side KDF derivation for PBKDF2 (deriving Master Key and Login Hash)
  - [x] Client-side KDF derivation for Argon2id (deriving Master Key and Login Hash)
  - [x] Cipher decryption helpers (AES-256-CBC and AES-256-GCM)
- [x] Implement REST HTTP API Client (`api` module)
  - [x] Fetch user KDF parameters via email
  - [x] Standard Login API (Email + Password) returning bearer token
  - [x] API Key Login (`client_id` + `client_secret`) returning bearer token
  - [x] Sync API (`/sync`) to download full encrypted vault payload
  - [x] Individual Cipher Details API (`GET /api/ciphers/<id>/details`)

## Phase 3: Secure Local Storage & Cache
- [x] Implement secure vault cache (`storage` module)
  - [x] Derive local cache encryption key using Argon2id + local salt from master password
  - [x] Encrypt/Decrypt local database using AES-256-GCM
- [x] Implement cipher parsing and filtering logic
  - [x] Parse and extract SSH keys from native SSH key items (type `100`)
  - [x] Parse and extract SSH keys from Secure Notes containing PEM/OpenSSH private key text
  - [x] Parse and extract SSH keys from Logins containing custom `ssh_private_key` fields
- [x] Implement local vault keys management CLI commands
  - [x] `sshwarden keys list`: List all synced SSH keys
  - [x] `sshwarden sync`: Manually trigger synchronization and refresh local cache
  - [x] `sshwarden keys add / edit / delete`: Modifying keys (Placeholder, deferred for post-agent implementation)

## Phase 4: SSH Agent Protocol & Unix Socket
- [x] Implement SSH Agent Protocol parser (`agent` module)
  - [x] Read and parse SSH agent request frames
  - [x] Implement SSH2_AGENTC_REQUEST_IDENTITIES (list available public keys)
  - [x] Implement SSH2_AGENTC_SIGN_REQUEST (sign challenge data using private keys)
- [x] Create Unix Domain Socket Server
  - [x] Handle concurrent incoming connections using Tokio async socket listener
- [x] Implement signing operations for standard SSH keys
  - [x] RSA, Ed25519, and ECDSA signature algorithms
- [x] Implement daemonization (`daemonize` crate)
  - [x] Launch `sshwarden agent start` to spin off the background agent process
  - [x] Auto-generate and clean up Unix socket file

## Phase 5: Session Timeout & Security Hardening
- [x] Implement memory protection rules
  - [x] Clear sensitive data from memory using `zeroize`
- [x] Store decrypted keys securely in agent daemon memory space only (no disk persistence)
- [x] Implement Background Timeout Monitor Thread
  - [x] Tracks idle time since last SSH signature request or interaction
  - [x] Supports timeout values: immediately, 1m, 5m, 15m, 30m, 1h, 4h, on logout, never, custom
  - [x] Ensure status queries do not reset inactivity timer
- [x] Implement TTY-hijacking for interactive unlock prompts
  - [x] Secure password prompt on client TTY using `libc` termios
  - [x] Synchronize concurrent client connection prompts using Tokio `Mutex`
- [x] Implement active user session checks (auto-quit daemon on zero active sessions)
- [x] Implement Timeout Actions
  - [x] **Lock**: Wipe decrypted keys from memory, requires `sshwarden unlock` (master password) to restore
  - [x] **Logout**: Wipe decrypted keys, delete local encrypted cache database, clear authentication tokens
- [x] Implement `sshwarden unlock` subcommand
  - [x] Securely prompt for master password, derive master key, and restore daemon to active state

## Phase 6: WebSocket Live Sync
- [x] Implement SignalR Negotiation Endpoint `/notifications/hub/negotiate`
- [x] Implement WebSocket client event listener (`tokio-tungstenite`)
  - [x] Connect to `wss://<server>/notifications/hub` with authorization token
  - [x] Parse SignalR framing protocol (JSON text messages ending in `0x1E` separator)
- [x] Implement Event Handlers
  - [x] On `SyncVault` event: Trigger full `/sync` run
  - [x] On `SyncCipherCreate` / `SyncCipherUpdate` event: Sync vault and merge decrypted SSH keys into keyring and cache database
  - [x] On `SyncCipherDelete` / `SyncLoginDelete` event: Sync vault and update keyring and cache database

## Phase 7: Testing, Status, & Packaging
- [x] Write unit tests for Bitwarden cryptography derivation and cipher decryption
- [x] Verify agent socket integration with `ssh-add` and `ssh` client
- [x] Implement global `status` command
  - [x] Prints server url, login status, login method, timeout configurations, and sync details
  - [x] Retrieves real-time agent memory, vault lock status, and time-to-lock from daemon via control socket
- [x] Verify `unsafe` blocks and add developer safety comments

---

## Phase 8: User Profile & Session Isolation
- [ ] Decouple configuration from credentials
  - [ ] Keep `config.toml` strictly for user/app preferences (server URL, timeout, custom socket paths)
  - [ ] Store login credentials (`email`, `device_id`, `access_token`, `refresh_token`) in a separate `session.json`
- [ ] Set strict `0600` owner permissions on `session.json`
- [ ] Refactor `storage` and CLI endpoints (`login`, `logout`, `sync`) to use separated files

## Phase 9: API Key, SSO, and Device Push Login
- [ ] Implement API Key Login CLI commands and backend validation
- [ ] Implement SSO OAuth authorization
  - [ ] Spin up temporary local HTTP redirect server
  - [ ] Launch browser flow and capture authorization codes
- [ ] Implement Device Push Approval Login
  - [ ] Trigger push notification on registered device
  - [ ] Implement asynchronous polling status checks on terminal

## Phase 10: TUI Dashboard & CRUD Management
- [ ] Add `ratatui` and `crossterm` dependencies to `Cargo.toml`
- [ ] Build interactive Dashboard
  - [ ] Fuzzy-searchable item list
  - [ ] Detailed item view pane (with password/key copy and view/mask toggles)
  - [ ] Settings manager pane (timeout, server URL)
- [ ] Implement secure clipboard helpers (asynchronous background thread that wipes clipboard memory after 20s)
- [ ] Implement item editing and creation
  - [ ] Forms for adding/editing vault ciphers
  - [ ] Folder selector and custom fields creator
- [ ] Implement Folder Management (create, rename, delete folders)
- [ ] Build automatic TUI lock overlay when inactivity timer triggers (wipes screens and requests master password)

## Phase 11: Organization Support & Multi-Vault Collections
- [ ] Expand database schema (`vault.db`) to support organization identifiers, collections, and folders
- [ ] Implement organization cryptographic key decryption
  - [ ] Retrieve and decrypt organization keys using decrypted user symmetric key
  - [ ] Decrypt organization-owned ciphers using their respective organization keys
- [ ] Add organization filtering layouts to CLI list commands and TUI dashboard

# sshwarden: Development Roadmap & Checklist

This document tracks the step-by-step progress of the `sshwarden` project. Tasks are marked as complete as we progress.

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
- [ ] Implement secure vault cache (`storage` module)
  - [ ] Derive local cache encryption key using Argon2id + local salt from master password
  - [ ] Encrypt/Decrypt local database using AES-256-GCM
- [ ] Implement cipher parsing and filtering logic
  - [ ] Parse and extract SSH keys from native SSH key items (type `100`)
  - [ ] Parse and extract SSH keys from Secure Notes containing PEM/OpenSSH private key text
  - [ ] Parse and extract SSH keys from Logins containing custom `ssh_private_key` fields
- [ ] Implement local vault keys management CLI commands
  - [ ] `sshwarden keys list`: List all synced SSH keys
  - [ ] `sshwarden sync`: Manually trigger synchronization and refresh local cache
  - [ ] `sshwarden keys add / edit / delete`: Modifying keys and sync changes back to Bitwarden server

## Phase 4: SSH Agent Protocol & Unix Socket
- [ ] Implement SSH Agent Protocol parser (`agent` module)
  - [ ] Read and parse SSH agent request frames
  - [ ] Implement SSH2_AGENTC_REQUEST_IDENTITIES (list available public keys)
  - [ ] Implement SSH2_AGENTC_SIGN_REQUEST (sign challenge data using private keys)
- [ ] Create Unix Domain Socket Server
  - [ ] Handle concurrent incoming connections using Tokio async socket listener
- [ ] Implement signing operations for standard SSH keys
  - [ ] RSA, Ed25519, and ECDSA signature algorithms
- [ ] Implement daemonization (`daemonize` crate)
  - [ ] Launch `sshwarden daemon` to spin off the background agent process
  - [ ] Auto-generate and clean up Unix socket file

## Phase 5: Session Timeout & Memory Hardening
- [ ] Implement memory protection rules
  - [ ] Clear sensitive data from memory using `zeroize` and `secrecy`
- [ ] Integrate Linux Kernel Keyring (`keyctl`)
  - [ ] Store decrypted master password/key securely in kernel keyring space
- [ ] Implement Background Timeout Monitor Thread
  - [ ] Tracks idle time since last SSH signature request or interaction
  - [ ] Supports timeout values: immediately, 1m, 5m, 15m, 30m, 1h, 4h, on logout, never, custom
- [ ] Implement Timeout Actions
  - [ ] **Lock**: Wipe decrypted keys from memory (kernel keyring), requires `sshwarden unlock` (master password) to restore
  - [ ] **Logout**: Wipe decrypted keys, delete local encrypted cache database, clear authentication tokens
- [ ] Implement `sshwarden unlock` subcommand
  - [ ] Securely prompt for master password, derive master key, and restore daemon to active state

## Phase 6: WebSocket Live Sync
- [ ] Implement SignalR Negotiation Endpoint `/notifications/hub/negotiate`
- [ ] Implement WebSocket client event listener (`tokio-tungstenite`)
  - [ ] Connect to `wss://<server>/notifications/hub` with authorization token
  - [ ] Parse SignalR framing protocol (JSON text messages ending in `0x1E` separator)
- [ ] Implement Event Handlers
  - [ ] On `SyncVault` event: Trigger full `/sync` run
  - [ ] On `SyncCipherCreate` / `SyncCipherUpdate` event: Target fetch cipher ID from server API, decrypt, parse, and merge into local cache
  - [ ] On `SyncCipherDelete` event: Remove cipher ID from local cache

## Phase 7: Testing & Packaging
- [ ] Write unit tests for Bitwarden cryptography derivation and cipher decryption
- [ ] Write mock server tests for authentication and sync API
- [ ] Perform integration tests with `ssh-add -l` and SSH connections to remote servers
- [ ] Package binary compilation scripts for Linux targets (statically linked musl builds)

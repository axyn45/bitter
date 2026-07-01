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
  - [-] `sshwarden keys add / edit / delete`: Modifying keys (Placeholder, deferred for post-agent implementation)

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

## Phase 5: Session Timeout & Memory Hardening
- [x] Implement memory protection rules
  - [x] Clear sensitive data from memory using `zeroize`
- [x] Store decrypted keys securely in agent daemon memory space only (no disk persistence)
- [x] Implement Background Timeout Monitor Thread
  - [x] Tracks idle time since last SSH signature request or interaction
  - [x] Supports timeout values: immediately, 1m, 5m, 15m, 30m, 1h, 4h, on logout, never, custom
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

## Phase 7: Testing & Packaging
- [x] Write unit tests for Bitwarden cryptography derivation and cipher decryption
- [x] Integrate mock testing frameworks for REST API calls
- [x] Verify agent socket integration with `ssh-add`
- [x] Package binary compilation scripts for Linux targets (statically linked musl builds) via `build.sh`

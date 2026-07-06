# bitter: Bitwarden Terminal Client & SSH Agent

`bitter` (Bitwarden Terminal) is a headless, server-friendly Bitwarden client implemented in Rust that acts as a local SSH agent and terminal vault client. It allows you to securely access, manage, and use SSH keys and credentials stored in your Bitwarden vault directly from your terminal, without requiring the official graphical desktop client.

---

## Key Features

* **Bitwarden Vault Integration:** Full support for Password login, Personal API Keys, and Single Sign-On (SSO) authentication.
* **Built-in SSH Agent:** Act as a standard SSH agent (`SSH_AUTH_SOCK`) to load private keys stored in your vault directly into memory for SSH connections.
* **Granular SQLite Caching:** Stores your vault in a fully normalized, local SQLite database (`vault.db`) with zero plaintext storage of private keys or passwords.
* **Security Timeout Action:** Automatically locks the vault (purging keys from memory) or logs out after a configurable period of inactivity.
* **Secure TTY Prompting:** If the vault is locked when an SSH signature request comes in, it securely prompts for your master password directly on your active terminal (TTY) to auto-unlock.
* **WebSocket Live Sync:** Real-time surgical synchronization with the Bitwarden server when modifications are made to your vault.

---

## Build & Installation

### Prerequisites
* Rust toolchain (MSRV 1.80+)
* SQLite dev libraries (or built-in support)

### Building from Source
Clone the repository and run:
```bash
cargo build --release
```
The compiled binary will be available at `target/release/bitter`.

### Statically Linked Musl Release (for Headless Servers)
To build a fully self-contained, statically linked binary:
```bash
./build.sh
```
The static binary will be located in the `dist/` directory.

---

## Usage Guide

### 1. Login to Bitwarden
`bitter` supports three login methods:

* **Interactive Password Login:**
  ```bash
  bitter login
  ```
* **Personal API Key Login:**
  ```bash
  bitter login --client-id <id> --client-secret <secret>
  ```
* **Single Sign-On (SSO) Login:**
  ```bash
  bitter login --sso
  ```

### 2. Start the Agent Daemon
Start the background agent process:
```bash
bitter start -b
```
Configure your environment to use the agent:
```bash
export SSH_AUTH_SOCK="$HOME/.cache/bitter/ssh-agent.sock"
```

### 3. Unlock and Load Keys
If the agent is locked, unlock it by providing your master password:
```bash
bitter unlock
```
Once unlocked, any SSH keys stored in your Bitwarden vault (as standard SSH Key items, or custom fields/attachments) will be loaded automatically into the agent's memory.

### 4. Check Status
Get a detailed summary of the login status, daemon running state, keys loaded, and time-to-lock:
```bash
bitter status
```

---

## Configuration & Auto-Start

All configurations are saved under `~/.config/bitter/config.toml` (secured with `0600` permissions).

### Autostart on Login (Systemd)
Create a user systemd service at `~/.config/systemd/user/bitter.service`:
```ini
[Unit]
Description=Bitter Daemon
After=network.target

[Service]
ExecStart=/usr/local/bin/bitter start
Restart=on-failure

[Install]
WantedBy=default.target
```
Enable and start the service:
```bash
systemctl --user daemon-reload
systemctl --user enable bitter.service
```

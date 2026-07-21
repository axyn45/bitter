#!/usr/bin/env bash
set -euo pipefail

# Style definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Helper output functions
info() {
    echo -e "${BLUE}ℹ${NC} $1"
}
success() {
    echo -e "${GREEN}✔${NC} $1"
}
warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}
error() {
    echo -e "${RED}✘ Error:${NC} $1"
}
prompt() {
    echo -e -n "${CYAN}➜${NC} $1 "
}

echo -e "${BOLD}${MAGENTA}=========================================${NC}"
echo -e "${BOLD}${MAGENTA}       bitter Installation Script        ${NC}"
echo -e "${BOLD}${MAGENTA}=========================================${NC}"
echo ""

# 1. Check prerequisites
info "Checking prerequisites..."
if ! command -v cargo &> /dev/null; then
    error "Rust/Cargo is not installed. Please install Rust first: https://rustup.rs/"
    exit 1
fi
success "Rust/Cargo is installed."

# 2. Build bitter in release mode
info "Building bitter in release mode (native compilation)..."
cargo build --release

if [ ! -f "target/release/bitter" ]; then
    error "Build failed. Binary 'target/release/bitter' not found."
    exit 1
fi
success "bitter built successfully."

# 3. Create destination directory and copy binary
BINARY_DIR="$HOME/.local/bin"
info "Installing binary to $BINARY_DIR..."
mkdir -p "$BINARY_DIR"
cp target/release/bitter "$BINARY_DIR/bitter"
chmod +x "$BINARY_DIR/bitter"
success "Binary copied to $BINARY_DIR/bitter"

# Ensure binary is in user PATH or print warning
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    warning "$HOME/.local/bin is not in your PATH. You might need to add it to your shell profile (~/.bashrc, ~/.zshrc, etc.)."
fi

# 4. Create systemd user service file
SYSTEMD_USER_DIR="$HOME/.config/systemd/user"
SERVICE_FILE="$SYSTEMD_USER_DIR/bitter.service"

info "Creating systemd user service..."
mkdir -p "$SYSTEMD_USER_DIR"

cat << EOF > "$SERVICE_FILE"
[Unit]
Description=Bitter Bitwarden Daemon & SSH Agent
After=network.target

[Service]
Type=simple
ExecStart=%h/.local/bin/bitter start
Restart=on-failure
RestartSec=5s
Environment=RUST_LOG=info

[Install]
WantedBy=default.target
EOF

success "Systemd service file created at $SERVICE_FILE"

# 5. Reload systemd user daemon
info "Reloading systemd user daemon..."
systemctl --user daemon-reload
success "Systemd user daemon reloaded."

# 6. Interactive installation options
echo ""
echo -e "${BOLD}Configuration options:${NC}"

# Option A: Enable service
prompt "Do you want to enable the service to start automatically at login? [y/N]"
read -r response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    info "Enabling bitter.service..."
    systemctl --user enable bitter.service
    success "Service enabled."
else
    info "Service was not enabled."
fi

# Option B: Start service now
prompt "Do you want to start the service right now? [y/N]"
read -r response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    info "Starting bitter.service..."
    systemctl --user start bitter.service
    success "Service started."
else
    info "Service was not started."
fi

# 7. Print summary
echo ""
echo -e "${BOLD}${GREEN}=========================================${NC}"
echo -e "${BOLD}${GREEN}     bitter Installation Completed!      ${NC}"
echo -e "${BOLD}${GREEN}=========================================${NC}"
echo ""
echo -e "You can manage the daemon using standard systemctl commands:"
echo -e "  - Check status:     ${CYAN}systemctl --user status bitter.service${NC}"
echo -e "  - View live logs:   ${CYAN}journalctl --user -u bitter.service -f${NC}"
echo -e "  - Stop daemon:      ${CYAN}systemctl --user stop bitter.service${NC}"
echo -e "  - Start daemon:     ${CYAN}systemctl --user start bitter.service${NC}"
echo ""

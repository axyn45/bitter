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

# Option C: Enable user lingering
prompt "Do you want to enable systemd user lingering (keeps daemon running even when you log out)? [y/N]"
read -r response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    info "Enabling user lingering..."
    loginctl enable-linger || true
    success "User lingering enabled."
else
    info "User lingering was not enabled."
fi

# Option D: Configure environment variables (SSH_AUTH_SOCK and PATH)
prompt "Do you want to configure your shell profile (adds SSH_AUTH_SOCK and PATH)? [y/N]"
read -r response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    # Detect shell profiles
    PROFILES=()
    [ -f "$HOME/.bashrc" ] && PROFILES+=("$HOME/.bashrc")
    [ -f "$HOME/.zshrc" ] && PROFILES+=("$HOME/.zshrc")
    [ -f "$HOME/.profile" ] && PROFILES+=("$HOME/.profile")
    [ -f "$HOME/.bash_profile" ] && PROFILES+=("$HOME/.bash_profile")
    
    if [ ${#PROFILES[@]} -eq 0 ]; then
        warning "No shell profile files (like .bashrc or .zshrc) were detected."
    else
        echo "Detected shell profiles:"
        for i in "${!PROFILES[@]}"; do
            echo "  [$i] $(basename "${PROFILES[$i]}")"
        done
        prompt "Select profile to update (e.g. 0, or enter a custom path):"
        read -r choice
        
        TARGET_PROFILE=""
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -lt "${#PROFILES[@]}" ]; then
            TARGET_PROFILE="${PROFILES[$choice]}"
        elif [ -n "$choice" ]; then
            if [[ "$choice" != /* ]]; then
                TARGET_PROFILE="$HOME/$choice"
            else
                TARGET_PROFILE="$choice"
            fi
        fi
        
        if [ -n "$TARGET_PROFILE" ]; then
            info "Updating $TARGET_PROFILE..."
            
            # Check if our block is already present
            if grep -q "# >>> bitter ssh-agent configuration >>>" "$TARGET_PROFILE" 2>/dev/null; then
                info "bitter configuration block is already present in $TARGET_PROFILE."
            else
                # Check for individual configs outside our block to avoid duplicating
                ADD_AUTH=true
                ADD_PATH=true
                
                if grep -q "SSH_AUTH_SOCK" "$TARGET_PROFILE" 2>/dev/null; then
                    ADD_AUTH=false
                    info "SSH_AUTH_SOCK is already configured in $TARGET_PROFILE."
                fi
                
                if grep -q "\.local/bin" "$TARGET_PROFILE" 2>/dev/null; then
                    ADD_PATH=false
                    info "PATH already contains .local/bin in $TARGET_PROFILE."
                fi
                
                # Write the block if at least one export is needed
                if [ "$ADD_AUTH" = true ] || [ "$ADD_PATH" = true ]; then
                    echo "" >> "$TARGET_PROFILE"
                    echo "# >>> bitter ssh-agent configuration >>>" >> "$TARGET_PROFILE"
                    
                    if [ "$ADD_AUTH" = true ]; then
                        echo 'export SSH_AUTH_SOCK="$HOME/.cache/bitter/ssh-agent.sock"' >> "$TARGET_PROFILE"
                        success "Added SSH_AUTH_SOCK to $TARGET_PROFILE"
                    fi
                    
                    if [ "$ADD_PATH" = true ]; then
                        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$TARGET_PROFILE"
                        success "Added $HOME/.local/bin to PATH in $TARGET_PROFILE"
                    fi
                    
                    echo "# <<< bitter ssh-agent configuration <<<" >> "$TARGET_PROFILE"
                fi
            fi
            
            echo -e "${YELLOW}ℹ Please run: source $TARGET_PROFILE (or restart your terminal) to apply changes.${NC}"
        fi
    fi
else
    info "Shell profile was not modified."
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

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

# Clean up legacy systemd service file if it exists
LEGACY_SERVICE="$HOME/.config/systemd/user/bitter.service"
if [ -f "$LEGACY_SERVICE" ]; then
    info "Removing old systemd service file..."
    systemctl --user stop bitter.service 2>/dev/null || true
    systemctl --user disable bitter.service 2>/dev/null || true
    rm -f "$LEGACY_SERVICE"
    systemctl --user daemon-reload 2>/dev/null || true
    success "Legacy systemd service removed successfully."
fi

# 4. Interactive installation options
echo ""
echo -e "${BOLD}Configuration options:${NC}"

CONFIGURE_ENV=false
CONFIGURE_AUTOSTART=false

# Option A: Shell environment variables (SSH_AUTH_SOCK and PATH)
prompt "Do you want to configure your shell profile environment variables (adds SSH_AUTH_SOCK and PATH)? [y/N]"
read -r response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    CONFIGURE_ENV=true
fi

# Option B: Shell auto-start at login
prompt "Do you want to enable automatic daemon start when you open a terminal? [y/N]"
read -r response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    CONFIGURE_AUTOSTART=true
fi

# Update shell profile if either option is selected
if [ "$CONFIGURE_ENV" = true ] || [ "$CONFIGURE_AUTOSTART" = true ]; then
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
                info "bitter configuration block is already present in $TARGET_PROFILE. Skipping."
            else
                echo "" >> "$TARGET_PROFILE"
                echo "# >>> bitter ssh-agent configuration >>>" >> "$TARGET_PROFILE"
                
                if [ "$CONFIGURE_ENV" = true ]; then
                    # Check if SSH_AUTH_SOCK is already configured in profile
                    if grep -q "SSH_AUTH_SOCK" "$TARGET_PROFILE" 2>/dev/null; then
                        info "SSH_AUTH_SOCK is already configured in $TARGET_PROFILE."
                    else
                        echo 'export SSH_AUTH_SOCK="$HOME/.cache/bitter/ssh-agent.sock"' >> "$TARGET_PROFILE"
                        success "Added SSH_AUTH_SOCK to $TARGET_PROFILE"
                    fi
                    
                    # Check if PATH already contains ~/.local/bin in active environment or profile
                    if [[ ":$PATH:" == *":$HOME/.local/bin:"* ]] || grep -q "\.local/bin" "$TARGET_PROFILE" 2>/dev/null; then
                        info "PATH already contains $HOME/.local/bin. Skipping path addition."
                    else
                        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$TARGET_PROFILE"
                        success "Added $HOME/.local/bin to PATH in $TARGET_PROFILE"
                    fi
                fi
                
                if [ "$CONFIGURE_AUTOSTART" = true ]; then
                    echo "" >> "$TARGET_PROFILE"
                    echo "# Start the daemon silently if the socket is not active" >> "$TARGET_PROFILE"
                    echo 'if [ ! -S "$HOME/.cache/bitter/ssh-agent.sock" ]; then' >> "$TARGET_PROFILE"
                    echo '    "$HOME/.local/bin/bitter" start -b >/dev/null 2>&1' >> "$TARGET_PROFILE"
                    echo 'fi' >> "$TARGET_PROFILE"
                    success "Added daemon auto-start logic to $TARGET_PROFILE"
                fi
                
                echo "# <<< bitter ssh-agent configuration <<<" >> "$TARGET_PROFILE"
            fi
            
            echo -e "${YELLOW}ℹ Please run: source $TARGET_PROFILE (or restart your terminal) to apply changes.${NC}"
        fi
    fi
else
    info "Shell profile was not modified."
fi

# Option C: Start daemon now
prompt "Do you want to start the daemon right now? [y/N]"
read -r response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
    info "Starting bitter daemon..."
    # Stop existing instance if running
    "$BINARY_DIR/bitter" stop >/dev/null 2>&1 || true
    if "$BINARY_DIR/bitter" start -b; then
        success "Daemon started successfully."
    else
        error "Failed to start daemon."
    fi
else
    info "Daemon was not started."
fi

# 5. Print summary
echo ""
echo -e "${BOLD}${GREEN}=========================================${NC}"
echo -e "${BOLD}${GREEN}     bitter Installation Completed!      ${NC}"
echo -e "${BOLD}${GREEN}=========================================${NC}"
echo ""
echo -e "You can manage the daemon using standard bitter CLI commands:"
echo -e "  - Check status:     ${CYAN}bitter status${NC}"
echo -e "  - Stop daemon:      ${CYAN}bitter stop${NC}"
echo -e "  - Start daemon:     ${CYAN}bitter start -b${NC}"
echo -e "  - Unlock vault:     ${CYAN}bitter unlock${NC}"
echo ""

#!/usr/bin/env bash
set -euo pipefail

echo "Building sshwarden release..."

# Ensure target is installed
if ! rustup target list --installed | grep -q "x86_64-unknown-linux-musl"; then
    echo "Installing x86_64-unknown-linux-musl target..."
    rustup target add x86_64-unknown-linux-musl
fi

# Build statically linked release binary
echo "Running cargo build..."
cargo build --release --target x86_64-unknown-linux-musl

# Create dist directory
mkdir -p dist
cp target/x86_64-unknown-linux-musl/release/sshwarden dist/

echo "Build complete! Statically linked binary is at: dist/sshwarden"
file dist/sshwarden

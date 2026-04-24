#!/bin/bash
set -e

# 1. Clean
cargo clean

# 2. Fix Gateway Warnings (Silence the unused cert_hash)
# (Adjusting the sed path for the renamed directory)
sed -i 's/let cert_hash =/let _cert_hash =/g' citadel-mcp-server/src/main.rs

# 3. Build Mudra Gate (Native Gateway)
echo "Building Native Gateway (citadel-mcp-server)..."
cargo build --release -p citadel-mcp-server

# 4. Build Sakshi Core (WASM)
echo "Building Sakshi Core WASM..."
cargo build --target wasm32-unknown-unknown --release -p sakshi-core --no-default-features

# 5. Package
NATIVE_BIN="./target/release/citadel-mcp-server"
WASM_BIN="./target/wasm32-unknown-unknown/release/sakshi_core.wasm"

echo "Release artifacts ready:"
ls -lh $NATIVE_BIN
ls -lh $WASM_BIN

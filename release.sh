#!/bin/bash
set -e

# 1. Clean
cargo clean

# 2. Build Mudra Gate (Native Gateway)
echo "Building Native Gateway (citadel-mcp-server) with TDX support..."
cargo build --release -p citadel-mcp-server --features tdx

# 4. Build Sakshi Core (WASM)
echo "Building Sakshi Core WASM..."
cargo build --target wasm32-unknown-unknown --release -p sakshi-core --no-default-features --features alloc

# 5. Package
NATIVE_BIN="./target/release/citadel-mcp-server"
WASM_BIN="./target/wasm32-unknown-unknown/release/sakshi_core.wasm"

echo "Release artifacts ready:"
ls -lh $NATIVE_BIN
ls -lh $WASM_BIN

#!/bin/bash
set -e

echo "--- Citadel Protocol - Initiating Deterministic Hybrid Build ---"

# 1. Clean Room Initialization
cargo clean

# 2. Fix Proxy Warnings (Silence the unused cert_hash)
sed -i 's/let cert_hash =/let _cert_hash =/g' proxy/src/main.rs

# 3. Native Build (GCP TDX)
echo "Building Native Proxy..."
cargo build --release -p proxy

# 4. WASM Build (Sovereign Boundary)
echo "Building WASM Boundary..."
cargo build --target wasm32-unknown-unknown --release -p witness-core --no-default-features

# 5. Artifact Extraction
NATIVE_BIN="./target/release/proxy"
WASM_BIN="./target/wasm32-unknown-unknown/release/witness_core.wasm"

# 6. Hashing & Provenance
MRTD=$(sha256sum $NATIVE_BIN | awk '{print $1}')
WASM_HASH=$(sha256sum $WASM_BIN | awk '{print $1}')

echo "---"
echo "NATIVE MRTD: $MRTD"
echo "WASM HASH:   $WASM_HASH"
echo "---"

# 7. Git Tagging
TAG_NAME="v$(date +%Y.%m.%d)-hybrid-${MRTD:0:8}"
git tag -f -a "$TAG_NAME" -m "Hybrid Build. Native: $MRTD | WASM: $WASM_HASH"
echo "GIT TAG ANCHORED: $TAG_NAME"

echo "$MRTD" > .latest_mrtd
echo "$WASM_HASH" > .latest_wasm_hash
echo "--- Sovereign Build Complete ---"

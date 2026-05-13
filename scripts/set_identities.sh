#!/bin/bash

# set_identities.sh - Provision Citadel identities into the secure system keyring

set -e

# Function to display usage
usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Governance (Anchor) Identity:"
    echo "  --gov-id <id>      Hedera Account ID (e.g., 0.0.8812975)"
    echo "  --gov-key <key>    Hedera Private Key (Hex or DER)"
    echo ""
    echo "Operator (Gateway) Identity:"
    echo "  --op-id <id>       Hedera Account ID (e.g., 0.0.8806399)"
    echo "  --op-key <key>     Hedera Private Key (Hex or DER)"
    echo ""
    echo "Telemetry Identity:"
    echo "  --telemetry-key <key>  MTCP Public Key (Hex)"
    echo ""
    echo "Other:"
    echo "  -h, --help         Show this help message"
    exit 1
}

# Parse arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --gov-id) GOV_ID="$2"; shift ;;
        --gov-key) GOV_KEY="$2"; shift ;;
        --op-id) OP_ID="$2"; shift ;;
        --op-key) OP_KEY="$2"; shift ;;
        --telemetry-key) TEL_KEY="$2"; shift ;;
        -h|--help) usage ;;
        *) echo "Unknown parameter: $1"; usage ;;
    esac
    shift
done

# Check if at least some credentials were provided
if [ -z "$GOV_ID" ] && [ -z "$GOV_KEY" ] && [ -z "$OP_ID" ] && [ -z "$OP_KEY" ] && [ -z "$TEL_KEY" ]; then
    echo "❌ Error: No identities provided."
    usage
fi

MGR_CMD="cargo run --quiet --bin citadel-secrets-mgr --features cli -p citadel-secrets --"

echo "🔐 Provisioning Citadel Identities into System Keyring..."

# 1. Governance Identity
if [ -n "$GOV_ID" ]; then
    $MGR_CMD set hiero-governance-id "$GOV_ID"
fi
if [ -n "$GOV_KEY" ]; then
    $MGR_CMD set hiero-governance-key "$GOV_KEY"
fi

# 2. Operator Identity
if [ -n "$OP_ID" ]; then
    $MGR_CMD set hiero-operator-id "$OP_ID"
fi
if [ -n "$OP_KEY" ]; then
    $MGR_CMD set hiero-operator-key "$OP_KEY"
fi

# 3. Telemetry Identity
if [ -n "$TEL_KEY" ]; then
    $MGR_CMD set telemetry-public-key "$TEL_KEY"
fi

echo "✅ Provisioning complete."
echo "   You can verify them using: cargo run --bin citadel-secrets-mgr --features cli -p citadel-secrets -- get <key-name>"

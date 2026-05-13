#!/bin/bash

# set_identities.sh - Provision Citadel identities into the secure file-based vault

set -e

# --- Configuration ---
DEFAULT_VAULT_PATH="~/.citadel/vault.enc"
DEFAULT_PASSWORD_ENV_VAR="CITADEL_MASTER_PASSWORD"
# --- End Configuration ---

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
    echo "Secret Store Options:"
    echo "  --vault-path <path>    Path to the encrypted vault file. Defaults to '${DEFAULT_VAULT_PATH}'"
    echo "  --password-env-var <name> Environment variable name for master password. Defaults to '${DEFAULT_PASSWORD_ENV_VAR}'"
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
        --vault-path) VAULT_PATH="$2"; shift ;;
        --password-env-var) PASSWORD_ENV_VAR="$2"; shift ;;
        -h|--help) usage ;;
        *) echo "Unknown parameter: $1"; usage ;;
    esac
    shift
done

# Use provided vault path or default
VAULT_PATH="${VAULT_PATH:-$DEFAULT_VAULT_PATH}"
# Use provided password env var name or default
PASSWORD_ENV_VAR="${PASSWORD_ENV_VAR:-$DEFAULT_PASSWORD_ENV_VAR}"


# Check if at least some credentials were provided
if [ -z "$GOV_ID" ] && [ -z "$GOV_KEY" ] && [ -z "$OP_ID" ] && [ -z "$OP_KEY" ] && [ -z "$TEL_KEY" ]; then
    echo "❌ Error: No identities provided."
    usage
fi

# --- Master Password Handling ---
# Check if the password environment variable is already set
if [ -z "${!PASSWORD_ENV_VAR}" ]; then
    echo "🔑 Master password not found in environment variable '${PASSWORD_ENV_VAR}'."
    read -sp "Enter master password: " MASTER_PASSWORD
    echo "" # Newline after password input
    if [ -z "$MASTER_PASSWORD" ]; then
        echo "❌ Error: Master password cannot be empty."
        exit 1
    fi
    # Export the password to the environment variable for citadel-secrets-mgr
    export "$PASSWORD_ENV_VAR"="$MASTER_PASSWORD"
else
    echo "🔑 Using master password from environment variable '${PASSWORD_ENV_VAR}'."
fi
# --- End Master Password Handling ---

# Construct the command for citadel-secrets-mgr
# Note: --vault-path and --password-env-var are passed as arguments to the binary
MGR_CMD="cargo run --quiet --bin citadel-secrets-mgr --features cli -p citadel-secrets -- --vault-path \"${VAULT_PATH}\" --password-env-var \"${PASSWORD_ENV_VAR}\""

echo "🔐 Provisioning Citadel Identities into File-Based Vault ('${VAULT_PATH}')..."

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
echo "   You can verify them using: ${MGR_CMD% --} get <key-name>"

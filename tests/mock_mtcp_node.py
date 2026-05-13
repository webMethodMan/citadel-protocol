import os
import struct
import json
import argparse
import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

def sign_telemetry(private_key_hex, ve_decay, authority_hash_hex, integrity_hash_hex):
    # 1. Load Private Key
    try:
        private_bytes = bytes.fromhex(private_key_hex.replace("0x", ""))
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
    except Exception as e:
        print(f"❌ Error loading private key: {e}")
        return None

    # 2. Prepare Data for Signing (TelemetryState::to_bytes() equivalent)
    # f64 (big-endian), [u8; 32], [u8; 32]
    try:
        authority_hash = bytes.fromhex(authority_hash_hex.replace("0x", ""))
        integrity_hash = bytes.fromhex(integrity_hash_hex.replace("0x", ""))
    except Exception as e:
        print(f"❌ Error parsing hashes: {e}")
        return None

    # ve_decay as 8-byte big-endian double
    data = struct.pack(">d", ve_decay)
    data += authority_hash
    data += integrity_hash

    # 3. Sign
    signature = private_key.sign(data)

    return {
        "v_e_decay": ve_decay,
        "integrity_hash": integrity_hash_hex,
        "signature": signature.hex()
    }

def main():
    parser = argparse.ArgumentParser(description="Citadel Mock MTCP Node - Telemetry Signer")
    parser.add_argument("--key", help="Ed25519 Private Key (Hex)")
    parser.add_argument("--decay", type=float, default=0.95, help="V_e Decay Rate (0.0 to 1.0)")
    parser.add_argument("--auth-id", help="Authority ID string (will be hashed using SHA3-256)")
    parser.add_argument("--authority", help="Pre-hashed Authority Identity Hash (Hex)")
    parser.add_argument("--integrity", default="0" * 64, help="Workload Integrity Hash (Hex)")
    parser.add_argument("--generate", action="store_true", help="Generate a new keypair and exit")

    args = parser.parse_args()

    if args.generate:
        private_key = ed25519.Ed25519PrivateKey.generate()
        private_hex = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ).hex()
        public_hex = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex()
        print(f"✅ Generated new MTCP Identity:")
        print(f"PRIVATE KEY (SECRET): {private_hex}")
        print(f"PUBLIC KEY (CITADEL_TELEMETRY_PUBLIC_KEY): {public_hex}")
        return

    if not args.key:
        print("❌ Error: --key is required unless using --generate")
        return

    auth_hash_hex = args.authority
    if args.auth_id:
        # Match sakshi-core Sha3_256Hasher
        auth_hash_hex = hashlib.sha3_256(args.auth_id.encode()).hexdigest()
    
    if not auth_hash_hex:
        auth_hash_hex = "0" * 64

    signed_block = sign_telemetry(args.key, args.decay, auth_hash_hex, args.integrity)
    if signed_block:
        # Add authority_id to the output for the harness
        if args.auth_id:
            signed_block["authority_id"] = args.auth_id
        else:
            signed_block["authority_id"] = "unknown"
            
        print(json.dumps(signed_block, indent=2))

if __name__ == "__main__":
    main()

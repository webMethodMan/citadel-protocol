import hashlib
import struct
import binascii
from ed25519 import SigningKey # Requires 'pip install ed25519' or similar

def generate_test_payload():
    # 1. Configuration
    ve_decay = 0.95
    authority_id = "mtcp-node-alpha"
    integrity_hash_hex = "0000000000000000000000000000000000000000000000000000000000000000"
    
    # Generate a random test key (In production, this is the MTCP Measurement Node's key)
    sk = SigningKey.generate()
    vk = sk.get_verifying_key()
    
    print(f"DEBUG: Using Test Public Key: {binascii.hexlify(vk.to_bytes()).decode()}")
    print(f"DEBUG: Set HEDERA_OPERATOR_PUBLIC_KEY={binascii.hexlify(vk.to_bytes()).decode()}")

    # 2. Hashing (Matching sakshi-core Sha3_256Hasher)
    auth_hash = hashlib.sha3_256(authority_id.encode()).digest()
    integ_hash = binascii.unhexlify(integrity_hash_hex)
    
    # 3. Serialize TelemetryState::to_bytes()
    # f64 big-endian + authority_hash + integrity_hash
    data = struct.pack(">d", ve_decay) + auth_hash + integ_hash
    
    # 4. Sign
    signature = sk.sign(data)
    
    # 5. Output JSON
    payload = {
        "jsonrpc": "2.0",
        "id": "1",
        "method": "citadel/attest",
        "params": {
            "tool_name": "attest",
            "telemetry": {
                "v_e_decay": ve_decay,
                "authority_id": authority_id,
                "integrity_hash": "0x" + integrity_hash_hex,
                "signature": binascii.hexlify(signature).decode()
            },
            "arguments": {
                "agent": "test-notary",
                "action": "verify"
            }
        }
    }
    
    import json
    print("\n--- TEST PAYLOAD ---")
    print(json.dumps(payload, indent=2))
    print("--- END ---")

if __name__ == "__main__":
    try:
        generate_test_payload()
    except ImportError:
        print("Error: 'ed25519' python library required. Run: pip install ed25519")

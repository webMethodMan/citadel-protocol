import os
import subprocess
import json
import time
import sys

# Configuration
TOPIC_ID = "0.0.8941781"
GATEWAY_URL = "http://127.0.0.1:9000/mcp"
BACKEND_PORT = 8080

# Rule Definition from green-blue-cyan
GREEN_BLUE_CYAN_ID = "sphere://demo/light/green-blue-cyan"
GREEN_BLUE_CYAN_HASH = "afdbddbb6ea91a3a6fa439d073d400a20fb6fd70fc0bf9b8b98c61feee560b6c"

# Rule Definition from white-transform
WHITE_TRANSFORM_ID = "sphere://demo/cmyk/white-transform"
WHITE_TRANSFORM_HASH = "afdbddbb6ea91a3a6fa439d073d400a20fb6fd70fc0bf9b8b98c61feee560b6c"

def run_command(cmd, wait=True):
    print(f"RUNNING: {' '.join(cmd)}")
    if wait:
        return subprocess.check_output(cmd).decode()
    else:
        return subprocess.Popen(cmd)

def setup_hiero_policy(tool_id, hash_hex):
    print(f"\n--- Establishing Ledger Registry Entry for {tool_id} ---")
    cmd = [
        "cargo", "run", "--quiet", "--bin", "anchor_policy", "-p", "citadel-adapter-hiero", "--",
        "--tool-id", tool_id,
        "--hash", hash_hex
    ]
    # Set Topic ID and Credentials for the tool (Bypassing non-persistent keyring)
    env = os.environ.copy()
    env["HIERO_TOPIC_ID"] = TOPIC_ID
    env["HIERO_OPERATOR_ID"] = "0.0.8812975"
    env["HIERO_OPERATOR_KEY"] = "302e020100300506032b657004220420c0280c523f7867de190c84ca0b0ddd7f392960673c573d1aef3c0bdae1f51768"
    subprocess.run(cmd, env=env, check=True)
    print("✅ Ledger Notarized.")

def main_menu():
    print("\n" + "="*60)
    print("       CITADEL PROTOCOL: COMPREHENSIVE E2E TEST SUITE")
    print("="*60)
    print("1.  [SUCCESS] RIOM Validated & Telemetry within bounds")
    print("2.  [FAIL]    Rule Hash Mismatch (Policy Drift)")
    print("3.  [FAIL]    Telemetry Out of Bounds (V_e threshold)")
    print("4.  [FAIL]    Unauthorized Tool Call (Not in Registry)")
    print("5.  [FAIL]    Telemetry Signature Invalid")
    print("99. Shutdown All Services")
    print("x.  Exit")
    
    choice = input("\nSelect a test scenario: ")
    return choice

def run_test(id, name, tool_name, hash, decay, tamper_signature=False):
    print(f"\n>>> SCENARIO {id}: {name}")
    
    # 1. Prepare Telemetry Block
    telemetry_cmd = [
        "python3", "tests/mock_mtcp_node.py",
        "--key", "9368a508b4761ec1979f32858940fd704aae094858272e668ae63f59009b5ece",
        "--decay", str(decay),
        "--auth-id", "theo-01"
    ]
    telemetry_raw = subprocess.check_output(telemetry_cmd).decode()
    telemetry = json.loads(telemetry_raw)
    
    if tamper_signature:
        telemetry["signature"] = "0" * 128
        print("⚠️  TAMPERING: Telemetry signature zeroed.")

    # 2. Construct MCP Request
    # Note: We put the rule hash in the 'mudra' field of arguments for this test
    # so the Gateway can extract it and verify against the ledger.
    payload = {
        "jsonrpc": "2.0",
        "method": "execute_mcp_tool",
        "params": {
            "tool_name": tool_name,
            "telemetry": telemetry,
            "arguments": {
                "rule_id": tool_name,
                "rule_hash": hash,
                "data": {"amount": 100}
            }
        },
        "id": id
    }
    
    # 3. Dispatch to Gateway
    print(f"SENDING: {tool_name}")
    try:
        import requests
        resp = requests.post(GATEWAY_URL, json=payload)
        print(f"RESPONSE (Status {resp.status_code}):")
        print(json.dumps(resp.json(), indent=2))
    except Exception as e:
        print(f"❌ Connection Error: {e}")

if __name__ == "__main__":
    # Ensure dependencies
    try:
        import requests
    except ImportError:
        print("Installing requests...")
        subprocess.run([sys.executable, "-m", "pip", "install", "requests"])

    while True:
        choice = main_menu()
        
        if choice == '1':
            # 1. SUCCESS: Valid rule anchored, valid telemetry
            setup_hiero_policy(GREEN_BLUE_CYAN_ID, GREEN_BLUE_CYAN_HASH)
            time.sleep(5) # Mirror node delay
            run_test(1, "SUCCESS - Integrated RIOM", GREEN_BLUE_CYAN_ID, GREEN_BLUE_CYAN_HASH, 0.98)
            
        elif choice == '2':
            # 2. FAIL: Rule hash on ledger is different (Policy Drift)
            setup_hiero_policy(WHITE_TRANSFORM_ID, "0" * 64) # Anchor invalid hash
            time.sleep(5)
            run_test(2, "FAIL - Rule Hash Mismatch", WHITE_TRANSFORM_ID, WHITE_TRANSFORM_HASH, 0.98)
            
        elif choice == '3':
            # 3. FAIL: Telemetry below 0.90 threshold
            setup_hiero_policy(GREEN_BLUE_CYAN_ID, GREEN_BLUE_CYAN_HASH)
            run_test(3, "FAIL - Telemetry Out of Bounds", GREEN_BLUE_CYAN_ID, GREEN_BLUE_CYAN_HASH, 0.85)
            
        elif choice == '4':
            # 4. FAIL: Tool not in registry
            run_test(4, "FAIL - Unauthorized Tool", "sphere://unknown/tool", "abc" * 16, 0.99)
            
        elif choice == '5':
            # 5. FAIL: Invalid Telemetry Signature
            setup_hiero_policy(GREEN_BLUE_CYAN_ID, GREEN_BLUE_CYAN_HASH)
            run_test(5, "FAIL - Invalid Telemetry Signature", GREEN_BLUE_CYAN_ID, GREEN_BLUE_CYAN_HASH, 0.99, tamper_signature=True)
            
        elif choice == 'x':
            break

import requests
import json
import time

GATEWAY_URL = "http://127.0.0.1:9000/mcp"

def truncate_json(obj):
    """Truncates long lists in JSON objects for cleaner logging."""
    if isinstance(obj, list):
        if len(obj) > 10:
            return obj[:5] + [f"... ({len(obj) - 10} more items) ..."] + obj[-5:]
        return [truncate_json(item) for item in obj]
    elif isinstance(obj, dict):
        return {k: truncate_json(v) for k, v in obj.items()}
    return obj

def format_compact_json(obj, indent=0):
    """Custom JSON formatter that keeps lists on one line."""
    spacing = " " * indent
    if isinstance(obj, dict):
        if not obj: return "{}"
        items = [f'\n{spacing}  "{k}": {format_compact_json(v, indent + 2)}' for k, v in obj.items()]
        return "{" + ",".join(items) + f"\n{spacing}}}"
    elif isinstance(obj, list):
        # Format list on a single line
        return "[" + ", ".join(json.dumps(x) for x in obj) + "]"
    else:
        return json.dumps(obj)

def run_test_case(payload):
    print(f"\n>>> SENDING PAYLOAD (ID: {payload.get('id')}):")
    print(format_compact_json(payload))
    
    try:
        response = requests.post(GATEWAY_URL, json=payload)
        print(f"<<< RECEIVED RESPONSE (Status: {response.status_code}):")
        try:
            resp_json = response.json()
            # Truncate for display but return full for validation
            display_json = truncate_json(resp_json)
            print(format_compact_json(display_json))
            return resp_json
        except:
            print(response.text)
            return None
            
    except Exception as e:
        print(f"!!! CONNECTION ERROR: {e}")
        return None
    print("-" * 60)

MOCK_TELEMETRY = {
    "v_e_decay": 0.95,
    "authority_id": "theo-01",
    "integrity_hash": "0x" + ("0" * 64),
    "signature": "0" * 128
}

test_cases = [
    # 1. Authorized Tool Call (Proxy Mode)
    {
        "jsonrpc": "2.0", 
        "method": "execute_mcp_tool", 
        "params": {
            "tool_name": "webMethods_Flow_Alpha", 
            "telemetry": MOCK_TELEMETRY,
            "arguments": {"amount": 100}
        }, 
        "id": 201
    },
    
    # 2. Unauthorized/Restricted Tool Call (Policy Refusal)
    {
        "jsonrpc": "2.0", 
        "method": "execute_mcp_tool", 
        "params": {
            "tool_name": "Restricted_Admin_Service", 
            "telemetry": MOCK_TELEMETRY,
            "arguments": {}
        }, 
        "id": 202
    },

    # 3. Admissibility Refusal (V_e threshold fail)
    {
        "jsonrpc": "2.0",
        "method": "execute_mcp_tool",
        "params": {
            "tool_name": "webMethods_Flow_Alpha",
            "telemetry": {
                **MOCK_TELEMETRY,
                "v_e_decay": 0.85 # Below 0.90 threshold
            },
            "arguments": {"amount": 100}
        },
        "id": 203
    },

    # 4. Telemetry Missing
    {
        "jsonrpc": "2.0",
        "method": "execute_mcp_tool",
        "params": {
            "tool_name": "webMethods_Flow_Alpha",
            "arguments": {"amount": 100}
        },
        "id": 204
    },

    # 5. Notary Success (attest tool)
    {
        "jsonrpc": "2.0",
        "method": "execute_mcp_tool",
        "params": {
            "tool_name": "attest",
            "telemetry": MOCK_TELEMETRY,
            "arguments": {"action": "verify"}
        },
        "id": 205
    },

    # 6. Proxy Target Error (Broken URL)
    {
        "jsonrpc": "2.0",
        "method": "execute_mcp_tool",
        "params": {
            "tool_name": "Broken_Target_Tool",
            "telemetry": MOCK_TELEMETRY,
            "arguments": {}
        },
        "id": 206
    },

    # 7. Nested Telemetry (in arguments)
    {
        "jsonrpc": "2.0",
        "method": "execute_mcp_tool",
        "params": {
            "arguments": {
                "tool_name": "webMethods_Flow_Alpha",
                "telemetry": MOCK_TELEMETRY,
                "amount": 100
            }
        },
        "id": 207
    },

    # 8. Standard MCP Initialize
    {
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test-harness", "version": "1.0.0"}
        },
        "id": 208
    },
    
    # 999. Citadel Shutdown (Notary Mode)
    {
        "jsonrpc": "2.0", 
        "method": "citadel_shutdown", 
        "params": {
            "tool_name": "shutdown", 
            "telemetry": MOCK_TELEMETRY,
            "arguments": {}
        }, 
        "id": 999
    }
]

def display_menu():
    print("\n--- CITADEL INTERACTIVE TEST HARNESS ---")
    print("1.  [201] Authorized Proxy (webMethods Alpha)")
    print("2.  [202] Policy Refusal (Restricted Admin)")
    print("3.  [203] Admissibility Refusal (V_e = 0.85)")
    print("4.  [204] Telemetry Missing")
    print("5.  [205] Notary Success (attest tool)")
    print("6.  [206] Proxy Target Error (Broken URL)")
    print("7.  [207] Nested Telemetry (in arguments)")
    print("8.  [208] Standard MCP Initialize")
    print("999. Citadel Shutdown (Notary: shutdown)")
    print("x.   Exit Test Menu")
    return input("\nSelect a test to run: ").strip().lower()

if __name__ == "__main__":
    test_map = {str(case["id"]): case for case in test_cases}
    # Add menu shortcuts
    for i in range(1, 9):
        id_str = str(200 + i)
        if id_str in test_map:
            test_map[str(i)] = test_map[id_str]

    while True:
        choice = display_menu()
        
        if choice == 'x':
            print("Exiting test harness.")
            break
            
        case = test_map.get(choice)
        if not case:
            print(f"Invalid selection: {choice}")
            continue

        resp = run_test_case(case)
        cid = case["id"]
        
        if cid == 201:
            if resp and "result" in resp and "witness_token" in str(resp["result"]):
                print("STATUS: ✅ PROXY VERIFIED. Received response from legacy backend.")
            else:
                print("STATUS: ❌ PROXY FAILED. Unexpected result format.")
                
        elif cid == 202:
            if resp and "error" in resp and "Policy refusal" in resp["error"]["message"]:
                 print("STATUS: ✅ POLICY GATE VERIFIED. Unauthorized tool rejected.")
            else:
                print("STATUS: ❌ POLICY GATE FAILED. Tool should have been rejected.")

        elif cid == 203:
            if resp and "error" in resp and resp["error"]["code"] == -32001 and "Admissibility Failure" in resp["error"]["message"]:
                 print("STATUS: ✅ ADMISSIBILITY GATE VERIFIED. Low V_e rejected.")
            else:
                print("STATUS: ❌ ADMISSIBILITY GATE FAILED. Low V_e should have been rejected.")

        elif cid == 204:
            if resp and "error" in resp and "Telemetry missing" in resp["error"]["message"]:
                 print("STATUS: ✅ TELEMETRY CHECK VERIFIED. Missing block caught.")
            else:
                print("STATUS: ❌ TELEMETRY CHECK FAILED. Should have caught missing block.")

        elif cid == 205:
            if resp and "result" in resp and "provenance" in resp:
                 print("STATUS: ✅ NOTARY VERIFIED. attest tool returned structured Mudra.")
            else:
                print("STATUS: ❌ NOTARY FAILED. Expected structured result.")

        elif cid == 206:
            if resp and "error" in resp and "Proxy Error" in resp["error"]["message"]:
                 print("STATUS: ✅ PROXY ERROR VERIFIED. Caught broken backend connection.")
            else:
                print("STATUS: ❌ PROXY ERROR FAILED. Should have reported backend error.")

        elif cid == 207:
            if resp and "result" in resp and "witness_token" in str(resp["result"]):
                print("STATUS: ✅ NESTED EXTRACTION VERIFIED. Telemetry pulled from arguments.")
            else:
                print("STATUS: ❌ NESTED EXTRACTION FAILED. Could not find nested telemetry.")

        elif cid == 208:
            if resp and "result" in resp and "protocolVersion" in resp["result"]:
                print("STATUS: ✅ MCP HANDSHAKE VERIFIED. Server responded to initialize.")
            else:
                print("STATUS: ❌ MCP HANDSHAKE FAILED. Unexpected initialization response.")

        elif cid == 999:
            if resp and "result" in resp and "provenance" in resp:
                 print("STATUS: ✅ NOTARY VERIFIED. Received structured result with provenance.")
            else:
                print("STATUS: ❌ NOTARY FAILED. Expected structured result with provenance.")

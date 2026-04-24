import requests
import json

GATEWAY_URL = "http://127.0.0.1:9000/messages"

def test_tool_call(name, tool_name, expected_status):
    print(f"--- Running Test: {name} ---")
    
    # Mocking a standard MCP JSON-RPC call
    payload = {
        "jsonrpc": "2.0",
        "method": "execute_mcp_tool",
        "params": {
            "tool_name": tool_name,
            "arguments": {"action": "sync"}
        },
        "id": 101
    }
    
    try:
        response = requests.post(GATEWAY_URL, json=payload)
        result = response.json()
        
        if "result" in result:
            data = result["result"]
            if isinstance(data, dict) and "certificate" in data:
                print("STATUS: ✅ Authorized (Sakshi Mudra Issued)")
                print(f"CERTIFICATE SUBJECT: {data.get('subject', 'Unknown')}")
                print("PEM PREVIEW:")
                cert_lines = data['certificate'].split('\n')
                print('\n'.join(cert_lines[:2]) + "\n...\n" + '\n'.join(cert_lines[-3:]))
            elif "success" in str(data):
                 print("STATUS: ✅ Authorized")
            else:
                 print(f"STATUS: ✅ Authorized (Result: {data})")
        else:
            print(f"STATUS: ❌ Refused ({result.get('error', {}).get('message', 'Unknown Error')})")
            
    except Exception as e:
        print(f"CONNECTION ERROR: {e}")
    print("-" * 40)

# 1. Test Authorized Flow (webMethods Alpha)
test_tool_call("Authorized Legacy Access", "webMethods_Flow_Alpha", "success")

# 2. Test Policy Refusal (Restricted Service)
test_tool_call("Unauthorized Intent Access", "Restricted_Admin_Service", "error")

# 3. Test Invalid Protocol (Malformed Call)
test_tool_call("Protocol Mismatch", "unknown_tool", "error")

import requests
import json
import time

GATEWAY_URL = "http://127.0.0.1:9000/messages"

def run_test_case(payload):
    print(f"\n>>> SENDING PAYLOAD (ID: {payload.get('id')}):")
    print(json.dumps(payload, indent=2))
    
    try:
        response = requests.post(GATEWAY_URL, json=payload)
        print(f"<<< RECEIVED RESPONSE (Status: {response.status_code}):")
        try:
            resp_json = response.json()
            print(json.dumps(resp_json, indent=2))
            return resp_json
        except:
            print(response.text)
            return None
            
    except Exception as e:
        print(f"!!! CONNECTION ERROR: {e}")
        return None
    print("-" * 60)

test_cases = [
    # 1. Authorized Tool Call (Proxy Mode)
    {
        "jsonrpc": "2.0", 
        "method": "execute_mcp_tool", 
        "params": {"tool_name": "webMethods_Flow_Alpha", "arguments": {"amount": 100}}, 
        "id": 201
    },
    
    # 2. Unauthorized/Restricted Tool Call
    {
        "jsonrpc": "2.0", 
        "method": "execute_mcp_tool", 
        "params": {"tool_name": "Restricted_Admin_Service", "arguments": {}}, 
        "id": 202
    },
    
    # 3. Citadel Shutdown (Notary Mode)
    {
        "jsonrpc": "2.0", 
        "method": "citadel_shutdown", 
        "params": {"tool_name": "shutdown", "arguments": {}}, 
        "id": 999
    }
]

if __name__ == "__main__":
    print("=== CITADEL INTEGRATION HARNESS: HYBRID ROUTING TEST START ===")
    
    for case in test_cases:
        resp = run_test_case(case)
        
        if case["id"] == 201:
            if resp and "result" in resp and "witness_token" in str(resp["result"]):
                print("STATUS: ✅ PROXY VERIFIED. Received response from legacy backend.")
            else:
                print("STATUS: ❌ PROXY FAILED. Unexpected result format.")
                
        elif case["id"] == 202:
            if resp and "error" in resp and resp["error"]["code"] == -32001:
                 print("STATUS: ✅ SECURITY GATE VERIFIED. Unauthorized tool rejected.")
            else:
                print("STATUS: ❌ SECURITY GATE FAILED. Tool should have been rejected.")

        elif case["id"] == 999:
            if resp and "result" in resp and len(str(resp["result"])) == 64:
                 print("STATUS: ✅ NOTARY VERIFIED. Received raw Mudra hex.")
            else:
                print("STATUS: ❌ NOTARY FAILED. Expected raw Mudra result.")

    print("=== CITADEL INTEGRATION HARNESS: TEST SEQUENCE COMPLETE ===")

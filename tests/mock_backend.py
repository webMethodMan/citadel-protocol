from http.server import BaseHTTPRequestHandler, HTTPServer
import json

class MockBackendHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        mudra = self.headers.get('X-Sakshi-Mudra')
        
        print(f"\n[MOCK BACKEND] Received request!")
        print(f"[MOCK BACKEND] X-Sakshi-Mudra: {mudra}")
        print(f"[MOCK BACKEND] Payload: {post_data.decode('utf-8')}")
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        
        response = {
            "status": "success",
            "message": "Legacy System Executed",
            "witness_token": mudra[:16]
        }
        self.wfile.write(json.dumps(response).encode('utf-8'))

def run(server_class=HTTPServer, handler_class=MockBackendHandler, port=8080):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f"Starting Mock Legacy Backend on port {port}...")
    httpd.serve_forever()

if __name__ == "__main__":
    run()

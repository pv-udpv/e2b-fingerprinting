#!/usr/bin/env python3
"""HTTP Echo Server - Connection metadata for E2B fingerprinting"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import json, socket
from datetime import datetime

class EchoHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"[{datetime.now():%H:%M:%S}] {fmt % args}")
    
    def do_GET(self):
        client_ip, client_port = self.client_address
        metadata = {
            'client': {'ip': client_ip, 'port': client_port},
            'server': {'time': datetime.now().isoformat(), 'host': socket.gethostname()},
            'request': {'method': self.command, 'path': self.path, 
                       'protocol': self.request_version, 'headers': dict(self.headers)}
        }
        resp = json.dumps(metadata, indent=2).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(resp)

if __name__ == '__main__':
    PORT = 8080
    print(f"HTTP Echo: 0.0.0.0:{PORT}")
    HTTPServer(('0.0.0.0', PORT), EchoHandler).serve_forever()

#!/usr/bin/env python3
"""HTTPS Echo - TLS cipher/version fingerprinting"""
import ssl, socket, json
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

class TLSHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            cipher = self.connection.cipher()
            tls_ver = self.connection.version()
        except:
            cipher, tls_ver = ('unknown', 'unknown')
        
        metadata = {
            'client': {'ip': self.client_address[0], 'port': self.client_address[1]},
            'tls': {'cipher': cipher, 'version': tls_ver},
            'request': {'path': self.path, 'headers': dict(self.headers)}
        }
        resp = json.dumps(metadata, indent=2).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(resp)

if __name__ == '__main__':
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.check_hostname = False
    ctx.load_cert_chain('/root/cert.pem', '/root/key.pem')
    
    server = HTTPServer(('0.0.0.0', 8443), TLSHandler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    print("HTTPS Echo: 0.0.0.0:8443")
    server.serve_forever()

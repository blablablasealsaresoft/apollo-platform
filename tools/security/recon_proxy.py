#!/usr/bin/env python3
"""Simple logging proxy for recon traffic."""
import http.server
import socketserver
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8081

class LoggingProxy(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        print(f"[recon] {self.client_address[0]} -> {self.path}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Apollo Recon Proxy")

with socketserver.TCPServer(("", PORT), LoggingProxy) as httpd:
    print(f"Recon proxy listening on {PORT}")
    httpd.serve_forever()

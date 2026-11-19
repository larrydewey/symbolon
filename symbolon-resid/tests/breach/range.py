#!/usr/bin/env python3
"""A stand-in for the Pwned Passwords range API, for tests/breach_e2e.sh.

    range.py PORT CERT KEY QUERYLOG PASSWORD...

Serves GET /range/PREFIX over HTTPS. The corpus is the passwords given on
the command line ("password" with count 9659365, every other one 4242),
plus 800 random suffixes under each prefix. Each answer is padded with
count-0 lines when the request carries "Add-Padding: true". Every request
is logged as "PATH padding" or "PATH plain".
"""
import hashlib, http.server, os, ssl, sys

port, cert, key, qlog = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
corpus = {}
for pw in sys.argv[5:]:
    h = hashlib.sha1(pw.encode()).hexdigest().upper()
    corpus.setdefault(h[:5], {})[h[5:]] = 9659365 if pw == 'password' else 4242


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        padded = self.headers.get('Add-Padding', '').lower() == 'true'
        with open(qlog, 'a') as f:
            f.write(f"{self.path} {'padding' if padded else 'plain'}\n")
        if not self.path.startswith('/range/') or len(self.path) != 12:
            self.send_response(400); self.end_headers(); return
        prefix = self.path[7:].upper()
        rows = [(os.urandom(18).hex().upper()[:35], 1 + b) for b in os.urandom(800)]
        rows += list(corpus.get(prefix, {}).items())
        if padded:
            rows += [(os.urandom(18).hex().upper()[:35], 0) for _ in range(200)]
        rows.sort()
        body = '\r\n'.join(f'{s}:{n}' for s, n in rows).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


srv = http.server.HTTPServer(('127.0.0.1', port), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.load_cert_chain(cert, key)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()

#!/usr/bin/env python3
"""The demo stack's helper for a phone (tools/demo.sh --lan): what a new
device needs to join, and pairing it with the cosigner. Demo only: it hands
out test-fixture Paillier primes and pairs whoever asks.

    demo_helper.py DEMO_DIR BIN PORT SETUP_JSON

GET  /setup  the relay, the cosigner's keys, the witnesses and the primes
POST /pair   body: the new device's keys (hex, printed by device new);
             runs `symbolon cosigner pair DEMO_DIR/cos KEYS`
"""
import http.server, json, re, subprocess, sys

DEMO, BIN, PORT, SETUP = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]


class H(http.server.BaseHTTPRequestHandler):
    def reply(self, code, body, ctype='application/json'):
        b = body.encode()
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path != '/setup':
            return self.reply(404, '{}')
        self.reply(200, open(SETUP).read())

    def do_POST(self):
        if self.path != '/pair':
            return self.reply(404, '{}')
        n = int(self.headers.get('Content-Length', '0'))
        keys = self.rfile.read(min(n, 4096)).decode().strip()
        if not re.fullmatch(r'[0-9a-f]{64,2048}', keys):
            return self.reply(400, json.dumps({'error': 'not device keys'}))
        r = subprocess.run([BIN, 'cosigner', 'pair', f'{DEMO}/cos', keys], capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            return self.reply(500, json.dumps({'error': (r.stderr or r.stdout).strip()[-300:]}))
        self.reply(200, json.dumps({'paired': True}))

    def log_message(self, fmt, *a):
        sys.stderr.write('helper: ' + fmt % a + '\n')


http.server.ThreadingHTTPServer(('0.0.0.0', PORT), H).serve_forever()

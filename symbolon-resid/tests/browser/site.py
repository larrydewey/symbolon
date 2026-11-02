#!/usr/bin/env python3
# Test sites for tests/browser_e2e.sh, all on one HTTPS port; the browser
# maps every host name here (--host-resolver-rules), so each page keeps its
# real origin: https://shop.example (a checkout with a payment processor's
# frame and an ad frame, and a sign-in page), https://js.stripe.com (the
# processor's card fields) and https://ads.example (a frame that must get
# nothing).
import http.server, ssl, sys

PAGES = {
    ("shop.example", "/checkout"): """<!doctype html><title>checkout</title>
<form><input id=name autocomplete=cc-name></form>
<iframe id=pay src="https://js.stripe.com/fields" width=400 height=200></iframe>
<iframe id=ad src="https://ads.example/frame" width=400 height=200></iframe>""",
    ("shop.example", "/login"): """<!doctype html><title>login</title>
<form><input id=user type=text name=login><input id=pw type=password name=pw><button>Sign in</button></form>""",
    ("js.stripe.com", "/fields"): """<!doctype html><title>pay</title>
<input id=num autocomplete=cc-number><input id=exp autocomplete=cc-exp placeholder="MM / YY"><input id=cvc autocomplete=cc-csc>
<input id=pw type=password>""",
    ("ads.example", "/frame"): """<!doctype html><title>ad</title>
<input id=num name=cardnumber><input id=pw type=password>""",
}

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        host = (self.headers.get("Host") or "").split(":")[0]
        body = PAGES.get((host, self.path))
        if body is None:
            self.send_response(404); self.end_headers(); return
        b = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)
    def log_message(self, *a): pass

port, cert, key = int(sys.argv[1]), sys.argv[2], sys.argv[3]
srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(cert, key)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
print("ready", flush=True)
srv.serve_forever()

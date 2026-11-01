#!/usr/bin/env python3
"""A local WebAuthn relying party for trying the passkey provider: a page
with Register and Sign in, checked by python-fido2's server. Runs on
localhost (a secure context without TLS); for an emulator or a phone over
USB, `adb reverse tcp:8765 tcp:8765` and open http://localhost:8765.

    tools/webauthn_site.py [port]

Each verified result is printed and appended to webauthn_site.log.
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity, UserVerificationRequirement, ResidentKeyRequirement
from fido2.utils import websafe_encode, websafe_decode

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
server = Fido2Server(PublicKeyCredentialRpEntity(id="localhost", name="Symbolon test site"), verify_origin=lambda o: o.startswith("http://localhost"))
state = {}
creds = []


def log(m):
    print(m, flush=True)
    with open("webauthn_site.log", "a") as f:
        f.write(m + "\n")


def jsonable(x):
    return json.loads(json.dumps(dict(x), default=lambda v: websafe_encode(v) if isinstance(v, bytes) else str(v)))


PAGE = """<!doctype html><meta name=viewport content="width=device-width,initial-scale=1">
<title>Symbolon test site</title>
<style>body{font-family:sans-serif;margin:24px}button{font-size:20px;padding:14px;width:100%;margin:8px 0}#out{white-space:pre-wrap}</style>
<h1>Symbolon test site</h1>
<button id=reg>Register a passkey</button><button id=auth>Sign in with a passkey</button><p id=out></p>
<script>
const b64 = s => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0));
const enc = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const out = m => document.getElementById('out').textContent = m;
async function post(p, body) { const r = await fetch(p, {method:'POST', body: JSON.stringify(body||{})}); return r.json(); }
// Older browsers have no parse*FromJSON / toJSON: convert by hand.
const ids = l => (l || []).map(c => ({...c, id: b64(c.id)}));
function creation(o) { return {...o, challenge: b64(o.challenge), user: {...o.user, id: b64(o.user.id)}, excludeCredentials: ids(o.excludeCredentials)}; }
function request(o) { return {...o, challenge: b64(o.challenge), allowCredentials: ids(o.allowCredentials)}; }
function json(c) {
  const r = c.response, x = {id: c.id, rawId: enc(c.rawId), type: c.type, clientExtensionResults: c.getClientExtensionResults(), response: {clientDataJSON: enc(r.clientDataJSON)}};
  if (r.attestationObject) x.response.attestationObject = enc(r.attestationObject);
  if (r.authenticatorData) x.response.authenticatorData = enc(r.authenticatorData);
  if (r.signature) x.response.signature = enc(r.signature);
  if (r.userHandle) x.response.userHandle = enc(r.userHandle);
  return x;
}
document.getElementById('reg').onclick = async () => {
  try {
    const o = await post('/register/begin');
    const c = await navigator.credentials.create({publicKey: creation(o.publicKey)});
    out('Registered: ' + JSON.stringify(await post('/register/complete', json(c))));
  } catch (e) { out('Register failed: ' + e); }
};
document.getElementById('auth').onclick = async () => {
  try {
    const o = await post('/authenticate/begin');
    const c = await navigator.credentials.get({publicKey: request(o.publicKey)});
    out('Signed in: ' + JSON.stringify(await post('/authenticate/complete', json(c))));
  } catch (e) { out('Sign-in failed: ' + e); }
};
</script>"""


class H(BaseHTTPRequestHandler):
    def reply(self, code, body, ctype="application/json"):
        b = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        self.reply(200, PAGE, "text/html")

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        try:
            if self.path == "/register/begin":
                opts, state["reg"] = server.register_begin(
                    PublicKeyCredentialUserEntity(id=b"user-1", name="alice@example.com", display_name="Alice"),
                    creds, resident_key_requirement=ResidentKeyRequirement.REQUIRED, user_verification=UserVerificationRequirement.REQUIRED)
                return self.reply(200, json.dumps(jsonable(opts)))
            if self.path == "/register/complete":
                auth = server.register_complete(state.pop("reg"), body)
                creds.append(auth.credential_data)
                log(f"REGISTERED credential {auth.credential_data.credential_id.hex()} flags {auth.flags:#04x} aaguid {auth.credential_data.aaguid}")
                return self.reply(200, json.dumps({"ok": True, "credential": websafe_encode(auth.credential_data.credential_id)}))
            if self.path == "/authenticate/begin":
                opts, state["auth"] = server.authenticate_begin(creds, user_verification=UserVerificationRequirement.REQUIRED)
                return self.reply(200, json.dumps(jsonable(opts)))
            if self.path == "/authenticate/complete":
                c = server.authenticate_complete(state.pop("auth"), creds, body)
                handle = body.get("response", {}).get("userHandle")
                log(f"SIGNED IN with {c.credential_id.hex()} user handle {websafe_decode(handle) if handle else None}")
                return self.reply(200, json.dumps({"ok": True, "user": websafe_decode(handle).decode() if handle else None}))
        except Exception as e:
            log(f"REFUSED {self.path}: {e!r}")
            return self.reply(400, json.dumps({"ok": False, "error": repr(e)}))
        self.reply(404, "{}")

    def log_message(self, *a):
        pass


log(f"Symbolon test site on http://localhost:{PORT}")
ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()

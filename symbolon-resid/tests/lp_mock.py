#!/usr/bin/env python3
"""A stand-in for LastPass's servers, for tests/lastpass_e2e.sh: the
endpoints and formats lastpass-cli uses (iterations.php, login.php with its
XML answers and two-step causes, getaccts.php and its blob), built from
lastpass-cli's endpoints-login.c, kdf.c, blob.c and cipher.c with Python's
cryptography, independently of the Resid code under test. There is no
LastPass account to test against.

  lp_mock.py PORT CERT KEY STATE.json

Accounts (in STATE.json, written at start):
  alice@example.com  600000 iterations; logins (CBC, ECB and GCM fields), a
                     custom field, typed secure notes (a card, a bank
                     account), a deleted account, and a shared folder
                     (its key RSA-OAEP-SHA-1 to her private key, as hex)
  bob@example.com    600000 iterations; a Google Authenticator code (TOTP)
  weak@example.com   5000 iterations (to be refused)
"""
import base64, binascii, hashlib, hmac, http.server, json, os, ssl, struct, sys, time, urllib.parse

from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import padding as apad, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ITER = 600000


def key_of(email, pw, n):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), email.encode(), n, 32)


def hash_of(email, pw, n):
    return hashlib.pbkdf2_hmac("sha256", key_of(email, pw, n), pw.encode(), 1, 32).hex()


def pad(d):
    p = padding.PKCS7(128).padder()
    return p.update(d) + p.finalize()


def cbc(k, d, iv=None):
    iv = iv or os.urandom(16)
    e = Cipher(algorithms.AES(k), modes.CBC(iv)).encryptor()
    return iv, e.update(pad(d)) + e.finalize()


def enc_cbc(k, s):
    iv, ct = cbc(k, s.encode() if isinstance(s, str) else s)
    return b"!" + iv + ct


def enc_ecb(k, s):
    e = Cipher(algorithms.AES(k), modes.ECB()).encryptor()
    return e.update(pad(s.encode())) + e.finalize()


def enc_gcm(k, s):
    iv = os.urandom(12)
    return b"#" + iv + AESGCM(k).encrypt(iv, s.encode(), None)


def text_cbc(k, s):
    iv, ct = cbc(k, s.encode())
    return "!" + base64.b64encode(iv).decode() + "|" + base64.b64encode(ct).decode()


def item(b):
    return struct.pack(">I", len(b)) + b


def chunk(name, data):
    return name.encode() + struct.pack(">I", len(data)) + data


def acct(k, aid, name, group, url, note, user, pw, enc=enc_cbc, deleted=False, url_hex=True):
    f = [aid.encode(), enc(k, name), enc(k, group) if group else b"", binascii.hexlify(url.encode()) if url_hex else enc(k, url),
         enc(k, note) if note else b"", b"0", b"", enc(k, user) if user else b"", enc(k, pw) if pw else b"", b"0", b"0", b"0", b"0"]
    f += [b""] * 12  # autologin .. groupid
    f += [b"1" if deleted else b"0"]  # deleted (26th)
    f += [b"", b"0", b"0", b"", b"0", b"0", b"0", b"0", b"0", b"0"]
    return chunk("ACCT", b"".join(item(x) for x in f))


def acfl(k, name, typ, value):
    return chunk("ACFL", b"".join(item(x) for x in [name.encode(), typ.encode(), enc_cbc(k, value), b"0"]))


def build(state):
    accounts = {}
    # Alice
    a_email, a_pw = "alice@example.com", "correct horse battery staple"
    k = key_of(a_email, a_pw, ITER)
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    der = priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    pke = text_cbc(k, "LastPassPrivateKey<" + der.hex().upper() + ">LastPassPrivateKey")
    share_key = os.urandom(32)
    share_ct = priv.public_key().encrypt(share_key.hex().encode(), apad.OAEP(mgf=apad.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None))
    card = "NoteType:Credit Card\nLanguage:en-US\nName on Card:Alice Example\nType:Visa\nNumber:4111111111111111\nSecurity Code:123\nStart Date:,\nExpiration Date:April,2030\nNotes:the travel card\nkeep it safe"
    bank = "NoteType:Bank Account\nBank Name:First Bank\nAccount Type:Checking\nRouting Number:021000021\nAccount Number:987654321\nSWIFT Code:\nIBAN Number:\nPin:4321\nNotes:"
    blob = chunk("LPAV", b"300")
    blob += acct(k, "1", "bank", "Finance\\Banks", "https://bank.example", "joint account", "alice", "s3cret-bank")
    blob += acfl(k, "PIN hint", "password", "birthday")
    blob += acct(k, "2", "mail", "", "https://mail.example", "", "alice@mail.example", "m4il-pass", enc=enc_ecb)
    blob += acct(k, "3", "news", "", "https://news.example", "", "reader", "n3ws-pass", enc=enc_gcm)
    blob += acct(k, "4", "travel card", "Cards", "http://sn", card, "", "")
    blob += acct(k, "5", "bank details", "", "http://sn", bank, "", "")
    blob += acct(k, "6", "old login", "", "https://old.example", "", "old", "old", deleted=True)
    blob += acct(k, "7", "plain note", "", "http://sn", "the wifi is in the hall", "", "")
    blob += chunk("SHAR", b"".join(item(x) for x in [b"9", share_ct.hex().encode(), text_cbc(share_key, "Family").encode(), b"0"]))
    blob += acct(share_key, "8", "family streaming", "", "https://stream.example", "", "family", "str3am")
    blob += chunk("ENDM", b"OK")
    accounts[a_email] = {"pw": a_pw, "iter": ITER, "otp": None, "blob": blob.hex(), "pke": pke}
    # Bob: a Google Authenticator code
    b_email, b_pw = "bob@example.com", "bob's long passphrase"
    kb = key_of(b_email, b_pw, ITER)
    secret = base64.b32encode(os.urandom(20)).decode().rstrip("=")
    bblob = chunk("LPAV", b"300") + acct(kb, "1", "router", "", "https://192.168.1.1", "", "admin", "r0uter") + chunk("ENDM", b"OK")
    accounts[b_email] = {"pw": b_pw, "iter": ITER, "otp": secret, "blob": bblob.hex(), "pke": ""}
    # Carol: approves on her phone (LastPass Authenticator push); the
    # mock approves on the second poll.
    c_email, c_pw = "carol@example.com", "carol's passphrase"
    kc = key_of(c_email, c_pw, ITER)
    cblob = chunk("LPAV", b"300") + acct(kc, "1", "printer", "", "https://printer.example", "", "carol", "pr1nt") + chunk("ENDM", b"OK")
    accounts[c_email] = {"pw": c_pw, "iter": ITER, "otp": None, "push": True, "blob": cblob.hex(), "pke": ""}
    accounts["weak@example.com"] = {"pw": "weak", "iter": 5000, "otp": None, "blob": "", "pke": ""}
    json.dump(accounts, open(state, "w"))
    return accounts


def totp(secret_b32, t=None):
    k = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))
    c = int((t or time.time()) // 30)
    d = hmac.new(k, struct.pack(">Q", c), hashlib.sha1).digest()
    o = d[-1] & 15
    return f"{(struct.unpack('>I', d[o:o + 4])[0] & 0x7fffffff) % 1000000:06d}"


ACCOUNTS = {}
SESSIONS = {}
POLLS = {}


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, body, ctype="text/xml"):
        b = body if isinstance(body, bytes) else body.encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        f = {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(n).decode(), keep_blank_values=True).items()}
        if self.path == "/iterations.php":
            a = ACCOUNTS.get(f.get("email", ""))
            return self.reply(str(a["iter"] if a else ITER), "text/plain")
        if self.path == "/login.php":
            a = ACCOUNTS.get(f.get("username", ""))
            if not a or f.get("hash") != hash_of(f["username"], a["pw"], a["iter"]) or f.get("iterations") != str(a["iter"]):
                return self.reply('<response><error message="Invalid password!" cause="unknownpassword"/></response>')
            if a["otp"]:
                if "otp" not in f:
                    return self.reply('<response><error message="Google Authenticator authentication required!" cause="googleauthrequired"/></response>')
                if f["otp"] not in (totp(a["otp"]), totp(a["otp"], time.time() - 30)):
                    return self.reply('<response><error message="Google Authenticator authentication failed!" cause="googleauthfailed"/></response>')
            if a.get("push"):
                if f.get("outofbandretry") == "1" and f.get("outofbandretryid") == "r1":
                    POLLS[f["username"]] = POLLS.get(f["username"], 0) + 1
                    if POLLS[f["username"]] < 2:
                        return self.reply('<response><error cause="outofbandrequired" retryid="r1" outofbandname="LastPass Authenticator"/></response>')
                elif f.get("outofbandrequest") == "1":
                    return self.reply('<response><error cause="outofbandrequired" retryid="r1" outofbandname="LastPass Authenticator"/></response>')
                else:
                    return self.reply('<response><error message="Multifactor authentication required!" cause="outofbandrequired" outofbandname="LastPass Authenticator" capabilities="outofband"/></response>')
            sid = binascii.hexlify(os.urandom(12)).decode()
            SESSIONS[sid] = f["username"]
            return self.reply(f'<response><ok uid="1" sessionid="{sid}" token="tok{sid}" privatekeyenc="{a["pke"]}" lpusername="{f["username"]}"/></response>')
        if self.path == "/getaccts.php":
            c = self.headers.get("Cookie", "")
            sid = c.split("PHPSESSID=")[-1].split(";")[0] if "PHPSESSID=" in c else ""
            if sid not in SESSIONS or f.get("token") != "tok" + sid:
                self.send_response(403)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            return self.reply(bytes.fromhex(ACCOUNTS[SESSIONS[sid]]["blob"]), "application/octet-stream")
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()


if __name__ == "__main__":
    if sys.argv[1] == "totp":
        print(totp(sys.argv[2]))
        sys.exit(0)
    port, cert, key, state = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
    ACCOUNTS.update(build(state))
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print("ready", flush=True)
    srv.serve_forever()

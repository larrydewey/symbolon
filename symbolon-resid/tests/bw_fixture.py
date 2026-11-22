#!/usr/bin/env python3
"""A small Bitwarden client for tests/bitwarden_e2e.sh: registers accounts on
a local Vaultwarden and fills them with items, encrypted the way Bitwarden's
own apps encrypt them (independently of the Resid code under test).

  bw_fixture.py setup URL CA OUT.json   accounts and items; OUT.json lists
                                        what an import must bring across
  bw_fixture.py totp SECRET-BASE32      the current authenticator code

Crypto (Bitwarden security whitepaper): master key = PBKDF2-SHA256 or
Argon2id over the password with the email as salt; login hash = base64
PBKDF2(master key, password, 1); stretched key = HKDF-Expand(master key,
"enc"/"mac"); EncString type 2 = AES-256-CBC + HMAC-SHA-256 over iv||ct;
organization keys are RSA-OAEP-SHA-1 (type 4) to the user's public key.
"""
import base64, hashlib, hmac, json, os, struct, sys, time, uuid

import requests
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding as apad, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

b64 = lambda b: base64.b64encode(b).decode()
b64url = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")


def hkdf_expand(k, info):
    return HKDFExpand(hashes.SHA256(), 32, info.encode()).derive(k)


def master_key(password, email, kdf):
    salt = email.strip().lower().encode()
    if kdf["kdf"] == 1:
        return Argon2id(salt=hashlib.sha256(salt).digest(), length=32, iterations=kdf["kdfIterations"],
                        lanes=kdf["kdfParallelism"], memory_cost=kdf["kdfMemory"] * 1024).derive(password.encode())
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, kdf["kdfIterations"], 32)


def login_hash(mk, password):
    return b64(hashlib.pbkdf2_hmac("sha256", mk, password.encode(), 1, 32))


def enc(key64, data):
    if isinstance(data, str):
        data = data.encode()
    iv = os.urandom(16)
    p = padding.PKCS7(128).padder()
    e = Cipher(algorithms.AES(key64[:32]), modes.CBC(iv)).encryptor()
    ct = e.update(p.update(data) + p.finalize()) + e.finalize()
    mac = hmac.new(key64[32:], iv + ct, hashlib.sha256).digest()
    return f"2.{b64(iv)}|{b64(ct)}|{b64(mac)}"


class Client:
    def __init__(self, url, ca):
        self.url, self.ca, self.token = url, ca, None
        self.dev = str(uuid.uuid4())

    def call(self, method, path, **kw):
        h = kw.pop("headers", {})
        if self.token:
            h["Authorization"] = "Bearer " + self.token
        r = requests.request(method, self.url + path, verify=self.ca, headers=h, timeout=60, **kw)
        if r.status_code >= 400:
            raise SystemExit(f"{method} {path}: {r.status_code} {r.text[:300]}")
        return r.json() if r.text.strip() else None

    def register(self, email, password, kdf):
        mk = master_key(password, email, kdf)
        stretched = hkdf_expand(mk, "enc") + hkdf_expand(mk, "mac")
        self.user_key = os.urandom(64)
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_der = priv.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        priv_der = priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        body = {"email": email, "name": email.split("@")[0], "masterPasswordHash": login_hash(mk, password), "masterPasswordHint": None,
                "key": enc(stretched, self.user_key), "kdf": kdf["kdf"], "kdfIterations": kdf["kdfIterations"],
                "kdfMemory": kdf.get("kdfMemory"), "kdfParallelism": kdf.get("kdfParallelism"),
                "keys": {"publicKey": b64(self.public_der), "encryptedPrivateKey": enc(self.user_key, priv_der)}}
        # Vaultwarden 1.34+: a verification token (returned directly when no
        # mail is set up), then register/finish.
        tok = requests.post(self.url + "/identity/accounts/register/send-verification-email", verify=self.ca, timeout=60,
                            json={"email": email, "name": body["name"], "receiveMarketingEmails": False}).text.strip().strip('"')
        fin = {"email": email, "emailVerificationToken": tok, "masterPasswordHash": body["masterPasswordHash"], "masterPasswordHint": None,
               "userSymmetricKey": body["key"], "userAsymmetricKeys": body["keys"], "kdf": kdf["kdf"], "kdfIterations": kdf["kdfIterations"],
               "kdfMemory": kdf.get("kdfMemory"), "kdfParallelism": kdf.get("kdfParallelism")}
        self.call("POST", "/identity/accounts/register/finish", json=fin)
        self.email, self.password, self.mk = email, password, mk

    def login(self, extra=None):
        form = {"grant_type": "password", "username": self.email, "password": login_hash(self.mk, self.password),
                "scope": "api offline_access", "client_id": "web", "deviceType": 9, "deviceIdentifier": self.dev, "deviceName": "fixture"}
        form.update(extra or {})
        self.token = None
        r = self.call("POST", "/identity/connect/token", data=form, headers={"Auth-Email": b64url(self.email.encode())})
        self.token = r["access_token"]
        self.uid = self.call("GET", "/api/accounts/profile")["id"]

    def folder(self, name):
        return self.call("POST", "/api/folders", json={"name": enc(self.user_key, name)})["id"]

    def cipher(self, c, key=None, org=None, collections=None):
        # Current servers want to know whose key the item is under.
        c = dict(c, encryptedFor=self.uid)
        if org:
            c["organizationId"] = org
            return self.call("POST", "/api/ciphers/create", json={"cipher": c, "collectionIds": collections})["id"]
        return self.call("POST", "/api/ciphers", json=c)["id"]


def totp(secret_b32, t=None):
    k = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))
    c = int((t or time.time()) // 30)
    d = hmac.new(k, struct.pack(">Q", c), hashlib.sha1).digest()
    o = d[-1] & 15
    return f"{(struct.unpack('>I', d[o:o + 4])[0] & 0x7fffffff) % 1000000:06d}"


def setup(url, ca, out):
    want = {}
    # Alice: PBKDF2, a folder, every item type, an item with its own key, a
    # passkey, an organization with a collection, and an item in the trash.
    a = Client(url, ca)
    a.register("alice@example.com", "correct horse battery staple", {"kdf": 0, "kdfIterations": 600000})
    a.login()
    uk = a.user_key
    work = a.folder("Work")
    a.cipher({"type": 1, "name": enc(uk, "bank"), "notes": enc(uk, "the joint account"), "folderId": work, "favorite": False,
              "login": {"username": enc(uk, "alice"), "password": enc(uk, "s3cret-bank"), "totp": enc(uk, "JBSWY3DPEHPK3PXP"),
                        "uris": [{"uri": enc(uk, "https://bank.example"), "match": None}]},
              "fields": [{"type": 0, "name": enc(uk, "PIN hint"), "value": enc(uk, "birthday")},
                         {"type": 1, "name": enc(uk, "security answer"), "value": enc(uk, "blue")}]})
    a.cipher({"type": 3, "name": enc(uk, "visa"), "card": {"cardholderName": enc(uk, "Alice Example"), "brand": enc(uk, "Visa"),
              "number": enc(uk, "4111111111111111"), "expMonth": enc(uk, "4"), "expYear": enc(uk, "2030"), "code": enc(uk, "123")}})
    a.cipher({"type": 2, "name": enc(uk, "wifi note"), "notes": enc(uk, "the router is in the hall"), "secureNote": {"type": 0}})
    a.cipher({"type": 4, "name": enc(uk, "me"), "identity": {"firstName": enc(uk, "Alice"), "lastName": enc(uk, "Example"),
              "email": enc(uk, "alice@example.com"), "city": enc(uk, "Springfield")}})
    # An item with its own key (cipher.key), the way current clients write.
    ik = os.urandom(64)
    a.cipher({"type": 1, "name": enc(ik, "mail"), "key": enc(uk, ik),
              "login": {"username": enc(ik, "alice@mail.example"), "password": enc(ik, "m4il-pass"), "uris": [{"uri": enc(ik, "https://mail.example"), "match": None}]}})
    # A passkey (fido2Credentials): an ES256 key as base64url PKCS#8.
    pk = ec.generate_private_key(ec.SECP256R1())
    kv = b64url(pk.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    cred = {"credentialId": enc(uk, str(uuid.uuid4())), "keyType": enc(uk, "public-key"), "keyAlgorithm": enc(uk, "ECDSA"), "keyCurve": enc(uk, "P-256"),
            "keyValue": enc(uk, kv), "rpId": enc(uk, "passkeys.example"), "userHandle": enc(uk, b64url(b"alice-handle")), "userName": enc(uk, "alice"),
            "counter": enc(uk, "0"), "rpName": enc(uk, "Passkeys Example"), "userDisplayName": enc(uk, "Alice"), "discoverable": enc(uk, "true"),
            "creationDate": "2026-11-01T00:00:00.000Z"}
    a.cipher({"type": 1, "name": enc(uk, "passkeys.example"), "login": {"username": enc(uk, "alice"), "uris": [{"uri": enc(uk, "https://passkeys.example"), "match": None}],
              "fido2Credentials": [cred]}})
    gone = a.cipher({"type": 1, "name": enc(uk, "old login"), "login": {"username": enc(uk, "old"), "password": enc(uk, "old")}})
    a.call("PUT", f"/api/ciphers/{gone}/delete")
    # An organization: its key RSA-OAEP-SHA-1 to Alice's public key.
    okey = os.urandom(64)
    opub = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    opub_der = opub.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    opriv_der = opub.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    pubk = serialization.load_der_public_key(a.public_der)
    wrapped = "4." + b64(pubk.encrypt(okey, apad.OAEP(mgf=apad.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None)))
    org = a.call("POST", "/api/organizations", json={"name": "Family", "billingEmail": "alice@example.com", "collectionName": enc(okey, "Shared"),
                                                     "key": wrapped, "keys": {"publicKey": b64(opub_der), "encryptedPrivateKey": enc(okey, opriv_der)}, "planType": 0})
    colls = a.call("GET", f"/api/organizations/{org['id']}/collections")["data"]
    a.cipher({"type": 1, "name": enc(okey, "family streaming"), "login": {"username": enc(okey, "family"), "password": enc(okey, "str3am"),
              "uris": [{"uri": enc(okey, "https://stream.example"), "match": None}]}}, org=org["id"], collections=[colls[0]["id"]])
    want["alice"] = {"email": a.email, "password": a.password, "items": ["bank", "visa", "wifi note", "me", "mail", "passkeys.example", "family streaming"],
                     "absent": ["old login"], "bank_password": "s3cret-bank", "mail_password": "m4il-pass", "family_password": "str3am"}

    # Bob: Argon2id and an authenticator app as the second step.
    b = Client(url, ca)
    b.register("bob@example.com", "bob's long passphrase", {"kdf": 1, "kdfIterations": 3, "kdfMemory": 64, "kdfParallelism": 4})
    b.login()
    b.cipher({"type": 1, "name": enc(b.user_key, "router"), "login": {"username": enc(b.user_key, "admin"), "password": enc(b.user_key, "r0uter")}})
    lh = login_hash(b.mk, b.password)
    g = b.call("POST", "/api/two-factor/get-authenticator", json={"masterPasswordHash": lh})
    secret = (g.get("authenticator") or g)["key"]
    t0 = time.time()
    enable_code = totp(secret, t0)
    b.call("POST", "/api/two-factor/authenticator", json={"key": secret, "token": enable_code, "masterPasswordHash": lh,
                                                          "userVerificationToken": g.get("userVerificationToken")})
    want["bob"] = {"email": b.email, "password": b.password, "items": ["router"], "absent": [], "totp": secret, "used_codes": [totp(secret, t0 - 30), enable_code, totp(secret, t0 + 30)], "router_password": "r0uter"}
    json.dump(want, open(out, "w"), indent=1)


if __name__ == "__main__":
    if sys.argv[1] == "setup":
        setup(sys.argv[2], sys.argv[3], sys.argv[4])
    elif sys.argv[1] == "totp":
        print(totp(sys.argv[2]))

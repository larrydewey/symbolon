#!/usr/bin/env python3
"""A CTAP2 authenticator for tests/fido_e2e.sh, written from the CTAP 2.1
specification on `cryptography` and python-fido2's CBOR and PinProtocolV2:
getInfo, clientPIN getKeyAgreement (protocol 2), makeCredential (ES256,
hmac-secret, non-resident) and getAssertion with hmac-secret.

    authenticator.py SOCKET STATE_DIR

It serves length-prefixed CTAP2 messages on a Unix socket (what
SYMBOLON_FIDO_SOCKET expects). Several keys live in STATE_DIR (one JSON file
each); the file "present" lists the keys plugged in (one name per line),
"target" names the one a new credential is made on, and "mode" can be
"ok", "deny" (no touch: operation denied) or "badsig" (a wrong signature).
"""
import hashlib, hmac, json, os, socket, struct, sys
import fido2.cbor as cbor
from fido2.ctap2.pin import PinProtocolV2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

SOCK, STATE = sys.argv[1], sys.argv[2]
V2 = PinProtocolV2()
agree = ec.generate_private_key(ec.SECP256R1())     # this power cycle's key-agreement key

def read(name, default=''):
    try: return open(os.path.join(STATE, name)).read().strip()
    except FileNotFoundError: return default
def load(key):
    p = os.path.join(STATE, key + '.json')
    return json.load(open(p)) if os.path.exists(p) else {'aaguid': os.urandom(16).hex(), 'creds': {}}
def save(key, st): json.dump(st, open(os.path.join(STATE, key + '.json'), 'w'))
def point(k): return k.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
def cose(pt, alg): return {1: 2, 3: alg, -1: 1, -2: pt[1:33], -3: pt[33:65]}
def log(*a): open(os.path.join(STATE, 'log'), 'a').write(' '.join(str(x) for x in a) + '\n')

def handle(msg):
    cmd, body = msg[0], (cbor.decode(msg[1:]) if len(msg) > 1 else {})
    mode = read('mode', 'ok')
    present = [k for k in read('present').split('\n') if k]
    if not present: return b''
    if cmd == 4:
        return b'\x00' + cbor.encode({1: ['FIDO_2_0', 'FIDO_2_1'], 2: ['hmac-secret'], 3: bytes.fromhex(load(present[0])['aaguid']), 4: {'rk': True, 'up': True, 'clientPin': False}, 6: [2]})
    if cmd == 6 and body.get(2) == 2 and body.get(1) == 2:
        return b'\x00' + cbor.encode({1: cose(point(agree), -25)})
    if cmd == 1:
        if mode == 'deny': return bytes([0x27])
        key = read('target') or present[0]
        st = load(key)
        if not any(p.get('alg') == -7 for p in body[4]): return bytes([0x26])
        priv = ec.generate_private_key(ec.SECP256R1())
        cid = os.urandom(48)
        st['creds'][cid.hex()] = {'priv': priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).hex(),
                                  'cred_random': os.urandom(32).hex(), 'rp': body[2]['id']}
        save(key, st)
        rph = hashlib.sha256(body[2]['id'].encode()).digest()
        att = bytes.fromhex(st['aaguid']) + struct.pack('>H', len(cid)) + cid + cbor.encode(cose(point(priv), -7))
        ext = cbor.encode({'hmac-secret': True}) if body.get(6, {}).get('hmac-secret') else b''
        ad = rph + bytes([0x41 | (0x80 if ext else 0)]) + struct.pack('>I', 0) + att + ext
        log('made', key, cid.hex()[:16])
        return b'\x00' + cbor.encode({1: 'none', 2: ad, 3: {}})
    if cmd == 2:
        allow = [c['id'] for c in body.get(3, [])]
        for key in present:
            st = load(key)
            for cid in allow:
                c = st['creds'].get(cid.hex())
                if not c or c['rp'] != body[1]: continue
                if mode == 'deny': return bytes([0x27])
                hs = body.get(4, {}).get('hmac-secret')
                ext = {}
                if hs:
                    peer = hs[1]
                    pk = ec.EllipticCurvePublicNumbers(int.from_bytes(peer[-2], 'big'), int.from_bytes(peer[-3], 'big'), ec.SECP256R1()).public_key()
                    shared = V2.kdf(agree.exchange(ec.ECDH(), pk))
                    if not hmac.compare_digest(V2.authenticate(shared, hs[2]), hs[3]): return bytes([0x2d])
                    salt = V2.decrypt(shared, hs[2])
                    ext = {'hmac-secret': V2.encrypt(shared, hmac.new(bytes.fromhex(c['cred_random']), salt, hashlib.sha256).digest())}
                st['count'] = st.get('count', 0) + 1
                save(key, st)
                ad = hashlib.sha256(body[1].encode()).digest() + bytes([0x01 | (0x80 if ext else 0)]) + struct.pack('>I', st['count']) + (cbor.encode(ext) if ext else b'')
                signer = ec.generate_private_key(ec.SECP256R1()) if mode == 'badsig' else serialization.load_der_private_key(bytes.fromhex(c['priv']), None)
                log('assert', key, cid.hex()[:16])
                return b'\x00' + cbor.encode({1: {'id': cid, 'type': 'public-key'}, 2: ad, 3: signer.sign(ad + body[2], ec.ECDSA(hashes.SHA256()))})
        return bytes([0x2e])
    return bytes([0x01])

if os.path.exists(SOCK): os.unlink(SOCK)
srv = socket.socket(socket.AF_UNIX); srv.bind(SOCK); os.chmod(SOCK, 0o600); srv.listen(4)
print('ready', flush=True)
while True:
    c, _ = srv.accept()
    try:
        n = struct.unpack('>I', c.recv(4, socket.MSG_WAITALL))[0]
        m = b''
        while len(m) < n: m += c.recv(n - len(m))
        r = handle(m)
        if r: c.sendall(struct.pack('>I', len(r)) + r)
    except Exception as e:
        log('error', repr(e))
    c.close()

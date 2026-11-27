#!/usr/bin/env python3
# For the e2e suites that play a malicious relay on a sealed Symbolon Home
# box: open, change and seal again an object of the relay's store, with
# the box key the running box unsealed into memory (agent/boxseal.resid:
# "SYMBSEAL" || IV (12) || AES-256-GCM(key, IV, plaintext, AAD)).
#   relay_seal.py KEYFILE open FILE OUT
#   relay_seal.py KEYFILE size FILE              plaintext length (0 when missing)
#   relay_seal.py KEYFILE replace FILE OLD NEW
#   relay_seal.py KEYFILE flip-last FILE | flip-mid FILE
import os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC, AAD = b'SYMBSEAL', b'symbolon v1 home sealed file'
key = open(sys.argv[1], 'rb').read()
op, path = sys.argv[2], sys.argv[3]

def unseal(b):
    if not b.startswith(MAGIC):
        return b
    return AESGCM(key).decrypt(b[8:20], b[20:], AAD)

def seal(p):
    iv = os.urandom(12)
    return MAGIC + iv + AESGCM(key).encrypt(iv, p, AAD)

if op == 'size':
    print(len(unseal(open(path, 'rb').read())) if os.path.exists(path) else 0)
    sys.exit(0)
p = bytearray(unseal(open(path, 'rb').read()))
if op == 'open':
    open(sys.argv[4], 'wb').write(bytes(p))
    sys.exit(0)
if op == 'replace':
    p = bytearray(bytes(p).replace(sys.argv[4].encode(), sys.argv[5].encode()))
elif op == 'flip-last':
    p[-1] ^= 1
elif op == 'flip-mid':
    p[len(p) // 2] ^= 1
else:
    sys.exit('unknown op ' + op)
open(path, 'wb').write(seal(bytes(p)))

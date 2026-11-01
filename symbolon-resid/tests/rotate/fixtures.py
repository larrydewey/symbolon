#!/usr/bin/env python3
"""Recipe repository and bundles for tests/rotate_e2e.sh, made here (CBOR by
hand, cryptography's ECDSA, an RFC 9162 tree), not by the agent:

    fixtures.py OUTDIR ORIGIN

writes repo.cbor (two-of-three repository keys and the log key) and
bundle-*.cbor: "good" (signed by two keys, logged 8 days ago), "one-sig"
(one signature), "fresh" (logged an hour ago: still in its 7-day hold),
"destructive" (clicks the site's delete button) and "badexpect" (the
change works but its expectation names text the site never shows).
"""
import hashlib, os, sys, time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

OUT, ORIGIN = sys.argv[1], sys.argv[2]
HOST = ORIGIN.split('://')[1].split(':')[0]


def head(major, n):
    if n < 24: return bytes([major << 5 | n])
    if n < 256: return bytes([major << 5 | 24, n])
    if n < 65536: return bytes([major << 5 | 25]) + n.to_bytes(2, 'big')
    if n < 2 ** 32: return bytes([major << 5 | 26]) + n.to_bytes(4, 'big')
    return bytes([major << 5 | 27]) + n.to_bytes(8, 'big')


uint = lambda n: head(0, n)
nint = lambda n: head(1, -1 - n)
bstr = lambda b: head(2, len(b)) + b
tstr = lambda s: head(3, len(s.encode())) + s.encode()
arr = lambda items: head(4, len(items)) + b''.join(items)
mp = lambda pairs: head(5, len(pairs)) + b''.join(k + v for k, v in pairs)
sha = lambda b: hashlib.sha256(b).digest()


def newkey():
    k = ec.generate_private_key(ec.SECP256R1())
    n = k.public_key().public_numbers()
    return k, b'\x04' + n.x.to_bytes(32, 'big') + n.y.to_bytes(32, 'big')


def cose_sign1(k, payload):
    prot = mp([(uint(1), nint(-7))])
    tbs = arr([tstr('Signature1'), bstr(prot), bstr(b''), bstr(payload)])
    r, s = decode_dss_signature(k.sign(tbs, ec.ECDSA(hashes.SHA256())))
    return head(6, 18) + arr([bstr(prot), mp([]), bstr(payload), bstr(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))])


nav = lambda p: arr([uint(0), tstr(ORIGIN + p)])
fill = lambda s, v: arr([uint(1), tstr(s), tstr(v)])
click = lambda s: arr([uint(2), tstr(s)])
expect = lambda k, t: arr([uint(3), arr([uint(k), tstr(t)])])
rules = mp([(uint(1), uint(16)), (uint(2), uint(40)), (uint(3), uint(7)), (uint(4), tstr('"\'<>&'))])
sign_in = [nav('/login'), fill('#user', 'username'), fill('#pw', 'password'), click('#go'), expect(1, '#account')]
change = [nav('/login'), fill('#user', 'username'), fill('#pw', 'old'), click('#go'), expect(1, '#account'),
          nav('/account/password'), fill('#old', 'old'), fill('#new', 'new'), click('#save'), expect(2, 'Password changed')]


def recipe(version, steps):
    return mp([(uint(1), tstr(HOST)), (uint(2), uint(version)), (uint(3), rules), (uint(4), arr(steps)),
               (uint(5), arr([tstr(ORIGIN)])), (uint(6), arr(sign_in))])


lh = lambda e: sha(b'\0' + e)
nh = lambda a, b: sha(b'\x01' + a + b)


def split(n):
    k = 1
    while k * 2 < n: k *= 2
    return k


def mth(es):
    if len(es) == 1: return lh(es[0])
    k = split(len(es)); return nh(mth(es[:k]), mth(es[k:]))


def path(m, es):
    if len(es) == 1: return []
    k = split(len(es))
    return path(m, es[:k]) + [mth(es[k:])] if m < k else path(m - k, es[k:]) + [mth(es[:k])]


keys = [newkey() for _ in range(3)]
log_k, log_pub = newkey()
now = int(time.time())
recipes = {
    'good': (recipe(1, change), now - 8 * 86400, [0, 2]),
    'one-sig': (recipe(1, change), now - 8 * 86400, [1]),
    'fresh': (recipe(2, change), now - 3600, [0, 1]),
    'destructive': (recipe(3, change[:5] + [nav('/account/password'), click('#delete'), expect(2, 'Password changed')]), now - 8 * 86400, [0, 1]),
    'badexpect': (recipe(4, change[:-1] + [expect(2, 'All done!')]), now - 8 * 86400, [1, 2]),
}
names = list(recipes)
entries = [arr([uint(t), bstr(p)]) for p, t, _ in recipes.values()]
root = mth(entries)
th = cose_sign1(log_k, mp([(uint(1), uint(len(entries))), (uint(2), bstr(root))]))
open(os.path.join(OUT, 'repo.cbor'), 'wb').write(arr([arr([bstr(p) for _, p in keys]), uint(2), bstr(log_pub)]))
for i, n in enumerate(names):
    p, t, signers = recipes[n]
    b = arr([bstr(p), arr([bstr(cose_sign1(keys[j][0], p)) for j in signers]), uint(t), uint(i), uint(len(entries)),
             arr([bstr(x) for x in path(i, entries)]), bstr(root), bstr(th)])
    open(os.path.join(OUT, f'bundle-{n}.cbor'), 'wb').write(b)

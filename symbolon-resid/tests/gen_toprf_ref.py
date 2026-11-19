#!/usr/bin/env python3
"""Generates src/vault/toprf_ref_test.resid from an independent implementation
of SPEC 18.10 written here in Python: RFC 9380 hash_to_curve
(P256_XMD:SHA-256_SSWU_RO_), RFC 9497 VOPRF P256-SHA256 (Blind,
BlindEvaluate with its DLEQ proof, Finalize), Shamir t-of-n sharing with
Feldman commitments, the 2HashTDH combination, and the protected item key.
P-256 arithmetic is plain affine integers here; the final key derivation
uses hashlib and cryptography's HKDF. The Resid code is checked against values
it did not produce.

The script first checks itself against the published vectors of RFC 9380
(J.1.1) and RFC 9497 (A.3.2, VOPRF mode) and stops if any differs.

    python3 tests/gen_toprf_ref.py
"""
import hashlib, os, random
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

random.seed(1810)
HERE = os.path.dirname(os.path.abspath(__file__))

# ---- P-256 ------------------------------------------------------------------
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
q = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
A = p - 3
Bc = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
     0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
INF = None

def add(P, Q):
    if P is INF: return Q
    if Q is INF: return P
    if P[0] == Q[0] and (P[1] + Q[1]) % p == 0: return INF
    if P == Q:
        l = (3 * P[0] * P[0] + A) * pow(2 * P[1], -1, p) % p
    else:
        l = (Q[1] - P[1]) * pow(Q[0] - P[0], -1, p) % p
    x = (l * l - P[0] - Q[0]) % p
    return (x, (l * (P[0] - x) - P[1]) % p)

def mul(k, P):
    R = INF
    k %= q
    while k:
        if k & 1: R = add(R, P)
        P = add(P, P); k >>= 1
    return R

def ser(P):  # SEC 1 compressed
    return bytes([2 + (P[1] & 1)]) + P[0].to_bytes(32, 'big')

def deser(b):
    assert len(b) == 33 and b[0] in (2, 3)
    x = int.from_bytes(b[1:], 'big'); assert x < p
    y = pow((x**3 + A * x + Bc) % p, (p + 1) // 4, p)
    assert y * y % p == (x**3 + A * x + Bc) % p
    if (y & 1) != (b[0] & 1): y = p - y
    return (x, y)

# cross-check the integer curve with cryptography once
_k = 0x1234567890abcdef
_pub = ec.derive_private_key(_k, ec.SECP256R1()).public_key().public_numbers()
assert mul(_k, G) == (_pub.x, _pub.y)

# ---- RFC 9380 ---------------------------------------------------------------
def i2osp(n, l): return n.to_bytes(l, 'big')

def expand_xmd(msg, dst, n):
    H = lambda b: hashlib.sha256(b).digest()
    ell = -(-n // 32); assert ell <= 255 and len(dst) <= 255
    dstp = dst + i2osp(len(dst), 1)
    b0 = H(b'\0' * 64 + msg + i2osp(n, 2) + b'\0' + dstp)
    bs = [H(b0 + b'\1' + dstp)]
    for i in range(2, ell + 1):
        bs.append(H(bytes(x ^ y for x, y in zip(b0, bs[-1])) + i2osp(i, 1) + dstp))
    return b''.join(bs)[:n]

def hash_to_field(msg, count, dst, mod):
    u = expand_xmd(msg, dst, count * 48)
    return [int.from_bytes(u[48 * i:48 * i + 48], 'big') % mod for i in range(count)]

def sqrt3mod4(a):
    r = pow(a, (p + 1) // 4, p)
    return r if r * r % p == a % p else None

def sswu(u):
    Z = p - 10
    tv1 = (Z * Z * pow(u, 4, p) + Z * u * u) % p
    if tv1 == 0:
        x1 = Bc * pow(Z * A, -1, p) % p
    else:
        x1 = (p - Bc) * pow(A, -1, p) * (1 + pow(tv1, -1, p)) % p
    gx1 = (x1**3 + A * x1 + Bc) % p
    y = sqrt3mod4(gx1)
    if y is not None:
        x = x1
    else:
        x = Z * u * u * x1 % p
        y = sqrt3mod4((x**3 + A * x + Bc) % p)
    if (u & 1) != (y & 1): y = p - y
    return (x, y)

def hash_to_curve(msg, dst):
    u0, u1 = hash_to_field(msg, 2, dst, p)
    return add(sswu(u0), sswu(u1))

H2C_VECTORS = [
    (b'', 0x2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4,
          0x8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9ab5c43e8415),
    (b'abc', 0x0bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f,
             0x5c41b3d0731a27a7b14bc0bf0ccded2d8751f83493404c84a88e71ffd424212e),
    (b'abcdef0123456789', 0x65038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c1526811864e544ed80,
                          0xcad44d40a656e7aff4002a8de287abc8ae0482b5ae825822bb870d6df9b56ca3),
]
H2C_DST = b'QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_'
for m, x, y in H2C_VECTORS:
    assert hash_to_curve(m, H2C_DST) == (x, y), m

# ---- RFC 9497, VOPRF mode, P256-SHA256 --------------------------------------
CTX = b'OPRFV1-\x01-P256-SHA256'
def h2g(x): return hash_to_curve(x, b'HashToGroup-' + CTX)
def h2s(x): return hash_to_field(x, 1, b'HashToScalar-' + CTX, q)[0]
def lp(b): return i2osp(len(b), 2) + b

def composites(B, Cs, Ds, k=None):
    seed = hashlib.sha256(lp(ser(B)) + lp(b'Seed-' + CTX)).digest()
    M = Z = INF
    for i, (C, D) in enumerate(zip(Cs, Ds)):
        di = h2s(lp(seed) + i2osp(i, 2) + lp(ser(C)) + lp(ser(D)) + b'Composite')
        M = add(mul(di, C), M)
        if k is None: Z = add(mul(di, D), Z)
    return M, (mul(k, M) if k is not None else Z)

def challenge(B, M, Z, t2, t3):
    return h2s(b''.join(lp(ser(X)) for X in (B, M, Z, t2, t3)) + b'Challenge')

def prove(k, A_, B, Cs, Ds, r):
    M, Z = composites(B, Cs, Ds, k)
    c = challenge(B, M, Z, mul(r, A_), mul(r, M))
    return c, (r - c * k) % q

def verify(A_, B, Cs, Ds, proof):
    c, s = proof
    M, Z = composites(B, Cs, Ds)
    return challenge(B, M, Z, add(mul(s, A_), mul(c, B)), add(mul(s, M), mul(c, Z))) == c

def finalize(inp, blind, Zel):
    N = mul(pow(blind, -1, q), Zel)
    return hashlib.sha256(lp(inp) + lp(ser(N)) + b'Finalize').digest()

def evaluate(k, inp):  # the single-key PRF, RFC 9497 Evaluate
    return hashlib.sha256(lp(inp) + lp(ser(mul(k, h2g(inp)))) + b'Finalize').digest()

H = bytes.fromhex
sk = 0xca5d94c8807817669a51b196c34c1b7f8442fde4334a7121ae4736364312fca6
assert ser(mul(sk, G)) == H('03e17e70604bcabe198882c0a1f27a92441e774224ed9c702e51dd17038b102462')
blind = 0x3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364
prs = 0xf9db001266677f62c095021db018cd8cbb55941d4073698ce45c405d1348b7b1
RFC9497 = [
    (b'\x00', '02dd05901038bb31a6fae01828fd8d0e49e35a486b5c5d4b4994013648c01277da',
     '0209f33cab60cf8fe69239b0afbcfcd261af4c1c5632624f2e9ba29b90ae83e4a2',
     'e7c2b3c5c954c035949f1f74e6bce2ed539a3be267d1481e9ddb178533df4c2664f69d065c604a4fd953e100b856ad83804eb3845189babfa5a702090d6fc5fa',
     '0412e8f78b02c415ab3a288e228978376f99927767ff37c5718d420010a645a1'),
    (H('5a' * 17), '03cd0f033e791c4d79dfa9c6ed750f2ac009ec46cd4195ca6fd3800d1e9b887dbd',
     '030d2985865c693bf7af47ba4d3a3813176576383d19aff003ef7b0784a0d83cf1',
     '2787d729c57e3d9512d3aa9e8708ad226bc48e0f1750b0767aaff73482c44b8d2873d74ec88aebd3504961acea16790a05c542d9fbff4fe269a77510db00abab',
     '771e10dcd6bcd3664e23b8f2a710cfaaa8357747c4a8cbba03133967b5c24f18'),
]
for inp, be, ee, pf, out in RFC9497:
    Bl = mul(blind, h2g(inp)); assert ser(Bl) == H(be)
    Ev = mul(sk, Bl); assert ser(Ev) == H(ee)
    c, s = prove(sk, G, mul(sk, G), [Bl], [Ev], prs)
    assert i2osp(c, 32) + i2osp(s, 32) == H(pf)
    assert verify(G, mul(sk, G), [Bl], [Ev], (c, s))
    assert finalize(inp, blind, Ev) == H(out) == evaluate(sk, inp)
# batch of two, RFC 9497 test vector 3
blind2 = prs
Bs = [mul(blind, h2g(b'\x00')), mul(blind2, h2g(H('5a' * 17)))]
Es = [mul(sk, b) for b in Bs]
c, s = prove(sk, G, mul(sk, G), Bs, Es, 0x350e8040f828bf6ceca27405420cdf3d63cb3aef005f40ba51943c8026877963)
assert i2osp(c, 32) + i2osp(s, 32) == H('bdcc351707d02a72ce49511c7db990566d29d6153ad6f8982fad2b435d6ce4d60da1e6b3fa740811bde34dd4fe0aa1b5fe6600d0440c9ddee95ea7fad7a60cf2')

# ---- SPEC 18.10: Shamir, 2HashTDH, the protected item key ---------------------
def rs(): return random.randrange(1, q)
def rb(n): return bytes(random.randrange(256) for _ in range(n))

def lagrange0(ids, i):
    num = den = 1
    for j in ids:
        if j != i: num = num * j % q; den = den * (j - i) % q
    return num * pow(den, -1, q) % q

def oprf_input(vault_id, item_id): return b'symbolon v1 protected' + vault_id + item_id

def pitem_key(vault_key, y, vault_id, item_id):
    return HKDF(hashes.SHA256(), 32, vault_id, b'symbolon v1 protected item' + item_id).derive(vault_key + y)

def rl(b): return '[' + ', '.join(str(x) for x in b) + ']'
def sc(n): return str(n)

cases = []
for (t, n, ids) in [(2, 3, [1, 2]), (2, 3, [3, 1]), (2, 4, [2, 4]), (3, 4, [1, 3, 4]), (3, 5, [5, 2, 4]), (1, 1, [1])]:
    coeffs = [rs() for _ in range(t)]
    kv = coeffs[0]
    shares = {j: sum(c * pow(j, l, q) for l, c in enumerate(coeffs)) % q for j in range(1, n + 1)}
    commits = [mul(c, G) for c in coeffs]
    vault_id, item_id, vault_key = rb(32), rb(16), rb(32)
    inp = oprf_input(vault_id, item_id)
    r = rs()
    Bl = mul(r, h2g(inp))
    parts = []
    for j in ids:
        Zj = mul(shares[j], Bl)
        Kj = INF
        for l, C in enumerate(commits): Kj = add(Kj, mul(pow(j, l, q), C))
        assert Kj == mul(shares[j], G)
        pr = rs()
        proof = prove(shares[j], G, Kj, [Bl], [Zj], pr)
        assert verify(G, Kj, [Bl], [Zj], proof)
        parts.append((j, shares[j], Zj, pr, proof))
    Zc = INF
    for j, _, Zj, _, _ in parts: Zc = add(Zc, mul(lagrange0(ids, j), Zj))
    assert Zc == mul(kv, Bl)
    y = finalize(inp, r, Zc)
    assert y == evaluate(kv, inp)
    cases.append(dict(t=t, n=n, ids=ids, commits=commits, vault_id=vault_id, item_id=item_id,
                      vault_key=vault_key, r=r, B=Bl, parts=parts, y=y,
                      key=pitem_key(vault_key, y, vault_id, item_id)))

# ---- emit -------------------------------------------------------------------
L = []
w = L.append
w('''// The threshold OPRF of SPEC 18.10 (src/vault/toprf.resid) against an
// independent Python implementation of RFC 9380, RFC 9497 and 2HashTDH
// (tests/gen_toprf_ref.py), which itself first reproduces the RFCs' published
// vectors. Generated; do not edit by hand.

import "../types.resid";
import "toprf.resid";
import "vault.resid";
import "word.resid";
import "crypto.resid";
import "p256ops.resid";

List(Int) widen(List(UInt(8)) b, Int i, ListBuf(Int) acc) {
    if (i >= b.len()) { return acc.finish(); }
    return widen(b, i + 1, acc.push((Int) b[i]));
}

@requires(declassify)
List(Int) opened(List(Secret(UInt(8))) b) {
    return widen(declassify(secret_join(b), "test compares to the reference"), 0, ListBuf());
}
''')
for i, (m, x, y) in enumerate(H2C_VECTORS):
    w(f'''test "RFC 9380 J.1.1 P256_XMD:SHA-256_SSWU_RO_ vector {i}" {{
    P256Aff pt = toprf_hash_to_curve({rl(m)}, {rl(H2C_DST)});
    assert(pt.ok);
    assert(pt.x == {sc(x)});
    assert(pt.y == {sc(y)});
}}
''')
for i, (inp, be, ee, pf, out) in enumerate(RFC9497):
    w(f'''@requires(declassify)
test "RFC 9497 A.3.2 VOPRF P256-SHA256 vector {i + 1}: blind, evaluate, proof, finalize" {{
    Secret(UInt(576)) sk = classify((UInt(576)) {sc(sk)});
    Secret(UInt(576)) r = classify((UInt(576)) {sc(blind)});
    List(Int) b = toprf_blind_with({rl(inp)}, r);
    assert(b == {rl(H(be))});
    ToprfEval ev = toprf_evaluate_with(sk, [b], classify((UInt(576)) {sc(prs)}));
    assert(ev.ok);
    assert(ev.elements[0] == {rl(H(ee))});
    assert(ev.proof == {rl(H(pf))});
    assert(toprf_verify(pt_dec({rl(H('03e17e70604bcabe198882c0a1f27a92441e774224ed9c702e51dd17038b102462'))}), [b], ev.elements, ev.proof));
    List(Secret(UInt(8))) y = toprf_finalize({rl(inp)}, r, pt_dec(ev.elements[0]));
    assert(opened(y) == {rl(H(out))});
}}
''')
w(f'''@requires(declassify)
test "RFC 9497 A.3.2 VOPRF P256-SHA256 vector 3: a batch of two, one proof" {{
    Secret(UInt(576)) sk = classify((UInt(576)) {sc(sk)});
    List(Int) b0 = toprf_blind_with([0], classify((UInt(576)) {sc(blind)}));
    List(Int) b1 = toprf_blind_with({rl(H('5a' * 17))}, classify((UInt(576)) {sc(blind2)}));
    ToprfEval ev = toprf_evaluate_with(sk, [b0, b1], classify((UInt(576)) {sc(0x350e8040f828bf6ceca27405420cdf3d63cb3aef005f40ba51943c8026877963)}));
    assert(ev.ok);
    assert(ev.proof == {rl(H('bdcc351707d02a72ce49511c7db990566d29d6153ad6f8982fad2b435d6ce4d60da1e6b3fa740811bde34dd4fe0aa1b5fe6600d0440c9ddee95ea7fad7a60cf2'))});
    P256Aff pk = pt_dec({rl(H('03e17e70604bcabe198882c0a1f27a92441e774224ed9c702e51dd17038b102462'))});
    assert(toprf_verify(pk, [b0, b1], ev.elements, ev.proof));
    assert(!toprf_verify(pk, [b1, b0], ev.elements, ev.proof));
}}
''')
for ci, c in enumerate(cases):
    commits = ', '.join(rl(ser(C)) for C in c['commits'])
    ids = ', '.join(str(j) for j in c['ids'])
    w(f'''@requires(declassify)
test "{c['t']}-of-{c['n']} evaluation by parties [{ids}]: shares verify, combine to the single-key PRF, and give the item key" {{
    List(List(Int)) commits = [{commits}];
    List(Int) vid = {rl(c['vault_id'])};
    List(Int) iid = {rl(c['item_id'])};
    List(Int) inp = toprf_item_input(vid, iid);
    Secret(UInt(576)) r = classify((UInt(576)) {sc(c['r'])});
    List(Int) b = toprf_blind_with(inp, r);
    assert(b == {rl(ser(c['B']))});''')
    for (j, share, Zj, pr, proof) in c['parts']:
        w(f'''    P256Aff k{j} = toprf_party_key(commits, {j});
    assert(k{j}.ok);
    ToprfEval e{j} = toprf_evaluate_with(classify((UInt(576)) {sc(share)}), [b], classify((UInt(576)) {sc(pr)}));
    assert(e{j}.ok);
    assert(e{j}.elements[0] == {rl(ser(Zj))});
    assert(e{j}.proof == {rl(i2osp(proof[0], 32) + i2osp(proof[1], 32))});
    assert(toprf_verify(k{j}, [b], e{j}.elements, e{j}.proof));''')
    parts = ', '.join(f'e{j}.elements[0]' for j, *_ in c['parts'])
    w(f'''    P256Aff z = toprf_combine([{ids}], [{parts}]);
    assert(z.ok);
    List(Secret(UInt(8))) y = toprf_finalize(inp, r, z);
    assert(opened(y) == {rl(c['y'])});
    List(Secret(UInt(8))) key = protected_item_key(secret_bytes({rl(c['vault_key'])}), y, vid, iid);
    assert(opened(key) == {rl(c['key'])});
}}
''')
c = cases[0]
j, share, Zj, pr, proof = c['parts'][0]
other = c['parts'][1]
w(f'''test "a proof for another party's key, a tampered element or a tampered proof is refused" {{
    List(List(Int)) commits = [{', '.join(rl(ser(C)) for C in c['commits'])}];
    List(Int) b = {rl(ser(c['B']))};
    List(Int) z = {rl(ser(Zj))};
    List(Int) pf = {rl(i2osp(proof[0], 32) + i2osp(proof[1], 32))};
    assert(toprf_verify(toprf_party_key(commits, {j}), [b], [z], pf));
    assert(!toprf_verify(toprf_party_key(commits, {other[0]}), [b], [z], pf));
    assert(!toprf_verify(toprf_party_key(commits, {j}), [b], [{rl(ser(other[2]))}], pf));
    List(Int) bad = pf[0..63].concat([pf[63] ^ 1]);
    assert(!toprf_verify(toprf_party_key(commits, {j}), [b], [z], bad));
    assert(!toprf_verify(toprf_party_key(commits, {j}), [b], [z], pf[0..32]));
}}
''')
open(os.path.join(HERE, '..', 'src', 'vault', 'toprf_ref_test.resid'), 'w').write('\n'.join(L))
print('wrote src/vault/toprf_ref_test.resid:', 4 + len(cases) + 1, 'reference tests, RFC 9380 and RFC 9497 vectors reproduced')

#!/usr/bin/env python3
"""Generates src/vault/kvshare_ref_test.resid: the vault OPRF key's dealing,
re-share scaling and commitment sums (src/vault/kvshare.resid, SPEC 18.10.1)
against P-256 arithmetic written here independently (affine formulas,
Fermat inverses, SEC1 compression).

    python3 tests/gen_kvshare_ref.py
"""
import os, random

random.seed(18101)
HERE = os.path.dirname(os.path.abspath(__file__))
P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
A = P - 3
G = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
     0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)


def add(p, q):
    if p is None: return q
    if q is None: return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0: return None
    if p == q: l = (3 * p[0] * p[0] + A) * pow(2 * p[1], P - 2, P) % P
    else: l = (q[1] - p[1]) * pow(q[0] - p[0], P - 2, P) % P
    x = (l * l - p[0] - q[0]) % P
    return (x, (l * (p[0] - x) - p[1]) % P)


def mul(k, p):
    r = None
    for bit in bin(k % N)[2:]:
        r = add(r, r)
        if bit == '1': r = add(r, p)
    return r


def comp(p): return bytes([2 + (p[1] & 1)]) + p[0].to_bytes(32, 'big')
def sec1(p): return b'\x04' + p[0].to_bytes(32, 'big') + p[1].to_bytes(32, 'big')
def lag0(ids, i):
    num, den = 1, 1
    for j in ids:
        if j != i: num = num * j % N; den = den * (j - i) % N
    return num * pow(den, N - 2, N) % N


L = lambda b: '[' + ', '.join(str(x) for x in b) + ']'
H = lambda b: '"' + bytes(b).hex() + '"'
sc = lambda: random.randrange(1, N)

# Dealer X (old index 1) and the cosigner (old index 3) generate k_v at t = 2
# for parties 1, 2 (the kit) and 3.
ids = [1, 2, 3]
ax = [sc(), sc()]
ac = [sc(), sc()]
f = lambda a, j: sum(c * pow(j, l, N) for l, c in enumerate(a)) % N
px = [f(ax, j) for j in ids]
pc = [f(ac, j) for j in ids]
cx = [mul(c, G) for c in ax]
cc = [mul(c, G) for c in ac]
csum = [add(cx[l], cc[l]) for l in range(2)]
share = [(px[i] + pc[i]) % N for i in range(3)]
# Re-share by old parties 1 and 3 to four new parties
dealers = [1, 3]
lam1, lam3 = lag0(dealers, 1), lag0(dealers, 3)
s1, s3 = lam1 * share[0] % N, lam3 * share[2] % N
assert (s1 + s3) % N == (ax[0] + ac[0]) % N
k_old = [mul(share[i], G) for i in range(3)]

out = f'''// The vault OPRF key's dealing, re-share scaling and commitment sums
// (src/vault/kvshare.resid) against independent P-256 arithmetic
// (tests/gen_kvshare_ref.py). Generated; do not edit by hand.

import "../types.resid";
import "kvshare.resid";
import "p256.resid";
import "word.resid";
import "crypto.resid";

Secret(UInt(576)) s(List(Int) b) {{ return p256_load(secret_bytes(b)); }}
KvScalar k(List(Int) b) {{ return kv_scalar(s(b)); }}

@requires(declassify)
List(Int) out(Secret(UInt(576)) v) {{ return ints(declassify(secret_join(kv_share_bytes(v)), "test compares values")); }}

List(Int) ints(List(UInt(8)) b) {{ return ints_at(b, 0, ListBuf()); }}
List(Int) ints_at(List(UInt(8)) b, Int i, ListBuf(Int) acc) {{ if (i >= b.len()) {{ return acc.finish(); }} return ints_at(b, i + 1, acc.push((Int) b[i])); }}

@requires(declassify)
test "a dealing's parts and commitments equal the reference" {{
    KvDealing d = kv_deal_with([k({L(ax[0].to_bytes(32, 'big'))}), k({L(ax[1].to_bytes(32, 'big'))})], {L(ids)});
    expect(hex_encode(d.commits[0])).toEqual({H(comp(cx[0]))});
    expect(hex_encode(d.commits[1])).toEqual({H(comp(cx[1]))});
    expect(hex_encode(out(d.parts[0].v))).toEqual({H(px[0].to_bytes(32, 'big'))});
    expect(hex_encode(out(d.parts[1].v))).toEqual({H(px[1].to_bytes(32, 'big'))});
    expect(hex_encode(out(d.parts[2].v))).toEqual({H(px[2].to_bytes(32, 'big'))});
    expect(kv_part_ok(d.commits, 3, d.parts[2].v)).toBeTrue();
}}

@requires(declassify)
test "summed commitments, a re-share's scaled secrets and its check equal the reference" {{
    List(List(Int)) cs = kv_sum_commits([{L([L(comp(c)) for c in cx]).replace("'", "")}, {L([L(comp(c)) for c in cc]).replace("'", "")}]);
    expect(hex_encode(cs[0])).toEqual({H(comp(csum[0]))});
    expect(hex_encode(cs[1])).toEqual({H(comp(csum[1]))});
    expect(hex_encode(out(kv_reshare_secret(s({L(share[0].to_bytes(32, 'big'))}), {L(dealers)}, 1)))).toEqual({H(s1.to_bytes(32, 'big'))});
    expect(hex_encode(out(kv_reshare_secret(s({L(share[2].to_bytes(32, 'big'))}), {L(dealers)}, 3)))).toEqual({H(s3.to_bytes(32, 'big'))});
    expect(kv_reshare_ok(cs, {L(dealers)}, 1, [{L(comp(mul(s1, G)))}])).toBeTrue();
    expect(kv_reshare_ok(cs, {L(dealers)}, 3, [{L(comp(mul(s1, G)))}])).toBeFalse();
    expect(hex_encode(kv_to_sec1(cs)[0])).toEqual({H(sec1(csum[0]))});
}}
'''
open(os.path.join(HERE, '..', 'src', 'vault', 'kvshare_ref_test.resid'), 'w').write(out)

#!/usr/bin/env python3
"""Generates src/threshold/threshold_ref_test.resid. The per-credential key
derivation (HKDF, HMAC, tau mod q, P = X + tau G), the offline-material info
bytes and a dealer's 2-of-3 key sharing (Shamir over the P-256 scalar field,
Paillier primes from the Resid CGGMP oracle's keys6.json) are made here, in
Python (cryptography, hmac, hashlib), not by the code under test.

    python3 tests/gen_threshold_ref.py
"""
import hashlib, hmac, json, math, os, random
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec

random.seed(47)
HERE = os.path.dirname(os.path.abspath(__file__))
ORACLE = os.path.expanduser('~/git/larry/resid/tests/crypto/cggmp_oracle')
Q = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
rb = lambda n: bytes(random.randrange(256) for _ in range(n))
L = lambda b: '[' + ', '.join(str(x) for x in b) + ']'
H = lambda b: '"' + bytes(b).hex() + '"'


def head(major, n):
    if n < 24: return bytes([major << 5 | n])
    if n < 256: return bytes([major << 5 | 24, n])
    if n < 65536: return bytes([major << 5 | 25]) + n.to_bytes(2, 'big')
    return bytes([major << 5 | 26]) + n.to_bytes(4, 'big')

uint = lambda n: head(0, n)
bstr = lambda b: head(2, len(b)) + b
tstr = lambda s: head(3, len(s.encode())) + s.encode()
arr = lambda items: head(4, len(items)) + b''.join(items)


def hkdf(ikm, info, n):
    return HKDF(algorithm=hashes.SHA256(), length=n, salt=None, info=info).derive(ikm)


def point(k):
    n = ec.derive_private_key(k, ec.SECP256R1()).public_key().public_numbers()
    return n


def unc(k):
    n = point(k)
    return b'\x04' + n.x.to_bytes(32, 'big') + n.y.to_bytes(32, 'big')


def comp(k):
    n = point(k)
    return bytes([2 + (n.y & 1)]) + n.x.to_bytes(32, 'big')


def add_points(a, b):
    # (aG) + (bG) = (a + b)G: the sum is computed by the scalar, which is an
    # independent route to P (no point addition code shared with Resid).
    return unc((a + b) % Q)


cc = rb(32)
rp, other_rp = 'login.example.com', 'evil.example.net'
nonce = rb(16)
k_cid = hkdf(cc, b'symbolon v1 cid', 32)
tag = hmac.new(k_cid, b'symbolon v1 cid' + rp.encode() + nonce, hashlib.sha256).digest()[:16]
cid = nonce + tag
okm = hkdf(cc, b'symbolon v1 tweak' + rp.encode() + nonce, 48)
tau = int.from_bytes(okm, 'big') % Q
x = random.randrange(1, Q)
X = unc(x)
P = add_points(x, tau)
other_tau = int.from_bytes(hkdf(cc, b'symbolon v1 tweak' + other_rp.encode() + nonce, 48), 'big') % Q

log_id, party = rb(32), rb(32)
info = arr([tstr('symbolon v1 offline'), bstr(log_id), uint(7), bstr(party)])

# Dealer: 2-of-3 (t = 2 signers, polynomial degree 1) over parties 1, 2, 3.
keys = json.load(open(os.path.join(ORACLE, 'keys6.json')))
coef = random.randrange(Q)
f = lambda i: (x + coef * i) % Q
parties = []
for i in range(1, 4):
    k = keys[i - 1]
    p, q = int(k['P'], 16), int(k['Q'], 16)
    N = p * q; phi = (p - 1) * (q - 1)
    while True:
        r = random.randrange(2, N)
        if math.gcd(r, N) == 1: break
    tt = r * r % N
    s = pow(tt, random.randrange(phi), N)
    e = random.randrange(1, Q)
    parties.append(dict(id=i, x=f(i), e=e, p=p, q=q, n=N, s=s, t=tt))

hexn = lambda v: '"' + (format(v, 'x') if len(format(v, 'x')) % 2 == 0 else '0' + format(v, 'x')) + '"'
pubs = ', '.join(
    f'CgPublicCfg {{ .id = {d["id"]}, .ecdsa = pt({H(comp(d["x"]))}), .elgamal = pt({H(comp(d["e"]))}), .n = nat({hexn(d["n"])}), '
    f'.ped = Pedersen {{ .n = nat({hexn(d["n"])}), .s = nat({hexn(d["s"])}), .t = nat({hexn(d["t"])}) }} }}' for d in parties)
cfgs = '\n'.join(
    f'    if (i == {d["id"]}) {{ return CgConfig {{ .id = {d["id"]}, .threshold = 1, .ecdsa = nat({hexn(d["x"])}), .elgamal = nat({hexn(d["e"])}), '
    f'.p = nat({hexn(d["p"])}), .q = nat({hexn(d["q"])}), .rid = [], .chain_key = [], .public = publics() }}; }}' for d in parties)
pid = [rb(32) for _ in range(3)]
digest = hashlib.sha256(b'authenticatorData || clientDataHash').digest()

out = f'''// The threshold glue (src/threshold/threshold.resid) against values made by an
// independent implementation (tests/gen_threshold_ref.py): key derivation,
// info bytes, and a dealer's 2-of-3 sharing for whole signing sessions.
// Generated; do not edit by hand.

import "../types.resid";
import "../core/log.resid";
import "threshold.resid";
import "crypto.resid";
import "ecdsa.resid";
import "word.resid";
import "../net/wire.resid";

Str hx(List(Int) b) {{ return hex_encode(b); }}
List(UInt(64)) nat(Str h) {{ return bn_from_be(cose_hex_decode(h)); }}
CvPt pt(Str h) {{ return match cv_dec(cose_hex_decode(h)) {{ Some(p) => p, None => cv_inf() }}; }}
List(Secret(UInt(8))) chain_code() {{ return secret_bytes(rt {L(cc)}); }}

@requires(declassify)
test "credential tag and ID equal the reference (HMAC under HKDF(cc))" {{
    expect(hx(credential_tag(chain_code(), "{rp}", {L(nonce)}))).toEqual({H(tag)});
    expect(hx(credential_id(chain_code(), "{rp}", {L(nonce)}))).toEqual({H(cid)});
}}

@requires(declassify)
Str nonce_of(Str rp, List(Int) cid) {{
    return match credential_nonce(chain_code(), rp, cid) {{ Some(n) => hx(n), None => "refused" }};
}}

@requires(declassify)
test "a credential ID is accepted only with the RP ID it was made for (A-12)" {{
    expect(nonce_of("{rp}", {L(cid)})).toEqual({H(nonce)});
    expect(nonce_of("{other_rp}", {L(cid)})).toEqual("refused");
    expect(nonce_of("{rp}", {L(cid[:31] + bytes([cid[31] ^ 1]))})).toEqual("refused");
    expect(nonce_of("{rp}", {L(cid[:31])})).toEqual("refused");
}}

@requires(declassify)
test "tau equals the reference: HKDF(cc, nil, tweak || rp || nonce, 48) mod q" {{
    expect(hx(bn_to_be(tweak_scalar(chain_code(), "{rp}", {L(nonce)}), 32))).toEqual({H(tau.to_bytes(32, 'big'))});
    expect(hx(bn_to_be(tweak_scalar(chain_code(), "{other_rp}", {L(nonce)}), 32))).toEqual({H(other_tau.to_bytes(32, 'big'))});
}}

@requires(declassify)
test "P = X + tau G equals the reference" {{
    expect(hx(credential_pubkey({L(X)}, tweak_scalar(chain_code(), "{rp}", {L(nonce)})))).toEqual({H(P)});
    expect(credential_pubkey([4, 1, 2], [1]).len()).toEqual(0);
    // A point off the curve (Y changed) is refused.
    expect(credential_pubkey({L(X[:64] + bytes([X[64] ^ 1]))}, [1]).len()).toEqual(0);
}}

@requires(declassify)
test "offline-material info bytes equal the reference" {{
    expect(hx(offline_info({L(log_id)}, 7, {L(party)}))).toEqual({H(info)});
}}

Party party_of(List(Int) id, UInt(8) kind) {{
    return Party {{ .id = id, .kind = kind, .auth_key = [], .hpke_key = [], .label = "p", .attestation = NoAttestation }};
}}

Quorum quorum() {{
    return Quorum {{ .parties = [party_of({L(pid[0])}, party_kind_device()), party_of({L(pid[1])}, party_kind_device()),
                                 party_of({L(pid[2])}, party_kind_cosigner())],
                     .t = 2, .root_pubkey = {L(X)}, .epoch = 3, .transcript_digest = [] }};
}}

List(CgPublicCfg) publics() {{ return [{pubs}]; }}

CgConfig config(Int i) {{
{cfgs}
    return CgConfig {{ .id = 0, .threshold = 0, .ecdsa = [], .elgamal = [], .p = [], .q = [], .rid = [], .chain_key = [], .public = [] }};
}}

@requires(declassify)
test "signers map to ascending CGGMP ids; a stranger or a repeat gives none" {{
    expect(cg_ids(quorum(), [{L(pid[2])}, {L(pid[0])}], 0, [])).toEqual([1, 3]);
    List(Int) ids = cg_ids(quorum(), [{L(pid[2])}, {L(pid[0])}], 0, []);
    expect(ids.len()).toEqual(2);
    expect(ids[0]).toEqual(1);
    expect(ids[1]).toEqual(3);
    expect(cg_ids(quorum(), [{L(pid[0])}, {L(rb(32))}], 0, []).len()).toEqual(0);
    expect(cg_ids(quorum(), [{L(pid[0])}, {L(pid[0])}], 0, []).len()).toEqual(0);
}}

// ─── Whole sessions, every party in this process ────────────────

type Party3 = {{ CgCtx ctx; ThState st; }};

Bool for_me(ThMsg m, Int me) {{
    return match m {{
        ThCg(c) => c.from != me && (c.to == 0 || c.to == me),
        ThTw(t) => t.to == me,
        ThAbortReq(f) => f != me,
        ThRs(r) => r.from != me && (r.to == 0 || r.to == me)
    }};
}}

List(ThMsg) inbox(List(ThMsg) all, Int me, Int i, ListBuf(ThMsg) acc) {{
    if (i >= all.len()) {{ return acc.finish(); }}
    return inbox(all, me, i + 1, if (for_me(all[i], me)) {{ acc.push(all[i]) }} else {{ acc }});
}}

type Round = {{ List(Party3) ps; List(ThMsg) out; Str fail; List(Int) culprits; }};

Round step_all(List(Party3) ps, List(ThMsg) in, Int i, ListBuf(Party3) acc, List(ThMsg) out) {{
    if (i >= ps.len()) {{ return Round {{ .ps = acc.finish(), .out = out, .fail = "", .culprits = [] }}; }}
    Party3 p = ps[i];
    return match th_step(p.st, inbox(in, p.ctx.self, 0, ListBuf())) {{
        Err(e) => failed(acc, e),
        Ok(s) => step_all(ps, in, i + 1, acc.push(Party3 {{ .ctx = p.ctx, .st = s.state }}), out.concat(s.out))
    }};
}}

Round failed(ListBuf(Party3) acc, CgFail e) {{
    _ = acc.finish();
    return Round {{ .ps = [], .out = [], .fail = e.why, .culprits = e.culprits }};
}}

Str signed_by(List(Party3) ps, Int i) {{
    if (i >= ps.len()) {{ return ""; }}
    ThState st = ps[i].st;
    return match st {{ ThSigned(sig) => hx(th_sig_raw(sig)), _ => signed_by(ps, i + 1) }};
}}

Int signed_count(List(Party3) ps, Int i, Int acc) {{
    if (i >= ps.len()) {{ return acc; }}
    ThState st = ps[i].st;
    return signed_count(ps, i + 1, acc + match st {{ ThSigned(_) => 1, _ => 0 }});
}}

// Every message crosses the wire: encoded, then decoded from the bytes.
List(ThMsg) through_wire(List(ThMsg) ms, Int i, ListBuf(ThMsg) acc) {{
    if (i >= ms.len()) {{ return acc.finish(); }}
    Option(ThMsg) d = msg_decode(msg_encode(ms[i]));
    return through_wire(ms, i + 1, match d {{ Some(m) => acc.push(m), None => acc }});
}}

Round run(List(Party3) ps, List(ThMsg) in, Int rounds) {{
    if (rounds == 0) {{ return Round {{ .ps = ps, .out = in, .fail = "", .culprits = [] }}; }}
    Round r = step_all(ps, through_wire(in, 0, ListBuf()), 0, ListBuf(), []);
    if (str_len(r.fail) > 0) {{ return r; }}
    return run(r.ps, r.out, rounds - 1);
}}

Option(Party3) start(List(List(Int)) signers, List(Int) who, List(Int) initiator, List(UInt(64)) tau, List(Int) sid) {{
    Quorum q = quorum();
    Int id = cg_id_of(q, who, 0);
    List(UInt(64)) mine = if (bytes_eq(who, initiator)) {{ tau }} else {{ [] }};
    Option(CgCtx) oc = th_ctx(config(id), q, signers, initiator, mine, sid, {L(digest)}, sha256_bytes(who.concat(sid)));
    return match oc {{
        None => None,
        Some(c) => Some(Party3 {{ .ctx = c, .st = th_start(c, th_role(c, q, initiator, mine)).state }})
    }};
}}

List(ThMsg) starts_out(List(Party3) ps, Int i, List(ThMsg) acc) {{
    if (i >= ps.len()) {{ return acc; }}
    ThState st = ps[i].st;
    List(ThMsg) out = match st {{ ThR1(s, _) => wrap_start(s.out, 0, ListBuf()), _ => [] }};
    return starts_out(ps, i + 1, acc.concat(out));
}}

List(ThMsg) wrap_start(List(CgMsg) ms, Int i, ListBuf(ThMsg) acc) {{
    if (i >= ms.len()) {{ return acc.finish(); }}
    return wrap_start(ms, i + 1, acc.push(ThCg(ms[i])));
}}

@requires(declassify)
Str session(List(List(Int)) signers, List(Int) initiator) {{
    List(UInt(64)) tau = tweak_scalar(chain_code(), "{rp}", {L(nonce)});
    List(Int) sid = {L(rb(32))};
    List(Party3) ps = start_all(signers, initiator, tau, sid, 0, ListBuf());
    if (ps.len() != signers.len()) {{ return "no context"; }}
    Round r = run(ps, starts_out(ps, 0, []), 6);
    if (str_len(r.fail) > 0) {{ return "fail: " + r.fail; }}
    if (signed_count(r.ps, 0, 0) != 1) {{ return f"signed by {{signed_count(r.ps, 0, 0)}} parties"; }}
    return signed_by(r.ps, 0);
}}

List(Party3) start_all(List(List(Int)) signers, List(Int) initiator, List(UInt(64)) tau, List(Int) sid, Int i, ListBuf(Party3) acc) {{
    if (i >= signers.len()) {{ return acc.finish(); }}
    return match start(signers, signers[i], initiator, tau, sid) {{
        None => start_all(signers, initiator, tau, sid, i + 1, acc),
        Some(p) => start_all(signers, initiator, tau, sid, i + 1, acc.push(p))
    }};
}}

test "the wire refuses truncated, oversized and non-CBOR bytes" {{
    List(Int) b = msg_encode(ThAbortReq(3));
    Bool ok = match msg_decode(b) {{ Some(m) => match m {{ ThAbortReq(f) => f == 3, _ => false }}, None => false }};
    expect(ok).toBeTrue();
    expect(match msg_decode(b[0..b.len() - 1]) {{ Some(_) => false, None => true }}).toBeTrue();
    expect(match msg_decode([255]) {{ Some(_) => false, None => true }}).toBeTrue();
    expect(match msg_decode([]) {{ Some(_) => false, None => true }}).toBeTrue();
}}

@requires(declassify)
test "device and cosigner sign: one signature, at the initiator, valid under P and not under X" {{
    Str sig = session([{L(pid[0])}, {L(pid[2])}], {L(pid[0])});
    expect(str_len(sig)).toEqual(128);
    List(Int) raw = cose_hex_decode(sig);
    expect(ecdsa_verify_digest(P256, {L(P)}, {L(digest)}, ecdsa_sig_raw(P256, raw))).toBeTrue();
    expect(ecdsa_verify_digest(P256, {L(X)}, {L(digest)}, ecdsa_sig_raw(P256, raw))).toBeFalse();
}}

@requires(declassify)
test "two devices sign, the second one initiating" {{
    Str sig = session([{L(pid[0])}, {L(pid[1])}], {L(pid[1])});
    List(Int) raw = cose_hex_decode(sig);
    expect(ecdsa_verify_digest(P256, {L(P)}, {L(digest)}, ecdsa_sig_raw(P256, raw))).toBeTrue();
}}

@requires(declassify)
test "an initiator outside the signers gives no context" {{
    expect(session([{L(pid[0])}, {L(pid[2])}], {L(pid[1])})).toEqual("no context");
}}
'''
open(os.path.join(HERE, '..', 'src', 'threshold', 'threshold_ref_test.resid'), 'w').write(out)

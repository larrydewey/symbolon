#!/usr/bin/env python3
"""Generates src/recovery/recovery_ref_test.resid. Event payload encodings
(separate deterministic CBOR encoder), the kit's keys (HKDF, RFC 9180
DeriveKeyPair for DHKEM(P-256)), guardian approvals (COSE_Sign1 ES256), and
a whole log -- inception, a kit recovery, a veto -- with every signature and
witness co-signature made here with cryptography's ECDSA, not by the code
under test.

    python3 tests/gen_recovery_ref.py
"""
import hashlib, hmac, os, random
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

random.seed(59)
HERE = os.path.dirname(os.path.abspath(__file__))
Q = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
rb = lambda n: bytes(random.randrange(256) for _ in range(n))
L = lambda b: '[' + ', '.join(str(x) for x in b) + ']'
H = lambda b: '"' + bytes(b).hex() + '"'
sha = lambda b: hashlib.sha256(b).digest()


def head(major, n):
    if n < 24: return bytes([major << 5 | n])
    if n < 256: return bytes([major << 5 | 24, n])
    if n < 65536: return bytes([major << 5 | 25]) + n.to_bytes(2, 'big')
    if n < 2**32: return bytes([major << 5 | 26]) + n.to_bytes(4, 'big')
    return bytes([major << 5 | 27]) + n.to_bytes(8, 'big')

uint = lambda n: head(0, n)
nint = lambda n: head(1, -1 - n)
bstr = lambda b: head(2, len(b)) + b
tstr = lambda s: head(3, len(s.encode())) + s.encode()
arr = lambda items: head(4, len(items)) + b''.join(items)
NULL, FALSE = b'\xf6', b'\xf4'


def cmap(pairs):
    # Deterministic: sort by the encoded key.
    items = sorted(((k, v) for k, v in pairs), key=lambda kv: kv[0])
    return head(5, len(items)) + b''.join(k + v for k, v in items)


def ikey(k): return uint(k) if k >= 0 else nint(k)


def cose_key(pt):
    return cmap([(ikey(1), uint(2)), (ikey(-1), uint(1)), (ikey(-2), bstr(pt[1:33])), (ikey(-3), bstr(pt[33:65]))])


def newkey(d=None):
    d = d or (int.from_bytes(rb(32), 'big') % (Q - 1) + 1)
    k = ec.derive_private_key(d, ec.SECP256R1())
    n = k.public_key().public_numbers()
    return k, b'\x04' + n.x.to_bytes(32, 'big') + n.y.to_bytes(32, 'big'), d


def sign(k, msg):
    r, s = decode_dss_signature(k.sign(msg, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, 'big') + s.to_bytes(32, 'big')


# ─── Data model ─────────────────────────────────────────────────

class Party:
    def __init__(self, kind, label, att=None):
        self.dk, self.auth, self.d = newkey()
        _, self.hpke, self.hpke_d = newkey()
        self.id = sha(self.auth)
        self.kind, self.label, self.att = kind, label, att

    def cbor(self):
        att = NULL if self.att is None else cmap([(ikey(1), tstr(self.att[0])), (ikey(2), bstr(self.att[1]))])
        return cmap([(ikey(1), bstr(self.id)), (ikey(2), uint(self.kind)), (ikey(3), cose_key(self.auth)),
                     (ikey(4), cose_key(self.hpke)), (ikey(5), tstr(self.label)), (ikey(6), att)])

    def resid(self):
        att = 'NoAttestation' if self.att is None else f'Attested(AttestationDigest {{ .format = "{self.att[0]}", .digest = {L(self.att[1])} }})'
        return (f'Party {{ .id = {L(self.id)}, .kind = {self.kind}, .auth_key = {L(self.auth)}, .hpke_key = {L(self.hpke)}, '
                f'.label = "{self.label}", .attestation = {att} }}')


def quorum_cbor(ps, t, root, epoch, td):
    return cmap([(ikey(1), arr([p.cbor() for p in ps])), (ikey(2), uint(t)), (ikey(3), cose_key(root)), (ikey(4), uint(epoch)), (ikey(5), bstr(td))])


def quorum_resid(ps, t, root, epoch, td):
    return (f'Quorum {{ .parties = [{", ".join(p.resid() for p in ps)}], .t = {t}, .root_pubkey = {L(root)}, '
            f'.epoch = {epoch}, .transcript_digest = {L(td)} }}')


def policy_cbor(p):
    cp = NULL if p['limit'] is None else cmap([(ikey(1), uint(p['limit'])), (ikey(2), FALSE)])
    ws = arr([cmap([(ikey(1), tstr(u)), (ikey(2), cose_key(k))]) for u, k in p['witnesses']])
    return cmap([(ikey(1), uint(p['dev'])), (ikey(2), uint(p['delay'])), (ikey(3), arr([bstr(g) for g in p['guardians']])),
                 (ikey(4), uint(p['gt'])), (ikey(5), ws), (ikey(6), uint(p['duress'])), (ikey(7), cp)])


def policy_resid(p):
    cp = 'NoCosignerPolicy' if p['limit'] is None else f'CosignerLimit({p["limit"]})'
    ws = ', '.join(f'WitnessRef {{ .url = "{u}", .key = {L(k)} }}' for u, k in p['witnesses'])
    gs = ', '.join(L(g) for g in p['guardians'])
    return (f'Policy {{ .device_sigs_for_authority = {p["dev"]}, .recovery_delay_sec = {p["delay"]}, .guardians = [{gs}], '
            f'.guardian_threshold = {p["gt"]}, .witnesses = [{ws}], .duress_window_sec = {p["duress"]}, .cosigner_policy = {cp} }}')


def payload_cbor(log_id, seq, pred, body_c, digests, t):
    return cmap([(ikey(1), NULL if log_id is None else bstr(log_id)), (ikey(2), uint(seq)), (ikey(3), NULL if pred is None else bstr(pred)),
                 (ikey(4), uint(1)), (ikey(5), body_c), (ikey(6), arr([bstr(d) for d in digests])), (ikey(7), uint(t))])


def payload_resid(log_id, seq, pred, body_r, digests, t):
    lo = 'None' if log_id is None else f'Some({L(log_id)})'
    pr = 'None' if pred is None else f'Some({L(pred)})'
    return (f'EventPayload {{ .log_id = {lo}, .sequence = {seq}, .predecessor_digest = {pr}, .suite = 1, .body = {body_r}, '
            f'.next_recovery_key_digests = [{", ".join(L(d) for d in digests)}], .advisory_time = {t} }}')


# ─── Kit keys ───────────────────────────────────────────────────

def hkdf(ikm, info, n, salt=None):
    return HKDF(algorithm=hashes.SHA256(), length=n, salt=salt, info=info).derive(ikm)


def hpke_derive_p256(ikm):
    suite = b'KEM' + (16).to_bytes(2, 'big')
    ext = lambda salt, label, ikm_: hmac.new(salt or bytes(32), b'HPKE-v1' + suite + label + ikm_, hashlib.sha256).digest()

    def expand(prk, label, info, n):
        full = n.to_bytes(2, 'big') + b'HPKE-v1' + suite + label + info
        out, t, c = b'', b'', 1
        while len(out) < n:
            t = hmac.new(prk, t + full + bytes([c]), hashlib.sha256).digest(); out += t; c += 1
        return out[:n]
    prk = ext(b'', b'dkp_prk', ikm)
    for counter in range(256):
        b = bytearray(expand(prk, b'candidate', bytes([counter]), 32)); b[0] &= 0xff
        sk = int.from_bytes(b, 'big')
        if 0 < sk < Q:
            return sk
    raise ValueError


seed = rb(32)
kit_d = int.from_bytes(hkdf(seed, b'symbolon v1 kit sign', 48), 'big') % (Q - 1) + 1
kit_k, kit_pub, _ = newkey(kit_d)
kit_hpke_d = hpke_derive_p256(hkdf(seed, b'symbolon v1 kit hpke', 32))
_, kit_hpke_pub, _ = newkey(kit_hpke_d)

# ─── A log: inception, kit recovery, veto ───────────────────────

A, B = Party(0, 'phone'), Party(0, 'laptop', ('tpm2', rb(32)))
KIT = Party(1, 'kit'); KIT.dk, KIT.auth, KIT.d = kit_k, kit_pub, kit_d; KIT.id = sha(kit_pub)
_, KIT.hpke, _ = newkey(kit_hpke_d)
C = Party(2, 'cosigner')
N = Party(0, 'new phone')
root = newkey()[1]
wit = [newkey() for _ in range(3)]
pol = dict(dev=2, delay=86400, guardians=[], gt=0, witnesses=[(f'https://w{i}.example', wit[i][1]) for i in range(3)], duress=600, limit=20)
td = rb(32)
next_kit_digest = rb(32)

q0 = [A, B, KIT, C]
e0_body_c = arr([uint(0), quorum_cbor(q0, 2, root, 1, td), policy_cbor(pol)])
e0_body_r = f'InceptionBody({quorum_resid(q0, 2, root, 1, td)}, {policy_resid(pol)})'
e0 = payload_cbor(None, 0, None, e0_body_c, [sha(kit_pub)], 1000)
log_id = sha(e0)


def wmsg(seq, d): return arr([tstr('symbolon v1 witness'), bstr(log_id), uint(seq), bstr(d)])


def cosigs(seq, d, t):
    return '[' + ', '.join(f'WitnessCosignature {{ .log_id = {L(log_id)}, .sequence = {seq}, .digest = {L(d)}, .witness_key = {L(wit[i][1])}, '
                           f'.signature = {L(sign(wit[i][0], wmsg(seq, d)))}, .witness_time = {t + i} }}' for i in range(3)) + ']'


def sigs(who, msg): return '[' + ', '.join(f'EventSig {{ .signer = {L(p.id)}, .sig = {L(sign(p.dk, msg))} }}' for p in who) + ']'


rec_parties = [N, C]
rec_body_c = arr([uint(6), arr([uint(1), arr([p.cbor() for p in rec_parties]), cose_key(kit_pub), arr([])])])
rec_body_r = (f'RecoverBody(RecoverBodyInner {{ .path = 1, .new_parties = [{", ".join(p.resid() for p in rec_parties)}], '
              f'.revealed_recovery_key = Some({L(kit_pub)}), .guardian_approvals = [] }})')
e1 = payload_cbor(log_id, 1, sha(e0), rec_body_c, [next_kit_digest], 2000)
veto_body_c = arr([uint(7), uint(1)])
e2 = payload_cbor(log_id, 2, sha(e1), veto_body_c, [sha(kit_pub)], 3000)

# ─── Other bodies, for the encoder alone ────────────────────────

pol2 = dict(pol, limit=None, guardians=[rb(32), rb(32)], gt=1)
others = [
    ('set-policy', arr([uint(4), policy_cbor(pol2)]), f'SetPolicyBody({policy_resid(pol2)})'),
    ('propose-party', arr([uint(1), N.cbor(), bstr(td)]), f'ProposePartyBody({N.resid()}, {L(td)})'),
    ('remove-party', arr([uint(2), bstr(B.id)]), f'RemovePartyBody({L(B.id)})'),
    ('reshare', arr([uint(3), quorum_cbor([A, N, KIT, C], 2, root, 2, td)]), f'ReshareBody({quorum_resid([A, N, KIT, C], 2, root, 2, td)})'),
    ('rotate-recovery', arr([uint(5)]), 'RotateRecoveryBody'),
    ('migrate', arr([uint(10), uint(2)]), 'MigrateBody(2)'),
    ('veto', veto_body_c, 'VetoBody(1)'),
]

# ─── Guardian approvals ─────────────────────────────────────────

G1, G2 = Party(0, 'g1 device'), Party(0, 'g2 device')
g1_log, g2_log = rb(32), rb(32)
gpol = dict(pol, guardians=[g1_log, g2_log], gt=2)
grec_body_c = arr([uint(6), arr([uint(2), arr([N.cbor()]), NULL, arr([])])])
grec_body_r = (f'RecoverBody(RecoverBodyInner {{ .path = 2, .new_parties = [{N.resid()}], .revealed_recovery_key = None, '
               f'.guardian_approvals = [] }})')
g_pred = rb(32)
g_payload = payload_cbor(log_id, 5, g_pred, grec_body_c, [sha(kit_pub)], 9000)
g_payload_other = payload_cbor(rb(32), 5, rb(32), grec_body_c, [sha(kit_pub)], 9000)
appr_body = arr([tstr('symbolon v1 guardian approval'), bstr(sha(g_payload))])
appr_body_other = arr([tstr('symbolon v1 guardian approval'), bstr(sha(g_payload_other))])


def cose_sign1(k, kid, payload):
    prot = cmap([(ikey(1), nint(-7)), (ikey(4), bstr(kid))])
    tbs = arr([tstr('Signature1'), bstr(prot), bstr(b''), bstr(payload)])
    return head(6, 18) + arr([bstr(prot), cmap([]), bstr(payload), bstr(sign(k, tbs))])


ap1 = cose_sign1(G1.dk, G1.id, appr_body)
ap2 = cose_sign1(G2.dk, G2.id, appr_body)
ap_other = cose_sign1(G2.dk, G2.id, appr_body_other)
stranger = Party(0, 'stranger')
ap_stranger = cose_sign1(stranger.dk, stranger.id, appr_body)


def ghead(lid, p):
    return (f'LogHead {{ .log_id = {L(lid)}, .sequence = 3, .digest = {L(rb(32))}, '
            f'.quorum = {quorum_resid([p], 1, root, 1, td)}, .policy = {policy_resid(pol)} }}')


resid_payload = lambda lid, seq, pred, br, dg, t: payload_resid(lid, seq, pred, br, dg, t)

out = f'''// The recovery module (src/recovery/recovery.resid) and the event encoder
// (src/core/event.resid) against bytes, keys and signatures made by an
// independent implementation (tests/gen_recovery_ref.py). Generated; do not
// edit by hand.

import "../types.resid";
import "../core/log.resid";
import "../core/event.resid";
import "../core/event_decode.resid";
import "recovery.resid";
import "crypto.resid";

Str hx(List(Int) b) {{ return hex_encode(b); }}
Str enc_hex(EventPayload p) {{ return match payload_cbor(p) {{ Some(b) => hx(b), None => "unencodable" }}; }}

EventPayload e0() {{ return {resid_payload(None, 0, None, e0_body_r, [sha(kit_pub)], 1000)}; }}
EventPayload e1() {{ return {resid_payload(log_id, 1, sha(e0), rec_body_r, [next_kit_digest], 2000)}; }}
EventPayload e2() {{ return {resid_payload(log_id, 2, sha(e1), 'VetoBody(1)', [sha(kit_pub)], 3000)}; }}

test "inception payload bytes equal the reference" {{
    expect(enc_hex(e0())).toEqual({H(e0)});
    expect(hx(sha256_bytes(cose_hex_decode(enc_hex(e0()))))).toEqual({H(log_id)});
}}

test "kit recovery and veto payload bytes equal the reference" {{
    expect(enc_hex(e1())).toEqual({H(e1)});
    expect(enc_hex(e2())).toEqual({H(e2)});
}}
'''
for i, (name, c, r) in enumerate(others):
    pc = payload_cbor(log_id, 10 + i, sha(e0), c, [sha(kit_pub)], 5000 + i)
    out += f'''
test "{name} payload bytes equal the reference" {{
    expect(enc_hex({resid_payload(log_id, 10 + i, sha(e0), r, [sha(kit_pub)], 5000 + i)})).toEqual({H(pc)});
}}
'''
out += f'''
test "a key that is not a SEC1 P-256 point makes the payload unencodable" {{
    Party bad = Party {{ .id = {L(N.id)}, .kind = 0, .auth_key = [4, 1], .hpke_key = {L(N.hpke)}, .label = "x", .attestation = NoAttestation }};
    expect(enc_hex({resid_payload(log_id, 3, sha(e0), 'ProposePartyBody(bad, [])', [sha(kit_pub)], 1)})).toEqual("unencodable");
}}

test "the kit's keys from its seed equal the reference (HKDF; RFC 9180 DeriveKeyPair)" {{
    KitKeys k = kit_keys({L(seed)}) else {{ KitKeys {{ .sign_priv = [], .sign_pub = [], .hpke_priv = [], .hpke_pub = [] }} }};
    expect(hx(k.sign_priv)).toEqual({H(kit_d.to_bytes(32, 'big'))});
    expect(hx(k.sign_pub)).toEqual({H(kit_pub)});
    expect(hx(k.hpke_priv)).toEqual({H(kit_hpke_d.to_bytes(32, 'big'))});
    expect(hx(k.hpke_pub)).toEqual({H(KIT.hpke)});
    expect(hx(recovery_key_digest(k.sign_pub))).toEqual({H(sha(kit_pub))});
}}

test "a kit recover made here is the reference's bytes, signed by the kit key" {{
    KitKeys k = kit_keys({L(seed)}) else {{ KitKeys {{ .sign_priv = [], .sign_pub = [], .hpke_priv = [], .hpke_pub = [] }} }};
    LogHead h = LogHead {{ .log_id = {L(log_id)}, .sequence = 0, .digest = {L(sha(e0))}, .quorum = {quorum_resid(q0, 2, root, 1, td)}, .policy = {policy_resid(pol)} }};
    Result(SignedEvent, SymbolonError) r = recover_by_kit(h, k, [{", ".join(p.resid() for p in rec_parties)}], [{L(next_kit_digest)}], 2000);
    SignedEvent e = match r {{ Ok(x) => x, Err(_) => SignedEvent {{ .payload = e0(), .encoded = [], .sigs = [], .cosigs = [] }} }};
    expect(hx(e.encoded)).toEqual({H(e1)});
    expect(ecdsa_verify_raw(P256, Sha256, {L(kit_pub)}, e.encoded, e.sigs[0].sig)).toBeTrue();
}}

SignedEvent ev0() {{ return SignedEvent {{ .payload = e0(), .encoded = {L(e0)}, .sigs = {sigs(q0, e0)}, .cosigs = {cosigs(0, sha(e0), 1000)} }}; }}
SignedEvent ev1() {{ return SignedEvent {{ .payload = e1(), .encoded = {L(e1)}, .sigs = [EventSig {{ .signer = {L(KIT.id)}, .sig = {L(sign(kit_k, e1))} }}], .cosigs = {cosigs(1, sha(e1), 2000)} }}; }}
SignedEvent ev2() {{ return SignedEvent {{ .payload = e2(), .encoded = {L(e2)}, .sigs = {sigs([A], e2)}, .cosigs = {cosigs(2, sha(e2), 3000)} }}; }}

Str quorum_names(Result(VerifiedHead, SymbolonError) r) {{
    return match r {{ Ok(v) => names(v.head.quorum.parties, 0, ""), Err(e) => "error" }};
}}

Str names(List(Party) ps, Int i, Str acc) {{
    if (i >= ps.len()) {{ return acc; }}
    return names(ps, i + 1, acc + (if (i > 0) {{ "," }} else {{ "" }}) + ps[i].label);
}}

Str released(List(SignedEvent) es, Int now) {{
    return match il_verify({L(log_id)}, es, now, lambda(p) {{ false }}) {{
        Err(_) => "log refused",
        Ok(v) => match release_target(es, v, {L(N.id)}) {{ Ok(k) => hx(k), Err(e) => match e {{ ErrRecoveryFailed(s) => s, _ => "other" }} }}
    }};
}}

test "a whole log signed in Python: the kit recovery takes effect only after the delay" {{
    expect(quorum_names(il_verify({L(log_id)}, [ev0(), ev1()], 2001 + 86399, lambda(p) {{ false }}))).toEqual("phone,laptop,kit,cosigner");
    expect(quorum_names(il_verify({L(log_id)}, [ev0(), ev1()], 2001 + 86400, lambda(p) {{ false }}))).toEqual("new phone,cosigner");
}}

test "the cosigner releases its kit half to the new device only after the delay, never after a veto" {{
    expect(released([ev0(), ev1()], 2001 + 86399)).toEqual("the recovery delay has not run");
    expect(released([ev0(), ev1()], 2001 + 86400)).toEqual({H(N.hpke)});
    expect(released([ev0(), ev1(), ev2()], 2001 + 86400 * 2)).toEqual("the device is not in the quorum (vetoed?)");
    expect(released([ev0()], 5000)).toEqual("no kit recovery names this device");
}}

'''
out += f'''EventPayload gp() {{ return {resid_payload(log_id, 5, g_pred, grec_body_r, [sha(kit_pub)], 9000)}; }}

test "guardian approval payload equals the reference" {{
    expect(enc_hex(gp())).toEqual({H(g_payload)});
    expect(match approval_payload(gp()) {{ Some(b) => hx(b), None => "" }}).toEqual({H(appr_body)});
}}

List(LogHead) gheads() {{ return [{ghead(g1_log, G1)}, {ghead(g2_log, G2)}]; }}
Policy gpolicy() {{ return {policy_resid(gpol)}; }}

test "approvals made in Python by two guardians' devices reach policy[4]" {{
    expect(guardian_approvals_ok(gpolicy(), gheads(), with_approvals(gp(), [{L(ap1)}, {L(ap2)}]))).toBeTrue();
}}

test "one guardian twice, a stranger, or an approval for another log do not count" {{
    expect(guardian_approvals_ok(gpolicy(), gheads(), with_approvals(gp(), [{L(ap1)}]))).toBeFalse();
    expect(guardian_approvals_ok(gpolicy(), gheads(), with_approvals(gp(), [{L(ap1)}, {L(ap1)}]))).toBeFalse();
    expect(guardian_approvals_ok(gpolicy(), gheads(), with_approvals(gp(), [{L(ap1)}, {L(ap_stranger)}]))).toBeFalse();
    expect(guardian_approvals_ok(gpolicy(), gheads(), with_approvals(gp(), [{L(ap1)}, {L(ap_other)}]))).toBeFalse();
    // A guardian not named in the policy does not count even when its head is supplied.
    expect(guardian_approvals_ok({policy_resid(dict(gpol, guardians=[g1_log]))}, gheads(), with_approvals(gp(), [{L(ap1)}, {L(ap2)}]))).toBeFalse();
}}
'''

# ─── The decoder: every Python payload decodes and re-encodes to itself ───
all_payloads = [e0, e1, e2, g_payload] + [payload_cbor(log_id, 10 + i, sha(e0), c, [sha(kit_pub)], 5000 + i) for i, (n, c, r) in enumerate(others)]
ap_payload = payload_cbor(log_id, 6, g_pred, arr([uint(6), arr([uint(2), arr([N.cbor()]), NULL, arr([ap1, ap2])])]), [sha(kit_pub)], 9001)
all_payloads.append(ap_payload)
dec_lines = '\n'.join(f'    expect(redecoded({L(b)})).toEqual({H(b)});' for b in all_payloads)
long_head = bytes([0xb8, 7]) + e1[1:]
swapped = bytearray(e2); 
out += f'''
Str redecoded(List(Int) b) {{
    return match payload_decode(b) {{ None => "refused", Some(p) => match payload_cbor(p) {{ Some(x) => hx(x), None => "unencodable" }} }};
}}

test "every payload made in Python decodes and re-encodes to the same bytes" {{
{dec_lines}
}}

test "the decoder keeps fields: sequence, predecessor, recover parties and approvals" {{
    EventPayload p = payload_decode({L(e1)}) else {{ e0() }};
    expect((Int)p.sequence).toEqual(1);
    expect(hx(p.predecessor_digest else {{ [] }})).toEqual({H(sha(e0))});
    EventBody b = p.body;
    expect(match b {{ RecoverBody(r) => r.new_parties.len() == 2 && r.new_parties[0].label == "new phone", _ => false }}).toBeTrue();
    EventPayload q = payload_decode({L(ap_payload)}) else {{ e0() }};
    EventBody qb = q.body;
    expect(match qb {{ RecoverBody(r) => r.guardian_approvals.len() == 2 && hx(r.guardian_approvals[1]) == {H(ap2)}, _ => false }}).toBeTrue();
}}

test "non-canonical, truncated or padded payloads are refused" {{
    expect(redecoded({L(long_head)})).toEqual("refused");
    expect(redecoded({L(e1[:-1])})).toEqual("refused");
    expect(redecoded({L(e1 + bytes([0]))})).toEqual("refused");
    expect(redecoded({L(bytes([0xa7]) + e1[1:].replace(bytes([1, 0x58, 0x20]), bytes([1, 0x59, 0, 0x20]), 1))})).toEqual("refused");
    expect(redecoded([])).toEqual("refused");
}}
'''
open(os.path.join(HERE, '..', 'src', 'recovery', 'recovery_ref_test.resid'), 'w').write(out)

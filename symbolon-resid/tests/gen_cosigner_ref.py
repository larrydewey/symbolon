#!/usr/bin/env python3
"""Generates src/cosigner/cosigner_ref_test.resid. The request and end-duress
signing bytes, the DK and duress sub-key signatures and the message hashes
are made here, in Python (separate CBOR encoder, cryptography's ECDSA,
hashlib), not by the code under test.

    python3 tests/gen_cosigner_ref.py
"""
import hashlib, os, random
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

random.seed(31)
HERE = os.path.dirname(os.path.abspath(__file__))
rb = lambda n: bytes(random.randrange(256) for _ in range(n))


def head(major, n):
    if n < 24: return bytes([major << 5 | n])
    if n < 256: return bytes([major << 5 | 24, n])
    if n < 65536: return bytes([major << 5 | 25]) + n.to_bytes(2, 'big')
    return bytes([major << 5 | 26]) + n.to_bytes(4, 'big')

uint = lambda n: head(0, n)
bstr = lambda b: head(2, len(b)) + b
tstr = lambda s: head(3, len(s.encode())) + s.encode()
arr = lambda items: head(4, len(items)) + b''.join(items)


def newkey():
    k = ec.derive_private_key(int.from_bytes(rb(32), 'big') % (2**255) + 1, ec.SECP256R1())
    n = k.public_key().public_numbers()
    return k, b'\x04' + n.x.to_bytes(32, 'big') + n.y.to_bytes(32, 'big')


def sign(k, msg):
    r, s = decode_dss_signature(k.sign(msg, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, 'big') + s.to_bytes(32, 'big')


L = lambda b: '[' + ', '.join(str(x) for x in b) + ']'
H = lambda b: '"' + bytes(b).hex() + '"'

SIGN, RESHARE, ENROLL, RECOVERY, KIT, POLICY = range(6)
EPOCH = 4
(a_dk, a_pub), (a_dur, a_dur_pub), (b_dk, b_pub), (c_dk, c_pub), (x_dk, x_pub) = [newkey() for _ in range(5)]
a_id, b_id, c_id, kit_id, cos_id = rb(32), rb(32), rb(32), rb(32), rb(32)
log_id, digest = rb(32), rb(32)


def tbs(sid, m, epoch, who, kind):
    return arr([tstr('symbolon v1 cosign'), bstr(sid), bstr(m), uint(epoch), bstr(who), uint(kind)])


def req(key, who, kind=SIGN, epoch=EPOCH, sid=None, m=None, flip=False):
    sid = sid or rb(32)
    m = m or rb(32)
    sg = bytearray(sign(key, tbs(sid, m, epoch, who, kind)))
    if flip: sg[7] ^= 1
    return (f'CosignRequest {{ .session_id = {L(sid)}, .message = {L(m)}, .epoch = {epoch}, '
            f'.requester = {L(who)}, .kind = {kind}, .sig = {L(sg)} }}'), sid, m


ref_sid, ref_m = rb(32), rb(32)
ref_tbs = tbs(ref_sid, ref_m, EPOCH, a_id, RESHARE)
first, _, first_m = req(a_dk, a_id)


def end_tbs(started): return arr([tstr('symbolon v1 end-duress'), bstr(log_id), uint(started)])


def esig(key, who, started): return f'EventSig {{ .signer = {L(who)}, .sig = {L(sign(key, end_tbs(started)))} }}'


DSTART = 5000
r = lambda *a, **k: req(*a, **k)[0]

out = f'''// The cosigner policy (src/cosigner/cosigner.resid) against signing bytes,
// signatures and hashes made by an independent implementation
// (tests/gen_cosigner_ref.py). Generated; do not edit by hand.

import "../types.resid";
import "../core/log.resid";
import "cosigner.resid";
import "crypto.resid";

Str hx(List(Int) b) {{ return hex_encode(b); }}

Party pt(List(Int) id, UInt(8) kind, List(Int) key) {{
    return Party {{ .id = id, .kind = kind, .auth_key = key, .hpke_key = [], .label = "p", .attestation = NoAttestation }};
}}

LogHead head_at(UInt(64) seq, List(Int) dig) {{
    Quorum q = Quorum {{
        .parties = [pt({L(a_id)}, party_kind_device(), {L(a_pub)}), pt({L(b_id)}, party_kind_device(), {L(b_pub)}),
                    pt({L(c_id)}, party_kind_device(), {L(c_pub)}), pt({L(kit_id)}, party_kind_kit(), {L(a_pub)}),
                    pt({L(cos_id)}, party_kind_cosigner(), {L(x_pub)})],
        .t = 2, .root_pubkey = [], .epoch = {EPOCH}, .transcript_digest = [] }};
    Policy p = Policy {{
        .device_sigs_for_authority = 2, .recovery_delay_sec = 86400, .guardians = [], .guardian_threshold = 0,
        .witnesses = [], .duress_window_sec = 600, .cosigner_policy = CosignerLimit(3) }};
    return LogHead {{ .log_id = {L(log_id)}, .sequence = seq, .digest = dig, .quorum = q, .policy = p }};
}}

VerifiedHead vh(UInt(64) seq, List(Int) dig) {{ return VerifiedHead {{ .head = head_at(seq, dig), .witness_cosigs = [], .pending = [] }}; }}

CosignerState fresh() {{
    return cosigner_new(vh(9, {L(digest)}), [DuressKey {{ .party = {L(a_id)}, .subkey = {L(a_dur_pub)} }}]);
}}

Str err_str(SymbolonError e) {{
    return match e {{
        ErrInvalidLog(s) => "log: " + s, ErrInvalidSignature(s) => "sig: " + s,
        ErrQuorumNotMet(h, n) => f"quorum {{h}}/{{n}}", ErrStaleEpoch(h, c) => f"epoch {{h}}/{{c}}",
        ErrVaultIntegrity(s) => s, ErrPolicyViolation(s) => "policy: " + s, ErrDuressContainment(s) => "duress: " + s,
        ErrRecoveryFailed(s) => s, ErrRotationFailed(s) => s, ErrAttestationFailed(s) => s,
        ErrCapabilityDenied(s) => s, ErrNetwork(s) => "net: " + s, ErrStorage(s) => s, ErrHardware(s) => s,
        ErrInternal(s) => s
    }};
}}

Str said(CosignOutcome o) {{ return match o {{ Proceed(_) => "proceed", Refuse(_, e) => err_str(e) }}; }}
CosignerState st(CosignOutcome o) {{ return match o {{ Proceed(s) => s, Refuse(s, _) => s }}; }}

test "request signing bytes equal the reference" {{
    expect(hx(request_tbs({L(ref_sid)}, {L(ref_m)}, {EPOCH}, {L(a_id)}, {RESHARE}))).toEqual({H(ref_tbs)});
}}

test "end-duress signing bytes equal the reference" {{
    expect(hx(end_duress_tbs({L(log_id)}, {DSTART}))).toEqual({H(end_tbs(DSTART))});
}}

test "a device's DK-signed request proceeds and is recorded with H(m)" {{
    CosignOutcome o = cosign_decide(fresh(), {first}, 100);
    expect(said(o)).toEqual("proceed");
    CosignerState s = st(o);
    expect(s.records.len()).toEqual(1);
    expect(hx(s.records[0].message_hash)).toEqual({H(hashlib.sha256(first_m).digest())});
    expect(hx(s.records[0].requester)).toEqual({H(a_id)});
    expect(s.records[0].time).toEqual(100);
}}

test "a session identifier is accepted once" {{
    CosignerState s = st(cosign_decide(fresh(), {first}, 100));
    expect(said(cosign_decide(s, {first}, 101))).toEqual("policy: session identifier seen before");
}}

test "the kit, the cosigner and strangers are refused even with a valid key" {{
    expect(said(cosign_decide(fresh(), {r(a_dk, kit_id)}, 1))).toEqual("policy: requester is not a device of the current quorum");
    expect(said(cosign_decide(fresh(), {r(x_dk, cos_id)}, 1))).toEqual("policy: requester is not a device of the current quorum");
    expect(said(cosign_decide(fresh(), {r(a_dk, rb(32))}, 1))).toEqual("policy: requester is not a device of the current quorum");
}}

test "a flipped signature bit, another device's key and a stale epoch are refused" {{
    expect(said(cosign_decide(fresh(), {r(a_dk, a_id, flip=True)}, 1))).toEqual("sig: cosign request");
    expect(said(cosign_decide(fresh(), {r(b_dk, a_id)}, 1))).toEqual("sig: cosign request");
    expect(said(cosign_decide(fresh(), {r(a_dk, a_id, epoch=EPOCH - 1)}, 1))).toEqual("epoch {EPOCH - 1}/{EPOCH}");
}}

test "the hourly rate limit counts one device's sessions only" {{
    CosignerState s1 = st(cosign_decide(fresh(), {r(a_dk, a_id)}, 10));
    CosignerState s2 = st(cosign_decide(s1, {r(a_dk, a_id)}, 20));
    CosignerState s3 = st(cosign_decide(s2, {r(a_dk, a_id)}, 30));
    expect(said(cosign_decide(s3, {r(a_dk, a_id)}, 40))).toEqual("policy: rate limit");
    expect(said(cosign_decide(s3, {r(b_dk, b_id)}, 40))).toEqual("proceed");
    // An hour after the first session one slot is free again.
    expect(said(cosign_decide(s3, {r(a_dk, a_id)}, 3611))).toEqual("proceed");
}}

test "a duress-key request signs; authority requests from any device then look like an outage" {{
    CosignOutcome o = cosign_decide(fresh(), {r(a_dur, a_id)}, {DSTART});
    expect(said(o)).toEqual("proceed");
    CosignerState s = st(o);
    expect(cosigner_in_duress(s, {DSTART + 1})).toBeTrue();
    expect(said(cosign_decide(s, {r(b_dk, b_id, kind=RESHARE)}, {DSTART + 2}))).toEqual("net: cosigner unreachable");
    expect(said(cosign_decide(s, {r(c_dk, c_id, kind=ENROLL)}, {DSTART + 2}))).toEqual("net: cosigner unreachable");
    expect(said(cosign_decide(s, {r(a_dk, a_id, kind=RECOVERY)}, {DSTART + 2}))).toEqual("net: cosigner unreachable");
    expect(said(cosign_decide(s, {r(b_dk, b_id, kind=KIT)}, {DSTART + 2}))).toEqual("net: cosigner unreachable");
    expect(said(cosign_decide(s, {r(b_dk, b_id, kind=POLICY)}, {DSTART + 2}))).toEqual("net: cosigner unreachable");
    // Every other refusal during the window has the same face.
    expect(said(cosign_decide(s, {r(a_dk, kit_id)}, {DSTART + 2}))).toEqual("net: cosigner unreachable");
    expect(said(cosign_decide(s, {r(a_dk, a_id, flip=True)}, {DSTART + 2}))).toEqual("net: cosigner unreachable");
    // Signing for the subset still works, from either key.
    expect(said(cosign_decide(s, {r(b_dk, b_id)}, {DSTART + 3}))).toEqual("proceed");
}}

test "outside duress the same authority requests proceed" {{
    expect(said(cosign_decide(fresh(), {r(b_dk, b_id, kind=RESHARE)}, 1))).toEqual("proceed");
    expect(said(cosign_decide(fresh(), {r(c_dk, c_id, kind=ENROLL)}, 1))).toEqual("proceed");
}}

test "the duress window ends after policy[6] seconds" {{
    CosignerState s = st(cosign_decide(fresh(), {r(a_dur, a_id)}, {DSTART}));
    expect(cosigner_in_duress(s, {DSTART + 599})).toBeTrue();
    expect(cosigner_in_duress(s, {DSTART + 600})).toBeFalse();
    expect(said(cosign_decide(s, {r(b_dk, b_id, kind=RESHARE)}, {DSTART + 600}))).toEqual("proceed");
}}

Str ended(CosignerState s, EndDuress m, Int now) {{
    return match cosigner_end_duress(s, m, now) {{
        Ok(x) => if (cosigner_in_duress(x, now)) {{ "still" }} else {{ "ended" }},
        Err(e) => err_str(e)
    }};
}}

test "end-duress needs policy[1] devices other than the duress device" {{
    CosignerState s = st(cosign_decide(fresh(), {r(a_dur, a_id)}, {DSTART}));
    expect(ended(s, EndDuress {{ .log_id = {L(log_id)}, .started_at = {DSTART}, .sigs = [{esig(b_dk, b_id, DSTART)}, {esig(c_dk, c_id, DSTART)}] }}, {DSTART + 5})).toEqual("ended");
    expect(ended(s, EndDuress {{ .log_id = {L(log_id)}, .started_at = {DSTART}, .sigs = [{esig(b_dk, b_id, DSTART)}] }}, {DSTART + 5})).toEqual("quorum 1/2");
    expect(ended(s, EndDuress {{ .log_id = {L(log_id)}, .started_at = {DSTART}, .sigs = [{esig(a_dk, a_id, DSTART)}, {esig(b_dk, b_id, DSTART)}] }}, {DSTART + 5})).toEqual("quorum 1/2");
    expect(ended(s, EndDuress {{ .log_id = {L(log_id)}, .started_at = {DSTART}, .sigs = [{esig(b_dk, b_id, DSTART)}, {esig(b_dk, b_id, DSTART)}] }}, {DSTART + 5})).toEqual("quorum 1/2");
    expect(ended(s, EndDuress {{ .log_id = {L(log_id)}, .started_at = {DSTART}, .sigs = [{esig(b_dk, b_id, DSTART + 1)}, {esig(c_dk, c_id, DSTART + 1)}] }}, {DSTART + 5})).toEqual("quorum 0/2");
    expect(ended(s, EndDuress {{ .log_id = {L(log_id)}, .started_at = {DSTART + 1}, .sigs = [{esig(b_dk, b_id, DSTART + 1)}, {esig(c_dk, c_id, DSTART + 1)}] }}, {DSTART + 5})).toEqual("duress: end-duress names another window");
}}

Str moved(CosignerState s, VerifiedHead v) {{
    return match cosigner_update_head(s, v) {{ Ok(x) => f"{{x.verified.head.sequence}}", Err(e) => err_str(e) }};
}}

test "the held head moves forward only" {{
    expect(moved(fresh(), vh(10, {L(rb(32))}))).toEqual("10");
    expect(moved(fresh(), vh(9, {L(digest)}))).toEqual("9");
    expect(moved(fresh(), vh(9, {L(rb(32))}))).toEqual("log: fork");
    expect(moved(fresh(), vh(8, {L(rb(32))}))).toEqual("log: rollback");
}}
'''
open(os.path.join(HERE, '..', 'src', 'cosigner', 'cosigner_ref_test.resid'), 'w').write(out)

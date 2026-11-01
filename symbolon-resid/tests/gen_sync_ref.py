#!/usr/bin/env python3
"""Generates src/sync/sync_ref_test.resid. The device-authentication bytes and
signatures and the witness co-signatures are made here, in Python (separate
CBOR encoder, cryptography's ECDSA), not by the code under test.

    python3 tests/gen_sync_ref.py
"""
import hashlib, os, random
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

random.seed(20)
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

dk, dk_pub = newkey()
other_dk, other_pub = newkey()
dev_id, kit_id = rb(32), rb(32)
challenge = rb(32)
audience = 'sync.example.org'
tbs = arr([tstr('symbolon v1 auth'), bstr(challenge), bstr(dev_id), tstr(audience)])
sig = sign(dk, tbs)
bad = bytearray(sig); bad[40] ^= 4

wk = [newkey() for _ in range(3)]
log_id, digest = rb(32), rb(32)
seq = 6
def wmsg(l, s, d): return arr([tstr('symbolon v1 witness'), bstr(l), uint(s), bstr(d)])
times = [1000, 1010, 1030]
cos = [(wk[i][1], sign(wk[i][0], wmsg(log_id, seq, digest)), times[i]) for i in range(3)]
intruder, intruder_pub = newkey()
intr = (intruder_pub, sign(intruder, wmsg(log_id, seq, digest)), 5)
wrong_seq = (wk[0][1], sign(wk[0][0], wmsg(log_id, seq + 1, digest)), 1)


def cs(c, l=None, s=seq, d=None):
    key, sg, t = c
    return (f'WitnessCosignature {{ .log_id = {L(l or log_id)}, .sequence = {s}, .digest = {L(d or digest)}, '
            f'.witness_key = {L(key)}, .signature = {L(sg)}, .witness_time = {t} }}')


out = f'''// The sync checks (src/sync/sync.resid) against bytes and signatures made by
// an independent implementation (tests/gen_sync_ref.py): device-authentication
// signing bytes and ECDSA signatures, and witness co-signatures. Generated;
// do not edit by hand.

import "../types.resid";
import "../core/log.resid";
import "sync.resid";
import "crypto.resid";

Str hx(List(Int) b) {{ return hex_encode(b); }}

Party test_party(List(Int) id, UInt(8) kind, List(Int) key) {{
    return Party {{ .id = id, .kind = kind, .auth_key = key, .hpke_key = [], .label = "p", .attestation = NoAttestation }};
}}

Quorum auth_quorum() {{
    return Quorum {{
        .parties = [test_party({L(dev_id)}, party_kind_device(), {L(dk_pub)}),
                    test_party({L(kit_id)}, party_kind_kit(), {L(dk_pub)})],
        .t = 1, .root_pubkey = [], .epoch = 0, .transcript_digest = [] }};
}}

test "auth signing bytes equal the reference" {{
    expect(hx(auth_tbs({L(challenge)}, {L(dev_id)}, "{audience}"))).toEqual({H(tbs)});
}}

test "a device signature made in Python verifies; every change to it fails" {{
    Quorum q = auth_quorum();
    expect(verify_device_auth(q, {L(dev_id)}, {L(challenge)}, "{audience}", {L(sig)})).toBeTrue();
    expect(verify_device_auth(q, {L(dev_id)}, {L(challenge)}, "other.example.org", {L(sig)})).toBeFalse();
    expect(verify_device_auth(q, {L(dev_id)}, {L(rb(32))}, "{audience}", {L(sig)})).toBeFalse();
    expect(verify_device_auth(q, {L(rb(32))}, {L(challenge)}, "{audience}", {L(sig)})).toBeFalse();
    expect(verify_device_auth(q, {L(dev_id)}, {L(challenge)}, "{audience}", {L(list(bad))})).toBeFalse();
    // The kit shares the key above but is not a device: it cannot authenticate as one.
    expect(verify_device_auth(q, {L(kit_id)}, {L(challenge)}, "{audience}", {L(sig)})).toBeFalse();
}}

LogHead log_head() {{
    Policy p = Policy {{
        .device_sigs_for_authority = 2, .recovery_delay_sec = 86400, .guardians = [], .guardian_threshold = 0,
        .witnesses = [WitnessRef {{ .url = "a", .key = {L(wk[0][1])} }}, WitnessRef {{ .url = "b", .key = {L(wk[1][1])} }},
                      WitnessRef {{ .url = "c", .key = {L(wk[2][1])} }}],
        .duress_window_sec = 0, .cosigner_policy = NoCosignerPolicy }};
    return LogHead {{ .log_id = {L(log_id)}, .sequence = {seq}, .digest = {L(digest)},
                      .quorum = auth_quorum(), .policy = p }};
}}

Int witnessed(List(WitnessCosignature) cosigs) {{
    return match require_witnessed(cosigs, log_head()) {{ Ok(t) => t, Err(_) => -1 }};
}}

test "witness co-signatures made in Python: majority gives the median time" {{
    expect(witnessed([{cs(cos[0])}, {cs(cos[1])}, {cs(cos[2])}])).toEqual({sorted(times)[1]});
    expect(witnessed([{cs(cos[0])}, {cs(cos[2])}])).toEqual({sorted([times[0], times[2]])[1]});
}}

test "one co-signature of three witnesses is refused" {{
    expect(witnessed([{cs(cos[1])}])).toEqual(-1);
}}

test "a duplicate, a stranger and a signature over another sequence do not count" {{
    expect(witnessed([{cs(cos[0])}, {cs(cos[0])}])).toEqual(-1);
    expect(witnessed([{cs(cos[0])}, {cs(intr)}])).toEqual(-1);
    expect(witnessed([{cs(cos[0])}, {cs(wrong_seq, s=seq)}])).toEqual(-1);
}}
'''
open(os.path.join(HERE, '..', 'src', 'sync', 'sync_ref_test.resid'), 'w').write(out)

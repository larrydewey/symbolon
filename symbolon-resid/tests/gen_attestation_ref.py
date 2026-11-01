#!/usr/bin/env python3
"""Generates src/attestation/attestation_ref_test.resid. TPM structures
(TPMT_PUBLIC, TPMS_ATTEST of type CERTIFY, TPMT_SIGNATURE) are built byte by
byte here from TPM 2.0 Part 2 and signed with cryptography's ECDSA; the
provenance bytes, release signatures, transparency log and rebuilder
signatures likewise. Nothing comes from the code under test.

    python3 tests/gen_attestation_ref.py
"""
import hashlib, os, random
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

random.seed(101)
HERE = os.path.dirname(os.path.abspath(__file__))
rb = lambda n: bytes(random.randrange(256) for _ in range(n))
L = lambda b: '[' + ', '.join(str(x) for x in b) + ']'
H = lambda b: '"' + bytes(b).hex() + '"'
sha = lambda b: hashlib.sha256(b).digest()
u16 = lambda v: v.to_bytes(2, 'big'); u32 = lambda v: v.to_bytes(4, 'big')
b2 = lambda b: u16(len(b)) + b


def head(major, n):
    if n < 24: return bytes([major << 5 | n])
    if n < 256: return bytes([major << 5 | 24, n])
    if n < 65536: return bytes([major << 5 | 25]) + n.to_bytes(2, 'big')
    return bytes([major << 5 | 26]) + n.to_bytes(4, 'big')

uint = lambda n: head(0, n); nint = lambda n: head(1, -1 - n)
bstr = lambda b: head(2, len(b)) + b; tstr = lambda s: head(3, len(s.encode())) + s.encode()
arr = lambda items: head(4, len(items)) + b''.join(items)
mp = lambda pairs: head(5, len(pairs)) + b''.join(k + v for k, v in pairs)


def newkey():
    k = ec.generate_private_key(ec.SECP256R1())
    n = k.public_key().public_numbers()
    return k, n.x.to_bytes(32, 'big'), n.y.to_bytes(32, 'big')


def sig_raw(k, msg):
    r, s = decode_dss_signature(k.sign(msg, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, 'big'), s.to_bytes(32, 'big')


def cose_sign1(k, payload):
    prot = mp([(uint(1), nint(-7))])
    tbs = arr([tstr('Signature1'), bstr(prot), bstr(b''), bstr(payload)])
    r, s = sig_raw(k, tbs)
    return head(6, 18) + arr([bstr(prot), mp([]), bstr(payload), bstr(r + s)])


FIXED_TPM, FIXED_PARENT, SENS, UWA, RESTRICTED, DECRYPT, SIGN = 2, 16, 32, 64, 65536, 131072, 262144


def ecc_public(x, y, attrs, policy, scheme):
    sch = u16(0x0018) + u16(0x000b) if scheme else u16(0x0010)
    return u16(0x0023) + u16(0x000b) + u32(attrs) + b2(policy) + u16(0x0010) + sch + u16(0x0003) + u16(0x0010) + b2(x) + b2(y)


def certify_attest(extra, obj_public):
    name = u16(0x000b) + sha(obj_public)
    clock = rb(8) + u32(3) + u32(1) + b'\x01'
    return u32(0xff544347) + u16(0x8017) + b2(rb(34)) + b2(extra) + clock + rb(8) + b2(name) + b2(rb(34))


def tpm_sig(k, attest):
    r, s = sig_raw(k, attest)
    return u16(0x0018) + u16(0x000b) + b2(r) + b2(s)


ak_k, akx, aky = newkey()
ak_pub = ecc_public(akx, aky, FIXED_TPM | FIXED_PARENT | SENS | UWA | RESTRICTED | SIGN, b'', True)
dk_k, dkx, dky = newkey()
policy = sha(bytes(32) + (0x16B).to_bytes(4, 'big'))   # PolicyAuthValue
dk_pub = ecc_public(dkx, dky, FIXED_TPM | FIXED_PARENT | SENS | SIGN, policy, False)
dk_point = b'\x04' + dkx + dky
challenge, log_id = rb(32), rb(32)
extra = sha(arr([tstr('symbolon v1 enroll'), bstr(challenge), bstr(log_id)]))
att = certify_attest(extra, dk_pub)
sg = tpm_sig(ak_k, att)

# Faulty variants.
dk_uwa = ecc_public(dkx, dky, FIXED_TPM | FIXED_PARENT | SENS | SIGN | UWA, policy, False)
dk_dec = ecc_public(dkx, dky, FIXED_TPM | FIXED_PARENT | SENS | SIGN | DECRYPT, policy, False)
dk_soft = ecc_public(dkx, dky, FIXED_PARENT | SENS | SIGN, policy, False)
dk_otherpol = ecc_public(dkx, dky, FIXED_TPM | FIXED_PARENT | SENS | SIGN, rb(32), False)
att_otherpol = certify_attest(extra, dk_otherpol)
att_uwa = certify_attest(extra, dk_uwa); att_dec = certify_attest(extra, dk_dec); att_soft = certify_attest(extra, dk_soft)
other_k, ox, oy = newkey()
att_stale = certify_attest(sha(b'another challenge'), dk_pub)
att_quote = bytearray(att); att_quote[4:6] = u16(0x8018); att_quote = bytes(att_quote)


def ev(a, s, pub):
    return f'DkEvidence {{ .attest = u8({L(a)}), .sig = u8({L(s)}), .dk_public = u8({L(pub)}) }}'


# Provenance and updates.
prov = mp([(uint(1), tstr('symbolon')), (uint(2), tstr('0.1.0')), (uint(3), bstr(rb(32))), (uint(4), arr([bstr(rb(32)), bstr(rb(32))])),
           (uint(5), arr([tstr('device'), tstr('network')])), (uint(6), mp([(uint(1), tstr('residc')), (uint(2), tstr('0.3.0')), (uint(3), b'\xf5')])),
           (uint(7), arr([mp([(uint(1), tstr('k1')), (uint(2), bstr(rb(32))), (uint(3), arr([tstr('device')]))])]))])
# Unpack the same fields for the Resid record.
import re
rel = [newkey()[0] for _ in range(3)]
rebuilders = [newkey()[0] for _ in range(3)]
pubpt = lambda k: (lambda n: b'\x04' + n.x.to_bytes(32, 'big') + n.y.to_bytes(32, 'big'))(k.public_key().public_numbers())
log_k = newkey()[0]
lh = lambda e: sha(b'\0' + e); nh = lambda a, b: sha(b'\x01' + a + b)
entries = [arr([uint(9000), bstr(prov)]), arr([uint(9100), bstr(rb(10))]), arr([uint(9200), bstr(rb(10))])]
root = nh(nh(lh(entries[0]), lh(entries[1])), lh(entries[2]))
proof0 = [lh(entries[1]), lh(entries[2])]
th = cose_sign1(log_k, mp([(uint(1), uint(3)), (uint(2), bstr(root))]))
rs = [cose_sign1(k, prov) for k in rel]
rbs = [cose_sign1(k, sha(prov)) for k in rebuilders]
rbs_wrong = cose_sign1(rebuilders[2], sha(prov + b'x'))

out = f'''// Attestation (src/attestation/attestation.resid) against TPM structures,
// signatures and logs made by an independent implementation
// (tests/gen_attestation_ref.py). Generated; do not edit by hand.

import "../types.resid";
import "attestation.resid";
import "crypto.resid";

Str hx(List(Int) b) {{ return hex_encode(b); }}
List(UInt(8)) u8(List(Int) b) {{ return u8_at(b, 0, ListBuf()); }}
List(UInt(8)) u8_at(List(Int) b, Int i, ListBuf(UInt(8)) acc) {{
    if (i >= b.len()) {{ return acc.finish(); }}
    return u8_at(b, i + 1, acc.push((UInt(8))b[i]));
}}

Str certified(DkEvidence e, List(Int) key, List(Int) challenge) {{
    return match dk_certified(e, u8({L(ak_pub)}), key, challenge, {L(log_id)}) {{
        Ok(_) => "ok", Err(x) => match x {{ ErrAttestationFailed(s) => s, _ => "other" }}
    }};
}}

test "a DK certified by the AK, bound to the challenge, PIN-policy bound: accepted" {{
    expect(hx(enroll_extra({L(challenge)}, {L(log_id)}))).toEqual({H(extra)});
    expect(certified({ev(att, sg, dk_pub)}, {L(dk_point)}, {L(challenge)})).toEqual("ok");
}}

test "another key, another challenge, another signer, or another attestation type: refused" {{
    expect(certified({ev(att, sg, dk_pub)}, {L(b'\\x04' + ox + oy)}, {L(challenge)})).toEqual("the certified key is not the device's DK");
    expect(str_len(certified({ev(att, sg, dk_pub)}, {L(dk_point)}, {L(rb(32))})) > 2).toBeTrue();
    expect(certified({ev(att, sg, dk_pub)}, {L(dk_point)}, {L(rb(32))}) == "ok").toBeFalse();
    expect(certified({ev(att_stale, tpm_sig(ak_k, att_stale), dk_pub)}, {L(dk_point)}, {L(challenge)}) == "ok").toBeFalse();
    expect(certified({ev(att, tpm_sig(other_k, att), dk_pub)}, {L(dk_point)}, {L(challenge)}) == "ok").toBeFalse();
    expect(certified({ev(att_quote, tpm_sig(ak_k, att_quote), dk_pub)}, {L(dk_point)}, {L(challenge)}) == "ok").toBeFalse();
    // The certification names the policy-bound DK; presenting a public area that differs is refused.
    expect(certified({ev(att, sg, dk_uwa)}, {L(dk_point)}, {L(challenge)}) == "ok").toBeFalse();
}}

test "a DK usable without its unlock policy, one that decrypts, or one not fixed to its TPM: refused" {{
    expect(certified({ev(att_uwa, tpm_sig(ak_k, att_uwa), dk_uwa)}, {L(dk_point)}, {L(challenge)})).toEqual("the DK is usable without its unlock policy");
    expect(certified({ev(att_otherpol, tpm_sig(ak_k, att_otherpol), dk_otherpol)}, {L(dk_point)}, {L(challenge)})).toEqual("the DK is usable without its unlock policy");
    expect(certified({ev(att_dec, tpm_sig(ak_k, att_dec), dk_dec)}, {L(dk_point)}, {L(challenge)})).toEqual("the DK can decrypt");
    expect(certified({ev(att_soft, tpm_sig(ak_k, att_soft), dk_soft)}, {L(dk_point)}, {L(challenge)})).toEqual("the DK is not a signing key generated in and fixed to its TPM");
}}
'''
# Provenance record in Resid: decode the generated fields back out of prov.
src_hash = prov[prov.index(bytes([3, 0x58, 0x20])) + 3:][:32]
deps_at = prov.index(bytes([4, 0x82])) + 2
dep1 = prov[deps_at + 2:deps_at + 34]; dep2 = prov[deps_at + 36:deps_at + 68]
k1_at = prov.index(tstr('k1')) + len(tstr('k1')) + 1 + 2
k1h = prov[k1_at:k1_at + 32]
out += f'''
ProvenanceRecord record() {{
    return ProvenanceRecord {{ .package_name = "symbolon", .package_version = "0.1.0", .source_hash = {L(src_hash)},
        .dependency_hashes = [{L(dep1)}, {L(dep2)}], .capability_requirements = ["device", "network"],
        .compiler_info = CompilerInfo {{ .name = "residc", .version = "0.3.0", .reproducible = true }},
        .cache_entry_provenance = [CacheProvenance {{ .key = "k1", .hash = {L(k1h)}, .capabilities = ["device"] }}], .signature = [] }};
}}

test "provenance bytes equal the reference; only a pinned build is accepted" {{
    expect(hx(provenance_cbor(record()))).toEqual({H(prov)});
    expect(hx(build_id(record()))).toEqual({H(sha(prov))});
    Bool pinned = match build_pinned(record(), [{L(rb(32))}, {L(sha(prov))}]) {{ Ok(_) => true, Err(_) => false }};
    Bool unpinned = match build_pinned(record(), [{L(rb(32))}]) {{ Ok(_) => true, Err(_) => false }};
    expect(pinned).toBeTrue();
    expect(unpinned).toBeFalse();
}}

UpdatePolicy upol() {{
    return UpdatePolicy {{ .release_keys = [{", ".join(L(pubpt(k)) for k in rel)}], .release_threshold = 2, .log_key = {L(pubpt(log_k))},
                           .rebuilder_keys = [{", ".join(L(pubpt(k)) for k in rebuilders)}], .rebuilders_needed = 2 }};
}}

UpdateBundle ub(List(List(Int)) sigs, List(List(Int)) rebuilds, Int index) {{
    return UpdateBundle {{ .provenance = {L(prov)}, .release_sigs = sigs, .log_time = 9000, .index = index, .size = 3,
                           .path = [{L(proof0[0])}, {L(proof0[1])}], .root = {L(root)}, .tree_head = {L(th)}, .rebuilds = rebuilds }};
}}

Str upd(UpdateBundle u) {{
    return match accept_update(upol(), u) {{ Ok(h) => hx(h), Err(e) => match e {{ ErrAttestationFailed(s) => s, _ => "other" }} }};
}}

test "an update with two release signatures, a log inclusion and two matching rebuilds installs" {{
    expect(upd(ub([{L(rs[0])}, {L(rs[2])}], [{L(rbs[0])}, {L(rbs[1])}], 0))).toEqual({H(sha(prov))});
}}

test "an update short of any condition is refused" {{
    expect(upd(ub([{L(rs[0])}], [{L(rbs[0])}, {L(rbs[1])}], 0))).toEqual("update not signed by the release threshold");
    expect(upd(ub([{L(rs[0])}, {L(rs[0])}], [{L(rbs[0])}, {L(rbs[1])}], 0))).toEqual("update not signed by the release threshold");
    expect(upd(ub([{L(rs[0])}, {L(rs[1])}], [{L(rbs[0])}, {L(rbs[1])}], 1))).toEqual("update not in the transparency log");
    expect(upd(ub([{L(rs[0])}, {L(rs[1])}], [{L(rbs[0])}], 0))).toEqual("too few independent rebuilds match");
    expect(upd(ub([{L(rs[0])}, {L(rs[1])}], [{L(rbs[0])}, {L(rbs_wrong)}], 0))).toEqual("too few independent rebuilds match");
}}
'''
open(os.path.join(HERE, '..', 'src', 'attestation', 'attestation_ref_test.resid'), 'w').write(out)

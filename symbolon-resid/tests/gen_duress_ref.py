#!/usr/bin/env python3
"""Generates src/duress/duress_ref_test.resid. Argon2id, the unlock-key HKDF,
the profile layouts and the AES-256-GCM blobs are made here with
cryptography (OpenSSL), not by the code under test.

    python3 tests/gen_duress_ref.py
"""
import os, random
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec

random.seed(71)
HERE = os.path.dirname(os.path.abspath(__file__))
rb = lambda n: bytes(random.randrange(256) for _ in range(n))
L = lambda b: '[' + ', '.join(str(x) for x in b) + ']'
H = lambda b: '"' + bytes(b).hex() + '"'
PROFILE = 4096
AAD = b'symbolon v1 profile blob'

pin, salt = b'246810', rb(16)
M, T = 64, 2          # small for the test; the SPEC's are 262144 KiB, 3
stretch = Argon2id(salt=salt, length=32, iterations=T, lanes=1, memory_cost=M).derive(pin)
hw = rb(32)
ukey = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b'symbolon v1 unlock').derive(hw)
dkey = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b'symbolon v1 unlock').derive(rb(32))

share, cc, vault, dek = rb(32), rb(32), rb(32), rb(32)
k = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
dpub = b'\x04' + k.x.to_bytes(32, 'big') + k.y.to_bytes(32, 'big')
real = (bytes([1]) + share + cc + vault + dek + bytes([1]) + dpub).ljust(PROFILE, b'\0')
sub, dvault, hpriv = rb(32), rb(32), rb(32)
tweaks = [(rb(32), rb(32)) for _ in range(3)]
duress = (bytes([2]) + share + sub + dvault + hpriv + bytes([len(tweaks)]) + b''.join(c + t for c, t in tweaks)).ljust(PROFILE, b'\0')
iv_r, iv_d = rb(12), rb(12)
blob_r = iv_r + AESGCM(ukey).encrypt(iv_r, real, AAD)
blob_d = iv_d + AESGCM(dkey).encrypt(iv_d, duress, AAD)
decoy = rb(len(blob_r))

S = lambda b: f'secret_bytes(rt {L(b)})'
tw = ', '.join(f'SubsetTweak {{ .cid = {L(c)}, .tau = {S(t)} }}' for c, t in tweaks)

out = f'''// Unlock and duress (src/duress/duress.resid) against values made by an
// independent implementation (tests/gen_duress_ref.py). Generated; do not
// edit by hand.

import "../types.resid";
import "duress.resid";
import "crypto.resid";
import "word.resid";
import "hpkeg.resid";
import "hpke.resid";

Str hx(List(Int) b) {{ return hex_encode(b); }}

@requires(declassify)
Str sh(List(Secret(UInt(8))) b) {{ return hx(ints(declassify(secret_join(b), "test output"), 0, [])); }}

List(Int) ints(List(UInt(8)) bs, Int i, List(Int) acc) {{
    if (i >= bs.len()) {{ return acc; }}
    return ints(bs, i + 1, acc.concat([(Int)bs[i]]));
}}

@requires(declassify, provision)
test "pin stretch is Argon2id (OpenSSL's) and the unlock key HKDF over it" {{
    expect(sh(pin_stretch({S(pin)}, {L(salt)}, {M}, {T}))).toEqual({H(stretch)});
    expect(sh(unlock_key({S(hw)}, {L(salt)}))).toEqual({H(ukey)});
}}

RealProfile real() {{
    return RealProfile {{ .share = {S(share)}, .cc = {S(cc)}, .vault_key = {S(vault)}, .dek = {S(dek)}, .duress_hpke_pub = {L(dpub)} }};
}}

DuressFull duress() {{
    return DuressFull {{ .share = {S(share)}, .subkey = {S(sub)}, .vault_key = {S(dvault)}, .hpke_priv = {S(hpriv)}, .tweaks = [{tw}] }};
}}

@requires(declassify, provision)
test "profile layouts and sealed blobs equal the reference (AES-256-GCM)" {{
    List(Secret(UInt(8))) rp = encode_real(real()) else {{ [] }};
    List(Secret(UInt(8))) dp = encode_duress(duress()) else {{ [] }};
    expect(sh(rp)).toEqual({H(real)});
    expect(sh(dp)).toEqual({H(duress)});
    expect(hx(seal_blob({S(ukey)}, {L(iv_r)}, rp))).toEqual({H(blob_r)});
    expect(hx(seal_blob({S(dkey)}, {L(iv_d)}, dp))).toEqual({H(blob_d)});
}}

@requires(declassify, provision)
test "every blob has one length, real, duress or random" {{
    expect({len(blob_r)}).toEqual(blob_len());
    expect({len(blob_d)}).toEqual(blob_len());
    expect({len(decoy)}).toEqual(blob_len());
}}

@requires(declassify, provision)
test "the real key opens the real profile from either position; the duress key the duress one" {{
    Unlocked a = unlock({S(ukey)}, {L(blob_r)}, {L(blob_d)});
    Unlocked b = unlock({S(ukey)}, {L(blob_d)}, {L(blob_r)});
    expect(a.kind).toEqual(1);
    expect(b.kind).toEqual(1);
    expect(sh(a.real.cc)).toEqual({H(cc)});
    expect(hx(a.real.duress_hpke_pub)).toEqual({H(dpub)});
    Unlocked d = unlock({S(dkey)}, {L(blob_r)}, {L(blob_d)});
    expect(d.kind).toEqual(2);
    expect(sh(d.duress.subkey)).toEqual({H(sub)});
    expect(d.duress.tweaks.len()).toEqual(3);
    expect(hx(d.duress.tweaks[1].cid)).toEqual({H(tweaks[1][0])});
    expect(sh(d.duress.tweaks[1].tau)).toEqual({H(tweaks[1][1])});
}}

@requires(declassify, provision)
test "a wrong PIN, or a device without a duress PIN, opens nothing with the other key" {{
    expect(unlock({S(rb(32))}, {L(blob_r)}, {L(blob_d)}).kind).toEqual(0);
    expect(unlock({S(dkey)}, {L(blob_r)}, {L(decoy)}).kind).toEqual(0);
    expect(unlock({S(ukey)}, {L(blob_r)}, {L(decoy)}).kind).toEqual(1);
}}

@requires(declassify, provision)
test "the duress profile has the subset's tweaks and nothing else" {{
    DuressFull d = duress();
    Str inside = match subset_tweak(d, {L(tweaks[2][0])}, 0) {{ Some(t) => sh(t), None => "none" }};
    Str outside = match subset_tweak(d, {L(rb(32))}, 0) {{ Some(t) => sh(t), None => "none" }};
    expect(inside).toEqual({H(tweaks[2][1])});
    expect(outside).toEqual("none");
}}

@requires(declassify, provision)
test "the real profile writes the slot it cannot read; the duress profile reads it; a decoy is the same size" {{
    HpkeKeyPairG(Secret(UInt(8))) kp = hpkeg_derive_keypair(16, {S(rb(32))});
    DuressFull d = DuressFull {{ .share = {S(share)}, .subkey = {S(sub)}, .vault_key = {S(dvault)}, .hpke_priv = kp.sk, .tweaks = [{tw}] }};
    List(Int) slot = seal_slot(kp.pk, 6, d, {S(rb(32))}) else {{ [] }};
    expect(slot.len()).toEqual(slot_len());
    expect(decoy_slot({L(rb(65 + 4096 + 16))}).len()).toEqual(slot_len());
    Str read = match open_slot(kp.sk, 6, slot) {{ Some(x) => sh(x.subkey), None => "none" }};
    Str stale = match open_slot(kp.sk, 7, slot) {{ Some(x) => sh(x.subkey), None => "none" }};
    // The real profile's own keys do not open the slot.
    Str by_real = match open_slot({S(ukey)}, 6, slot) {{ Some(x) => sh(x.subkey), None => "none" }};
    expect(read).toEqual({H(sub)});
    expect(stale).toEqual("none");
    expect(by_real).toEqual("none");
}}

@requires(declassify, provision)
test "malformed profiles are refused" {{
    RealProfile r = RealProfile {{ .share = {S(share)}, .cc = {S(cc)}, .vault_key = {S(vault)}, .dek = {S(dek)}, .duress_hpke_pub = [4, 1] }};
    Bool refused = match encode_real(r) {{ Some(_) => false, None => true }};
    expect(refused).toBeTrue();
}}
'''
open(os.path.join(HERE, '..', 'src', 'duress', 'duress_ref_test.resid'), 'w').write(out)

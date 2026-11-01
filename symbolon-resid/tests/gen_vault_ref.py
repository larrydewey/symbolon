#!/usr/bin/env python3
"""Generates src/vault/vault_ref_test.resid from an independent implementation
of SPEC Section 18 written here in Python (cryptography's HKDF, AESGCM and
ECDSA, hashlib, and a small canonical CBOR encoder), so the Resid vault is
checked against values it did not produce.

    python3 tests/gen_vault_ref.py
"""
import hashlib, os, random
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

random.seed(18)
rb = lambda n: bytes(random.randrange(256) for _ in range(n))
HERE = os.path.dirname(os.path.abspath(__file__))


# ---- CBOR (RFC 8949), the subset the spec uses --------------------------
def head(major, n):
    if n < 24: return bytes([major << 5 | n])
    if n < 256: return bytes([major << 5 | 24, n])
    if n < 65536: return bytes([major << 5 | 25]) + n.to_bytes(2, 'big')
    if n < 2**32: return bytes([major << 5 | 26]) + n.to_bytes(4, 'big')
    return bytes([major << 5 | 27]) + n.to_bytes(8, 'big')

def uint(n): return head(0, n)
def bstr(b): return head(2, len(b)) + b
def tstr(s): b = s.encode(); return head(3, len(b)) + b
def arr(items): return head(4, len(items)) + b''.join(items)
BOOL = {False: bytes([0xf4]), True: bytes([0xf5])}
NULL = bytes([0xf6])


# ---- SPEC 18 ---------------------------------------------------------------
def hkdf(ikm, salt, info, n):
    return HKDF(algorithm=hashes.SHA256(), length=n, salt=salt, info=info).derive(ikm)

def item_key(vk, vid, iid): return hkdf(vk, vid, b'symbolon v1 item' + iid, 32)
def field_key(ik, f, ver): return hkdf(ik, None, b'symbolon v1 field' + f.encode() + ver.to_bytes(8, 'big'), 32)
def field_nonce(ik, f, ver): return hkdf(ik, None, b'symbolon v1 nonce' + f.encode() + ver.to_bytes(8, 'big'), 12)
def aad(vid, iid, ver, kind, f): return arr([uint(1), bstr(vid), bstr(iid), uint(ver), tstr(kind), tstr(f)])

def seal(vk, vid, iid, ver, kind, f, pt):
    ik = item_key(vk, vid, iid)
    return AESGCM(field_key(ik, f, ver)).encrypt(field_nonce(ik, f, ver), pt, aad(vid, iid, ver, kind, f))

def item_cbor(iid, ver, kind, fields, duress, handling):
    names = sorted(fields)
    m = head(5, 6) + uint(1) + bstr(iid) + uint(2) + uint(ver) + uint(3) + tstr(kind)
    m += uint(4) + head(5, len(names)) + b''.join(tstr(n) + bstr(fields[n]) for n in names)
    m += uint(5) + BOOL[duress] + uint(6) + (tstr(handling) if handling is not None else NULL)
    return m

sha = lambda b: hashlib.sha256(b).digest()
u64 = lambda n: n.to_bytes(8, 'big')

def leaf(iid, ver, cb): return sha(b'\x00' + iid + u64(ver) + sha(cb))

def root(leaves):
    if not leaves: return sha(b'')
    while len(leaves) > 1:
        nxt = []
        for i in range(0, len(leaves) - 1, 2):
            nxt.append(sha(b'\x01' + leaves[i] + leaves[i + 1]))
        if len(leaves) % 2: nxt.append(leaves[-1])
        leaves = nxt
    return leaves[0]


def L(b): return '[' + ', '.join(str(x) for x in b) + ']'
def RT(b): return 'rt ' + L(b)
def S(s): return '"' + s + '"'


vk = rb(32); vid = rb(32)
spec = [  # id byte, version, kind, {field: plaintext}, duress, handling
    (1, 1, 'login', {'user': b'alice', 'password': b'hunter2'}, False, None),
    (2, 3, 'login', {'user': b'bob', 'pässwörd': b'\xc3\xa9\xe2\x82\xac', 'note': rb(40)}, True, 'confirm'),
    (3, 7, 'totp', {'seed': rb(20)}, False, None),
    (4, 2, 'note', {'text': rb(300)}, True, None),
    (5, 1, 'card', {'number': rb(16), 'cvv': rb(3), 'name': rb(25), 'pin': rb(4)}, False, 'never'),
]
items = []
for (n, ver, kind, plain, duress, handling) in spec:
    iid = bytes([n]) * 16
    cts = {f: seal(vk, vid, iid, ver, kind, f, p) for f, p in plain.items()}
    items.append(dict(iid=iid, ver=ver, kind=kind, plain=plain, cts=cts, duress=duress, handling=handling,
                      cb=item_cbor(iid, ver, kind, cts, duress, handling)))

leaves = [leaf(i['iid'], i['ver'], i['cb']) for i in items]
mroot = root(leaves)
# Items in a different order must give the same root: the tree is over ids.
shuffled = list(items); random.shuffle(shuffled)

# Signed head: COSE Sig_structure over the payload, ES256 by a device key.
log_id = rb(32)
dk = ec.derive_private_key(int.from_bytes(rb(32), 'big') % (2**255) + 1, ec.SECP256R1())
dk_pub = dk.public_key().public_numbers()
dk_pub_bytes = b'\x04' + dk_pub.x.to_bytes(32, 'big') + dk_pub.y.to_bytes(32, 'big')
signer_id = rb(32)
version, log_seq = 9, 4
payload = (head(5, 6) + uint(1) + bstr(vid) + uint(2) + uint(version) + uint(3) + bstr(mroot)
           + uint(4) + bstr(log_id) + uint(5) + uint(log_seq) + uint(6) + uint(1))
tbs = arr([tstr('Signature1'), bstr(bytes([0xa1, 0x01, 0x26])), bstr(b''), bstr(payload)])
r, s = decode_dss_signature(dk.sign(tbs, ec.ECDSA(hashes.SHA256())))
sig = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
bad_sig = bytearray(sig); bad_sig[10] ^= 1


out = '''// The Resid vault (src/vault/vault.resid) against an independent
// implementation of SPEC Section 18: HKDF, AES-GCM and ECDSA from Python's
// cryptography package, hashlib, and a separate CBOR encoder. Every expected
// value below was produced by tests/gen_vault_ref.py, not by the code under
// test. Generated; do not edit by hand.

import "../types.resid";
import "vault.resid";
import "word.resid";
import "crypto.resid";

Str hx(List(Int) b) { return hex_encode(b); }

List(Int) widen_u8(List(UInt(8)) b, Int i, ListBuf(Int) acc) {
    if (i >= b.len()) { return acc.finish(); }
    return widen_u8(b, i + 1, acc.push((Int) b[i]));
}

@requires(declassify)
List(Int) opened(List(Secret(UInt(8))) b) {
    return widen_u8(declassify(secret_join(b), "test compares to the reference plaintext"), 0, ListBuf());
}

List(Int) vault_key_bytes() { return ''' + RT(vk) + '''; }
List(Int) vault_id() { return ''' + L(vid) + '''; }

Bool has_all(List(FieldPlain) got, Int i) { return true; }
'''
# One item_cbor-bearing Item per spec entry, built from the reference ciphertexts.
for k, it in enumerate(items):
    fields = ', '.join(f'{S(f)}: {L(c)}' for f, c in sorted(it['cts'].items()))
    hp = f'Some({S(it["handling"])})' if it['handling'] is not None else 'None'
    out += f'''
Item ref_item_{k}() {{
    return Item {{
        .id = {L(it["iid"])}, .version = {it["ver"]}, .kind = {S(it["kind"])},
        .fields = {{{fields}}},
        .in_duress_subset = {str(it["duress"]).lower()}, .handling_policy = {hp} }};
}}
'''
out += '''
List(Item) ref_items() { return [''' + ', '.join(f'ref_item_{k}()' for k in range(len(items))) + '''];  }
List(Item) ref_items_shuffled() { return [''' + ', '.join(f'ref_item_{items.index(i)}()' for i in shuffled) + '''];  }
'''
# plaintext check per item: open the reference item, compare each field to the reference plaintext
for k, it in enumerate(items):
    out += f'''
@requires(declassify)
test "item {k}: the reference ciphertexts open to the reference plaintexts" {{
    List(Secret(UInt(8))) vk = secret_bytes(vault_key_bytes());
    Result(List(FieldPlain), SymbolonError) r = item_open(vk, vault_id(), ref_item_{k}());
    List(FieldPlain) got = r else {{ [] }};
    expect(got.len()).toEqual({len(it["plain"])});
'''
    for j, (f, p) in enumerate(sorted(it['plain'].items())):
        out += f'    expect(hx(field_named(got, {S(f)}))).toEqual("{p.hex()}");\n'
    out += '}\n'
out += '''
@requires(declassify)
List(Int) field_named(List(FieldPlain) fs, Str name) { return field_named_at(fs, name, 0); }

@requires(declassify)
List(Int) field_named_at(List(FieldPlain) fs, Str name, Int i) {
    if (i >= fs.len()) { return []; }
    if (fs[i].name == name) { return opened(fs[i].value); }
    return field_named_at(fs, name, i + 1);
}
'''
for k, it in enumerate(items):
    plain_fields = ', '.join(f'FieldPlain {{.name = {S(f)}, .value = secret_bytes({RT(p)})}}' for f, p in sorted(it['plain'].items()))
    out += f'''
@requires(declassify)
test "item {k}: sealing the reference plaintexts gives the reference ciphertexts" {{
    List(Secret(UInt(8))) vk = secret_bytes(vault_key_bytes());
    List(FieldPlain) plain = [{plain_fields}];
    Result(Item, SymbolonError) r = item_seal(vk, vault_id(), {L(it["iid"])}, {it["ver"]}, {S(it["kind"])}, plain, {str(it["duress"]).lower()}, {f'Some({S(it["handling"])})' if it["handling"] is not None else 'None'});
    Item sealed = r else {{ ref_item_{k}() }};
    expect(r_ok(r)).toBeTrue();
    expect(hx(item_cbor(sealed))).toEqual("{it["cb"].hex()}");
}}
'''
out += '''
Bool r_ok(Result(Item, SymbolonError) r) { return match r { Ok(_) => true, Err(_) => false }; }

test "merkle root equals the reference, whatever the order" {
    expect(hx(merkle_root(ref_items()))).toEqual("''' + mroot.hex() + '''");
    expect(hx(merkle_root(ref_items_shuffled()))).toEqual("''' + mroot.hex() + '''");
}
'''
# head acceptance
out += f'''
List(Int) ref_dk() {{ return {L(dk_pub_bytes)}; }}

LogHead ref_log_head(UInt(64) seq) {{
    Party p = Party {{ .id = {L(signer_id)}, .kind = party_kind_device(), .auth_key = ref_dk(),
                      .hpke_key = [], .label = "d", .attestation = NoAttestation }};
    return LogHead {{
        .log_id = {L(log_id)}, .sequence = seq, .digest = [],
        .quorum = Quorum {{ .parties = [p], .t = 1, .root_pubkey = [], .epoch = 0, .transcript_digest = [] }},
        .policy = Policy {{ .device_sigs_for_authority = 1, .recovery_delay_sec = 86400, .guardians = [],
                           .guardian_threshold = 0, .witnesses = [], .duress_window_sec = 0,
                           .cosigner_policy = NoCosignerPolicy }} }};
}}

VaultHead ref_head(List(Int) sig) {{
    return VaultHead {{
        .vault_id = vault_id(), .version = {version}, .merkle_root = {L(mroot)}, .log_id = {L(log_id)},
        .log_sequence = {log_seq}, .suite = 1, .signer = {L(signer_id)}, .sig = sig }};
}}

Bool accepted(Result(VaultState, SymbolonError) r) {{ return match r {{ Ok(_) => true, Err(_) => false }}; }}

test "head signed by Python's ECDSA: tbs bytes equal the reference" {{
    expect(hx(head_tbs(ref_head({L(sig)})))).toEqual("{tbs.hex()}");
}}

test "head signed by Python's ECDSA is accepted; a flipped signature bit is refused" {{
    VaultState good = VaultState {{ .head = ref_head({L(sig)}), .items = ref_items() }};
    expect(accepted(vault_accept(good, vault_id(), ref_log_head(10), 9))).toBeTrue();
    VaultState bad = VaultState {{ .head = ref_head({L(list(bad_sig))}), .items = ref_items() }};
    expect(accepted(vault_accept(bad, vault_id(), ref_log_head(10), 9))).toBeFalse();
}}
'''
open(os.path.join(HERE, '..', 'src', 'vault', 'vault_ref_test.resid'), 'w').write(out)
print('items', len(items), 'root', mroot.hex())

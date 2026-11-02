#!/usr/bin/env python3
"""Generates src/ssh/sshwire_ref_test.resid. Keys are made by ssh-keygen;
fingerprints come from ssh-keygen -l; signatures from Python's
`cryptography` (deterministic ECDSA, RFC 6979); wire encodings are built
here by hand from RFC 4251 -- none of it from the code under test.

    python3 tests/gen_ssh_ref.py
"""
import os, struct, subprocess, tempfile
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils

HERE = os.path.dirname(os.path.abspath(__file__))
L = lambda b: '[' + ', '.join(str(x) for x in b) + ']'
R = lambda s: '"' + s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n') + '"'
def sstr(b): return struct.pack('>I', len(b)) + b
def mpint(v):
    if v == 0: return struct.pack('>I', 0)
    b = v.to_bytes((v.bit_length() + 8) // 8, 'big')
    return sstr(b)

W = tempfile.mkdtemp()
keys = {}
for name, args in [('ed', ['-t', 'ed25519']), ('p256', ['-t', 'ecdsa', '-b', '256']), ('p384', ['-t', 'ecdsa', '-b', '384']), ('rsa', ['-t', 'rsa', '-b', '2048'])]:
    f = f'{W}/{name}'
    subprocess.run(['ssh-keygen', '-q', *args, '-N', '', '-C', f'{name}@test', '-f', f], check=True)
    fp = subprocess.run(['ssh-keygen', '-l', '-E', 'sha256', '-f', f + '.pub'], capture_output=True, text=True, check=True).stdout.split()[1]
    keys[name] = (open(f).read(), open(f + '.pub').read().strip(), fp, serialization.load_ssh_private_key(open(f, 'rb').read(), None))

msg = b'symbolon ssh agent test message'
out = ['// SSH formats (src/ssh/sshwire.resid) against ssh-keygen and Python\'s',
       '// cryptography (tests/gen_ssh_ref.py). Generated; do not edit by hand.', '',
       'import "sshwire.resid";', 'import "crypto.resid";', 'import "word.resid";', 'import "ecdsa.resid";', 'import "ed25519g.resid";', 'import "hash.resid";', '',
       'Str hx(List(Int) b) { return hex_encode(b); }',
       'SshPriv parsed(Str text) {',
       '    Option(KeyFile) f = key_file_of(text);',
       '    KeyFile k = f else { KeyFile {.cipher = "", .kdf = "", .kdf_opts = [], .pub_blob = [], .sealed = []} };',
       '    Option(SshPriv) p = priv_of_section(k.sealed, k.pub_blob);',
       '    return p else { SshPriv {.pub = no_pub(), .secret = [], .d = [], .p = [], .q = [], .iqmp = [], .comment = "none"} };',
       '}',
       'Bool none_k(Option(KeyFile) x) { return match x { None => true, Some(_) => false }; }',
       'Bool none_p(Option(SshPriv) x) { return match x { None => true, Some(_) => false }; }', '']

out.append('test "mpint and string encodings are RFC 4251\'s" {')
for v in [0, 1, 0x7f, 0x80, 0xff, 0x1234, 0x00ff00, 2**255 + 3]:
    be = v.to_bytes(max(1, (v.bit_length() + 7) // 8), 'big')
    padded = bytes(2) + be
    out.append(f'    expect(hx(mpint({L(padded)}))).toEqual("{mpint(v).hex()}");')
out.append(f'    expect(hx(sstr("abc"))).toEqual("{sstr(b"abc").hex()}");')
out.append('}\n')

for name, (text, line, fp, priv) in keys.items():
    blob = __import__('base64').b64decode(line.split()[1])
    out.append(f'@requires(declassify)')
    out.append(f'test "{name}: ssh-keygen\'s file parses; ssh_fingerprint, public line and comment agree" {{')
    out.append(f'    Option(List(Int)) b = ssh_blob_of_line({R(line)});')
    out.append(f'    List(Int) blob = b else {{ [] }};')
    out.append(f'    expect(hx(blob)).toEqual("{blob.hex()}");')
    out.append(f'    expect(ssh_fingerprint(blob)).toEqual({R(fp)});')
    out.append(f'    expect(ssh_pub_line(blob, "{name}@test")).toEqual({R(line)});')
    out.append(f'    Option(KeyFile) f = key_file_of({R(text)});')
    out.append(f'    KeyFile k = f else {{ KeyFile {{.cipher = "x", .kdf = "x", .kdf_opts = [], .pub_blob = [], .sealed = []}} }};')
    out.append(f'    expect(k.cipher).toEqual("none");')
    out.append(f'    expect(k.kdf).toEqual("none");')
    out.append(f'    expect(hx(k.pub_blob)).toEqual("{blob.hex()}");')
    out.append(f'    SshPriv p = parsed({R(text)});')
    out.append(f'    expect(p.comment).toEqual("{name}@test");')
    out.append(f'    expect(hx(p.pub.blob)).toEqual("{blob.hex()}");')
    if name == 'ed':
        sig = priv.sign(msg)
        sb = sstr(b'ssh-ed25519') + sstr(sig)
        out.append(f'    expect(hx(ed25519_sig_blob(ed25519g_sign(p.secret, {L(msg)})))).toEqual("{sb.hex()}");')
        out.append(f'    expect(hx(ed25519g_pub(p.secret))).toEqual("{blob[-32:].hex()}");')
    elif name in ('p256', 'p384'):
        h = hashes.SHA256() if name == 'p256' else hashes.SHA384()
        der = priv.sign(msg, ec.ECDSA(h, deterministic_signing=True))
        r, s = utils.decode_dss_signature(der)
        size = 32 if name == 'p256' else 48
        rs = r.to_bytes(size, 'big') + s.to_bytes(size, 'big')
        curve = 'nistp256' if name == 'p256' else 'nistp384'
        sb = sstr(f'ecdsa-sha2-{curve}'.encode()) + sstr(mpint(r) + mpint(s))
        c, ha = ('P256', 'Sha256') if name == 'p256' else ('P384', 'Sha384')
        out.append(f'    List(Int) rs = ecdsag_sign_raw({c}, {ha}, p.secret, {L(msg)});')
        out.append(f'    expect(hx(rs)).toEqual("{rs.hex()}");')
        out.append(f'    expect(hx(ecdsa_sig_blob("{curve}", rs))).toEqual("{sb.hex()}");')
        out.append(f'    Option(SigParts) sp = sig_parts({L(sb)}, {size});')
        out.append(f'    SigParts q = sp else {{ SigParts {{.alg = "", .sig = []}} }};')
        out.append(f'    expect(hx(q.sig)).toEqual("{rs.hex()}");')
    else:
        n = priv.private_numbers()
        out.append(f'    expect(hx(p.pub.n)).toEqual("{n.public_numbers.n.to_bytes(256, "big").hex()}");')
        out.append(f'    expect(p.d.len()).toEqual({(n.d.bit_length() + 7) // 8});')
    out.append('}\n')

# Malformed inputs: truncated file, a wrong public half, bad padding.
text, line, fp, priv = keys['ed']
import base64
body = ''.join(l for l in text.splitlines() if not l.startswith('-----'))
raw = base64.b64decode(body)
def pem(b): return '-----BEGIN OPENSSH PRIVATE KEY-----\n' + base64.b64encode(b).decode() + '\n-----END OPENSSH PRIVATE KEY-----\n'
other = keys['p256']
ob = base64.b64decode(''.join(l for l in other[0].splitlines() if not l.startswith('-----')))
out.append('test "a truncated file, a section that is not for its public key, and bad padding are refused" {')
out.append(f'    expect(none_k(key_file_of({R(pem(raw[:-9]))}))).toBeTrue();')
out.append(f'    expect(none_k(key_file_of("not a key"))).toBeTrue();')
# section of ed with p256's public blob
def parts(b):
    i = 15
    out_ = []
    for _ in range(3):
        n = struct.unpack('>I', b[i:i+4])[0]; out_.append(b[i+4:i+4+n]); i += 4 + n
    i += 4
    n = struct.unpack('>I', b[i:i+4])[0]; pb = b[i+4:i+4+n]; i += 4 + n
    n = struct.unpack('>I', b[i:i+4])[0]; sec = b[i+4:i+4+n]
    return pb, sec
epb, esec = parts(raw)
opb, osec = parts(ob)
out.append(f'    expect(none_p(priv_of_section({L(esec)}, {L(opb)}))).toBeTrue();')
bad = bytearray(esec); bad[-1] ^= 0x40
out.append(f'    expect(none_p(priv_of_section({L(bytes(bad))}, {L(epb)}))).toBeTrue();')
chk = bytearray(esec); chk[0] ^= 1
out.append(f'    expect(none_p(priv_of_section({L(bytes(chk))}, {L(epb)}))).toBeTrue();')
out.append(f'    expect(none_p(priv_of_section({L(esec)}, {L(epb)}))).toBeFalse();')
out.append('}\n')

# What is signed.
sid = os.urandom(32)
kb = base64.b64decode(keys['ed'][1].split()[1])
auth = sstr(sid) + bytes([50]) + sstr(b'git') + sstr(b'ssh-connection') + sstr(b'publickey') + b'\x01' + sstr(b'ssh-ed25519') + sstr(kb)
sshsig = b'SSHSIG' + sstr(b'git') + sstr(b'') + sstr(b'sha512') + sstr(os.urandom(64))
bind = sstr(b'session-bind@openssh.com') + sstr(kb) + sstr(sid) + sstr(b'sig') + b'\x01'
sreq = sstr(kb) + sstr(auth) + struct.pack('>I', 4)
hostk = os.urandom(51)
hb = sstr(sid) + bytes([50]) + sstr(b'me') + sstr(b'ssh-connection') + sstr(b'publickey-hostbound-v00@openssh.com') + b'\x01' + sstr(b'ssh-ed25519') + sstr(kb) + sstr(hostk)
out.append('test "a user authentication request, an SSHSIG blob and a session binding are read" {')
out.append(f'    Signed a = signed_of({L(auth)});')
out.append(f'    expect(a.kind).toEqual("auth");')
out.append(f'    expect(a.user).toEqual("git");')
out.append(f'    expect(a.service).toEqual("ssh-connection");')
out.append(f'    expect(hx(a.session_id)).toEqual("{sid.hex()}");')
out.append(f'    expect(hx(a.key)).toEqual("{kb.hex()}");')
out.append(f'    Signed h = signed_of({L(hb)});')
out.append(f'    expect(h.kind).toEqual("auth");')
out.append(f'    expect(h.user).toEqual("me");')
out.append(f'    expect(hx(h.host_key)).toEqual("{hostk.hex()}");')
out.append(f'    expect(signed_of({L(hb[:-1])}).kind).toEqual("");')
out.append(f'    expect(a.host_key.len()).toEqual(0);')
out.append(f'    Signed g = signed_of({L(sshsig)});')
out.append(f'    expect(g.kind).toEqual("sshsig");')
out.append(f'    expect(g.namespace).toEqual("git");')
out.append(f'    expect(g.alg).toEqual("sha512");')
out.append(f'    expect(signed_of({L(auth[:-1])}).kind).toEqual("");')
out.append(f'    expect(signed_of({L(b"SSHSIG" + sstr(b""))}).kind).toEqual("");')
out.append(f'    Option(Bind) ob = bind_of({L(bind)});')
out.append(f'    Bind b = ob else {{ Bind {{.host_key = [], .session_id = [], .sig = [], .forwarding = false}} }};')
out.append(f'    expect(hx(b.session_id)).toEqual("{sid.hex()}");')
out.append(f'    expect(b.forwarding).toBeTrue();')
out.append(f'    Option(SignReq) osr = sign_req_of({L(sreq)});')
out.append(f'    SignReq r = osr else {{ SignReq {{.key = [], .data = [], .flags = -1}} }};')
out.append(f'    expect(r.flags).toEqual(4);')
out.append(f'    expect(hx(r.data)).toEqual("{auth.hex()}");')
ia = struct.pack('>I', 1 + 4 + 4 + len(kb) + 4 + 3) + bytes([12]) + struct.pack('>I', 1) + sstr(kb) + sstr(b'abc')
out.append(f'    expect(hx(identities_answer([Ident {{.blob = {L(kb)}, .comment = "abc"}}]))).toEqual("{ia.hex()}");')
out.append('}')
open(os.path.join(HERE, '..', 'src', 'ssh', 'sshwire_ref_test.resid'), 'w').write('\n'.join(out) + '\n')
print('wrote src/ssh/sshwire_ref_test.resid')

#!/usr/bin/env python3
"""Generates src/ssh/agentd_ref_test.resid: session bindings signed by host
keys made with Python's `cryptography` (Ed25519, P-256, RSA-SHA2-256/512),
and signatures the agent must accept or refuse -- none from the code
under test.

    python3 tests/gen_sshagent_ref.py
"""
import os, struct
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, padding, utils

HERE = os.path.dirname(os.path.abspath(__file__))
L = lambda b: '[' + ', '.join(str(x) for x in b) + ']'
def sstr(b): return struct.pack('>I', len(b)) + b
def mpint(v):
    if v == 0: return struct.pack('>I', 0)
    return sstr(v.to_bytes((v.bit_length() + 8) // 8, 'big'))
def pubblob(k):
    return k.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).split()[1]
import base64
B = lambda k: base64.b64decode(pubblob(k))

sid = os.urandom(32)
edk = ed25519.Ed25519PrivateKey.generate()
p256 = ec.generate_private_key(ec.SECP256R1())
rk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
def sig_ed(m): return sstr(b'ssh-ed25519') + sstr(edk.sign(m))
def sig_p256(m):
    r, s = utils.decode_dss_signature(p256.sign(m, ec.ECDSA(hashes.SHA256())))
    return sstr(b'ecdsa-sha2-nistp256') + sstr(mpint(r) + mpint(s))
def sig_rsa(m, h, name): return sstr(name) + sstr(rk.sign(m, padding.PKCS1v15(), h))
def bind(hk, s, sig, fwd): return sstr(b'session-bind@openssh.com') + sstr(hk) + sstr(s) + sstr(sig) + bytes([fwd])

cases = [
    ('ed25519', B(edk), sig_ed(sid), True),
    ('p256', B(p256), sig_p256(sid), True),
    ('rsa-sha2-256', B(rk), sig_rsa(sid, hashes.SHA256(), b'rsa-sha2-256'), True),
    ('rsa-sha2-512', B(rk), sig_rsa(sid, hashes.SHA512(), b'rsa-sha2-512'), True),
    ('a signature over another session', B(edk), sig_ed(os.urandom(32)), False),
    ('a signature by another key', B(p256), sig_p256(sid)[:-1] + b'\x00', False),
    ('rsa with the old ssh-rsa (SHA-1) name', B(rk), sig_rsa(sid, hashes.SHA256(), b'ssh-rsa'), False),
]
out = ['// The SSH agent\'s checks (src/ssh/agentd.resid) against keys and',
       '// signatures from Python\'s cryptography (tests/gen_sshagent_ref.py).',
       '// Generated; do not edit by hand.', '',
       'import "agentd.resid";', 'import "sshwire.resid";', 'import "../agent/sshcli.resid";', 'import "crypto.resid";', '',
       'Bool bound(Option(AgentSession) s) { return match s { None => false, Some(x) => x.bound }; }', '']
out.append('test "a session binding is taken only with the host key\'s signature over the session" {')
for name, hk, sig, ok in cases:
    out.append(f'    // {name}')
    out.append(f'    expect(bound(checked_bind({L(bind(hk, sid, sig, 0))}))).{"toBeTrue" if ok else "toBeFalse"}();')
out.append(f'    expect(bound(checked_bind({L(bind(B(edk), sid, sig_ed(sid), 2))}))).toBeFalse();')
out.append('}\n')

# A sign request for an auth to a bound session, and one for another session.
kb = B(edk)
def auth(s): return sstr(s) + bytes([50]) + sstr(b'git') + sstr(b'ssh-connection') + sstr(b'publickey') + b'\x01' + sstr(b'ssh-ed25519') + sstr(kb)
other = os.urandom(32)
def hbauth(s, hk): return sstr(s) + bytes([50]) + sstr(b'git') + sstr(b'ssh-connection') + sstr(b'publickey-hostbound-v00@openssh.com') + b'\x01' + sstr(b'ssh-ed25519') + sstr(kb) + sstr(hk)
out.append('test "a user authentication request must name the key and the bound session" {')
out.append(f'    AgentSession s = AgentSession {{.host_key = {L(B(p256))}, .session_id = {L(sid)}, .forwarding = false, .bound = true}};')
out.append(f'    expect(refused(s, {L(kb)}, signed_of({L(auth(sid))}))).toEqual("");')
out.append(f'    expect(refused(s, {L(kb)}, signed_of({L(auth(other))}))).toEqual("the request is for another session than the one bound");')
out.append(f'    expect(refused(s, {L(B(p256))}, signed_of({L(auth(sid))}))).toEqual("the request names another key");')
out.append(f'    expect(refused(unbound(), {L(kb)}, signed_of({L(auth(other))}))).toEqual("");')
out.append(f'    expect(refused(s, {L(kb)}, signed_of({L(hbauth(sid, B(p256)))}))).toEqual("");')
out.append(f'    expect(refused(s, {L(kb)}, signed_of({L(hbauth(sid, B(edk)))}))).toEqual("the request names another server than the one bound");')
out.append('}\n')

msg = os.urandom(40)
out.append('test "a returned signature is checked against the key before the client gets it" {')
out.append(f'    expect(verifies({L(kb)}, {L(msg)}, {L(sig_ed(msg))})).toBeTrue();')
out.append(f'    expect(verifies({L(kb)}, {L(msg)}, {L(sig_ed(os.urandom(40)))})).toBeFalse();')
out.append(f'    expect(verifies({L(B(p256))}, {L(msg)}, {L(sig_p256(msg))})).toBeTrue();')
out.append(f'    expect(verifies({L(B(p256))}, {L(msg)}, {L(sig_ed(msg))})).toBeFalse();')
out.append(f'    expect(verifies({L(B(rk))}, {L(msg)}, {L(sig_rsa(msg, hashes.SHA512(), b"rsa-sha2-512"))})).toBeTrue();')
out.append('}\n')
out.append('test "the public index is read and written back the same" {')
out.append('    List(SshEntry) es = entries_of("6769746875622d6b6579 ssh-ed25519 AAAA github\\nnot a line\\n77 ecdsa-sha2-nistp256 BBBB w\\n");')
out.append('    expect(es.len()).toEqual(2);')
out.append('    expect(es[0].name).toEqual("github-key");')
out.append('    expect(es[0].line).toEqual("ssh-ed25519 AAAA github");')
out.append('    expect(es[1].name).toEqual("w");')
out.append('}')
open(os.path.join(HERE, '..', 'src', 'ssh', 'agentd_ref_test.resid'), 'w').write('\n'.join(out) + '\n')
print('wrote src/ssh/agentd_ref_test.resid')

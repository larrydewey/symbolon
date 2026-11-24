#!/usr/bin/env python3
"""Generates src/ssh/sshcert_ref_test.resid. Certificates are made by
ssh-keygen -s (a P-256 certificate authority, user keys of each type
Symbolon holds) with the extensions Symbolon issues; the test rebuilds
what the authority signed from the same nonce, serial and validity and
must get ssh-keygen's bytes. Certificates are read back, their
signatures checked, a changed one refused -- none of it from the code
under test. It also covers the certificate list and what the agent
offers.

    python3 tests/gen_sshcert_ref.py
"""
import base64, os, struct, subprocess, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
L = lambda b: '[' + ', '.join(str(x) for x in b) + ']'
R = lambda s: '"' + s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n') + '"'

def rd_str(b, i):
    n = struct.unpack('>I', b[i:i + 4])[0]
    return b[i + 4:i + 4 + n], i + 4 + n

def parse_cert(b):
    """The parts of an OpenSSH certificate, by PROTOCOL.certkeys."""
    alg, i = rd_str(b, 0)
    nonce, i = rd_str(b, i)
    nfields = 1 if alg.startswith(b'ssh-ed25519') else 2
    for _ in range(nfields):
        _, i = rd_str(b, i)
    serial = b[i:i + 8]; i += 8
    ctype = struct.unpack('>I', b[i:i + 4])[0]; i += 4
    key_id, i = rd_str(b, i)
    pr, i = rd_str(b, i)
    va = struct.unpack('>Q', b[i:i + 8])[0]; i += 8
    vb = struct.unpack('>Q', b[i:i + 8])[0]; i += 8
    crit, i = rd_str(b, i)
    ext, i = rd_str(b, i)
    _, i = rd_str(b, i)
    ca, i = rd_str(b, i)
    tbs_end = i
    sig, i = rd_str(b, i)
    assert i == len(b)
    ps, j = [], 0
    while j < len(pr):
        p, j = rd_str(pr, j)
        ps.append(p.decode())
    return dict(alg=alg.decode(), nonce=nonce, serial=serial, type=ctype, key_id=key_id.decode(), principals=ps, va=va, vb=vb, ext=ext, ca=ca, tbs=b[:tbs_end], sig=sig)

W = tempfile.mkdtemp()
def keygen(name, args, comment):
    f = f'{W}/{name}'
    subprocess.run(['ssh-keygen', '-q', *args, '-N', '', '-C', comment, '-f', f], check=True)
    return f

ca = keygen('ca', ['-t', 'ecdsa', '-b', '256'], 'ca@test')
ca_line = open(ca + '.pub').read().strip()
users = [('ed', ['-t', 'ed25519']), ('p256', ['-t', 'ecdsa', '-b', '256']), ('p384', ['-t', 'ecdsa', '-b', '384']), ('rsa', ['-t', 'rsa', '-b', '2048'])]
certs = []
for name, args in users:
    f = keygen(name, args, f'{name}@test')
    validity = '-5m:+30d' if name != 'p384' else 'always:forever'
    subprocess.run(['ssh-keygen', '-q', '-s', ca, '-I', f'symbolon:{name}', '-n', 'alice,bob', '-V', validity, '-z', '12345678901234',
                    '-O', 'clear', '-O', 'permit-port-forwarding', '-O', 'permit-pty', f + '.pub'], check=True, capture_output=True)
    cert_line = open(f + '-cert.pub').read().strip()
    certs.append((name, open(f + '.pub').read().strip(), cert_line, parse_cert(base64.b64decode(cert_line.split()[1]))))

out = ['// OpenSSH certificates (src/ssh/sshcert.resid) against ssh-keygen -s',
       '// (tests/gen_sshcert_ref.py), and the certificate list and what the agent',
       '// offers from it. Generated; do not edit by hand.', '',
       'import "sshcert.resid";', 'import "sshwire.resid";', 'import "agentd.resid";', 'import "../agent/sshcli.resid";', 'import "crypto.resid";', '',
       'Str hx(List(Int) b) { return hex_encode(b); }',
       'List(Int) blob_of(Str line) { Option(List(Int)) b = ssh_blob_of_line(line); return b else { [] }; }',
       'List(Int) cblob_of(Str line) { Option(List(Int)) b = cert_blob_of_line(line); return b else { [] }; }',
       'SshPub pub_of(Str line) { Option(SshPub) k = pub_of_blob(blob_of(line)); return k else { no_pub() }; }',
       'SshCert cert_or_none(Option(SshCert) c) { return c else { SshCert {.alg = "none", .key_blob = [], .nonce = [], .serial = [], .kind = 0, .key_id = "", .principals = [], .valid_after = 0, .valid_before = 0, .critical = [], .extensions = [], .ca_blob = [], .tbs = [], .sig = []} }; }',
       'Bool none_c(Option(SshCert) c) { return match c { None => true, Some(_) => false }; }', '']

ca_blob = base64.b64decode(ca_line.split()[1])
for name, pub_line, cert_line, c in certs:
    blob = base64.b64decode(cert_line.split()[1])
    kblob = base64.b64decode(pub_line.split()[1])
    out.append(f'test "{name}: ssh-keygen\'s certificate is the one Symbolon builds from the same nonce, serial and times" {{')
    out.append(f'    CertSpec spec = CertSpec {{.nonce = {L(c["nonce"])}, .serial = {L(c["serial"])}, .key_id = {R(c["key_id"])}, .principals = ["alice", "bob"], .valid_after = {min(c["va"], 2**63 - 1)}, .valid_before = {min(c["vb"], 2**63 - 1)}}};')
    if c['vb'] >= 2**63:
        # Symbolon never issues "forever" (past Int); this one is only read back.
        out.append('    expect(spec.valid_after).toEqual(0);')
    else:
        out.append(f'    expect(hx(cert_tbs(pub_of({R(pub_line)}), spec, blob_of({R(ca_line)})))).toEqual("{c["tbs"].hex()}");')
    out.append(f'    expect(cert_alg_of(pub_of({R(pub_line)}).alg)).toEqual("{c["alg"]}");')
    out.append(f'    expect(hx(cert_extensions())).toEqual("{c["ext"].hex()}");')
    out.append('}\n')
    out.append(f'test "{name}: the certificate reads back, and its signature is its authority\'s" {{')
    out.append(f'    SshCert c = cert_or_none(cert_of_line({R(cert_line)}));')
    out.append(f'    expect(c.alg).toEqual("{c["alg"]}");')
    out.append(f'    expect(hx(c.key_blob)).toEqual("{kblob.hex()}");')
    out.append(f'    expect(hx(c.ca_blob)).toEqual("{ca_blob.hex()}");')
    out.append(f'    expect(c.kind).toEqual(1);')
    out.append(f'    expect(c.key_id).toEqual({R(c["key_id"])});')
    out.append(f'    expect(c.principals.len()).toEqual(2);')
    out.append(f'    expect(c.principals[0]).toEqual("alice");')
    out.append(f'    expect(c.principals[1]).toEqual("bob");')
    out.append(f'    expect(c.valid_after).toEqual({min(c["va"], 2**63 - 1)});')
    out.append(f'    expect(c.valid_before).toEqual({min(c["vb"], 2**63 - 1)});')
    out.append(f'    expect(hx(c.tbs)).toEqual("{c["tbs"].hex()}");')
    out.append(f'    expect(cert_signed(c)).toBeTrue();')
    # The same certificate with one principal's byte changed: the signature no longer covers it.
    bad = bytearray(blob); k = bytes(blob).index(b'alice'); bad[k] ^= 1
    out.append(f'    expect(cert_signed(cert_or_none(cert_of_blob({L(bad)})))).toBeFalse();')
    out.append(f'    expect(none_c(cert_of_blob({L(blob[:-1])}))).toBeTrue();')
    out.append(f'    expect(none_c(cert_of_blob({L(kblob)}))).toBeTrue();')
    out.append('}\n')

ed = certs[0]
now = ed[3]['va'] + 600
life = ed[3]['vb'] - ed[3]['va']
out.append('test "a certificate is current within its times and due with a third of its life left" {')
out.append(f'    SshCert c = cert_or_none(cert_of_line({R(ed[2])}));')
out.append(f'    expect(cert_current(c, {ed[3]["va"]})).toBeTrue();')
out.append(f'    expect(cert_current(c, {ed[3]["va"] - 1})).toBeFalse();')
out.append(f'    expect(cert_current(c, {ed[3]["vb"]})).toBeFalse();')
out.append(f'    expect(cert_due(c, {now})).toBeFalse();')
out.append(f'    expect(cert_due(c, {ed[3]["vb"] - life // 3 - 1})).toBeFalse();')
out.append(f'    expect(cert_due(c, {ed[3]["vb"] - life // 3})).toBeTrue();')
out.append(f'    expect(cert_due(c, {ed[3]["vb"] + 1})).toBeTrue();')
out.append(f'    expect(u64_val([255, 255, 255, 255, 255, 255, 255, 255])).toEqual(9223372036854775807);')
out.append(f'    expect(hx(u64_be(1700000000))).toEqual("{struct.pack(">Q", 1700000000).hex()}");')
out.append('}\n')

out.append('test "principals are user names, safe in authorized_keys and a shell" {')
for p, ok in [('alice', True), ('git', True), ('a.b-c_d@e+f', True), ('', False), ('a,b', False), ('a b', False), ('a"b', False), ("a'b", False), ('a*', False), ('x' * 64, True), ('x' * 65, False)]:
    out.append(f'    expect(principal_ok({R(p)})).{"toBeTrue" if ok else "toBeFalse"}();')
out.append('    CertOpts o = cert_opts(["--principal", "alice", "--days", "7", "--principal", "bob", "--principal", "alice"], 0, CertOpts {.principals = [], .days = 30, .err = ""});')
out.append('    expect(o.err).toEqual("");')
out.append('    expect(o.days).toEqual(7);')
out.append('    expect(o.principals.len()).toEqual(2);')
out.append('    expect(cert_opts(["--days", "367"], 0, CertOpts {.principals = [], .days = 30, .err = ""}).err).toEqual("--days takes 1 to 366");')
out.append('    expect(cert_opts(["--days", "0"], 0, CertOpts {.principals = [], .days = 30, .err = ""}).err).toEqual("--days takes 1 to 366");')
out.append('    expect(str_len(cert_opts(["--principal", "a,b"], 0, CertOpts {.principals = [], .days = 30, .err = ""}).err) > 0).toBeTrue();')
out.append('    expect(str_len(cert_opts(["--force"], 0, CertOpts {.principals = [], .days = 30, .err = ""}).err) > 0).toBeTrue();')
out.append('}\n')

# The list and the agent: the ed25519 key with its certificate.
key_line = ed[1]
cert_line = ed[2]
va, vb = ed[3]['va'], ed[3]['vb']
entry = f'{"my key".encode().hex()} {"ca".encode().hex()} 30 alice,bob {va} {vb} {cert_line}'
out.append('test "the certificate list is read and written back the same" {')
out.append(f'    List(CertEntry) es = certs_of({R(entry + chr(10) + "not a line" + chr(10))});')
out.append('    expect(es.len()).toEqual(1);')
out.append('    expect(es[0].key).toEqual("my key");')
out.append('    expect(es[0].ca).toEqual("ca");')
out.append('    expect(es[0].days).toEqual(30);')
out.append('    expect(es[0].principals.len()).toEqual(2);')
out.append(f'    expect(es[0].valid_before).toEqual({vb});')
out.append(f'    expect(es[0].line).toEqual({R(cert_line)});')
out.append(f'    expect(cert_text(es[0])).toEqual({R(entry)});')
out.append('}\n')

kb = base64.b64decode(key_line.split()[1])
cb = base64.b64decode(cert_line.split()[1])
out.append('test "the agent offers a current certificate before its key, and signs for it with the key" {')
out.append(f'    List(SshEntry) keys = [SshEntry {{.name = "my key", .line = {R(key_line)}}}];')
out.append(f'    List(CertEntry) cs = certs_of({R(entry)});')
out.append(f'    List(Ident) now_ids = idents_of(keys, cs, {va + 60}, 0, []);')
out.append('    expect(now_ids.len()).toEqual(2);')
out.append(f'    expect(hx(now_ids[0].blob)).toEqual("{cb.hex()}");')
out.append('    expect(now_ids[0].comment).toEqual("my key (certificate)");')
out.append(f'    expect(hx(now_ids[1].blob)).toEqual("{kb.hex()}");')
out.append('    expect(now_ids[1].comment).toEqual("my key");')
out.append('    // Expired, or not yet valid: the key alone.')
out.append(f'    expect(idents_of(keys, cs, {vb}, 0, []).len()).toEqual(1);')
out.append(f'    expect(idents_of(keys, cs, {va - 1}, 0, []).len()).toEqual(1);')
out.append('    // A certificate listed for another key is not offered.')
out.append(f'    expect(idents_of([SshEntry {{.name = "my key", .line = {R(certs[1][1])}}}], cs, {va + 60}, 0, []).len()).toEqual(1);')
out.append(f'    Option(Target) t = target_for(keys, cs, {va + 60}, {L(cb)}, 0);')
out.append('    Target tg = t else { Target {.e = SshEntry {.name = "", .line = ""}, .key = [], .cert = None, .named = []} };')
out.append('    expect(tg.e.name).toEqual("my key");')
out.append(f'    expect(hx(tg.key)).toEqual("{kb.hex()}");')
out.append('    Option(CertEntry) tc = tg.cert;')
out.append('    expect(match tc { None => "", Some(c) => c.ca }).toEqual("ca");')
out.append(f'    Option(Target) plain = target_for(keys, cs, {va + 60}, {L(kb)}, 0);')
out.append('    Target pt = plain else { tg };')
out.append('    Option(CertEntry) pc = pt.cert;')
out.append('    expect(match pc { None => true, Some(_) => false }).toBeTrue();')
out.append('    expect(pt.e.name).toEqual("my key");')
out.append(f'    expect(match target_for(keys, cs, {vb + 1}, {L(cb)}, 0) {{ None => true, Some(_) => false }}).toBeTrue();')
out.append(f'    expect(cert_json(tg.cert, {va + 60})).toEqual("{{\\"ca\\":\\"ca\\",\\"principals\\":[\\"alice\\",\\"bob\\"],\\"valid_before\\":{vb},\\"renews\\":false}}");')
out.append(f'    expect(cert_json(tg.cert, {vb - 60})).toEqual("{{\\"ca\\":\\"ca\\",\\"principals\\":[\\"alice\\",\\"bob\\"],\\"valid_before\\":{vb},\\"renews\\":true}}");')
out.append('    expect(cert_json(None, 0)).toEqual("");')
out.append('    // OpenSSH signs a certificate it loaded from a file with the key: the')
out.append('    // request names the key, the signed authentication the certificate.')
out.append(f'    Signed via = Signed {{.kind = "auth", .session_id = [], .user = "alice", .service = "ssh-connection", .alg = "ssh-ed25519-cert-v01@openssh.com", .key = {L(cb)}, .host_key = [], .namespace = ""}};')
out.append('    Target viat = for_signed(pt, offered_cert(cs, keys[0], ' + str(va + 60) + '), via);')
out.append('    Option(CertEntry) vc = viat.cert;')
out.append('    expect(match vc { None => "", Some(c) => c.ca }).toEqual("ca");')
out.append(f'    expect(hx(viat.named)).toEqual("{cb.hex()}");')
out.append('    expect(refused(unbound(), viat.named, via)).toEqual("");')
out.append('    // Expired, or a certificate that is not this key\'s: still another key.')
out.append('    Target late = for_signed(pt, offered_cert(cs, keys[0], ' + str(vb + 1) + '), via);')
out.append(f'    expect(hx(late.named)).toEqual("{kb.hex()}");')
out.append('    expect(refused(unbound(), late.named, via)).toEqual("the request names another key");')
out.append(f'    Signed other = Signed {{.kind = "auth", .session_id = [], .user = "alice", .service = "ssh-connection", .alg = "x", .key = {L(base64.b64decode(certs[1][2].split()[1]))}, .host_key = [], .namespace = ""}};')
out.append('    expect(refused(unbound(), for_signed(pt, offered_cert(cs, keys[0], ' + str(va + 60) + '), other).named, other)).toEqual("the request names another key");')
out.append('    CertEntry ce = cs[0];')
out.append(f'    expect(entry_due(ce, {vb - (vb - va) // 3 - 1})).toBeFalse();')
out.append(f'    expect(entry_due(ce, {vb - (vb - va) // 3})).toBeTrue();')
out.append(f'    expect(entry_due(ce, {vb + 5})).toBeTrue();')
out.append('}')

open(os.path.join(HERE, '..', 'src', 'ssh', 'sshcert_ref_test.resid'), 'w').write('\n'.join(out) + '\n')
print('wrote src/ssh/sshcert_ref_test.resid')

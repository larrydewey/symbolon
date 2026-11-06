#!/usr/bin/env python3
"""Generates src/agent/link_ref_test.resid: the QR link and the offer/accept
messages of device link-new / link-add (SPEC 11.4), with their HMAC-SHA256
macs computed here by Python's hmac -- nothing from the code under test.

    python3 tests/gen_link_ref.py
"""
import base64, hashlib, hmac, os
HERE = os.path.dirname(os.path.abspath(__file__))
L = lambda b: '[' + ', '.join(str(x) for x in b) + ']'
R = lambda s: '"' + s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n') + '"'
secret = os.urandom(32)
b64u = lambda b: base64.urlsafe_b64encode(b).decode().rstrip('=')
link = f'symbolon://link?a=192.168.1.20,10.0.0.5&p=40123&s={b64u(secret)}'
keys = os.urandom(140); keys2 = os.urandom(140)
ca = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n'
body = f'SYMBOLON-LINK 1\nrelay 192.168.100.106 47101\nca {ca.encode().hex()}\nkeys {keys.hex()}\n'
omac = hmac.new(secret, b'symbolon v1 link offer\n' + body.encode(), hashlib.sha256).hexdigest()
offer = body + f'mac {omac}\nend\n'
abody = f'keys {keys2.hex()}\n'
amac = hmac.new(secret, b'symbolon v1 link accept\n' + omac.encode() + b'\n' + abody.encode(), hashlib.sha256).hexdigest()
accept = abody + f'mac {amac}\nend\n'
other = os.urandom(32)
out = ['// The link and its messages (src/agent/link.resid) against Python\'s hmac', '// (tests/gen_link_ref.py). Generated; do not edit by hand.', '',
       'import "link.resid";', 'import "crypto.resid";', '',
       'Bool none_l(Option(Link) x) { return match x { None => true, Some(_) => false }; }',
       'Bool none_o(Option(Offer) x) { return match x { None => true, Some(_) => false }; }', '']
out.append('test "a link is written and read back; malformed ones are refused" {')
out.append(f'    expect(link_text(["192.168.1.20", "10.0.0.5"], 40123, {L(secret)})).toEqual({R(link)});')
out.append(f'    Option(Link) ol = link_of({R(link)});')
out.append(f'    Link l = ol else {{ Link {{.hosts = [], .port = 0, .secret = []}} }};')
out.append(f'    expect(str_join(l.hosts, ",")).toEqual("192.168.1.20,10.0.0.5");')
out.append(f'    expect(l.port).toEqual(40123);')
out.append(f'    expect(hex_encode(l.secret)).toEqual("{secret.hex()}");')
for bad in ['symbolon://pair?h=1&p=2', link.replace('p=40123', 'p=70000'), link[:-3], link.replace('a=192.168.1.20,10.0.0.5', 'a=bad host'), 'symbolon://link?a=x&p=1']:
    out.append(f'    expect(none_l(link_of({R(bad)}))).toBeTrue();')
out.append('}\n')
out.append('test "the offer and accept are written as Python computes them" {')
out.append(f'    expect(offer_text({L(secret)}, "192.168.100.106", 47101, {R(ca)}, {L(keys)})).toEqual({R(offer)});')
out.append(f'    expect(accept_text({L(secret)}, "{omac}", {L(keys2)})).toEqual({R(accept)});')
out.append('}\n')
out.append('test "an offer is taken only with the code\'s key; the accept likewise" {')
out.append(f'    Option(Offer) oo = offer_of({R(offer)}, {L(secret)});')
out.append(f'    Offer o = oo else {{ Offer {{.relay_host = "", .relay_port = 0, .ca = "", .keys = [], .mac = ""}} }};')
out.append(f'    expect(o.relay_host).toEqual("192.168.100.106");')
out.append(f'    expect(o.relay_port).toEqual(47101);')
out.append(f'    expect(o.ca).toEqual({R(ca)});')
out.append(f'    expect(hex_encode(o.keys)).toEqual("{keys.hex()}");')
out.append(f'    expect(none_o(offer_of({R(offer)}, {L(other)}))).toBeTrue();')
tampered = offer.replace(keys.hex()[:8], 'deadbeef', 1)
out.append(f'    expect(none_o(offer_of({R(tampered)}, {L(secret)}))).toBeTrue();')
out.append(f'    expect(none_o(offer_of({R(offer.replace("47101", "47102"))}, {L(secret)}))).toBeTrue();')
out.append(f'    expect(hex_encode(accept_keys({R(accept)}, {L(secret)}, "{omac}"))).toEqual("{keys2.hex()}");')
out.append(f'    expect(accept_keys({R(accept)}, {L(other)}, "{omac}").len()).toEqual(0);')
out.append(f'    expect(accept_keys({R(accept)}, {L(secret)}, "{"0" * 64}").len()).toEqual(0);')
out.append(f'    expect(accept_keys({R(accept.replace(keys2.hex()[:6], "abcdef", 1))}, {L(secret)}, "{omac}").len()).toEqual(0);')
nca = body.replace(f'ca {ca.encode().hex()}', 'ca -')
nmac = hmac.new(secret, b'symbolon v1 link offer\n' + nca.encode(), hashlib.sha256).hexdigest()
out.append(f'    Option(Offer) on = offer_of({R(nca + f"mac {nmac}" + chr(10) + "end" + chr(10))}, {L(secret)});')
out.append(f'    expect((on else {{ Offer {{.relay_host = "", .relay_port = 0, .ca = "x", .keys = [], .mac = ""}} }}).ca).toEqual("");')
out.append('}')
open(os.path.join(HERE, '..', 'src', 'agent', 'link_ref_test.resid'), 'w').write('\n'.join(out) + '\n')
print('wrote src/agent/link_ref_test.resid')

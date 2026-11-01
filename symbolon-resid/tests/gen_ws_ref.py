#!/usr/bin/env python3
"""Generates src/browser/ws_ref_test.resid. The accept value (hashlib,
base64) and the frames are made here, not by the code under test.

    python3 tests/gen_ws_ref.py
"""
import base64, hashlib, os
HERE = os.path.dirname(os.path.abspath(__file__))
k = 'dGhlIHNhbXBsZSBub25jZQ=='
acc = base64.b64encode(hashlib.sha1((k + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()


def fr(fin, op, p, mask=None):
    b = bytes([(0x80 if fin else 0) | op]); n = len(p); m = 0x80 if mask else 0
    if n < 126: b += bytes([m | n])
    elif n < 65536: b += bytes([m | 126]) + n.to_bytes(2, 'big')
    else: b += bytes([m | 127]) + n.to_bytes(8, 'big')
    if mask: b += mask; p = bytes(x ^ mask[i % 4] for i, x in enumerate(p))
    return b + p


L = lambda b: '[' + ', '.join(map(str, b)) + ']'
one = fr(True, 1, b'{"id":1}')
frag = fr(False, 1, b'{"id":') + fr(True, 0, b'2}')
f126 = fr(True, 1, b'y' * 300)
f127 = fr(True, 1, b'x' * 70000)
masked = fr(True, 1, b'abc', b'\x01\x02\x03\x04')
out = f'''// The WebSocket framing (src/browser/ws.resid) against frames and the
// accept value made by Python (hashlib, base64) in tests/gen_ws_ref.py.
// Generated; do not edit by hand.

import "ws.resid";
import "httpserv.resid";

test "Sec-WebSocket-Accept is RFC 6455's example value" {{
    expect(ws_accept_of("{k}")).toEqual("{acc}");
}}

Str text_of(Frame f) {{ return http_text(f.payload, 0, f.payload.len()); }}

test "frames of each length form parse; short buffers ask for more" {{
    Frame a = frame_at({L(one)});
    expect(text_of(a)).toEqual("{{\\"id\\":1}}");
    expect(a.used).toEqual({len(one)});
    expect(frame_at({L(f126)}).payload.len()).toEqual(300);
    expect(frame_at({L(f127[:20])}).need).toEqual({len(f127) - 20});
    expect(text_of(frame_at({L(masked)}))).toEqual("abc");
    expect(frame_at([129]).need).toEqual(1);
}}

test "fragments: the first frame is not final, the continuation is" {{
    List(Int) b = {L(frag)};
    Frame a = frame_at(b);
    expect(a.fin).toBeFalse();
    Frame c = frame_at(b[a.used..b.len()]);
    expect(c.fin).toBeTrue();
    expect(c.opcode).toEqual(0);
}}
'''
open(os.path.join(HERE, '..', 'src', 'browser', 'ws_ref_test.resid'), 'w').write(out)

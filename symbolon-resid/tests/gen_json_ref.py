#!/usr/bin/env python3
"""Generates src/browser/json_ref_test.resid. Quoted strings and parsed
values come from Python's json module, not from the code under test.

    python3 tests/gen_json_ref.py
"""
import json, os
HERE = os.path.dirname(os.path.abspath(__file__))
L = lambda b: '[' + ', '.join(str(x) for x in b) + ']'
R = lambda s: '"' + s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n').replace('\t', '\\t') + '"'

quotes = ['plain', 'say "hi"', 'back\\slash', 'line\nbreak\ttab', 'ctl\x01\x1f\x7f', 'caf\u00e9 \u2603 \U0001F600']
qtests = '\n'.join(f'    expect(hx(json_utf8(json_quote(txt({L(s.encode())}))))).toEqual("{json.dumps(s, ensure_ascii=False).encode().hex()}");' for s in quotes)
# Python escapes DEL? json.dumps leaves \x7f raw; the agent escapes it, so compare by parsing back instead for that case.
docs = [
    ('{"id":7,"result":{"result":{"type":"string","value":"a\\"b\\u00e9\\ud83d\\ude00"}}}', ['result', 'result', 'value']),
    ('{"id": 12, "sessionId": "AB12", "params": {"x": [1, 2, {"y": null}], "ok": true}}', ['sessionId']),
    ('  {"method":"Target.attachedToTarget","params":{"sessionId":"S1","targetInfo":{"url":"about:blank"}}} ', ['params', 'targetInfo', 'url']),
]
ptests = '\n'.join(f'    expect(jstr(at({L(d.encode())}, [{", ".join(R(k) for k in ks)}]))).toEqual({R(json.dumps(eval_path(json.loads(d), ks), ensure_ascii=False)[1:-1]) if False else ""});' for d, ks in []) 
def walk(v, ks):
    for k in ks: v = v[k]
    return v
ptests = '\n'.join(f'    expect(hx(json_utf8(jstr(at({L(d.encode())}, [{", ".join(R(k) for k in ks)}]))))).toEqual("{walk(json.loads(d), ks).encode().hex()}");' for d, ks in docs)
bad = ['{"a":1,}', '[1 2]', '{"a" 1}', '"open', '{"a":1} x', '\x01', '{"a":"\x01"}', '[' * 70 + ']' * 70, '']
btests = '\n'.join(f'    expect(rejects({L(b.encode())})).toBeTrue();' for b in bad)
for b in bad[:-2]:
    try: json.loads(b); raise SystemExit(f'python accepts {b!r}')
    except ValueError: pass

out = f'''// JSON (src/browser/json.resid) against Python's json module
// (tests/gen_json_ref.py). Generated; do not edit by hand.

import "json.resid";
import "crypto.resid";
import "httpserv.resid";

Str hx(List(Int) b) {{ return hex_encode(b); }}
Str txt(List(Int) b) {{ return http_text(b, 0, b.len()); }}

Option(Jv) at(List(Int) doc, List(Str) path) {{
    Option(Jv) v = json_parse(doc);
    return match v {{ None => None, Some(x) => jpath(x, path, 0) }};
}}

Bool rejects(List(Int) doc) {{ return match json_parse(doc) {{ None => true, Some(_) => false }}; }}

test "strings are quoted as Python's json.dumps quotes them" {{
{qtests}
}}

test "values are read at member paths as Python's json.loads reads them" {{
{ptests}
    expect(jint(at({L(docs[1][0].encode())}, ["id"]))).toEqual(12);
    expect(jbool(at({L(docs[1][0].encode())}, ["params", "ok"]))).toBeTrue();
}}

test "malformed JSON and nesting deeper than 64 are refused" {{
{btests}
}}

test "a quoted string parses back to itself" {{
    Str s = txt({L('ctl\x01\x1f\x7f "q" \\ caf\u00e9'.encode())});
    expect(hx(json_utf8(jstr(json_parse(json_utf8(json_quote(s))))))).toEqual(hx(json_utf8(s)));
}}
'''
open(os.path.join(HERE, '..', 'src', 'browser', 'json_ref_test.resid'), 'w').write(out)

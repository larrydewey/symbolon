#!/usr/bin/env python3
"""Generates src/rotation/rotation_ref_test.resid. Generated passwords are
computed here by a separate implementation of SPEC 26.3's generator
(uniform rejection sampling over the allowed characters, redrawn until every
class drawn from is present); the rest of the file checks the rotation
rules by behaviour.

    python3 tests/gen_rotation_ref.py
"""
import os, random

random.seed(83)
HERE = os.path.dirname(os.path.abspath(__file__))
rb = lambda n: bytes(random.randrange(256) for _ in range(n))
L = lambda b: '[' + ', '.join(str(x) for x in b) + ']'
CLASSES = ['abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', '0123456789', '!#$%&()*+,-./:;<=>?@[]^_{|}~']


def generate(minl, maxl, req, forbidden, rnd):
    cs = [''.join(c for c in s if c not in forbidden) for s in CLASSES]
    if any((req >> i) & 1 and not cs[i] for i in range(4)): return None
    used = [c for c in cs if c]
    allc = ''.join(used)
    if len(allc) < 2: return None
    lo = max(8, minl); hi = 64 if maxl == 0 else maxl
    n = min(max(24, lo), hi)
    pos = 0
    for _ in range(16):
        pw = ''
        while len(pw) < n:
            if pos >= len(rnd): return None
            b = rnd[pos]; pos += 1
            if b < 256 - 256 % len(allc): pw += allc[b % len(allc)]
        if all(any(ch in c for ch in pw) for c in used): return pw
    return None


rules = [(0, 0, 15, ''), (12, 16, 7, '0O1lI'), (8, 10, 1, '!#$%&()*+,-./:;<=>?@[]^_{|}~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'), (8, 64, 8, CLASSES[3])]
cases = []
for r in rules:
    rnd = rb(600)
    cases.append((r, rnd, generate(*r, rnd)))

esc = lambda s: s.replace('\\', '\\\\').replace('"', '\\"').replace('{', '{{').replace('}', '}}')
tests = ''
for i, ((mn, mx, rq, fb), rnd, pw) in enumerate(cases):
    want = 'none' if pw is None else esc(pw)
    tests += f'''
test "generated password {i} equals the reference" {{
    PasswordRules r = PasswordRules {{ .min_length = {mn}, .max_length = {mx}, .required_classes = {rq}, .forbidden_chars = "{esc(fb)}" }};
    Str got = match generate_password(r, {L(rnd)}) {{ Some(p) => p, None => "none" }};
    expect(got).toEqual("{want}");
}}
'''

out = f'''// Rotation (src/rotation/rotation.resid): generated passwords against an
// independent implementation (tests/gen_rotation_ref.py), and the rotation
// rules by behaviour. Generated; do not edit by hand.

import "../types.resid";
import "../vault/vault.resid";
import "rotation.resid";
import "crypto.resid";
import "word.resid";

List(Int) rep(Int b, Int n) {{ return if (n == 0) {{ [] }} else {{ [b].concat(rep(b, n - 1)) }}; }}
List(Int) idn(Int n) {{ return rep(n, 32); }}
{tests}
test "rules that forbid a required class give no password" {{
    PasswordRules r = PasswordRules {{ .min_length = 8, .max_length = 16, .required_classes = 4, .forbidden_chars = "0123456789" }};
    Bool none = match generate_password(r, rep(7, 600)) {{ Some(_) => false, None => true }};
    expect(none).toBeTrue();
}}

RotationItem item(Int n, Str kind, Str domain, UInt(8) value, Option(List(Int)) via, Bool duress, Bool readable) {{
    return RotationItem {{ .id = idn(n), .kind = kind, .domain = domain, .value = value, .resets_via = via,
                           .in_duress_subset = duress, .readable_by_removed = readable }};
}}

List(RotationItem) items() {{
    return [item(1, "password", "shop.example", 0, Some(idn(4)), false, true),
            item(2, "password", "bank.example", 3, Some(idn(4)), true, true),
            item(3, "passkey", "news.example", 0, None, false, true),
            item(4, "password", "mail.example", 2, None, true, true),
            item(5, "totp", "bank.example", 3, None, false, false),
            item(6, "password", "blog.example", 1, Some(idn(4)), false, true)];
}}

Str ids(List(RotationItem) xs, Int i, Str acc) {{
    if (i >= xs.len()) {{ return acc; }}
    return ids(xs, i + 1, acc + f"{{xs[i].id[0]}}");
}}

test "a removed device: every password and seed it could read, financial and email first, email before what resets through it" {{
    expect(ids(rotation_plan(TriggerDeviceRemoved(idn(9)), items()), 0, "")).toEqual("4261");
}}

test "a suspected compromise adds the passkeys" {{
    expect(ids(rotation_plan(TriggerSuspectedCompromise(idn(9)), items()), 0, "")).toEqual("42613");
}}

test "a breached site, a weak password, the end of duress, a request" {{
    expect(ids(rotation_plan(TriggerBreach("bank.example"), items()), 0, "")).toEqual("25");
    expect(ids(rotation_plan(TriggerWeakPassword(idn(6)), items()), 0, "")).toEqual("6");
    expect(ids(rotation_plan(TriggerDuressEnd, items()), 0, "")).toEqual("42");
    expect(ids(rotation_plan(TriggerPrincipalRequest([idn(1), idn(3)]), items()), 0, "")).toEqual("13");
    // A schedule rotates only items the principal marked.
    expect(ids(rotation_plan(TriggerPolicySchedule([idn(1), idn(6)]), items()), 0, "")).toEqual("6");
}}

test "an email item ranked below a site that resets through it still goes first" {{
    List(RotationItem) xs = [item(1, "password", "bank.example", 3, Some(idn(2)), false, true),
                             item(2, "password", "mail.example", 0, None, false, true)];
    expect(ids(rotation_plan(TriggerDeviceRemoved(idn(9)), xs), 0, "")).toEqual("21");
}}

FieldPlain fp(Str n, Int b) {{ return FieldPlain {{ .name = n, .value = secret_bytes([b]) }}; }}

@requires(declassify)
Str val(List(FieldPlain) fs, Str n, Int i) {{
    if (i >= fs.len()) {{ return "-"; }}
    if (fs[i].name == n) {{ Int v = (Int)declassify(fs[i].value[0], "test output"); return f"{{v}}"; }}
    return val(fs, n, i + 1);
}}

@requires(declassify)
Str said(Result(List(FieldPlain), SymbolonError) r) {{
    return match r {{
        Err(e) => match e {{ ErrRotationFailed(s) => s, _ => "other" }},
        Ok(fs) => "cur=" + val(fs, "current", 0) + " pen=" + val(fs, "pending", 0) + " h0=" + val(fs, "history.0", 0)
                  + " h1=" + val(fs, "history.1", 0) + " u=" + val(fs, "unresolved", 0) + " user=" + val(fs, "username", 0)
    }};
}}

List(FieldPlain) start() {{ return [fp("username", 7), fp("current", 10), fp("history.0", 9)]; }}

List(FieldPlain) prepared() {{ return match prepare(start(), secret_bytes([11])) {{ Ok(f) => f, Err(_) => [] }}; }}

@requires(declassify)
test "prepare keeps current and adds pending; a second prepare is refused" {{
    expect(said(prepare(start(), secret_bytes([11])))).toEqual("cur=10 pen=11 h0=9 h1=- u=- user=7");
    expect(said(prepare(prepared(), secret_bytes([12])))).toEqual("a change is already in progress");
}}

@requires(declassify)
test "verify: the vault always holds a password the site accepts" {{
    expect(said(verify(prepared(), NewWorks))).toEqual("cur=11 pen=- h0=10 h1=9 u=- user=7");
    expect(said(verify(prepared(), OldWorks))).toEqual("cur=10 pen=- h0=9 h1=- u=- user=7");
    expect(said(verify(prepared(), NeitherWorks))).toEqual("cur=10 pen=11 h0=9 h1=- u=49 user=7");
    expect(said(verify(start(), NewWorks))).toEqual("nothing pending");
}}

@requires(declassify)
test "an unresolved item is resolved by whichever candidate signs in, deleting none" {{
    List(FieldPlain) u = match verify(prepared(), NeitherWorks) {{ Ok(f) => f, Err(_) => [] }};
    expect(candidates(u).len()).toEqual(3);
    expect(said(resolve(u, 1))).toEqual("cur=11 pen=- h0=10 h1=9 u=- user=7");
    expect(said(resolve(u, 2))).toEqual("cur=9 pen=- h0=10 h1=11 u=- user=7");
}}

test "a change interrupted after prepare resumes at verify" {{
    Phase p = phase_of(prepared());
    expect(match p {{ Pending => true, _ => false }}).toBeTrue();
}}

test "sign-in attempts: three failures a day per site, with backoff" {{
    List(Attempt) none = [];
    expect(may_attempt(none, "bank.example", 1000)).toBeTrue();
    List(Attempt) one = [Attempt {{ .domain = "bank.example", .time = 1000 }}];
    expect(may_attempt(one, "bank.example", 1059)).toBeFalse();
    expect(may_attempt(one, "bank.example", 1060)).toBeTrue();
    expect(may_attempt(one, "mail.example", 1001)).toBeTrue();
    List(Attempt) two = one.concat([Attempt {{ .domain = "bank.example", .time = 1100 }}]);
    expect(may_attempt(two, "bank.example", 1219)).toBeFalse();
    expect(may_attempt(two, "bank.example", 1220)).toBeTrue();
    List(Attempt) three = two.concat([Attempt {{ .domain = "bank.example", .time = 1300 }}]);
    expect(may_attempt(three, "bank.example", 50000)).toBeFalse();
    expect(may_attempt(three, "bank.example", 1000 + 86401)).toBeTrue();
}}

Str leased(Result(List(RotationLease), SymbolonError) r) {{
    return match r {{ Ok(ls) => f"{{ls.len()}}", Err(e) => match e {{ ErrRotationFailed(s) => s, _ => "other" }} }};
}}

test "one rotation per item: another device's live lease blocks, an expired one does not" {{
    List(RotationLease) ls = match take_lease([], idn(1), idn(20), 100, 600) {{ Ok(x) => x, Err(_) => [] }};
    expect(leased(take_lease(ls, idn(1), idn(21), 200, 600))).toEqual("item leased by another device");
    expect(leased(take_lease(ls, idn(1), idn(20), 200, 600))).toEqual("1");
    expect(leased(take_lease(ls, idn(1), idn(21), 700, 600))).toEqual("1");
    expect(leased(take_lease(ls, idn(2), idn(21), 200, 600))).toEqual("2");
    expect(release_lease(ls, idn(1)).len()).toEqual(0);
}}

test "status counts current, pending and the items that need the principal" {{
    RotationStatus s = status([Idle, Pending, Unresolved, Idle], 0, RotationStatus {{ .current = 0, .pending = 0, .need_principal = 0 }});
    expect(s.current).toEqual(2);
    expect(s.pending).toEqual(1);
    expect(s.need_principal).toEqual(1);
}}
'''
open(os.path.join(HERE, '..', 'src', 'rotation', 'rotation_ref_test.resid'), 'w').write(out)

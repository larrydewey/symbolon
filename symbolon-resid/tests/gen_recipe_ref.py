#!/usr/bin/env python3
"""Generates src/recipe/recipe_ref_test.resid. Recipe bytes (separate CBOR
encoder), repository COSE_Sign1 signatures, an RFC 9162 Merkle tree with its
inclusion proofs and a signed tree head are made here (hashlib,
cryptography's ECDSA), not by the code under test.

    python3 tests/gen_recipe_ref.py
"""
import hashlib, os, random
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

random.seed(97)
HERE = os.path.dirname(os.path.abspath(__file__))
rb = lambda n: bytes(random.randrange(256) for _ in range(n))
L = lambda b: '[' + ', '.join(str(x) for x in b) + ']'
H = lambda b: '"' + bytes(b).hex() + '"'
sha = lambda b: hashlib.sha256(b).digest()


def head(major, n):
    if n < 24: return bytes([major << 5 | n])
    if n < 256: return bytes([major << 5 | 24, n])
    if n < 65536: return bytes([major << 5 | 25]) + n.to_bytes(2, 'big')
    return bytes([major << 5 | 26]) + n.to_bytes(4, 'big')

uint = lambda n: head(0, n)
nint = lambda n: head(1, -1 - n)
bstr = lambda b: head(2, len(b)) + b
tstr = lambda s: head(3, len(s.encode())) + s.encode()
arr = lambda items: head(4, len(items)) + b''.join(items)
mp = lambda pairs: head(5, len(pairs)) + b''.join(k + v for k, v in pairs)
TRUE = b'\xf5'


def newkey():
    k = ec.generate_private_key(ec.SECP256R1())
    n = k.public_key().public_numbers()
    return k, b'\x04' + n.x.to_bytes(32, 'big') + n.y.to_bytes(32, 'big')


def sign(k, msg):
    r, s = decode_dss_signature(k.sign(msg, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, 'big') + s.to_bytes(32, 'big')


def cose_sign1(k, payload):
    prot = mp([(uint(1), nint(-7))])
    tbs = arr([tstr('Signature1'), bstr(prot), bstr(b''), bstr(payload)])
    return head(6, 18) + arr([bstr(prot), mp([]), bstr(payload), bstr(sign(k, tbs))])


def rules(mn, mx, rq, fb): return mp([(uint(1), uint(mn)), (uint(2), uint(mx)), (uint(3), uint(rq)), (uint(4), tstr(fb))])


def recipe(domain, version, rl, steps, origins, sign_in=()):
    f6 = [(uint(6), arr(list(sign_in)))] if sign_in else []
    return mp([(uint(1), tstr(domain)), (uint(2), uint(version)), (uint(3), rl), (uint(4), arr(steps)), (uint(5), arr([tstr(o) for o in origins]))] + f6)


nav = lambda u: arr([uint(0), tstr(u)])
fill = lambda s, v: arr([uint(1), tstr(s), tstr(v)])
click = lambda s: arr([uint(2), tstr(s)])
expect = lambda k, t: arr([uint(3), arr([uint(k), tstr(t)])])
passkey = arr([uint(4), TRUE])

steps_v1 = [nav('https://acct.example.com/security'), fill('#old', 'old'), fill('#new', 'new'), fill('#otp', 'totp'),
            click('#save'), expect(2, 'Password changed'), passkey]
origins = ['https://acct.example.com', 'https://login.example.com']
r_v1 = recipe('example.com', 3, rules(12, 64, 7, '"\\'), steps_v1, origins)
r_v2 = recipe('example.com', 4, rules(12, 64, 7, '"\\'), [s for i, s in enumerate(steps_v1) if i != 3], origins[:1])   # only removes
sign_in_v1 = [nav('https://login.example.com/signin'), fill('#user', 'username'), fill('#pw', 'password'), click('#go'), expect(1, '#account')]
r_si = recipe('example.com', 6, rules(12, 64, 7, '"\\'), steps_v1, origins, sign_in_v1)
r_v3 = recipe('example.com', 5, rules(12, 64, 7, '"\\'), steps_v1 + [click('#confirm')], origins)                   # adds a step

resid_steps = ('[StepNavigate("https://acct.example.com/security"), StepFill("#old", "old"), StepFill("#new", "new"), '
               'StepFill("#otp", "totp"), StepClick("#save"), StepExpect(ExpectText("Password changed")), StepPasskeyRegister]')

# RFC 9162 tree over 7 entries [time, payload].
entries = [arr([uint(1000 + 100 * i), bstr(rb(20))]) for i in range(7)]
entries[2] = arr([uint(5000), bstr(r_v1)])
lh = lambda e: sha(b'\0' + e)
nh = lambda a, b: sha(b'\x01' + a + b)


def mth(es):
    if len(es) == 1: return lh(es[0])
    k = 1
    while k * 2 < len(es): k *= 2
    return nh(mth(es[:k]), mth(es[k:]))


def path(m, es):
    if len(es) == 1: return []
    k = 1
    while k * 2 < len(es): k *= 2
    return path(m, es[:k]) + [mth(es[k:])] if m < k else path(m - k, es[k:]) + [mth(es[:k])]


root = mth(entries)
keys = [newkey() for _ in range(3)]
log_k, log_pub = newkey()
th = cose_sign1(log_k, mp([(uint(1), uint(7)), (uint(2), bstr(root))]))
sigs = [cose_sign1(k, r_v1) for k, _ in keys]
outsider, _ = newkey()
P = lambda m: '[' + ', '.join(L(x) for x in path(m, entries)) + ']'

incl_tests = '\n'.join(f'    expect(inclusion_ok({m}, 7, {L(entries[m])}, {P(m)}, {L(root)})).toBeTrue();' for m in range(7))
bad = path(4, entries); bad[0] = bytes([bad[0][0] ^ 1]) + bad[0][1:]

repo_file = arr([arr([bstr(p) for _, p in keys]), uint(2), bstr(log_pub)])
bundle_file = arr([bstr(r_v1), arr([bstr(sigs[0]), bstr(sigs[2])]), uint(5000), uint(2), uint(7), arr([bstr(x) for x in path(2, entries)]), bstr(root), bstr(th)])

out = f'''// Recipes (src/recipe/recipe.resid) against bytes, signatures and a Merkle
// tree made by an independent implementation (tests/gen_recipe_ref.py).
// Generated; do not edit by hand.

import "../types.resid";
import "recipe.resid";
import "crypto.resid";

Str hx(List(Int) b) {{ return hex_encode(b); }}

RecipePayload v1() {{
    return RecipePayload {{ .domain = "example.com", .version = 3,
        .password_rules = PasswordRules {{ .min_length = 12, .max_length = 64, .required_classes = 7, .forbidden_chars = "\\"\\\\" }},
        .steps = {resid_steps}, .allowed_origins = ["https://acct.example.com", "https://login.example.com"], .sign_in = [] }};
}}

RecipePayload with_sign_in() {{
    return RecipePayload {{ .domain = "example.com", .version = 6, .password_rules = v1().password_rules, .steps = v1().steps,
        .allowed_origins = v1().allowed_origins,
        .sign_in = [StepNavigate("https://login.example.com/signin"), StepFill("#user", "username"), StepFill("#pw", "password"), StepClick("#go"), StepExpect(ExpectElement("#account"))] }};
}}

test "recipe bytes equal the reference and decode back" {{
    expect(hx(recipe_cbor(v1()))).toEqual({H(r_v1)});
    RecipePayload d = recipe_decode({L(r_v1)}) else {{ v1() }};
    expect(hx(recipe_cbor(d))).toEqual({H(r_v1)});
    expect(d.steps.len()).toEqual(7);
    expect(d.password_rules.forbidden_chars).toEqual("\\"\\\\");
}}

test "a recipe with a sign-in procedure (field 6) equals the reference and decodes back" {{
    expect(hx(recipe_cbor(with_sign_in()))).toEqual({H(r_si)});
    RecipePayload d = recipe_decode({L(r_si)}) else {{ v1() }};
    expect(d.sign_in.len()).toEqual(5);
    expect(hx(recipe_cbor(d))).toEqual({H(r_si)});
    Bool empty6 = match recipe_decode({L(recipe('example.com', 6, rules(12, 64, 7, '"\\'), steps_v1, origins)[:0] + head(5, 6) + recipe('example.com', 6, rules(12, 64, 7, '"\\'), steps_v1, origins)[1:] + uint(6) + arr([]))}) {{ Some(_) => false, None => true }};
    expect(empty6).toBeTrue();
}}

test "a non-canonical or truncated recipe does not decode" {{
    Bool long_head = match recipe_decode({L(bytes([0xb8, 5]) + r_v1[1:])}) {{ Some(_) => false, None => true }};
    Bool cut = match recipe_decode({L(r_v1[:-3])}) {{ Some(_) => false, None => true }};
    Bool trail = match recipe_decode({L(r_v1 + b'\\x00')}) {{ Some(_) => false, None => true }};
    expect(long_head).toBeTrue();
    expect(cut).toBeTrue();
    expect(trail).toBeTrue();
}}

test "RFC 9162 inclusion proofs made in Python verify at every index of a 7-leaf tree" {{
{incl_tests}
    expect(inclusion_ok(4, 7, {L(entries[4])}, {'[' + ', '.join(L(x) for x in bad) + ']'}, {L(root)})).toBeFalse();
    expect(inclusion_ok(3, 7, {L(entries[4])}, {P(4)}, {L(root)})).toBeFalse();
    // RFC 9162's check alone accepts this path with size 8 (so does the
    // reference algorithm); the size is bound to the root by the signed
    // tree head, which verify_bundle checks (see the next tests).
    expect(inclusion_ok(4, 8, {L(entries[4])}, {P(4)}, {L(root)})).toBeTrue();
    expect(inclusion_ok(7, 7, {L(entries[4])}, {P(4)}, {L(root)})).toBeFalse();
}}

Repository repo() {{ return Repository {{ .keys = [{", ".join(L(p) for _, p in keys)}], .threshold = 2, .log_key = {L(log_pub)} }}; }}

RecipeBundle bundle(List(List(Int)) sigs, List(Int) tree_head, List(List(Int)) path) {{
    return RecipeBundle {{ .payload = {L(r_v1)}, .sigs = sigs, .log_time = 5000, .index = 2, .size = 7, .path = path, .root = {L(root)}, .tree_head = tree_head }};
}}

Str verdict(Result(RecipePayload, SymbolonError) r) {{
    return match r {{ Ok(x) => f"ok v{{x.version}}", Err(e) => match e {{ ErrPolicyViolation(s) => s, _ => "other" }} }};
}}

test "a recipe signed by two of three repository keys and logged verifies" {{
    expect(verdict(verify_bundle(repo(), bundle([{L(sigs[0])}, {L(sigs[2])}], {L(th)}, {P(2)})))).toEqual("ok v3");
}}

test "repository and bundle files encoded in Python decode and verify" {{
    Repository r = repository_decode({L(repo_file)}) else {{ Repository {{ .keys = [], .threshold = 0, .log_key = [] }} }};
    RecipeBundle b = bundle_decode({L(bundle_file)}) else {{ bundle([], [], []) }};
    expect(verdict(verify_bundle(r, b))).toEqual("ok v3");
    Bool trail = match bundle_decode({L(bundle_file + b'\x00')}) {{ Some(_) => false, None => true }};
    Bool short = match repository_decode({L(repo_file[:-1])}) {{ Some(_) => false, None => true }};
    expect(trail && short).toBeTrue();
}}

test "one signature, one key twice, an outsider, a forged tree head or a wrong path are refused" {{
    expect(verdict(verify_bundle(repo(), bundle([{L(sigs[1])}], {L(th)}, {P(2)})))).toEqual("recipe not signed by the repository's threshold");
    expect(verdict(verify_bundle(repo(), bundle([{L(sigs[1])}, {L(sigs[1])}], {L(th)}, {P(2)})))).toEqual("recipe not signed by the repository's threshold");
    expect(verdict(verify_bundle(repo(), bundle([{L(sigs[1])}, {L(cose_sign1(outsider, r_v1))}], {L(th)}, {P(2)})))).toEqual("recipe not signed by the repository's threshold");
    expect(verdict(verify_bundle(repo(), bundle([{L(sigs[0])}, {L(sigs[1])}], {L(cose_sign1(outsider, mp([(uint(1), uint(7)), (uint(2), bstr(root))])))}, {P(2)})))).toEqual("tree head not signed by the log");
    expect(verdict(verify_bundle(repo(), bundle([{L(sigs[0])}, {L(sigs[1])}], {L(th)}, {P(3)})))).toEqual("recipe not in the transparency log");
    RecipeBundle b8 = bundle([{L(sigs[0])}, {L(sigs[1])}], {L(th)}, {P(2)});
    RecipeBundle wrong_size = RecipeBundle {{ .payload = b8.payload, .sigs = b8.sigs, .log_time = b8.log_time, .index = 2, .size = 8,
                                              .path = b8.path, .root = b8.root, .tree_head = b8.tree_head }};
    expect(verdict(verify_bundle(repo(), wrong_size))).toEqual("tree head not signed by the log");
}}

test "a new version runs after its 7-day hold, at once if it only removes, never if it adds before the hold" {{
    RecipePayload a = recipe_decode({L(r_v1)}) else {{ v1() }};
    RecipePayload b = recipe_decode({L(r_v2)}) else {{ v1() }};
    RecipePayload c = recipe_decode({L(r_v3)}) else {{ v1() }};
    expect(only_removes(b, a)).toBeTrue();
    expect(only_removes(c, a)).toBeFalse();
    Int t = 100000;
    Str now_shrink = match choose([a, b], [t - 700000, t], Some(a), "example.com", t) {{ Some(r) => f"v{{r.version}}", None => "none" }};
    Str now_grow = match choose([a, c], [t - 700000, t], Some(a), "example.com", t) {{ Some(r) => f"v{{r.version}}", None => "none" }};
    Str later = match choose([a, c], [t - 700000, t], Some(a), "example.com", t + 7 * 86400) {{ Some(r) => f"v{{r.version}}", None => "none" }};
    Str other = match choose([a, c], [t - 700000, t], None, "other.org", t + 7 * 86400) {{ Some(r) => f"v{{r.version}}", None => "none" }};
    expect(now_shrink).toEqual("v4");
    expect(now_grow).toEqual("v3");
    expect(later).toEqual("v5");
    expect(other).toEqual("none");
}}

test "origins: the recipe's, intersected with the item's exact origins" {{
    expect(origin_of("https://Acct.Example.com/security?x=1")).toEqual("https://acct.example.com");
    expect(origin_of("https://user@evil.example/")).toEqual("");
    expect(origin_of("javascript:alert(1)")).toEqual("");
    List(Str) run = run_origins(v1(), ["https://acct.example.com", "https://other.example.com"]);
    expect(run.len()).toEqual(1);
    expect(run[0]).toEqual("https://acct.example.com");
}}

Str planned(RecipePayload r, List(Str) item) {{
    return match check_plan(r, item) {{ Ok(os) => f"ok {{os.len()}}", Err(e) => match e {{ ErrPolicyViolation(s) => s, _ => "other" }} }};
}}

test "the plan check: navigation on the run origins only, slots only, an expectation required" {{
    expect(planned(v1(), ["https://acct.example.com"])).toEqual("ok 1");
    expect(planned(v1(), ["https://login.example.com"])).toEqual("step 0 leaves the allowed origins or names no slot");
    expect(planned(v1(), ["https://elsewhere.example"])).toEqual("no origin the recipe and the item share");
    RecipePayload leaky = RecipePayload {{ .domain = "example.com", .version = 1, .password_rules = v1().password_rules,
        .steps = [StepFill("#q", "hunter2"), StepExpect(ExpectText("ok"))], .allowed_origins = ["https://acct.example.com"], .sign_in = [] }};
    expect(planned(leaky, ["https://acct.example.com"])).toEqual("step 0 leaves the allowed origins or names no slot");
    RecipePayload blind = RecipePayload {{ .domain = "example.com", .version = 1, .password_rules = v1().password_rules,
        .steps = [StepFill("#p", "new"), StepClick("#go")], .allowed_origins = ["https://acct.example.com"], .sign_in = [] }};
    expect(planned(blind, ["https://acct.example.com"])).toEqual("a recipe must check its outcome");
    expect(planned(with_sign_in(), ["https://acct.example.com", "https://login.example.com"])).toEqual("ok 2");
    RecipePayload old_in_sign_in = RecipePayload {{ .domain = "example.com", .version = 7, .password_rules = v1().password_rules, .steps = v1().steps,
        .allowed_origins = v1().allowed_origins, .sign_in = [StepFill("#pw", "new"), StepExpect(ExpectElement("#account"))] }};
    expect(planned(old_in_sign_in, ["https://acct.example.com", "https://login.example.com"])).toEqual("step 0 leaves the allowed origins or names no slot");
}}

test "slots go only into fields of their kind, on a run origin" {{
    List(Str) run = ["https://acct.example.com"];
    expect(fill_allowed("new", InputInfo {{ .input_type = "password", .autocomplete = "new-password" }}, "https://acct.example.com", run)).toBeTrue();
    expect(fill_allowed("new", InputInfo {{ .input_type = "text", .autocomplete = "" }}, "https://acct.example.com", run)).toBeFalse();
    expect(fill_allowed("old", InputInfo {{ .input_type = "password", .autocomplete = "" }}, "https://evil.example", run)).toBeFalse();
    expect(fill_allowed("totp", InputInfo {{ .input_type = "text", .autocomplete = "one-time-code" }}, "https://acct.example.com", run)).toBeTrue();
    expect(fill_allowed("totp", InputInfo {{ .input_type = "text", .autocomplete = "" }}, "https://acct.example.com", run)).toBeFalse();
    expect(fill_allowed("username", InputInfo {{ .input_type = "email", .autocomplete = "" }}, "https://acct.example.com", run)).toBeTrue();
    expect(fill_allowed("username", InputInfo {{ .input_type = "password", .autocomplete = "" }}, "https://acct.example.com", run)).toBeFalse();
    expect(fill_allowed("password", InputInfo {{ .input_type = "password", .autocomplete = "current-password" }}, "https://acct.example.com", run)).toBeTrue();
    expect(fill_allowed("password", InputInfo {{ .input_type = "text", .autocomplete = "" }}, "https://acct.example.com", run)).toBeFalse();
}}

test "destructive clicks are refused" {{
    expect(click_allowed("Save changes", "/account/password")).toBeTrue();
    expect(click_allowed("Delete account", "/account")).toBeFalse();
    expect(click_allowed("Save", "/account/remove-2fa")).toBeTrue();
    expect(click_allowed("Disable two-factor", "/x")).toBeFalse();
    expect(click_allowed("OK", "/settings/transfer")).toBeFalse();
}}
'''
open(os.path.join(HERE, '..', 'src', 'recipe', 'recipe_ref_test.resid'), 'w').write(out)

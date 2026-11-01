#!/usr/bin/env bash
# Organizations (SPEC 29) end to end on a loopback Symbolon Home: alice
# founds Acme, bob and carol join and are added; roles (only owners change
# roles and policy, administrators manage people and groups); a group and
# a group folder its members read and write; a tampered membership record
# and a governance chain cut short are refused; the policy against offline
# copies makes devices forget theirs; carol leaves the group, loses the
# folder at once, and alice's org sync re-keys it; the signed audit log
# verifies and shows a tampered event.
set -uo pipefail
cd "$(dirname "$0")/.."
BIN="${BIN:-$PWD/target/symbolon}"
[ -x "$BIN" ] || { echo "build target/symbolon first"; exit 2; }
W="$(mktemp -d)"
cleanup() { pkill -f -- "$W/" 2>/dev/null; [ -n "${KEEP:-}" ] && echo "kept $W" || rm -rf "$W"; }
trap cleanup EXIT
trap "exit 1" INT TERM HUP
run() { ( ulimit -v 40000000; ulimit -s unlimited; timeout "$1" "${@:2}" ); }
fail() { echo "FAIL: $*"; for f in "$W"/*.log; do echo "== $f"; tail -5 "$f"; done; KEEP=1; exit 1; }
wait_port() { for _ in $(seq 150); do (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0; sleep 0.2; done; return 1; }
hx() { printf '%s' "$1" | od -An -tx1 | tr -d ' \n'; }
unhx() { printf '%s' "$1" | xxd -r -p; }
BASE=$(python3 -c 'import random; print(random.randrange(20000, 60000, 10))')
BLOB="$W/box/relay/blob"

python3 - "$W" <<'EOF'
import json, os, sys
k = json.load(open(os.path.expanduser('~/git/larry/resid/tests/crypto/cggmp_oracle/keys6.json')))
for name, i in (('alice.device', 0), ('alice.kit', 1), ('bob.device', 2), ('bob.kit', 3), ('carol.device', 4), ('carol.kit', 5)):
    open(f'{sys.argv[1]}/{name}.primes', 'w').write(f"{k[i]['P']} {k[i]['Q']}\n")
EOF

run 60 "$BIN" home init "$W/box" 127.0.0.1 --ports "$BASE" --bind 127.0.0.1 > "$W/init.log" 2>&1 || fail "home init: $(cat "$W/init.log")"
LA=$(run 60 "$BIN" home invite "$W/box" alice) || fail "invite alice"
LB=$(run 60 "$BIN" home invite "$W/box" bob) || fail "invite bob"
LC=$(run 60 "$BIN" home invite "$W/box" carol) || fail "invite carol"
( setsid "$BIN" home serve "$W/box" > "$W/serve.log" 2>&1 & )
for p in 0 1 2 3 4; do wait_port $((BASE + p)) || fail "port $((BASE + p)) did not open"; done
URL="https://127.0.0.1:$BASE"

# What the app does with a pairing link: setup, pair, inception.
person() {
    local who=$1 link=$2 dpin=${3:-} code
    code=$(sed -n 's/.*[?&]c=\([^&]*\).*/\1/p' <<< "$link")
    curl -sS --cacert "$W/box/tls/ca.pem" "$URL/setup?c=$code" > "$W/$who.setup.json" || fail "setup $who"
    read -r RH RPORT COSK W1 W2 W3 < <(python3 -c '
import json, sys
j = json.load(open(sys.argv[1]))
print(j["relay_host"], j["relay_port"], j["cosigner_keys"], *j["witnesses"])' "$W/$who.setup.json")
    for _ in $(seq 60); do pgrep -f "cosigner serve-for $W/box/people/$who/cos" > /dev/null && break; sleep 1; done
    local dev
    dev=$(printf '2468\n%s\n' "$dpin" | run 120 "$BIN" device new "$W/$who" "$RH" "$RPORT" --unprotected --fast-kdf --ca "$W/box/tls/ca.pem") || fail "device new $who"
    curl -sS --cacert "$W/box/tls/ca.pem" -X POST --data "$dev" "$URL/pair?c=$code" | grep -q '"paired": true' || fail "pair $who"
    printf '2468\n' | run 1800 "$BIN" device init "$W/$who" "$COSK" "$W1" "$W2" "$W3" "$W/$who.device.primes" "$W/$who.kit.primes" > "$W/$who.init.log" 2>&1 || fail "device init $who: $(tail -3 "$W/$who.init.log")"
}
echo "three inceptions against the box (key generation; a few minutes)..."
person alice "$LA"
person bob "$LB"
person carol "$LC"
A="$W/alice"; B="$W/bob"; C="$W/carol"
pin() { printf '2468\n' | run 300 "$BIN" "$@"; }
dpin() { printf '1357\n' | run 300 "$BIN" "$@"; }


ALOG=$(run 60 "$BIN" device share me "$A" | cut -d' ' -f1)
BLOG=$(run 60 "$BIN" device share me "$B" | cut -d' ' -f1)
CLOG=$(run 60 "$BIN" device share me "$C" | cut -d' ' -f1)

# Founding and joining.
read -r ORG FOUNDER < <(pin device org new "$A" Acme) || fail "org new"
[[ "$ORG" =~ ^[0-9a-f]{32}$ ]] && [ "$FOUNDER" = "$ALOG" ] || fail "org new: $ORG $FOUNDER"
pin device org join "$B" "$ORG" "$FOUNDER" > "$W/join.log" 2>&1 || fail "bob joins: $(cat "$W/join.log")"
grep -qx "$ORG $(hx Acme) pending" "$W/join.log" || fail "bob joins: $(cat "$W/join.log")"
pin device org join "$C" "$ORG" "$FOUNDER" > /dev/null 2>&1 || fail "carol joins"
pin device org join "$C" "$ORG" "$BLOG" > "$W/badjoin.log" 2>&1 && fail "joined with the wrong founder"
pin device org add "$A" "$BLOG" Bob bob-ext > "$W/add.log" 2>&1 || fail "add bob: $(cat "$W/add.log")"
pin device org add "$A" "$CLOG" Carol carol-ext > /dev/null 2>&1 || fail "add carol"
run 120 "$BIN" device org show "$B" > "$W/show.log" 2>&1 || fail "show: $(cat "$W/show.log")"
grep -qx "org $ORG $(hx Acme)" "$W/show.log" && grep -qx "role member" "$W/show.log" && grep -q "allow_offline_copy=yes" "$W/show.log" || fail "show: $(cat "$W/show.log")"
run 120 "$BIN" device org members "$C" > "$W/members.log" 2>&1 || fail "members: $(cat "$W/members.log")"
grep -qx "$BLOG $(hx Bob) $(hx bob-ext) member -" "$W/members.log" && grep -q "^$ALOG .* owner -$" "$W/members.log" || fail "members: $(cat "$W/members.log")"
echo "founding: alice founds Acme; bob and carol join, bound to the founder, and are added"

# Roles.
pin device org add "$B" "$CLOG" Carol2 > "$W/badadd.log" 2>&1 && fail "a member added someone"
grep -q "only an owner or administrator" "$W/badadd.log" || fail "member's add: $(cat "$W/badadd.log")"
pin device org role "$A" "$BLOG" admin > /dev/null 2>&1 || fail "make bob admin"
pin device org policy "$B" allow_duress no > "$W/badpol.log" 2>&1 && fail "an administrator changed the policy"
grep -q "only an owner" "$W/badpol.log" || fail "admin's policy: $(cat "$W/badpol.log")"
GID=$(pin device org group new "$B" Engineering | tail -1) || fail "bob makes a group"
pin device org group add "$B" "$GID" "$CLOG" > /dev/null 2>&1 || fail "carol into the group"
run 120 "$BIN" device org groups "$A" | grep -qx "$GID $(hx Engineering) 1" || fail "groups: $(run 120 "$BIN" device org groups "$A")"
echo "roles: members cannot add people; administrators manage people and groups, not policy"

# A group folder.
FID=$(pin device org folder new "$B" Eng-secrets "$GID") || fail "folder new"
pin device share list "$C" > "$W/clist.log" 2>&1 || fail "carol's list: $(cat "$W/clist.log")"
grep -qx "$FID $(hx Eng-secrets) member 3" "$W/clist.log" || fail "carol's list: $(cat "$W/clist.log")"
printf '2468\ntext %s\n' "$(hx 'deploy key')" | run 300 "$BIN" device vault set "$C" Deploy note --share "$FID" > "$W/set.log" 2>&1 || fail "carol writes: $(cat "$W/set.log")"
pin device vault show "$A" Deploy --share "$FID" > "$W/ashow.log" 2>&1 || fail "alice reads: $(cat "$W/ashow.log")"
grep -qx "text $(hx 'deploy key')" "$W/ashow.log" || fail "alice reads: $(cat "$W/ashow.log")"
pin device share add "$C" "$FID" "$ALOG" X > "$W/gadd.log" 2>&1 && fail "someone added a person to a group folder by hand"
echo "group folder: made for Engineering; carol writes, the owner reads; no one adds people by hand"

# What the server could try.
cp "$BLOB/org-$ORG" "$W/org.saved"
python3 - "$BLOB/org-$ORG" <<'PY'
import sys
p = sys.argv[1]; b = open(p, 'rb').read()
open(p, 'wb').write(b.replace(b'Carol', b'Mallo'))
PY
run 120 "$BIN" device org show "$C" > "$W/tamper.log" 2>&1 && fail "a tampered membership record was accepted"
grep -q "signature does not verify" "$W/tamper.log" || fail "tampered record: $(cat "$W/tamper.log")"
cp "$W/org.saved" "$BLOB/org-$ORG"
LASTGOV=$(ls "$BLOB" | grep "^orggov-$ORG-" | sort -t- -k3 -n | tail -1)
mv "$BLOB/$LASTGOV" "$W/gov.saved"
run 120 "$BIN" device org show "$C" > "$W/govback.log" 2>&1 && fail "a governance chain cut short was accepted"
grep -q "went back" "$W/govback.log" || fail "cut chain: $(cat "$W/govback.log")"
mv "$W/gov.saved" "$BLOB/$LASTGOV"
echo "server: a tampered membership record and a governance chain cut short are refused"

# Policy: no copies of group folders on devices.
[ -s "$C/share-$FID.cache" ] || fail "carol has no copy before the policy"
pin device org policy "$A" allow_offline_copy no > /dev/null 2>&1 || fail "policy"
pin device share list "$C" > /dev/null 2>&1 || fail "carol's list after the policy"
[ -s "$C/share-$FID.cache" ] && fail "carol's device kept its copy against the policy"
[ -s "$C/share-$FID.key" ] && fail "carol's device kept the key against the policy"
pin device share duress "$C" "$FID" on > /dev/null 2>&1 && fail "duress choice against the policy"
echo "policy: devices forget their copies of group folders when the policy says so"

# Leaving a group: access goes at once; the next sync re-keys.
pin device org group remove "$A" "$GID" "$CLOG" > /dev/null 2>&1 || fail "carol out of the group"
pin device vault show "$C" Deploy --share "$FID" > "$W/cgone.log" 2>&1 && fail "carol still reads the folder"
grep -q "not in this shared folder" "$W/cgone.log" || fail "carol after leaving the group: $(cat "$W/cgone.log")"
pin device org sync "$A" > "$W/sync.log" 2>&1 || fail "sync: $(cat "$W/sync.log")"
grep -qx "$FID rekeyed 1" "$W/sync.log" || fail "sync: $(cat "$W/sync.log")"
pin device org sync "$A" > "$W/sync2.log" 2>&1 || fail "sync again"
grep -qx "$FID ok" "$W/sync2.log" || fail "second sync: $(cat "$W/sync2.log")"
pin device vault show "$B" Deploy --share "$FID" > "$W/bshow.log" 2>&1 || fail "bob after the re-key: $(cat "$W/bshow.log")"
grep -qx "text $(hx 'deploy key')" "$W/bshow.log" || fail "bob after the re-key: $(cat "$W/bshow.log")"
echo "groups: carol out of Engineering loses the folder at once; alice's sync re-keys it; bob still reads"

# The audit log.
run 120 "$BIN" device org audit "$A" > "$W/audit.log" 2>&1 || fail "audit: $(cat "$W/audit.log")"
grep -q " share $FID " "$W/audit.log" && ! grep -q broken "$W/audit.log" || fail "audit: $(cat "$W/audit.log")"
[ "$(grep -c " ok$" "$W/audit.log")" -ge 8 ] || fail "audit: $(cat "$W/audit.log")"
EV=$(ls "$BLOB" | grep "^audit-$ORG-$ALOG-" | sort | sed -n 2p)
python3 - "$BLOB/$EV" <<'PY'
import sys
p = sys.argv[1]; b = bytearray(open(p, 'rb').read())
b[-1] ^= 1
open(p, 'wb').write(bytes(b))
PY
run 120 "$BIN" device org audit "$A" > "$W/audit2.log" 2>&1 || fail "audit: $(cat "$W/audit2.log")"
grep -q broken "$W/audit2.log" || fail "a tampered event was not shown: $(cat "$W/audit2.log")"
echo "audit: every device's events verify in order; a tampered one shows as broken"

# The relay's access control (SPEC 29.4).
RELAY="https://127.0.0.1:$((BASE + 1))"
code() { curl -s -o /dev/null -w '%{http_code}' --cacert "$W/box/tls/ca.pem" "$@"; }
tok() { cut -d' ' -f1 "$1/relay.token"; }
[ "$(code "$RELAY/blob/org-$ORG")" = 401 ] || fail "the membership record was served to nobody"
[ "$(code -H "Authorization: Bearer $(tok "$B")" "$RELAY/blob/org-$ORG")" = 200 ] || fail "a member could not read the membership record"
[ "$(code -H "Authorization: Bearer $(tok "$C")" "$RELAY/blob/audit-$ORG-$ALOG-000000000001")" = 403 ] || fail "a member read the audit log"
[ "$(code -H "Authorization: Bearer $(tok "$C")" -X PUT --data junk "$RELAY/blob/coll-$FID")" = 403 ] || fail "someone out of the group wrote to its folder"
[ "$(code -H "Authorization: Bearer $(tok "$C")" "$RELAY/blob/wrap-$CLOG-$FID")" = 403 ] || fail "someone out of the group read its folder"
NEXTGOV=$(( $(ls "$BLOB" | grep -c "^orggov-$ORG-") + 1 ))
[ "$(code -H "Authorization: Bearer $(tok "$B")" -X PUT --data-binary @"$BLOB/orggov-$ORG-1" "$RELAY/blob/orggov-$ORG-$NEXTGOV")" = 403 ] || fail "the relay stored a governance record out of order"
[ "$(code -H "Authorization: Bearer $(tok "$B")" -X PUT --data-binary @"$BLOB/org-$ORG" "$RELAY/blob/org-$ORG")" = 403 ] || fail "the relay stored an old membership record again"
[ "$(code -X PUT --data junk "$RELAY/blob/audit-$ORG-$BLOG-000000000099")" = 401 ] || fail "the relay stored an audit event from nobody"
curl -s --cacert "$W/box/tls/ca.pem" "$RELAY/list/org" | grep -q . && fail "the relay listed an organization's records to nobody"
echo "relay: only members read the membership, only administrators the audit log; people out of a group neither read nor write its folder; records out of order are refused"

pin device org remove "$A" "$BLOG" > "$W/rmadmin.log" 2>&1 && fail "an administrator was removed without losing the role"
pin device org remove "$A" "$CLOG" > /dev/null 2>&1 || fail "remove carol"
run 120 "$BIN" device org members "$A" | grep -q "$CLOG" && fail "carol is still a member"
echo "remove: carol leaves the organization; an administrator must lose the role first"

# Invites (SPEC 29.3): carol comes back through the company directory.
read -r ICODE IID < <(pin device org invite "$A" carol@acme.example Carol "$GID") || fail "invite"
[[ "$ICODE" =~ ^[0-9a-f]{32}$ ]] || fail "invite: $ICODE"
pin device org join "$C" "$ORG" "$FOUNDER" 0123456789abcdef0123456789abcdef > "$W/badcode.log" 2>&1 || fail "carol answers with a wrong code: $(cat "$W/badcode.log")"
pin device org sync "$A" > "$W/isync0.log" 2>&1 || fail "sync after a wrong code: $(cat "$W/isync0.log")"
grep -q "^joined" "$W/isync0.log" && fail "a wrong code let carol in"
pin device org join "$C" "$ORG" "$FOUNDER" "$ICODE" > "$W/ijoin.log" 2>&1 || fail "carol answers the invite: $(cat "$W/ijoin.log")"
grep -qx "$ORG $(hx Acme) pending" "$W/ijoin.log" || fail "carol answers the invite: $(cat "$W/ijoin.log")"
pin device org join "$B" "$ORG" "$FOUNDER" "$ICODE" > "$W/ijoin2.log" 2>&1
pin device org sync "$A" > "$W/isync.log" 2>&1 || fail "sync with an answered invite: $(cat "$W/isync.log")"
grep -qx "joined $CLOG $(hx carol@acme.example)" "$W/isync.log" || fail "sync with an answered invite: $(cat "$W/isync.log")"
run 120 "$BIN" device org members "$A" | grep -qx "$CLOG $(hx Carol) $(hx carol@acme.example) member $GID" || fail "carol after the invite: $(run 120 "$BIN" device org members "$A")"
pin device vault show "$C" Deploy --share "$FID" > "$W/cback.log" 2>&1 || fail "carol reads again: $(cat "$W/cback.log")"
grep -qx "text $(hx 'deploy key')" "$W/cback.log" || fail "carol reads again: $(cat "$W/cback.log")"
pin device org join "$C" "$ORG" "$FOUNDER" "$ICODE" > /dev/null 2>&1
[ "$(ls "$BLOB" | grep -c "^invite-$ORG-")" -ge 1 ] && [ ! -s "$BLOB/invite-$ORG-$IID" ] || fail "the used invite was not cleared"
echo "invites: a wrong code does nothing; the right one brings carol back with her directory id and group, once"

# The company directory over SCIM (SPEC 29.7).
STOK=$(run 60 "$BIN" relay scim-token "$W/box/relay" "$ORG") || fail "scim-token"
scim() { curl -sS --cacert "$W/box/tls/ca.pem" -H "Authorization: Bearer $STOK" -H 'Content-Type: application/scim+json' "$@"; }
[ "$(code -H "Authorization: Bearer 000000000000000000000000000000000000000000000000" "$RELAY/scim/v2/Users")" = 401 ] || fail "SCIM without the token"
user() { scim -X POST --data "{\"schemas\":[\"urn:ietf:params:scim:schemas:core:2.0:User\"],\"userName\":\"$1\",\"name\":{\"givenName\":\"$2\",\"familyName\":\"X\"},\"active\":true}" "$RELAY/scim/v2/Users" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])'; }
UB=$(user bob-ext Bob) && UC=$(user carol@acme.example Carol) && UE=$(user erin@acme.example Erin) || fail "SCIM users"
[ "$(code -H "Authorization: Bearer $STOK" -X POST --data '{"userName":"BOB-EXT"}' "$RELAY/scim/v2/Users")" = 409 ] || fail "SCIM took a userName twice"
scim "$RELAY/scim/v2/Users?filter=userName%20eq%20%22erin%40acme.example%22" | grep -q '"totalResults":1' || fail "SCIM filter"
scim -X POST --data "{\"displayName\":\"Engineering\",\"members\":[{\"value\":\"$UC\"}]}" "$RELAY/scim/v2/Groups" > "$W/sg.json" || fail "SCIM group"
SG=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$W/sg.json")
scim -X PATCH --data "{\"Operations\":[{\"op\":\"add\",\"path\":\"members\",\"value\":[{\"value\":\"$UE\"}]}]}" "$RELAY/scim/v2/Groups/$SG" | grep -q "$UE" || fail "SCIM group patch"
pin device org sync "$A" > "$W/dsync.log" 2>&1 || fail "directory sync: $(cat "$W/dsync.log")"
grep -q "^invite $(hx erin@acme.example) [0-9a-f]\{32\} [0-9a-f]\{32\}$" "$W/dsync.log" || fail "directory sync did not invite erin: $(cat "$W/dsync.log")"
grep -q "^removed" "$W/dsync.log" && fail "directory sync removed someone listed: $(cat "$W/dsync.log")"
pin device org sync "$A" > "$W/dsync2.log" 2>&1 || fail "directory sync again"
grep -q "^invite" "$W/dsync2.log" && fail "erin was invited twice: $(cat "$W/dsync2.log")"
scim -X PATCH --data '{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","path":"active","value":"False"}]}' "$RELAY/scim/v2/Users/$UC" | grep -q '"active":false' || fail "SCIM deactivate"
[ "$(code -H "Authorization: Bearer $(tok "$C")" "$RELAY/blob/org-$ORG")" = 401 ] || fail "carol's session still worked after the directory turned her off"
run 120 "$BIN" device org show "$C" > /dev/null 2>&1 && fail "carol still reads the organization"
pin device org sync "$A" > "$W/dsync3.log" 2>&1 || fail "directory sync after deactivation: $(cat "$W/dsync3.log")"
grep -qx "removed $CLOG $(hx carol@acme.example)" "$W/dsync3.log" && grep -qx "$FID rekeyed 1" "$W/dsync3.log" || fail "directory sync after deactivation: $(cat "$W/dsync3.log")"
run 120 "$BIN" device org members "$A" | grep -q "$CLOG" && fail "carol is still a member after the directory turned her off"
echo "directory: SCIM users and groups; sync invites the new person once; turning carol off ends her sessions at once, and the next sync removes her and re-keys"
# Opt-in recovery of work folders (SPEC 29.8).
pin device org recovery on "$A" 2 3600 "$ALOG,$BLOG" > "$W/recon.log" 2>&1 || fail "recovery on: $(cat "$W/recon.log")"
run 120 "$BIN" device org show "$B" | grep -qx "recovery on 2/2 delay 3600" || fail "recovery on: $(run 120 "$BIN" device org show "$B")"
WID=$(pin device share new "$B" Work) || fail "bob's work folder"
printf '2468\ntext %s\n' "$(hx 'q3 plan')" | run 300 "$BIN" device vault set "$B" Plan note --share "$WID" > /dev/null 2>&1 || fail "bob writes his work folder"
pin device org escrow "$B" "$WID" | grep -qx "escrowed $WID 1" || fail "escrow"
pin device org recover request "$A" "$WID" > "$W/req.log" 2>&1 || fail "request: $(cat "$W/req.log")"
run 120 "$BIN" device org show "$B" | grep -q "^recovery-request $WID $ALOG " || fail "bob was not told of the request"
pin device org recover approve "$B" "$WID" > "$W/early.log" 2>&1 && fail "approved before the delay"
grep -q "opens at" "$W/early.log" || fail "early approval: $(cat "$W/early.log")"
pin device org recovery on "$A" 2 0 "$ALOG,$BLOG" > /dev/null 2>&1 || fail "recovery on, no delay"
pin device org recover request "$A" "$WID" > /dev/null 2>&1 || fail "request again"
pin device org recover open "$A" "$WID" > "$W/open0.log" 2>&1 && fail "opened without approvals"
pin device org recover approve "$A" "$WID" > /dev/null 2>&1 || fail "alice approves"
pin device org recover open "$A" "$WID" > "$W/open1.log" 2>&1 && fail "opened with one approval of two"
grep -q "1 of 2" "$W/open1.log" || fail "one approval: $(cat "$W/open1.log")"
pin device org recover approve "$B" "$WID" > /dev/null 2>&1 || fail "bob approves"
pin device org recover open "$A" "$WID" > "$W/open2.log" 2>&1 && fail "opened an escrow made under the old recovery key"
pin device org escrow "$B" "$WID" > /dev/null 2>&1 || fail "escrow again"
pin device org recover open "$A" "$WID" > "$W/open3.log" 2>&1 || fail "open: $(cat "$W/open3.log")"
grep -qx "opened $WID 1" "$W/open3.log" && grep -q "Plan" "$W/open3.log" || fail "open: $(cat "$W/open3.log")"
run 120 "$BIN" device org audit "$A" > "$W/raudit.log" 2>&1; grep -q " recovery $WID " "$W/raudit.log" || fail "recovery not audited"
echo "recovery: an owner turns it on 2 of 2; bob escrows his work folder; he is told of alice's request; nothing opens before the delay or with one approval; two approvals open it"
# Export to a SIEM, item-level events, and how long a copy may be read offline.
run 120 "$BIN" device org export "$A" > "$W/export.jsonl" 2> "$W/export.err" || fail "export: $(cat "$W/export.err")"
python3 - "$W/export.jsonl" <<'PY' || fail "export: $(head -3 "$W/export.jsonl")"
import json, sys
ev = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
assert len(ev) >= 10, len(ev)
assert any(e["action"] == "item" for e in ev), "no item events"
assert any(e["action"] == "recovery" for e in ev), "no recovery events"
assert any(not e["verified"] for e in ev) and sum(e["verified"] for e in ev) >= 10, "verification"
PY
SP=$((BASE + 7))
python3 - "$SP" "$W/siem.body" "$W/siem.auth" <<'PY' &
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        b = self.rfile.read(int(self.headers['Content-Length']))
        open(sys.argv[2], 'wb').write(b); open(sys.argv[3], 'w').write(self.headers.get('Authorization', ''))
        self.send_response(200); self.send_header('Content-Length', '0'); self.end_headers()
    def log_message(self, *a): pass
http.server.HTTPServer(('127.0.0.1', int(sys.argv[1])), H).handle_request()
PY
sleep 1
run 120 "$BIN" device org export "$A" --https "http://127.0.0.1:$SP/ingest" --token hec-123 > /dev/null 2>&1 || fail "export over HTTP(S)"
[ "$(wc -l < "$W/siem.body")" = "$(grep -c . "$W/export.jsonl")" ] && [ "$(cat "$W/siem.auth")" = "Bearer hec-123" ] || fail "the SIEM got: $(head -c 300 "$W/siem.body")"
SY=$((BASE + 8))
python3 - "$SY" "$W/box/tls/server.pem" "$W/box/tls/server.key" "$W/syslog.bin" <<'PY' &
import socket, ssl, sys
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(sys.argv[2], sys.argv[3])
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(('127.0.0.1', int(sys.argv[1]))); s.listen(1)
c, _ = s.accept(); t = ctx.wrap_socket(c, server_side=True); data = b''
while True:
    try: chunk = t.recv(65536)
    except Exception: break
    if not chunk: break
    data += chunk
open(sys.argv[4], 'wb').write(data)
PY
sleep 1
run 120 "$BIN" device org export "$A" --syslog "127.0.0.1:$SY" --ca "$W/box/tls/ca.pem" > "$W/sysexp.log" 2>&1 || fail "export over syslog/TLS: $(cat "$W/sysexp.log")"
sleep 1
python3 - "$W/syslog.bin" "$(grep -c . "$W/export.jsonl")" <<'PY' || fail "syslog frames"
import sys
b = open(sys.argv[1], 'rb').read(); n = 0
while b:
    sp = b.index(b' '); ln = int(b[:sp]); msg = b[sp + 1:sp + 1 + ln]; b = b[sp + 1 + ln:]
    assert msg.startswith(b'<110>1 '), msg[:20]; n += 1
assert n == int(sys.argv[2]), (n, sys.argv[2])
PY
echo "export: verified events as JSON lines, to an HTTP collector and to syslog over TLS; vault changes and recovery steps are among them"

pin device org policy "$A" allow_offline_copy yes > /dev/null 2>&1 && pin device org policy "$A" max_offline_days 1 > /dev/null 2>&1 || fail "policy max_offline_days"
pin device vault show "$B" Deploy --share "$FID" > /dev/null 2>&1 || fail "bob reads online"
cp "$BLOB/coll-$FID" "$W/coll.saved"
python3 -c 'import sys; p=sys.argv[1]; b=bytearray(open(p,"rb").read()); b[len(b)//2]^=1; open(p,"wb").write(b)' "$BLOB/coll-$FID"
pin device vault show "$B" Deploy --share "$FID" > "$W/off1.log" 2>&1 || fail "bob's local copy within the limit: $(cat "$W/off1.log")"
echo 0 > "$B/share-$FID.seen"
pin device vault show "$B" Deploy --share "$FID" > "$W/off2.log" 2>&1 && fail "bob read a copy older than the policy allows"
grep -q "offline for 1 days" "$W/off2.log" || fail "offline limit: $(cat "$W/off2.log")"
cp "$W/coll.saved" "$BLOB/coll-$FID"
echo "policy: a local copy reads offline within max_offline_days, not after"
CP=$((BASE + 9))
( setsid "$BIN" device org console "$A" "$CP" > "$W/console.log" 2>&1 & )
for _ in $(seq 50); do grep -q "^console at" "$W/console.log" && break; sleep 0.2; done
CURL=$(sed -n 's/^console at //p' "$W/console.log")
[ "$(code "http://127.0.0.1:$CP/")" = 403 ] || fail "the console answered without its token"
curl -sS "$CURL" > "$W/console.html" || fail "console"
grep -q "Acme" "$W/console.html" && grep -q "class=ok>verified" "$W/console.html" && grep -q "class=bad>" "$W/console.html" && grep -q "erin\|bob-ext" "$W/console.html" || fail "console page: $(head -c 400 "$W/console.html")"
pkill -f -- "org console $A" 2>/dev/null
echo "console: a read-only page on 127.0.0.1 behind a token: people, policy, and the audit log with each event verified"
echo "PASS org_e2e"

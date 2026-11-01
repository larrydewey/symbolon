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

pin device org remove "$A" "$BLOG" > "$W/rmadmin.log" 2>&1 && fail "an administrator was removed without losing the role"
pin device org remove "$A" "$CLOG" > /dev/null 2>&1 || fail "remove carol"
run 120 "$BIN" device org members "$A" | grep -q "$CLOG" && fail "carol is still a member"
echo "remove: carol leaves the organization; an administrator must lose the role first"
echo "PASS org_e2e"

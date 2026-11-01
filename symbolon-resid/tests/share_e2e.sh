#!/usr/bin/env bash
# Shared folders (SPEC 19) end to end on a loopback Symbolon Home: two
# people, alice and bob, each with their own identity and cosigner on the
# box. They publish cards and find each other (fingerprints match what
# each device says of itself); alice makes a folder, adds bob from his
# verified log, and they both read and write it; bob, not the owner,
# cannot add people; a tampered roster, a replayed older roster and another
# vault's items put in the folder's place are refused; alice removes bob
# (new key, every item sealed again), bob's devices no longer get in, and
# alice still reads everything; alice deletes the folder. Also: items
# moved between a person's own vault and a folder; bob reads a folder he
# chose for his duress PIN under it (and only that one, read only); bob
# leaves a second folder and alice's device takes him out; with the box
# down, alice reads the folder from her device's copy.
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
for name, i in (('alice.device', 0), ('alice.kit', 1), ('bob.device', 2), ('bob.kit', 3)):
    open(f'{sys.argv[1]}/{name}.primes', 'w').write(f"{k[i]['P']} {k[i]['Q']}\n")
EOF

run 60 "$BIN" home init "$W/box" 127.0.0.1 --ports "$BASE" --bind 127.0.0.1 > "$W/init.log" 2>&1 || fail "home init: $(cat "$W/init.log")"
LA=$(run 60 "$BIN" home invite "$W/box" alice) || fail "invite alice"
LB=$(run 60 "$BIN" home invite "$W/box" bob) || fail "invite bob"
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
echo "two inceptions against the box (key generation; a few minutes)..."
person alice "$LA"
person bob "$LB" 1357
A="$W/alice"; B="$W/bob"
pin() { printf '2468\n' | run 300 "$BIN" "$@"; }
dpin() { printf '1357\n' | run 300 "$BIN" "$@"; }

# Cards, and finding each other.
read -r ALOG AFP < <(pin device share card "$A" Alice) || fail "alice card"
read -r BLOG BFP < <(pin device share card "$B" Bob) || fail "bob card"
[ "$(run 60 "$BIN" device share me "$B")" = "$BLOG $BFP" ] || fail "share me: $(run 60 "$BIN" device share me "$B")"
run 120 "$BIN" device share people "$A" > "$W/people.log" 2>&1 || fail "people: $(cat "$W/people.log")"
grep -qx "$BLOG $(hx Bob) $BFP -" "$W/people.log" && grep -qx "$ALOG $(hx Alice) $AFP me" "$W/people.log" || fail "people: $(cat "$W/people.log")"
[[ "$AFP" =~ ^[0-9]{5}(-[0-9]{5}){5}$ ]] || fail "fingerprint $AFP"
# A card someone else signed is not listed.
cp "$BLOB/card-$BLOG" "$W/bobcard"
python3 - "$BLOB/card-$BLOG" <<'EOF'
import sys
p = sys.argv[1]; b = open(p, 'rb').read()
open(p, 'wb').write(b.replace(b'Bob', b'Eve'))
EOF
run 120 "$BIN" device share people "$A" > "$W/people2.log" 2>&1
grep -q "$(hx Eve)" "$W/people2.log" && fail "a card altered at the relay was listed"
cp "$W/bobcard" "$BLOB/card-$BLOG"
echo "cards: people find each other; fingerprints match each device's own; an altered card is not listed"

# A folder.
ID=$(pin device share new "$A" Family) || fail "share new"
[[ "$ID" =~ ^[0-9a-f]{32}$ ]] || fail "share id $ID"
printf '2468\ntext %s\n' "$(hx 'the code is 4711')" | run 300 "$BIN" device vault set "$A" "Garage" note --share "$ID" > "$W/set1.log" 2>&1 || fail "set in folder: $(cat "$W/set1.log")"
pin device share list "$A" > "$W/list1.log" 2>&1 || fail "list: $(cat "$W/list1.log")"
grep -qx "$ID $(hx Family) owner 1" "$W/list1.log" || fail "alice's list: $(cat "$W/list1.log")"
pin device share list "$B" > "$W/list2.log" 2>&1 || fail "bob's list: $(cat "$W/list2.log")"
[ -s "$W/list2.log" ] && fail "bob sees a folder he is not in: $(cat "$W/list2.log")"
pin device vault list "$A" > "$W/own.log" 2>&1
grep -q Garage "$W/own.log" && fail "the folder's item is in alice's own vault"
echo "folder: made, an item in it, not in alice's own vault, bob not in it yet"

pin device share add "$A" "$ID" "$BLOG" Bob > "$W/add.log" 2>&1 || fail "add: $(cat "$W/add.log")"
pin device share list "$B" > "$W/list3.log" 2>&1 || fail "bob's list: $(cat "$W/list3.log")"
grep -qx "$ID $(hx Family) member 2" "$W/list3.log" || fail "bob's list: $(cat "$W/list3.log")"
pin device vault show "$B" Garage --share "$ID" > "$W/show.log" 2>&1 || fail "bob show: $(cat "$W/show.log")"
grep -qx "text $(hx 'the code is 4711')" "$W/show.log" || fail "bob reads: $(cat "$W/show.log")"
printf '2468\norigin %s\nusername %s\ncurrent %s\n' "$(hx https://tv.example)" "$(hx family)" "$(hx s3cret)" | run 300 "$BIN" device vault set "$B" "TV" login --share "$ID" > "$W/set2.log" 2>&1 || fail "bob writes: $(cat "$W/set2.log")"
pin device vault list "$A" --long --share "$ID" > "$W/long.log" 2>&1 || fail "alice list: $(cat "$W/long.log")"
grep -q "^note $(hx Garage) " "$W/long.log" && grep -q "^login $(hx TV) $(hx https://tv.example) " "$W/long.log" || fail "alice's view: $(cat "$W/long.log")"
pin device share members "$B" "$ID" > "$W/members.log" 2>&1 || fail "members: $(cat "$W/members.log")"
grep -qx "$ALOG $(hx Alice) $AFP owner" "$W/members.log" && grep -qx "$BLOG $(hx Bob) $BFP member" "$W/members.log" || fail "members: $(cat "$W/members.log")"
pin device share add "$B" "$ID" "$ALOG" Alice > "$W/badadd.log" 2>&1 && fail "bob, not the owner, added someone"
grep -q "only the folder's owner" "$W/badadd.log" || fail "bob's add: $(cat "$W/badadd.log")"
echo "members: bob added from his verified log; both read and write; members and fingerprints; bob cannot add"

# Moving items: alice's own item into the folder, bob takes it into his own vault.
printf '2468\nsecret %s\n' "$(hx r0uter)" | run 300 "$BIN" device vault set "$A" Router secret > "$W/router.log" 2>&1 || fail "router: $(cat "$W/router.log")"
pin device vault move "$A" Router "$ID" > "$W/move1.log" 2>&1 || fail "move in: $(cat "$W/move1.log")"
pin device vault list "$A" > "$W/own2.log" 2>&1
grep -qx Router "$W/own2.log" && fail "the moved item stayed in alice's vault"
pin device vault show "$B" Router --share "$ID" > "$W/move2.log" 2>&1 || fail "bob reads the moved item: $(cat "$W/move2.log")"
grep -qx "secret $(hx r0uter)" "$W/move2.log" || fail "moved item: $(cat "$W/move2.log")"
pin device vault move "$B" Garage Router --share "$ID" > "$W/move3.log" 2>&1 && fail "moved to a bad destination"
pin device vault move "$B" Router own --share "$ID" > "$W/move4.log" 2>&1 || fail "move out: $(cat "$W/move4.log")"
pin device vault show "$B" Router > "$W/move5.log" 2>&1 || fail "bob's own copy: $(cat "$W/move5.log")"
grep -qx "secret $(hx r0uter)" "$W/move5.log" || fail "bob's own copy: $(cat "$W/move5.log")"
pin device vault show "$A" Router --share "$ID" > "$W/move6.log" 2>&1 && fail "the item stayed in the folder after moving out"
echo "move: own vault to folder and folder to own vault, by owner and member"

# The duress PIN: bob chooses Family for it; a second folder, Work, he does not.
ID2=$(pin device share new "$A" Work) || fail "second folder"
pin device share add "$A" "$ID2" "$BLOG" Bob > "$W/add2.log" 2>&1 || fail "add to Work: $(cat "$W/add2.log")"
pin device share duress "$A" "$ID" on > "$W/nodur.log" 2>&1 && fail "alice, without a duress PIN, marked a folder"
grep -q "no duress PIN" "$W/nodur.log" || fail "alice's mark: $(cat "$W/nodur.log")"
pin device share list "$B" > "$W/blist.log" 2>&1 || fail "bob's list: $(cat "$W/blist.log")"
grep -qx "$ID2 $(hx Work) member 2" "$W/blist.log" || fail "bob's list: $(cat "$W/blist.log")"
pin device share duress "$B" "$ID" on > "$W/mark.log" 2>&1 || fail "bob marks: $(cat "$W/mark.log")"
pin device share list "$B" > "$W/blist2.log" 2>&1 || fail "bob's list: $(cat "$W/blist2.log")"
grep -qx "$ID $(hx Family) member 2 duress" "$W/blist2.log" && grep -qx "$ID2 $(hx Work) member 2" "$W/blist2.log" || fail "bob's marked list: $(cat "$W/blist2.log")"
[ "$(stat -c %s "$B/share-$ID.dkey")" = "$(stat -c %s "$B/share-$ID2.dkey")" ] || fail "the duress files differ in size"
dpin device share list "$B" > "$W/dlist.log" 2>&1 || fail "bob's duress list: $(cat "$W/dlist.log")"
[ "$(cat "$W/dlist.log")" = "$ID $(hx Family) member 2" ] || fail "bob's duress list: $(cat "$W/dlist.log")"
dpin device vault show "$B" Garage --share "$ID" > "$W/dshow.log" 2>&1 || fail "bob reads under duress: $(cat "$W/dshow.log")"
grep -qx "text $(hx 'the code is 4711')" "$W/dshow.log" || fail "under duress: $(cat "$W/dshow.log")"
dpin device vault list "$B" --share "$ID2" > "$W/dwork.log" 2>&1 && fail "bob read Work under duress"
printf '1357\ntext %s\n' "$(hx x)" | run 300 "$BIN" device vault set "$B" Note note --share "$ID" > "$W/dset.log" 2>&1 && fail "bob changed the folder under duress"
grep -q "relay refused" "$W/dset.log" || fail "a change under duress: $(cat "$W/dset.log")"
echo "duress: bob reads the folder he chose under his duress PIN, not the other one, and changes nothing"

# Leaving: bob leaves Work; alice's device takes him out with a new key.
pin device share leave "$A" "$ID" > "$W/ownleave.log" 2>&1 && fail "the owner left"
pin device share leave "$B" "$ID2" > "$W/leave.log" 2>&1 || fail "leave: $(cat "$W/leave.log")"
pin device share list "$B" > "$W/blist3.log" 2>&1 || fail "bob's list: $(cat "$W/blist3.log")"
grep -q "$ID2" "$W/blist3.log" && fail "bob still lists the folder he left: $(cat "$W/blist3.log")"
pin device share list "$A" > "$W/alist.log" 2>&1 || fail "alice's list: $(cat "$W/alist.log")"
grep -qx "$ID2 $(hx Work) owner 1" "$W/alist.log" || fail "alice's device did not take bob out: $(cat "$W/alist.log")"
pin device share members "$A" "$ID2" > "$W/members2.log" 2>&1 || fail "members: $(cat "$W/members2.log")"
grep -q "$BLOG" "$W/members2.log" && fail "bob is still in Work: $(cat "$W/members2.log")"
echo "leave: bob leaves Work; alice's device removes him and gives it a new key"

# What the relay could try.
cp "$BLOB/roster-$ID" "$W/roster.v2"
python3 - "$BLOB/roster-$ID" <<'EOF'
import sys
p = sys.argv[1]; b = open(p, 'rb').read()
open(p, 'wb').write(b.replace(b'Bob', b'Bot'))
EOF
pin device vault list "$B" --share "$ID" > "$W/tamper.log" 2>&1 || fail "bob's copy: $(cat "$W/tamper.log")"
grep -q "local copy: .*signature does not verify" "$W/tamper.log" || fail "tampered roster: $(cat "$W/tamper.log")"
cp "$W/roster.v2" "$BLOB/roster-$ID"
cp "$BLOB/coll-$ID" "$W/coll.saved"
printf '2468\nsecret %s\n' "$(hx x)" | run 300 "$BIN" device vault set "$A" own secret > "$W/ownset.log" 2>&1 || fail "alice's own item: $(cat "$W/ownset.log")"
cp "$BLOB/vault-$ALOG" "$BLOB/coll-$ID" || fail "alice has no vault blob"
pin device vault list "$B" --share "$ID" > "$W/swap.log" 2>&1 || fail "bob's copy: $(cat "$W/swap.log")"
grep -q "local copy: .*another vault" "$W/swap.log" || fail "swapped items: $(cat "$W/swap.log")"
cp "$W/coll.saved" "$BLOB/coll-$ID"
echo "relay: a tampered roster and another vault's items in the folder's place refused (bob reads his own copy, saying why)"

# Removing bob: a new key, every item sealed again.
cp "$BLOB/wrap-$BLOG-$ID" "$W/bobwrap.v2"
pin device share remove "$A" "$ID" "$BLOG" > "$W/remove.log" 2>&1 || fail "remove: $(cat "$W/remove.log")"
pin device share list "$B" > "$W/list4.log" 2>&1
[ -s "$W/list4.log" ] && fail "bob still sees the folder: $(cat "$W/list4.log")"
pin device vault show "$B" Garage --share "$ID" > "$W/gone.log" 2>&1 && fail "bob read the folder after removal"
grep -q "not in this shared folder" "$W/gone.log" || fail "bob after removal: $(cat "$W/gone.log")"
pin device vault show "$A" TV --share "$ID" > "$W/after.log" 2>&1 || fail "alice reads after the key change: $(cat "$W/after.log")"
grep -qx "current $(hx s3cret)" "$W/after.log" || fail "alice's item after the key change: $(cat "$W/after.log")"
# Bob's old wrap and the old roster put back: alice saw the newer roster
# and refuses; bob's old key does not open the items sealed again.
cp "$BLOB/roster-$ID" "$W/roster.v3"
cp "$W/roster.v2" "$BLOB/roster-$ID"
pin device vault list "$A" --share "$ID" > "$W/replay.log" 2>&1 || fail "alice's copy: $(cat "$W/replay.log")"
grep -q "local copy: .*went back" "$W/replay.log" || fail "replay: $(cat "$W/replay.log")"
cp "$W/bobwrap.v2" "$BLOB/wrap-$BLOG-$ID"
pin device vault show "$B" TV --share "$ID" > "$W/oldroster.log" 2>&1 && fail "bob accepted the older roster"
grep -q "went back" "$W/oldroster.log" || fail "bob and the older roster: $(cat "$W/oldroster.log")"
# A device of bob's that never saw version 3 takes the old roster, and
# its old key opens none of the items sealed again.
rm -f "$B/share-$ID.roster"
pin device vault show "$B" TV --share "$ID" > "$W/oldkey.log" 2>&1 && fail "bob's old key opened the items sealed again: $(cat "$W/oldkey.log")"
grep -q "no such item" "$W/oldkey.log" || fail "bob's old key: $(cat "$W/oldkey.log")"
cp "$W/roster.v3" "$BLOB/roster-$ID"
echo "remove: new key; bob no longer gets in, his old key opens nothing new; alice reads all; an older roster refused by both"

# Offline: the box down, alice reads the folder from her device's copy.
pkill -f -- "$W/box" 2>/dev/null; sleep 1
pin device vault show "$A" TV --share "$ID" > "$W/off.log" 2>"$W/off.err" || fail "offline read: $(cat "$W/off.log" "$W/off.err")"
grep -qx "current $(hx s3cret)" "$W/off.log" && grep -q "local copy:" "$W/off.err" || fail "offline read: $(cat "$W/off.log" "$W/off.err")"
pin device share list "$A" > "$W/offlist.log" 2>"$W/offlist.err" || fail "offline list: $(cat "$W/offlist.err")"
grep -qx "$ID $(hx Family) owner 1" "$W/offlist.log" && grep -q "local copy:" "$W/offlist.err" || fail "offline list: $(cat "$W/offlist.log" "$W/offlist.err")"
printf '2468\ntext %s\n' "$(hx x)" | run 300 "$BIN" device vault set "$A" Off note --share "$ID" > "$W/offset.log" 2>&1 && fail "a change offline"
( setsid "$BIN" home serve "$W/box" > "$W/serve2.log" 2>&1 & )
for p in 0 1 2 3 4; do wait_port $((BASE + p)) || fail "port $((BASE + p)) did not open again"; done
for _ in $(seq 60); do pgrep -f "cosigner serve-for $W/box/people/alice/cos" > /dev/null && break; sleep 1; done
echo "offline: alice reads the folder and lists her folders from her device's copy; no change offline"

pin device share delete "$A" "$ID" > "$W/delete.log" 2>&1 || fail "delete: $(cat "$W/delete.log")"
pin device share list "$A" > "$W/list5.log" 2>&1
grep -q "$ID" "$W/list5.log" && fail "alice still lists the deleted folder: $(cat "$W/list5.log")"
echo "delete: the folder is gone"
echo "PASS share_e2e"

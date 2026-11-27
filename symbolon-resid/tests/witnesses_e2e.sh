#!/usr/bin/env bash
# `symbolon device witnesses` end to end on loopback (SPEC 8.2, 20.3): a
# relay, three witnesses and a cosigner as processes, a device (one device,
# so policy[1] is 1) taken through inception; then
#   - a fourth witness is added: in force at once (one added to three does
#     not weaken the policy), and the next event is co-signed by the new set;
#   - a witness whose address or key is wrong is refused before anything is
#     signed (its time, for a fresh nonce, must verify under the key given);
#   - a witness is removed: a weakening, so the set-policy is pending for the
#     recovery delay; running the command again says so; the device vetoes it.
set -uo pipefail
cd "$(dirname "$0")/.."
BIN="${BIN:-$PWD/target/symbolon}"
[ -x "$BIN" ] || { echo "build target/symbolon first"; exit 2; }
W="$(mktemp -d)"
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; pkill -f -- "$W/" 2>/dev/null; [ -n "${KEEP:-}" ] && echo "kept $W" || rm -rf "$W"; }
trap cleanup EXIT
trap "exit 1" INT TERM HUP
run() { ( ulimit -v 40000000; ulimit -s unlimited; timeout "$1" "${@:2}" ); }
runs() { ( ulimit -v 40000000; ulimit -s unlimited; export RESID_MEM_LIMIT=4000; timeout "$1" "${@:2}" ); }
runc() { ( ulimit -v 40000000; ulimit -s unlimited; export RESID_MEM_LIMIT=16000; timeout "$1" "${@:2}" ); }
port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
wait_port() { for _ in $(seq 100); do (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0; sleep 0.1; done; return 1; }
fail() { echo "FAIL: $*"; for f in "$W"/*.log; do echo "== $f"; tail -5 "$f"; done; KEEP=1; exit 1; }

python3 - "$W" <<'EOF'
import json, os, sys
k = json.load(open(os.path.expanduser('~/git/larry/resid/tests/crypto/cggmp_oracle/keys6.json')))
for name, i in (('device', 0), ('kit', 1)):
    open(f'{sys.argv[1]}/{name}.primes', 'w').write(f"{k[i]['P']} {k[i]['Q']}\n")
open(f'{sys.argv[1]}/cosigner.primes', 'w').write(f"{k[2]['P']} {k[2]['Q']}\n{k[4]['P']} {k[4]['Q']}\n")
EOF

RP=$(port)
runs 3600 "$BIN" relay serve "$W/relay" "$RP" --allow-private-witnesses --name "127.0.0.1:$RP" > "$W/relay.log" 2>&1 & PIDS+=($!)
WS=()
for i in 1 2 3 4 5; do
  P=$(port)
  KEY=$(run 30 "$BIN" witness keygen "$W/w$i.key") || fail "witness keygen"
  WS+=("127.0.0.1:$P:$KEY"); WPORT[$i]=$P; WKEY[$i]=$KEY
done
# Witnesses 1 to 4 run; 5 has a key and a port but never runs.
for i in 1 2 3 4; do
  runs 3600 "$BIN" witness serve "$W/w$i" "${WPORT[$i]}" "$W/w$i.key" > "$W/w$i.log" 2>&1 & PIDS+=($!)
  wait_port "${WPORT[$i]}" || fail "witness $i did not start"
done
wait_port "$RP" || fail "relay did not start"

COS=$(run 60 "$BIN" cosigner new "$W/cos" 127.0.0.1 "$RP") || fail "cosigner new"
DEV=$(printf '2468\n1357\n' | run 120 "$BIN" device new "$W/dev" 127.0.0.1 "$RP" --unprotected --fast-kdf) || fail "device new"
run 60 "$BIN" cosigner pair "$W/cos" "$DEV" || fail "cosigner pair"
runc 3600 "$BIN" cosigner serve "$W/cos" "$W/cosigner.primes" > "$W/cosigner.log" 2>&1 & PIDS+=($!)

echo "inception (key generation with three parties; a minute or two)..."
printf '2468\n' | run 1800 "$BIN" device init "$W/dev" "$COS" "${WS[0]}" "${WS[1]}" "${WS[2]}" "$W/device.primes" "$W/kit.primes" > "$W/init.log" 2>&1 || fail "device init"

# Refused before anything is signed: a witness that does not run, one that
# runs under another key, a key already in the policy, too few left, a wrong PIN.
printf '2468\n' | run 300 "$BIN" device witnesses "$W/dev" --add "${WS[4]}" > "$W/dead.log" 2>&1 && fail "a witness that does not answer was added"
grep -q "does not answer" "$W/dead.log" || fail "dead witness: $(cat "$W/dead.log")"
printf '2468\n' | run 300 "$BIN" device witnesses "$W/dev" --add "127.0.0.1:${WPORT[4]}:${WKEY[5]}" > "$W/typo.log" 2>&1 && fail "a witness under the wrong key was added"
grep -q "does not answer" "$W/typo.log" || fail "wrong key: $(cat "$W/typo.log")"
printf '2468\n' | run 300 "$BIN" device witnesses "$W/dev" --add "127.0.0.1:${WPORT[4]}:${WKEY[1]}" > "$W/dup.log" 2>&1 && fail "a key already in the policy was added"
printf '2468\n' | run 300 "$BIN" device witnesses "$W/dev" --remove "127.0.0.1:${WPORT[1]}" > "$W/few.log" 2>&1 && fail "the policy was left with two witnesses"
grep -q "at least three" "$W/few.log" || fail "too few: $(cat "$W/few.log")"
printf '9999\n' | run 300 "$BIN" device witnesses "$W/dev" --add "${WS[3]}" > "$W/pin.log" 2>&1 && fail "a wrong PIN changed the witnesses"
run 120 "$BIN" device status "$W/dev" > "$W/s0.log" 2>&1 || fail "status"
grep -q 'head sequence 0 ' "$W/s0.log" || fail "a refused change reached the log: $(cat "$W/s0.log")"
echo "refused before signing: a witness that does not answer, one under another key, a duplicate key, too few, a wrong PIN"

# A fourth witness: one device is policy[1] here and one added to three does
# not weaken the policy, so it is in force at once.
printf '2468\n' | run 600 "$BIN" device witnesses "$W/dev" --add "${WS[3]}" > "$W/add.log" 2>&1 || fail "add: $(cat "$W/add.log")"
grep -q "witnesses are now" "$W/add.log" || fail "add not in force: $(cat "$W/add.log")"
printf '2468\n' | run 300 "$BIN" device witnesses "$W/dev" --add "${WS[3]}" > "$W/again.log" 2>&1 || fail "add again: $(cat "$W/again.log")"
grep -q "already" "$W/again.log" || fail "add again: $(cat "$W/again.log")"
echo "a fourth witness added, in force at once; the same command again changes nothing"

# The next event needs three of the four: with witness 1 stopped, the other
# three (the new one among them) co-sign it. Removing witness 1 weakens the
# policy: pending for the recovery delay.
kill "$(pgrep -f -- "witness child $W/w1 " | head -1)" 2>/dev/null; pkill -f -- "witness serve $W/w1 " 2>/dev/null
printf '2468\n' | run 600 "$BIN" device witnesses "$W/dev" --remove "127.0.0.1:${WPORT[1]}" > "$W/rm.log" 2>&1 || fail "remove: $(cat "$W/rm.log")"
grep -q "take effect once the recovery delay" "$W/rm.log" || fail "remove not delayed: $(cat "$W/rm.log")"
run 120 "$BIN" device status "$W/dev" > "$W/s2.log" 2>&1 || fail "status"
grep -q 'head sequence 2 .* pending 1' "$W/s2.log" || fail "status after remove: $(cat "$W/s2.log")"
printf '2468\n' | run 300 "$BIN" device witnesses "$W/dev" --remove "127.0.0.1:${WPORT[1]}" > "$W/rm2.log" 2>&1 || fail "remove again: $(cat "$W/rm2.log")"
grep -q "pending already" "$W/rm2.log" || fail "remove again: $(cat "$W/rm2.log")"
echo "removing a witness is delayed (co-signed by the new set without the witness removed); running it again reports it pending"

printf '2468\n' | run 600 "$BIN" device veto "$W/dev" > "$W/veto.log" 2>&1 || fail "veto: $(cat "$W/veto.log")"
run 120 "$BIN" device status "$W/dev" > "$W/s3.log" 2>&1 || fail "status"
grep -q 'head sequence 3 .* pending 0' "$W/s3.log" || fail "status after veto: $(cat "$W/s3.log")"
echo "the device vetoes the removal; the log keeps four witnesses"
echo "PASS"

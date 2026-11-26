#!/usr/bin/env bash
# Protected vault items (SPEC 18.10) end to end on loopback: a relay, three
# witnesses and a cosigner as processes, a device taken through inception,
# which deals the vault OPRF key k_v. An item made protected opens only with
# the cosigner (one evaluation per opening), lists without it, stays
# protected when edited, opens on an enrolled second device (the same y),
# stops at the cosigner's hourly budget, and is refused as an outage during
# a duress window.
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
hx() { printf '%s' "$1" | od -An -tx1 | tr -d ' \n'; }

python3 - "$W" <<'PY'
import json, os, sys
k = json.load(open(os.path.expanduser('~/git/larry/resid/tests/crypto/cggmp_oracle/keys6.json')))
for name, i in (('device', 0), ('kit', 1), ('devrs', 3), ('dev2', 5)):
    open(f'{sys.argv[1]}/{name}.primes', 'w').write(f"{k[i]['P']} {k[i]['Q']}\n")
open(f'{sys.argv[1]}/cosigner.primes', 'w').write(f"{k[2]['P']} {k[2]['Q']}\n{k[4]['P']} {k[4]['Q']}\n")
PY

RP=$(port)
runs 3600 "$BIN" relay serve "$W/relay" "$RP" --allow-private-witnesses --name "127.0.0.1:$RP" > "$W/relay.log" 2>&1 & PIDS+=($!)
WS=()
for i in 1 2 3; do
  P=$(port)
  KEY=$(run 30 "$BIN" witness keygen "$W/w$i.key") || fail "witness keygen"
  runs 3600 "$BIN" witness serve "$W/w$i" "$P" "$W/w$i.key" > "$W/w$i.log" 2>&1 & PIDS+=($!)
  WS+=("127.0.0.1:$P:$KEY")
  wait_port "$P" || fail "witness $i did not start"
done
wait_port "$RP" || fail "relay did not start"

COS=$(run 60 "$BIN" cosigner new "$W/cos" 127.0.0.1 "$RP") || fail "cosigner new"
DEV=$(printf '2468\n1357\n' | run 120 "$BIN" device new "$W/dev" 127.0.0.1 "$RP" --unprotected --fast-kdf) || fail "device new"
run 60 "$BIN" cosigner pair "$W/cos" "$DEV" || fail "cosigner pair"
start_cosigner() { runc 3600 "$BIN" cosigner serve "$W/cos" "$W/cosigner.primes" >> "$W/cosigner.log" 2>&1 & COSPID=$!; PIDS+=($!); }
stop_cosigner() { kill "$COSPID" 2>/dev/null; pkill -f -- "cosigner (serve|child) $W/cos" 2>/dev/null; sleep 1; }
start_cosigner

echo "inception (key generation with three parties; a minute or two)..."
printf '2468\n' | run 1800 "$BIN" device init "$W/dev" "$COS" "${WS[0]}" "${WS[1]}" "${WS[2]}" "$W/device.primes" "$W/kit.primes" > "$W/init.log" 2>&1 || fail "device init"
run 120 "$BIN" device status "$W/dev" > "$W/status.log" 2>&1 || fail "status"
C0=$(sed -n 's/^protected on //p' "$W/status.log")
[ ${#C0} -eq 130 ] || fail "the inception has no vault OPRF key: $(cat "$W/status.log")"
printf '2468\n' | run 300 "$BIN" device protection enable "$W/dev" > "$W/enable.log" 2>&1 || fail "protection enable"
grep -q 'on already' "$W/enable.log" || fail "protection enable: $(cat "$W/enable.log")"

show() { printf '%s\n' "$2" | run 300 "$BIN" device vault show "$1" bank 2>&1; }
current() { show "$1" "$2" | awk '$1 == "current" {print $2}'; }
setbank() { printf '2468\nusername %s\ncurrent %s\norigin %s\n\n' "$(hx ada)" "$(hx "$1")" "$(hx https://bank.example)" | run 300 "$BIN" device vault set "$W/dev" bank login > "$W/set.log" 2>&1; }

setbank 'correct horse' || fail "vault set: $(cat "$W/set.log")"
printf '2468\n' | run 300 "$BIN" device vault protect "$W/dev" bank > "$W/protect.log" 2>&1 || fail "vault protect: $(cat "$W/protect.log")"
printf '2468\n' | run 300 "$BIN" device vault list "$W/dev" --long > "$W/list.log" 2>&1 || fail "list"
grep -qx "login $(hx bank) $(hx https://bank.example) - - protected" "$W/list.log" || fail "list --long: $(cat "$W/list.log")"
[ "$(current "$W/dev" 2468)" = "$(hx 'correct horse')" ] || fail "show: $(show "$W/dev" 2468)"
grep -q 'evaluated 1 protected item element' "$W/cosigner.log" || fail "the cosigner logged no evaluation"
setbank 'battery staple' || fail "edit: $(cat "$W/set.log")"
printf '2468\n' | run 300 "$BIN" device vault list "$W/dev" --long | grep -q ' protected$' || fail "an edit made the item standard"
[ "$(current "$W/dev" 2468)" = "$(hx 'battery staple')" ] || fail "show after the edit"
echo "protected: set, protected, listed, opened and edited (one evaluation each)"

stop_cosigner
printf '2468\n' | run 300 "$BIN" device vault list "$W/dev" > "$W/list2.log" 2>&1 || fail "list without the cosigner: $(cat "$W/list2.log")"
grep -qx bank "$W/list2.log" || fail "list without the cosigner: $(cat "$W/list2.log")"
show "$W/dev" 2468 > "$W/show2.log" && fail "a protected item opened without the cosigner"
grep -q 'needs the cosigner' "$W/show2.log" || fail "show without the cosigner: $(cat "$W/show2.log")"
start_cosigner
echo "protected: lists without the cosigner, does not open without it"

printf '2468\n' | run 300 "$BIN" device vault unprotect "$W/dev" bank > /dev/null 2>&1 || fail "unprotect"
printf '2468\n' | run 300 "$BIN" device vault list "$W/dev" --long | grep -q ' protected$' && fail "still protected"
stop_cosigner
[ "$(current "$W/dev" 2468)" = "$(hx 'battery staple')" ] || fail "an unprotected item does not open without the cosigner"
start_cosigner
printf '2468\n' | run 300 "$BIN" device vault protect "$W/dev" bank > /dev/null 2>&1 || fail "protect again"
echo "protected: unprotected (opens alone), protected again"

DEV2=$(printf '1111\n\n' | run 120 "$BIN" device new "$W/dev2" 127.0.0.1 "$RP" --unprotected --fast-kdf) || fail "device new (second)"
printf '1111\n' | run 1800 "$BIN" device join "$W/dev2" "$DEV" "$W/dev2.primes" > "$W/join.log" 2>&1 & JP=$!
echo "enrollment (re-share with fresh Paillier keys; a minute or two)..."
printf '2468\n' | run 1800 "$BIN" device enroll "$W/dev" "$DEV2" "$W/devrs.primes" > "$W/enroll.log" 2>&1 || fail "enroll"
wait $JP || fail "join"
run 120 "$BIN" device status "$W/dev2" | grep -q "protected on $C0" || fail "the enrollment changed the vault OPRF key"
[ "$(current "$W/dev2" 1111)" = "$(hx 'battery staple')" ] || fail "the enrolled device does not open the protected item: $(show "$W/dev2" 1111)"
[ "$(current "$W/dev" 2468)" = "$(hx 'battery staple')" ] || fail "the first device at epoch 2: $(show "$W/dev" 2468)"
echo "protected: both devices open it after the enrollment (the same k_v)"

# The hourly budget (policy field 3, 60 elements per device): every opening
# above counted; the loop runs until the cosigner refuses.
N=0
while [ $N -lt 70 ]; do
  current "$W/dev" 2468 > "$W/rl.out" 2>&1; [ "$(cat "$W/rl.out")" = "$(hx 'battery staple')" ] || break
  N=$((N + 1))
done
[ $N -lt 70 ] || fail "no hourly limit after 70 more openings"
show "$W/dev" 2468 > "$W/refused.log"
grep -q 'needs the cosigner' "$W/refused.log" || fail "the refusal: $(cat "$W/refused.log")"
[ "$(current "$W/dev2" 1111)" = "$(hx 'battery staple')" ] || fail "the limit is per device: the second device was refused too"
echo "protected: refused after the hourly budget ($N more openings), per device"
printf '1111\n' | run 300 "$BIN" device openings "$W/dev2" > "$W/openings.log" 2>&1 || fail "openings: $(cat "$W/openings.log")"
grep -qx 'limit 60' "$W/openings.log" || fail "openings limit: $(cat "$W/openings.log")"
grep -q "^device $(sed -n 's/^party //p' "$W/status.log") .* hour 60 day 60 week 60 unusual$" "$W/openings.log" || fail "openings of the first device: $(cat "$W/openings.log")"
grep -q " hour 2 day 2 week 2 usual$" "$W/openings.log" || fail "openings of the second device: $(cat "$W/openings.log")"
echo "protected: the openings log counts each device's openings and flags the unusual day"

# Duress (SPEC 14.3, 18.10.4): a signature under the duress PIN opens the
# window; every evaluation is then refused, as an outage.
MSGD=$(python3 -c 'import hashlib; print(hashlib.sha256(b"under duress").hexdigest())')
printf '2468\n' | run 300 "$BIN" device register "$W/dev" login3.example.com --duress > "$W/reg3.log" 2>&1 || fail "register --duress (first device)"
CID3=$(awk '/^credential-id/ {print $2}' "$W/reg3.log")
printf '1357\n' | run 600 "$BIN" device sign "$W/dev" login3.example.com "$CID3" "$MSGD" > "$W/dsign.log" 2>&1 || fail "duress sign: $(tail -2 "$W/dsign.log")"
show "$W/dev2" 1111 > "$W/dshow.log" && fail "a protected item opened during a duress window"
grep -q 'needs the cosigner' "$W/dshow.log" || fail "show during duress: $(cat "$W/dshow.log")"
echo "protected: refused as an outage during a duress window"
echo "PASS protected_e2e"

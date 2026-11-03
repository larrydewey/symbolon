#!/usr/bin/env bash
# A real USB security key end to end (SPEC 9.4), by hand: the stack of
# cli_e2e.sh with an unprotected device, and the FIDO key plugged in
# (reached through Resid's device host, lib/dev/fido.resid). Touch the key
# each time it blinks (four times: two to enroll, one to open the vault,
# one to remove it); a missed touch is retried.
set -uo pipefail
cd "$(dirname "$0")/.."
BIN="${BIN:-$PWD/target/symbolon}"
[ -x "$BIN" ] || { echo "build target/symbolon first"; exit 2; }
fido=0
for rd in /sys/class/hidraw/hidraw*/device/report_descriptor; do [ "$(od -An -tx1 -N3 "$rd" 2>/dev/null | tr -d ' ')" = 06d0f1 ] && fido=1; done
[ "$fido" -eq 1 ] || { echo "SKIP fido_usb: no FIDO key plugged in"; exit 0; }
unset SYMBOLON_FIDO_SOCKET
W="$(mktemp -d)"
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; pkill -f -- "$W/" 2>/dev/null; [ -n "${KEEP:-}" ] && echo "kept $W" || rm -rf "$W"; }
trap cleanup EXIT
trap "exit 1" INT TERM HUP
run() { ( ulimit -v 40000000; ulimit -s unlimited; timeout "$1" "${@:2}" ); }
# Long-running servers: a heap budget, so a leak aborts the server, not the machine.
runs() { ( ulimit -v 40000000; ulimit -s unlimited; export RESID_MEM_LIMIT=4000; timeout "$1" "${@:2}" ); }
# The cosigner: one re-share in one process takes up to ~10 GB (memory is not
# reclaimed within a protocol session).
runc() { ( ulimit -v 40000000; ulimit -s unlimited; export RESID_MEM_LIMIT=16000; timeout "$1" "${@:2}" ); }
# The browser needs more address space than the cap allows: soft cap only,
# which its launcher lifts.
runb() { ( ulimit -S -v 40000000; ulimit -s unlimited; timeout "$1" "${@:2}" ); }
port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
wait_port() { for _ in $(seq 100); do (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0; sleep 0.1; done; return 1; }
fail() { echo "FAIL: $*"; for f in "$W"/*.log; do echo "== $f"; tail -5 "$f"; done; ls -la "$W"/relay/mbox/*/ 2>/dev/null | awk '{print $5}' | sort -n | tail -3 | sed 's/^/largest mailbox message: /'; KEEP=1; exit 1; }

python3 - "$W" <<'EOF'
import json, os, sys
k = json.load(open(os.path.expanduser('~/git/larry/resid/tests/crypto/cggmp_oracle/keys6.json')))
for name, i in (('device', 0), ('kit', 1)):
    open(f'{sys.argv[1]}/{name}.primes', 'w').write(f"{k[i]['P']} {k[i]['Q']}\n")
# The cosigner: line 1 for key generation, line 2 for the re-share.
open(f'{sys.argv[1]}/cosigner.primes', 'w').write(f"{k[2]['P']} {k[2]['Q']}\n{k[4]['P']} {k[4]['Q']}\n")
EOF

RP=$(port)
runs 3600 "$BIN" relay serve "$W/relay" "$RP" > "$W/relay.log" 2>&1 & PIDS+=($!)
WS=()
for i in 1 2 3; do
  P=$(port)
  KEY=$(run 30 "$BIN" witness keygen "$W/w$i.key") || fail "witness keygen"
  runs 3600 "$BIN" witness serve "$W/w$i" "$P" "$W/w$i.key" > "$W/w$i.log" 2>&1 & WPID[$i]=$!; PIDS+=($!)
  WS+=("127.0.0.1:$P:$KEY"); WPORT[$i]=$P
  wait_port "$P" || fail "witness $i did not start"
done
wait_port "$RP" || fail "relay did not start"

COS=$(run 60 "$BIN" cosigner new "$W/cos" 127.0.0.1 "$RP") || fail "cosigner new"
DEV=$(printf '2468\n1357\n' | run 120 "$BIN" device new "$W/dev" 127.0.0.1 "$RP" --unprotected --fast-kdf) || fail "device new"
run 60 "$BIN" cosigner pair "$W/cos" "$DEV" || fail "cosigner pair"
runc 3600 "$BIN" cosigner serve "$W/cos" "$W/cosigner.primes" > "$W/cosigner.log" 2>&1 & PIDS+=($!)
echo "inception (key generation with three parties; a minute or two)..."
printf '2468\n' | run 1800 "$BIN" device init "$W/dev" "$COS" "${WS[0]}" "${WS[1]}" "${WS[2]}" "$W/device.primes" "$W/kit.primes" > "$W/init.log" 2>&1 || fail "device init"


tries() { local n=0; while [ $n -lt 3 ]; do "$@" && return 0; n=$((n + 1)); echo "  (no touch? trying again)"; done; return 1; }
put() { printf '2468\n%s\n' "$2" | run 300 "$BIN" device vault put "$W/dev" "$1" > "$W/put.log" 2>&1; }
put before secret-0 || fail "vault put: $(cat "$W/put.log")"
add() { printf '2468\n' | run 300 "$BIN" device key add "$W/dev" yubikey > "$W/add.log" 2>&1; }
echo ">>> touch the key twice as it blinks (enrolling)"
tries add || fail "key add: $(cat "$W/add.log")"
cat "$W/add.log"
[ -s "$W/dev/blob_a.k" ] && [ ! -s "$W/dev/blob_a" ] || fail "the profiles were not sealed"
get() { printf '2468\n' | run 300 "$BIN" device vault get "$W/dev" before > "$W/got" 2> "$W/get.err" && [ "$(cat "$W/got")" = secret-0 ]; }
echo ">>> touch the key once (opening the vault)"
tries get || fail "vault get with the key: $(cat "$W/get.err")"
echo "opened the vault with the key: $(cat "$W/got")"
printf '1111\n' | run 300 "$BIN" device vault get "$W/dev" before > /dev/null 2>&1 && fail "a wrong PIN opened it" || true
rm1() { printf '2468\n' | run 300 "$BIN" device key remove "$W/dev" yubikey > "$W/rm.log" 2>&1; }
echo ">>> touch the key once more (removing it; if it blinked for the wrong PIN above, touch then too)"
tries rm1 || fail "key remove: $(cat "$W/rm.log")"
cat "$W/rm.log"
printf '2468\n' | run 300 "$BIN" device vault get "$W/dev" before > "$W/got" 2>&1 && [ "$(cat "$W/got")" = secret-0 ] || fail "PIN alone after removal"
echo "PASS fido_usb"

#!/usr/bin/env bash
# Security keys as a second factor end to end (SPEC 9.4): the stack of
# cli_e2e.sh with an unprotected device, and a CTAP2 authenticator written
# from the specification (tests/fido/authenticator.py) holding two keys,
# reached through SYMBOLON_FIDO_SOCKET:
#   a key is added (two touches); the profiles are then sealed under W and
#   the device opens only with an enrolled key present;
#   a backup key is added, the first removed, and the backup alone opens it;
#   refused: a key that does not hold the credential, no touch, a wrong
#   assertion signature, a wrong PIN with the key present;
#   removing the last key returns the device to the PIN alone.
set -uo pipefail
cd "$(dirname "$0")/.."
BIN="${BIN:-$PWD/target/symbolon}"
[ -x "$BIN" ] || { echo "build target/symbolon first"; exit 2; }
python3 -I -c "import fido2, cryptography" 2>/dev/null || { echo "SKIP fido_e2e: python-fido2 or cryptography missing"; exit 0; }
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


# --- the authenticator --------------------------------------------------
mkdir -m 700 "$W/fido"
echo main > "$W/fido/present"; echo main > "$W/fido/target"; echo ok > "$W/fido/mode"
export SYMBOLON_FIDO_SOCKET="$W/fido/ctap.sock"
python3 -I tests/fido/authenticator.py "$SYMBOLON_FIDO_SOCKET" "$W/fido" > "$W/fido.log" 2>&1 & PIDS+=($!)
for _ in $(seq 50); do [ -S "$SYMBOLON_FIDO_SOCKET" ] && break; sleep 0.1; done
present() { printf '%s\n' "$@" > "$W/fido/present"; }
put() { printf '2468\n%s\n' "$2" | run 300 "$BIN" device vault put "$W/dev" "$1" > "$W/put.log" 2>&1; }
get() { printf '2468\n' | run 300 "$BIN" device vault get "$W/dev" "$1" 2> "$W/get.err"; }

put before secret-0 || fail "vault put before any key: $(cat "$W/put.log")"
printf '2468\n' | run 300 "$BIN" device key add "$W/dev" main > "$W/add.log" 2>&1 || fail "key add: $(cat "$W/add.log") $(tail -3 "$W/fido/log")"
[ "$(run 30 "$BIN" device key list "$W/dev")" = "$(printf main | xxd -p)" ] || fail "key list"
[ -s "$W/dev/blob_a.k" ] && [ -s "$W/dev/blob_b.k" ] && [ ! -s "$W/dev/blob_a" ] && [ ! -s "$W/dev/blob_b" ] || fail "the profiles were not sealed under W"
[ "$(get before)" = secret-0 ] || fail "vault get with the key: $(cat "$W/get.err")"
put after secret-1 || fail "vault put with the key: $(cat "$W/put.log")"
grep -c assert "$W/fido/log" > /dev/null || fail "the key was not asked"
echo "added: the profiles are sealed under W; the vault opens with the key touched"

present other
get before > /dev/null && fail "opened with a key that does not hold the credential"
grep -q "none of the enrolled security keys is present" "$W/get.err" || fail "other key: $(cat "$W/get.err")"
present
get before > /dev/null && fail "opened with no key"
grep -q "no security key answers" "$W/get.err" || fail "no key: $(cat "$W/get.err")"
present main; echo deny > "$W/fido/mode"
get before > /dev/null && fail "opened without a touch"
grep -q "operation denied" "$W/get.err" || fail "deny: $(cat "$W/get.err")"
echo badsig > "$W/fido/mode"
get before > /dev/null && fail "opened with a wrong assertion signature"
grep -q "signature does not verify" "$W/get.err" || fail "badsig: $(cat "$W/get.err")"
echo ok > "$W/fido/mode"
printf '1111\n' | run 300 "$BIN" device vault get "$W/dev" before > /dev/null 2>&1 && fail "opened with a wrong PIN and the key"
echo "refused: another key, no key, no touch, a wrong signature, a wrong PIN"

present main backup; echo backup > "$W/fido/target"
printf '2468\n' | run 300 "$BIN" device key add "$W/dev" backup > "$W/add2.log" 2>&1 || fail "add backup: $(cat "$W/add2.log")"
printf '2468\n' | run 300 "$BIN" device key remove "$W/dev" main > "$W/rm.log" 2>&1 || fail "remove main: $(cat "$W/rm.log")"
present backup
[ "$(get after)" = secret-1 ] || fail "the backup key alone: $(cat "$W/get.err")"
present main
get after > /dev/null && fail "the removed key still opens it"
echo "a backup key added and the first removed: only the backup opens it"

present backup
printf '2468\n' | run 300 "$BIN" device key remove "$W/dev" backup > "$W/rm2.log" 2>&1 || fail "remove the last key: $(cat "$W/rm2.log")"
[ -s "$W/dev/blob_a" ] && [ ! -s "$W/dev/blob_a.k" ] || fail "the profiles were not returned to the PIN alone"
present
[ "$(get after)" = secret-1 ] || fail "PIN alone after removing every key: $(cat "$W/get.err")"
echo "the last key removed: the PIN alone opens the device again"
echo "PASS fido_e2e"

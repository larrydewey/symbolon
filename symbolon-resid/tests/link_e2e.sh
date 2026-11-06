#!/usr/bin/env bash
# Adding a device by QR code end to end (SPEC 11.5): the stack of
# cli_e2e.sh over TLS, an identity on a first device, then a second device
# that runs `device link-new` (it prints the code) while the first runs
# `device link-add` with that code. The second device learns the relay and
# its CA from the first, makes itself, and joins: the identity re-shares to
# four parties and the second device reads the first one's vault.
# Refused: a connection without the code's key (the new device keeps
# waiting), a link-add with another code's key, and a wrong PIN on the
# existing device, which stops before the new one acts. A first attempt cut
# short is retried, using the device it made.
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
# Long-running servers: a heap budget, so a leak aborts the server, not the machine.
runs() { ( ulimit -v 40000000; ulimit -s unlimited; export RESID_MEM_LIMIT=4000; timeout "$1" "${@:2}" ); }
# The cosigner: one re-share in one process takes up to ~10 GB (memory is not
# reclaimed within a protocol session).
runc() { ( ulimit -v 40000000; ulimit -s unlimited; export RESID_MEM_LIMIT=16000; timeout "$1" "${@:2}" ); }
port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
wait_port() { for _ in $(seq 100); do (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0; sleep 0.1; done; return 1; }
fail() { echo "FAIL: $*"; for f in "$W"/*.log; do echo "== $f"; tail -5 "$f"; done; ls -la "$W"/relay/mbox/*/ 2>/dev/null | awk '{print $5}' | sort -n | tail -3 | sed 's/^/largest mailbox message: /'; KEEP=1; exit 1; }

python3 - "$W" <<'EOF'
import json, os, sys
k = json.load(open(os.path.expanduser('~/git/larry/resid/tests/crypto/cggmp_oracle/keys6.json')))
for name, i in (('device', 0), ('kit', 1), ('devrs', 3), ('dev2', 5)):
    open(f'{sys.argv[1]}/{name}.primes', 'w').write(f"{k[i]['P']} {k[i]['Q']}\n")
# The cosigner: line 1 for key generation, line 2 for the re-share.
open(f'{sys.argv[1]}/cosigner.primes', 'w').write(f"{k[2]['P']} {k[2]['Q']}\n{k[4]['P']} {k[4]['Q']}\n")
EOF

# TLS=1: the relay and the witnesses serve HTTPS with a certificate for
# 127.0.0.1 from a test CA; the device and the cosigner trust that CA.
SERVE_TLS=(); CA=()
if true; then   # always TLS: the link carries the relay's CA to the new device
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=symbolon-test-ca \
    -keyout "$W/ca.key" -out "$W/ca.pem" >/dev/null 2>&1 || fail "test CA"
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=127.0.0.1 -keyout "$W/srv.key" -out "$W/srv.csr" >/dev/null 2>&1 || fail "server key"
  printf 'subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n' > "$W/srv.ext"
  openssl x509 -req -in "$W/srv.csr" -CA "$W/ca.pem" -CAkey "$W/ca.key" -CAcreateserial -days 2 -extfile "$W/srv.ext" -out "$W/srv.pem" >/dev/null 2>&1 || fail "server cert"
  cat "$W/srv.pem" "$W/ca.pem" > "$W/chain.pem"
  SERVE_TLS=(--tls "$W/chain.pem" "$W/srv.key"); CA=(--ca "$W/ca.pem")
fi

RP=$(port)
runs 3600 "$BIN" relay serve "$W/relay" "$RP" "${SERVE_TLS[@]}" ${RELAY_STORE:+--store "$RELAY_STORE"} > "$W/relay.log" 2>&1 & PIDS+=($!)
WS=()
for i in 1 2 3; do
  P=$(port)
  KEY=$(run 30 "$BIN" witness keygen "$W/w$i.key") || fail "witness keygen"
  runs 3600 "$BIN" witness serve "$W/w$i" "$P" "$W/w$i.key" "${SERVE_TLS[@]}" > "$W/w$i.log" 2>&1 & WPID[$i]=$!; PIDS+=($!)
  WS+=("127.0.0.1:$P:$KEY"); WPORT[$i]=$P
  wait_port "$P" || fail "witness $i did not start"
done
wait_port "$RP" || fail "relay did not start"

COS=$(run 60 "$BIN" cosigner new "$W/cos" 127.0.0.1 "$RP" "${CA[@]}") || fail "cosigner new"
DEV=$(printf '2468\n1357\n' | run 120 "$BIN" device new "$W/dev" 127.0.0.1 "$RP" --unprotected --fast-kdf "${CA[@]}") || fail "device new"
run 60 "$BIN" cosigner pair "$W/cos" "$DEV" || fail "cosigner pair"
runc 3600 "$BIN" cosigner serve "$W/cos" "$W/cosigner.primes" > "$W/cosigner.log" 2>&1 & PIDS+=($!)

echo "inception (key generation with three parties; a minute or two)..."
printf '2468\n' | run 1800 "$BIN" device init "$W/dev" "$COS" "${WS[0]}" "${WS[1]}" "${WS[2]}" "$W/device.primes" "$W/kit.primes" > "$W/init.log" 2>&1 || fail "device init"
grep -q '^log ' "$W/init.log" || fail "no log id printed"
printf '2468\nshared-secret-1\n' | run 300 "$BIN" device vault put "$W/dev" mail > "$W/put.log" 2>&1 || fail "vault put: $(cat "$W/put.log")"

# The new device shows its code.
printf '1111\n\n' | run 1800 "$BIN" device link-new "$W/dev2" --host 127.0.0.1 --unprotected --fast-kdf --primes "$W/dev2.primes" > "$W/linknew.log" 2>&1 & LN=$!
for _ in $(seq 100); do grep -q '^link ' "$W/linknew.log" && break; sleep 0.1; done
LINK=$(sed -n 's/^link //p' "$W/linknew.log")
case "$LINK" in symbolon://link\?a=127.0.0.1\&p=*\&s=*) ;; *) fail "no code printed: $(cat "$W/linknew.log")" ;; esac
LPORT=$(printf '%s' "$LINK" | sed 's/.*&p=\([0-9]*\)&.*/\1/')
echo "the new device shows: $LINK"

# Someone else on the network connects first with an offer under another key.
python3 -I - "$LPORT" <<'PY' || fail "the stranger could not connect"
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
s.sendall(b"SYMBOLON-LINK 1\nrelay 10.6.6.6 1\nca -\nkeys aabb\nmac " + b"00" * 32 + b"\nend\n")
s.settimeout(15); print(repr(s.recv(100)))
PY
# A link-add with the right address but another code's key.
BAD=$(printf '%s' "$LINK" | sed 's/&s=.*/\&s=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/')
printf '2468\n' | run 300 "$BIN" device link-add "$W/dev" "$BAD" > "$W/badadd.log" 2>&1 && fail "link-add with another code's key succeeded"
grep -q "did not answer with this code's key" "$W/badadd.log" || fail "bad key: $(cat "$W/badadd.log")"
# A wrong PIN on the existing device stops before anything is sent.
printf '9999\n' | run 300 "$BIN" device link-add "$W/dev" "$LINK" > "$W/badpin.log" 2>&1 && fail "link-add with a wrong PIN succeeded"
grep -q "wrong PIN" "$W/badpin.log" || fail "wrong PIN: $(cat "$W/badpin.log")"
[ "$(grep -c 'without this code' "$W/linknew.log")" -ge 2 ] || fail "the new device did not refuse the strangers: $(cat "$W/linknew.log")"
kill -0 $LN 2>/dev/null || fail "the new device stopped waiting: $(cat "$W/linknew.log")"
echo "refused: a stranger's offer, another code's key, a wrong PIN; the new device kept waiting"

# A first attempt cut short: the old device stops right after sending its
# offer; the new one makes itself, answers, and waits to join until it too
# is stopped. A retry must use that device again, with its PIN.
printf '2468\n' | run 300 "$BIN" device link-add "$W/dev" "$LINK" > "$W/cut.log" 2>&1 &
for _ in $(seq 300); do grep -q "waiting for the new device" "$W/cut.log" && break; sleep 0.1; done
pkill -f -- "[l]ink-add $W/dev " ; sleep 0.5
for _ in $(seq 300); do grep -q "joining the identity" "$W/linknew.log" && break; sleep 0.1; done
grep -q "joining the identity" "$W/linknew.log" || fail "the first attempt did not get as far as joining: $(cat "$W/linknew.log")"
pkill -f -- "[l]ink-new $W/dev2 " ; wait $LN 2>/dev/null
[ -s "$W/dev2/config.cbor" ] || fail "the first attempt left no device"
printf '2222\n\n' | run 120 "$BIN" device link-new "$W/dev2" --host 127.0.0.1 --unprotected --fast-kdf > "$W/retrypin.log" 2>&1 && fail "a retry with another PIN started"
grep -q "made by an earlier try: use the PIN chosen then" "$W/retrypin.log" || fail "retry with another PIN: $(cat "$W/retrypin.log")"
printf '1111\n\n' | run 1800 "$BIN" device link-new "$W/dev2" --host 127.0.0.1 --unprotected --fast-kdf --primes "$W/dev2.primes" > "$W/linknew.log" 2>&1 & LN=$!
for _ in $(seq 100); do grep -q '^link ' "$W/linknew.log" && break; sleep 0.1; done
LINK=$(sed -n 's/^link //p' "$W/linknew.log")
[ -n "$LINK" ] || fail "no code on the retry: $(cat "$W/linknew.log")"
echo "a first attempt cut short after the new device made itself; the retry shows a new code (another PIN refused)"

echo "linking (re-share with fresh Paillier keys; a few minutes)..."
printf '2468\n' | run 1800 "$BIN" device link-add "$W/dev" "$LINK" --primes "$W/devrs.primes" > "$W/linkadd.log" 2>&1 || fail "link-add: $(tail -5 "$W/linkadd.log")"
wait $LN || fail "link-new: $(tail -5 "$W/linknew.log")"
grep -q "using this device, made by an earlier try, against 127.0.0.1:$RP" "$W/linknew.log" || fail "the retry did not use the device the first attempt made: $(cat "$W/linknew.log")"
grep -q "BEGIN CERTIFICATE" "$W/dev2/config.cbor" 2>/dev/null || python3 -I -c "import sys; sys.exit(0 if b'BEGIN CERTIFICATE' in open(sys.argv[1],'rb').read() else 1)" "$W/dev2/config.cbor" || fail "the new device did not take the relay's CA"
run 120 "$BIN" device status "$W/dev2" > "$W/status2.log" 2>&1 || fail "status (second): $(cat "$W/status2.log")"
grep -q 'epoch 2 parties 4 threshold 2' "$W/status2.log" || fail "status after linking: $(cat "$W/status2.log")"
[ "$(printf '1111\n' | run 300 "$BIN" device vault get "$W/dev2" mail 2>&1)" = shared-secret-1 ] || fail "the new device cannot read the vault"
echo "linked: the new device took the relay and its CA from the code's exchange, joined (epoch 2, 4 parties) and reads the vault"
echo "PASS link_e2e"

#!/usr/bin/env bash
# Where a vault operation's time goes over a slow link (by hand, not part of
# run.sh): the stack of cli_e2e.sh over TLS with the relay and each witness
# behind tests/perf/latency_proxy.py, a device with one item, then
# `device vault get` timed with no added delay and with DELAY_MS each way
# (default 40: an 80 ms round trip, a VPN's), counting the connections it
# opens.
set -uo pipefail
cd "$(dirname "$0")/../.."
BIN="${BIN:-$PWD/target/symbolon}"
D="${DELAY_MS:-40}"
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
for name, i in (('device', 0), ('kit', 1), ('devrs', 3), ('dev2', 5), ('dev3', 3)):
    open(f'{sys.argv[1]}/{name}.primes', 'w').write(f"{k[i]['P']} {k[i]['Q']}\n")
# The cosigner: line 1 for key generation, line 2 for the re-share.
open(f'{sys.argv[1]}/cosigner.primes', 'w').write(f"{k[2]['P']} {k[2]['Q']}\n{k[4]['P']} {k[4]['Q']}\n")
EOF

# TLS=1: the relay and the witnesses serve HTTPS with a certificate for
# 127.0.0.1 from a test CA; the device and the cosigner trust that CA.
SERVE_TLS=(); CA=()
if true; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=symbolon-test-ca \
    -keyout "$W/ca.key" -out "$W/ca.pem" >/dev/null 2>&1 || fail "test CA"
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=127.0.0.1 -keyout "$W/srv.key" -out "$W/srv.csr" >/dev/null 2>&1 || fail "server key"
  printf 'subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n' > "$W/srv.ext"
  openssl x509 -req -in "$W/srv.csr" -CA "$W/ca.pem" -CAkey "$W/ca.key" -CAcreateserial -days 2 -extfile "$W/srv.ext" -out "$W/srv.pem" >/dev/null 2>&1 || fail "server cert"
  cat "$W/srv.pem" "$W/ca.pem" > "$W/chain.pem"
  SERVE_TLS=(--tls "$W/chain.pem" "$W/srv.key"); CA=(--ca "$W/ca.pem")
fi

echo 0 > "$W/delay"
proxy() { python3 -I tests/perf/latency_proxy.py "$1" "$2" "$W/delay" "$W/count.$1" > /dev/null 2>&1 & PIDS+=($!); }
RPX=$(port); RP=$(port)
runs 3600 "$BIN" relay serve "$W/relay" "$RP" "${SERVE_TLS[@]}" > "$W/relay.log" 2>&1 & PIDS+=($!)
proxy "$RPX" "$RP"
WS=()
for i in 1 2 3; do
  P=$(port); PX=$(port)
  KEY=$(run 30 "$BIN" witness keygen "$W/w$i.key") || fail "witness keygen"
  runs 3600 "$BIN" witness serve "$W/w$i" "$P" "$W/w$i.key" "${SERVE_TLS[@]}" > "$W/w$i.log" 2>&1 & PIDS+=($!)
  proxy "$PX" "$P"
  WS+=("127.0.0.1:$PX:$KEY")
  wait_port "$P" || fail "witness $i did not start"
done
wait_port "$RP" || fail "relay did not start"; sleep 0.5
COS=$(run 60 "$BIN" cosigner new "$W/cos" 127.0.0.1 "$RP" "${CA[@]}") || fail "cosigner new"
DEV=$(printf '2468\n1357\n' | run 120 "$BIN" device new "$W/dev" 127.0.0.1 "$RPX" --unprotected --fast-kdf "${CA[@]}") || fail "device new"
run 60 "$BIN" cosigner pair "$W/cos" "$DEV" || fail "cosigner pair"
runc 3600 "$BIN" cosigner serve "$W/cos" "$W/cosigner.primes" > "$W/cosigner.log" 2>&1 & PIDS+=($!)
echo "inception..."
printf '2468\n' | run 1800 "$BIN" device init "$W/dev" "$COS" "${WS[0]}" "${WS[1]}" "${WS[2]}" "$W/device.primes" "$W/kit.primes" > "$W/init.log" 2>&1 || fail "device init"
printf '2468\nhunter2\n' | run 300 "$BIN" device vault put "$W/dev" mail > /dev/null 2>&1 || fail "put"
total() { for f in "$W"/count.*; do cat "$f"; echo; done | awk "{s += \$1} END {print s + 0}"; }
measure() {
  echo "$1" > "$W/delay"
  for k in 1 2 3; do
    c0=$(total); t0=$(date +%s.%N)
    out=$(printf '2468\n' | run 300 "$BIN" device vault get "$W/dev" mail 2>&1)
    t1=$(date +%s.%N); c1=$(total)
    [ "$out" = hunter2 ] || fail "vault get: $out"
    printf '  delay %3s ms each way: %5.2f s, %s connections\n' "$1" "$(echo "$t1 - $t0" | bc)" "$((c1 - c0))"
  done
}
echo "vault get:"
measure 0
measure "$D"

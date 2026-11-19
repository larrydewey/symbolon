#!/usr/bin/env bash
# The breach check end to end (SPEC 26.1): relay, witnesses, cosigner and an
# unprotected device through inception as in cli_e2e.sh; three logins in the
# vault; `device vault breach` against a stand-in for Pwned Passwords
# (tests/breach/range.py, HTTPS under a CA made here) that holds two of the
# three passwords and pads its answers. Checked: the breached logins are
# named with their counts, the clean one is not, only five hex digits of
# each SHA-1 reached the service, one query per distinct prefix, padding was
# asked for; an untrusted certificate fails the check instead of passing it.
# RESID_DIR: the Resid checkout (default ~/git/larry/resid), for its test keys.
set -uo pipefail
cd "$(dirname "$0")/.."
BIN="${BIN:-$PWD/target/symbolon}"
[ -x "$BIN" ] || { echo "build target/symbolon first"; exit 2; }
command -v openssl >/dev/null || { echo "SKIP breach_e2e: no openssl"; exit 0; }
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

RESID_DIR="${RESID_DIR:-$HOME/git/larry/resid}"
python3 - "$W" "$RESID_DIR" <<'EOF'
import json, os, sys
k = json.load(open(os.path.join(sys.argv[2], 'tests/crypto/cggmp_oracle/keys6.json')))
for name, i in (('device', 0), ('kit', 1)):
    open(f'{sys.argv[1]}/{name}.primes', 'w').write(f"{k[i]['P']} {k[i]['Q']}\n")
open(f'{sys.argv[1]}/cosigner.primes', 'w').write(f"{k[2]['P']} {k[2]['Q']}\n{k[4]['P']} {k[4]['Q']}\n")
EOF

RP=$(port)
runs 3600 "$BIN" relay serve "$W/relay" "$RP" > "$W/relay.log" 2>&1 & PIDS+=($!)
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
runc 3600 "$BIN" cosigner serve "$W/cos" "$W/cosigner.primes" > "$W/cosigner.log" 2>&1 & PIDS+=($!)
echo "inception (key generation with three parties; a minute or two)..."
printf '2468\n' | run 1800 "$BIN" device init "$W/dev" "$COS" "${WS[0]}" "${WS[1]}" "${WS[2]}" "$W/device.primes" "$W/kit.primes" > "$W/init.log" 2>&1 || fail "device init"

login() { printf '2468\n%s\n' "$3" | run 300 "$BIN" device vault login "$W/dev" "$1" "$2" ada > "$W/login-$1.log" 2>&1 || fail "vault login $1: $(cat "$W/login-$1.log")"; }
login mail https://mail.example password
login bank https://bank.example 'Tr0ub4dor&3'
login shop https://shop.example 'kX9!vR2#qL7@wN4$'

# A CA, and a certificate for 127.0.0.1 under it; another CA nobody uses.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=breach-test-ca -keyout "$W/ca.key" -out "$W/ca.pem" 2>/dev/null || fail "ca"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=other-ca -keyout "$W/other.key" -out "$W/other.pem" 2>/dev/null || fail "other ca"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=127.0.0.1 -keyout "$W/srv.key" -out "$W/srv.csr" 2>/dev/null || fail "csr"
printf 'subjectAltName=IP:127.0.0.1\n' > "$W/san.ext"
openssl x509 -req -in "$W/srv.csr" -CA "$W/ca.pem" -CAkey "$W/ca.key" -CAcreateserial -days 2 -extfile "$W/san.ext" -out "$W/srv.pem" 2>/dev/null || fail "certificate"

BP=$(port)
python3 -I tests/breach/range.py "$BP" "$W/srv.pem" "$W/srv.key" "$W/queries.log" password 'Tr0ub4dor&3' > "$W/range.log" 2>&1 & PIDS+=($!)
wait_port "$BP" || fail "range service did not start"

breach() { printf '2468\n' | SYMBOLON_BREACH_URL="https://127.0.0.1:$BP" SYMBOLON_BREACH_CA="$1" run 300 "$BIN" device vault breach "$W/dev"; }
OUT=$(breach "$W/ca.pem" 2>&1) || fail "breach: $OUT"
hexname() { printf '%s' "$1" | od -An -tx1 | tr -d ' \n'; }
echo "$OUT" | grep -qx "breached $(hexname mail) 9659365" || fail "mail not reported: $OUT"
echo "$OUT" | grep -qx "breached $(hexname bank) 4242" || fail "bank not reported: $OUT"
echo "$OUT" | grep -q "breached $(hexname shop)" && fail "a clean password reported: $OUT"
echo "$OUT" | grep -qx "checked 3 breached 2" || fail "tally: $OUT"
echo "two breached logins named with their counts; the clean one not"

[ "$(grep -c . "$W/queries.log")" = 3 ] || fail "expected three queries: $(cat "$W/queries.log")"
grep -qvE '^/range/[0-9A-F]{5} padding$' "$W/queries.log" && fail "a query sent more than a padded 5-digit prefix: $(cat "$W/queries.log")"
echo "each query carried five hex digits and asked for padding"

OUT=$(breach "$W/other.pem" 2>&1) && fail "an untrusted certificate passed: $OUT"
echo "$OUT" | grep -q "breach check" || fail "untrusted: $OUT"
echo "an untrusted service fails the check"
echo "PASS breach_e2e"

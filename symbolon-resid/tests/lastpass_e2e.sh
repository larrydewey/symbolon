#!/usr/bin/env bash
# Moving in from LastPass by signing in (src/agent/lpsignin.resid,
# experimental), end to end against tests/lp_mock.py: a stand-in for
# LastPass's servers built from lastpass-cli's protocol (there is no
# LastPass account to test against), over TLS under a test CA. Alice's
# vault has CBC, ECB and GCM fields, a custom field, typed secure notes (a
# card, a bank account), a plain note, a deleted account and a shared
# folder whose key is RSA-OAEP to her private key; Bob signs in with a
# Google Authenticator code, Carol by approving on her phone. Weak key derivation and a wrong password are
# refused.
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
fail() { echo "FAIL: $*"; for f in "$W"/*.log; do echo "== $f"; tail -8 "$f"; done; KEEP=1; exit 1; }
hx() { printf '%s' "$1" | od -An -tx1 | tr -d ' \n'; }

# ── The stand-in LastPass over TLS ─────────────────────────────────────
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$W/ca.key" -out "$W/ca.pem" -days 1 -subj "/CN=lastpass_e2e CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null || fail "openssl CA"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$W/srv.key" -out "$W/srv.csr" -subj "/CN=localhost" 2>/dev/null
printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n" > "$W/ext"
openssl x509 -req -in "$W/srv.csr" -CA "$W/ca.pem" -CAkey "$W/ca.key" -CAcreateserial -out "$W/srv.pem" -days 1 -extfile "$W/ext" 2>/dev/null || fail "openssl cert"
LP=$(port)
python3 tests/lp_mock.py "$LP" "$W/srv.pem" "$W/srv.key" "$W/state.json" > "$W/mock.log" 2>&1 & PIDS+=($!)
wait_port "$LP" || fail "the mock did not start"
export SYMBOLON_CA="$W/ca.pem" SYMBOLON_LASTPASS_URL="https://localhost:$LP"
python3 - "$W/state.json" "$W/want.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
w = {"alice": {"email": "alice@example.com", "password": s["alice@example.com"]["pw"]},
     "bob": {"email": "bob@example.com", "password": s["bob@example.com"]["pw"], "totp": s["bob@example.com"]["otp"]},
     "carol": {"email": "carol@example.com", "password": s["carol@example.com"]["pw"]},
     "weak": {"email": "weak@example.com", "password": "weak"},
     "wrong": {"email": "alice@example.com", "password": "not her password"}}
json.dump(w, open(sys.argv[2], "w"))
PY

# ── A device on a loopback quorum ──────────────────────────────────────
python3 - "$W" <<'PY'
import json, os, sys
k = json.load(open(os.path.expanduser('~/git/larry/resid/tests/crypto/cggmp_oracle/keys6.json')))
for name, i in (('device', 0), ('kit', 1)):
    open(f'{sys.argv[1]}/{name}.primes', 'w').write(f"{k[i]['P']} {k[i]['Q']}\n")
open(f'{sys.argv[1]}/cosigner.primes', 'w').write(f"{k[2]['P']} {k[2]['Q']}\n{k[4]['P']} {k[4]['Q']}\n")
PY
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
runc 3600 "$BIN" cosigner serve "$W/cos" "$W/cosigner.primes" >> "$W/cosigner.log" 2>&1 & PIDS+=($!)
echo "inception (a minute or two)..."
printf '2468\n' | run 1800 "$BIN" device init "$W/dev" "$COS" "${WS[0]}" "${WS[1]}" "${WS[2]}" "$W/device.primes" "$W/kit.primes" > "$W/init.log" 2>&1 || fail "device init"

conv() { run 900 python3 tests/bw_converse.py "$W/want.json" "$1" "$2" -- "$BIN" device vault signin-lastpass "$W/dev" "${@:3}"; }

# ── Alice: preview ─────────────────────────────────────────────────────
conv alice - --dry-run > "$W/alice-dry.log" 2>&1 || fail "alice dry run: $(cat "$W/alice-dry.log")"
grep -q '^item login bank Finance/Banks$' "$W/alice-dry.log" || fail "bank (CBC, a nested folder): $(cat "$W/alice-dry.log")"
grep -q '^item login mail -$' "$W/alice-dry.log" || fail "mail (ECB)"
grep -q '^item login news -$' "$W/alice-dry.log" || fail "news (GCM)"
grep -q '^item card travel card Cards$' "$W/alice-dry.log" || fail "the typed card note"
grep -q '^item bank bank details -$' "$W/alice-dry.log" || fail "the typed bank note"
grep -q '^item note plain note -$' "$W/alice-dry.log" || fail "the plain note"
grep -q '^item login family streaming Family$' "$W/alice-dry.log" || fail "the shared folder's item"
grep -q ' old login ' "$W/alice-dry.log" && fail "a deleted account came across"
grep -q '^total 7$' "$W/alice-dry.log" || fail "alice: want 7 items: $(grep total "$W/alice-dry.log")"
echo "alice: preview of 7 items (CBC, ECB, GCM; typed notes; a shared folder; the deleted one left behind)"

# ── Alice: import ──────────────────────────────────────────────────────
conv alice 2468 > "$W/alice.log" 2>&1 || fail "alice import: $(cat "$W/alice.log")"
show() { printf '2468\n' | run 300 "$BIN" device vault show "$W/dev" "$1" 2>&1; }
field() { show "$1" | awk -v f="$2" '$1 == f {print $2}'; }
[ "$(field bank current)" = "$(hx s3cret-bank)" ] || fail "bank's password: $(show bank)"
[ "$(field bank username)" = "$(hx alice)" ] || fail "bank's username"
show bank | grep -q "$(hx birthday)" || fail "bank's custom field"
[ "$(field mail current)" = "$(hx m4il-pass)" ] || fail "an ECB field: $(show mail)"
[ "$(field news current)" = "$(hx n3ws-pass)" ] || fail "a GCM field: $(show news)"
[ "$(field 'travel card' number)" = "$(hx 4111111111111111)" ] || fail "the card's number: $(show 'travel card')"
[ "$(field 'travel card' expiry)" = "$(hx 04/30)" ] || fail "the card's expiry: $(show 'travel card')"
[ "$(field 'travel card' cvv)" = "$(hx 123)" ] || fail "the card's code"
[ "$(field 'travel card' notes)" = "$(hx 'the travel card
keep it safe')" ] || fail "the card's notes run to the end: $(show 'travel card')"
[ "$(field 'bank details' account_number)" = "$(hx 987654321)" ] || fail "the bank note: $(show 'bank details')"
[ "$(field 'family streaming' current)" = "$(hx str3am)" ] || fail "the shared folder's item: $(show 'family streaming')"
echo "alice: imported; the values open as the stand-in wrote them"

# ── Bob: a Google Authenticator code ──────────────────────────────────
conv bob - --dry-run > "$W/bob.log" 2>&1 || fail "bob: $(cat "$W/bob.log")"
grep -q '^need code google$' "$W/bob.log" || fail "bob was not asked for a code: $(cat "$W/bob.log")"
grep -q '^item login router -$' "$W/bob.log" || fail "bob's item: $(cat "$W/bob.log")"
echo "bob: a two-step code"
conv carol - --dry-run > "$W/carol.log" 2>&1 || fail "carol: $(cat "$W/carol.log")"
grep -q '^wait push ' "$W/carol.log" || fail "carol was not told to approve on her phone: $(cat "$W/carol.log")"
grep -q '^item login printer -$' "$W/carol.log" || fail "carol's item: $(cat "$W/carol.log")"
echo "carol: approved on her phone (polled)"

# ── Refusals ───────────────────────────────────────────────────────────
conv weak - --dry-run > "$W/weak.log" 2>&1 && fail "weak key derivation was accepted"
grep -q "^fail the account's key derivation is weak" "$W/weak.log" || fail "weak: $(cat "$W/weak.log")"
conv wrong - --dry-run > "$W/wrong.log" 2>&1 && fail "a wrong password signed in"
grep -q '^fail the email or master password is wrong' "$W/wrong.log" || fail "wrong password: $(cat "$W/wrong.log")"
echo "refused: weak key derivation; a wrong password"
echo "PASS lastpass_e2e"

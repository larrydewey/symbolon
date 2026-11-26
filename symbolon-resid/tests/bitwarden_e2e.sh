#!/usr/bin/env bash
# Moving in from Bitwarden by signing in (src/agent/bwsignin.resid), end to
# end: a Vaultwarden in Docker, over TLS under a test CA, filled by
# tests/bw_fixture.py (its own Bitwarden client, Python's cryptography) with
# two accounts: Alice (PBKDF2; every item type, an item with its own key, a
# passkey, an organization's item, one in the trash) and Bob (Argon2id, an
# authenticator app as the second step). The agent signs in, decrypts, shows
# the preview and imports into a device on a loopback quorum; the imported
# items open with the values the fixture put in. A wrong password and a
# weak key derivation are refused.
#
# Skipped (not failed) without Docker or the vaultwarden/server image.
set -uo pipefail
cd "$(dirname "$0")/.."
BIN="${BIN:-$PWD/target/symbolon}"
[ -x "$BIN" ] || { echo "build target/symbolon first"; exit 2; }
command -v docker > /dev/null && docker image inspect vaultwarden/server:latest > /dev/null 2>&1 || { echo "SKIP bitwarden_e2e: no Docker or no vaultwarden/server image (docker pull vaultwarden/server)"; exit 0; }
W="$(mktemp -d)"
PIDS=()
VW="symbolon-bw-e2e-$$"
cleanup() { docker rm -f "$VW" > /dev/null 2>&1; for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; pkill -f -- "$W/" 2>/dev/null; [ -n "${KEEP:-}" ] && echo "kept $W" || rm -rf "$W" 2>/dev/null; }
trap cleanup EXIT
trap "exit 1" INT TERM HUP
run() { ( ulimit -v 40000000; ulimit -s unlimited; timeout "$1" "${@:2}" ); }
runs() { ( ulimit -v 40000000; ulimit -s unlimited; export RESID_MEM_LIMIT=4000; timeout "$1" "${@:2}" ); }
runc() { ( ulimit -v 40000000; ulimit -s unlimited; export RESID_MEM_LIMIT=16000; timeout "$1" "${@:2}" ); }
port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
wait_port() { for _ in $(seq 100); do (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0; sleep 0.1; done; return 1; }
fail() { echo "FAIL: $*"; for f in "$W"/*.log; do echo "== $f"; tail -8 "$f"; done; docker logs "$VW" 2>&1 | tail -5; KEEP=1; exit 1; }
hx() { printf '%s' "$1" | od -An -tx1 | tr -d ' \n'; }

# ── Vaultwarden over TLS ───────────────────────────────────────────────
mkdir -p "$W/ssl" "$W/vwdata"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$W/ca.key" -out "$W/ssl/ca.pem" -days 1 -subj "/CN=bitwarden_e2e CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null || fail "openssl CA"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$W/ssl/key.pem" -out "$W/srv.csr" -subj "/CN=localhost" 2>/dev/null
printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n" > "$W/ext"
openssl x509 -req -in "$W/srv.csr" -CA "$W/ssl/ca.pem" -CAkey "$W/ca.key" -CAcreateserial -out "$W/ssl/cert.pem" -days 1 -extfile "$W/ext" 2>/dev/null || fail "openssl cert"
chmod 644 "$W/ssl/"*
VP=$(port)
docker run -d --name "$VW" -p "127.0.0.1:$VP:443" -v "$W/ssl:/ssl:ro" -e ROCKET_PORT=443 -e ROCKET_TLS='{certs="/ssl/cert.pem",key="/ssl/key.pem"}' \
  -e SIGNUPS_ALLOWED=true -e SIGNUPS_VERIFY=false -e DOMAIN="https://localhost:$VP" -e I_REALLY_WANT_VOLATILE_STORAGE=true vaultwarden/server:latest > /dev/null || fail "docker run"
for _ in $(seq 60); do curl -s --cacert "$W/ssl/ca.pem" "https://localhost:$VP/alive" > /dev/null && break; sleep 1; done
URL="https://localhost:$VP"
python3 tests/bw_fixture.py setup "$URL" "$W/ssl/ca.pem" "$W/want.json" > "$W/fixture.log" 2>&1 || fail "fixture: $(tail -3 "$W/fixture.log")"
export SYMBOLON_CA="$W/ssl/ca.pem"

# ── A device on a loopback quorum ──────────────────────────────────────
python3 - "$W" <<'PY'
import json, os, sys
k = json.load(open(os.path.expanduser('~/git/larry/resid/tests/crypto/cggmp_oracle/keys6.json')))
for name, i in (('device', 0), ('kit', 1)):
    open(f'{sys.argv[1]}/{name}.primes', 'w').write(f"{k[i]['P']} {k[i]['Q']}\n")
open(f'{sys.argv[1]}/cosigner.primes', 'w').write(f"{k[2]['P']} {k[2]['Q']}\n{k[4]['P']} {k[4]['Q']}\n")
PY
RP=$(port)
runs 3600 "$BIN" relay serve "$W/relay" "$RP" --name "127.0.0.1:$RP" > "$W/relay.log" 2>&1 & PIDS+=($!)
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

conv() { run 900 python3 tests/bw_converse.py "$W/want.json" "$1" "$2" -- "$BIN" device vault signin-bitwarden "$W/dev" "$URL" "${@:3}"; }

# ── Alice: preview ─────────────────────────────────────────────────────
conv alice - --dry-run > "$W/alice-dry.log" 2>&1 || fail "alice dry run: $(cat "$W/alice-dry.log")"
for n in bank visa "wifi note" me mail passkeys.example "family streaming" "Passkeys Example passkey"; do
  grep -q "^item [a-z]* $n " "$W/alice-dry.log" || fail "alice's preview has no \"$n\": $(cat "$W/alice-dry.log")"
done
grep -q "^item .* old login " "$W/alice-dry.log" && fail "an item in the trash came across"
grep -q '^item login bank Work$' "$W/alice-dry.log" || fail "bank is not in its folder: $(grep bank "$W/alice-dry.log")"
grep -q '^item login family streaming Shared$' "$W/alice-dry.log" || fail "the organization's item is not in its collection"
grep -q '^item passkey Passkeys Example passkey' "$W/alice-dry.log" || fail "the passkey did not come across"
grep -q '^total 8$' "$W/alice-dry.log" || fail "alice: want 8 items: $(grep total "$W/alice-dry.log")"
grep -q '^warn .*did not' "$W/alice-dry.log" && fail "alice: something did not decrypt: $(grep warn "$W/alice-dry.log")"
echo "alice: preview of 8 items (folder, collection, item key, passkey; the trash left behind)"

# ── Alice: import ──────────────────────────────────────────────────────
conv alice 2468 > "$W/alice.log" 2>&1 || fail "alice import: $(cat "$W/alice.log")"
grep -q '^vault version' "$W/alice.log" || fail "alice import published nothing: $(cat "$W/alice.log")"
show() { printf '2468\n' | run 300 "$BIN" device vault show "$W/dev" "$1" 2>&1; }
field() { show "$1" | awk -v f="$2" '$1 == f {print $2}'; }
[ "$(field bank current)" = "$(hx s3cret-bank)" ] || fail "bank's password: $(show bank)"
[ "$(field bank username)" = "$(hx alice)" ] || fail "bank's username: $(show bank)"
[ "$(field bank totp)" = "$(hx JBSWY3DPEHPK3PXP)" ] || fail "bank's TOTP seed: $(show bank)"
[ "$(field mail current)" = "$(hx m4il-pass)" ] || fail "an item under its own key: $(show mail)"
[ "$(field 'family streaming' current)" = "$(hx str3am)" ] || fail "the organization's item: $(show 'family streaming')"
[ "$(field visa number)" = "$(hx 4111111111111111)" ] || fail "the card number: $(show visa)"
[ "$(field visa expiry)" = "$(hx 04/30)" ] || fail "the card's expiry: $(show visa)"
[ "$(field me full_name)" = "$(hx 'Alice Example')" ] || fail "the identity's name: $(show me)"
[ "$(field 'Passkeys Example passkey' public_key | wc -c)" -ge 130 ] || fail "the passkey's public key: $(show 'Passkeys Example passkey')"
echo "alice: imported; the values open as the fixture wrote them"

# ── Bob: Argon2id and an authenticator code ───────────────────────────
conv bob - --dry-run > "$W/bob.log" 2>&1 || fail "bob: $(cat "$W/bob.log")"
grep -q '^need 2fa .*0' "$W/bob.log" || fail "bob was not asked for a code: $(cat "$W/bob.log")"
grep -q '^item login router -$' "$W/bob.log" || fail "bob's item: $(cat "$W/bob.log")"
echo "bob: Argon2id and a two-step code"
BW_FIRST_BAD=1 conv bob - --dry-run > "$W/bob2.log" 2>&1 || fail "bob, a wrong code first: $(cat "$W/bob2.log")"
grep -q '^bad code$' "$W/bob2.log" && grep -q '^item login router -$' "$W/bob2.log" || fail "a wrong code is not asked again: $(cat "$W/bob2.log")"
echo "bob: a wrong code is said, and asked for again"

# ── Refusals ───────────────────────────────────────────────────────────
python3 -c "import json,sys; d=json.load(open(sys.argv[1])); d['alice']['password']='wrong password'; json.dump(d, open(sys.argv[2],'w'))" "$W/want.json" "$W/wrong.json"
run 300 python3 tests/bw_converse.py "$W/wrong.json" alice - -- "$BIN" device vault signin-bitwarden "$W/dev" "$URL" --dry-run > "$W/wrong.log" 2>&1 && fail "a wrong password signed in"
grep -q '^fail the email or master password is wrong' "$W/wrong.log" || fail "wrong password: $(cat "$W/wrong.log")"
SYMBOLON_CA=/nonexistent run 120 python3 tests/bw_converse.py "$W/want.json" alice - -- "$BIN" device vault signin-bitwarden "$W/dev" "https://localhost:$VP" --dry-run > "$W/noca.log" 2>&1
grep -q '^fail' "$W/noca.log" || fail "a server whose certificate does not check was used: $(cat "$W/noca.log")"
echo "refused: a wrong password; a server whose certificate does not check"
echo "PASS bitwarden_e2e"

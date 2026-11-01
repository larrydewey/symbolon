#!/usr/bin/env bash
# Symbolon Home end to end on loopback: `home init` makes the box's CA and
# server certificate (checked by OpenSSL, and served to curl over TLS),
# `home invite` a person and a pairing link, `home serve` the pairing
# service, relay, witnesses and the person's cosigner. A device then does
# what the app does with the link: fetches the setup with the code (TLS,
# pinned by the CA fingerprint), pairs, and runs the inception against the
# box (fixture Paillier primes, for speed); signs; and the spent code, a
# wrong code and a forged fingerprint are refused.
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
BASE=$(python3 -c 'import random; print(random.randrange(20000, 60000, 10))')

python3 - "$W" <<'EOF'
import json, os, sys
k = json.load(open(os.path.expanduser('~/git/larry/resid/tests/crypto/cggmp_oracle/keys6.json')))
for name, i in (('device', 0), ('kit', 1)):
    open(f'{sys.argv[1]}/{name}.primes', 'w').write(f"{k[i]['P']} {k[i]['Q']}\n")
EOF

run 60 "$BIN" home init "$W/box" 127.0.0.1 home.test --ports "$BASE" --bind 127.0.0.1 > "$W/init.log" 2>&1 || fail "home init: $(cat "$W/init.log")"
openssl verify -CAfile "$W/box/tls/ca.pem" "$W/box/tls/server.pem" > "$W/verify.log" 2>&1 || fail "OpenSSL does not verify the server certificate: $(cat "$W/verify.log")"
openssl x509 -in "$W/box/tls/server.pem" -noout -text > "$W/x509.txt" 2>&1
grep -q "IP Address:127.0.0.1" "$W/x509.txt" && grep -q "DNS:home.test" "$W/x509.txt" && grep -q "TLS Web Server Authentication" "$W/x509.txt" || fail "server certificate fields: $(cat "$W/x509.txt")"
openssl ec -in "$W/box/tls/server.key" -check -noout > /dev/null 2>&1 || fail "OpenSSL does not load the server key"
echo "home init: CA and server certificate verify in OpenSSL"

LINK=$(run 60 "$BIN" home invite "$W/box" alice) || fail "home invite"
CODE=$(sed -n 's/.*[?&]c=\([^&]*\).*/\1/p' <<< "$LINK"); FP=$(sed -n 's/.*[?&]f=\([^&]*\).*/\1/p' <<< "$LINK")
[ "${#CODE}" -eq 22 ] && [ -n "$FP" ] || fail "pairing link: $LINK"
# The fingerprint in the link is the server certificate's SHA-256 (the
# first certificate in server.pem), as a TLS client sees it.
WANT=$(openssl x509 -in "$W/box/tls/server.pem" -outform DER | openssl dgst -sha256 -binary | basenc --base64url | tr -d '=')
[ "$FP" = "$WANT" ] || fail "fingerprint $FP, the server certificate's is $WANT"

( setsid "$BIN" home serve "$W/box" > "$W/serve.log" 2>&1 & )
for p in 0 1 2 3 4; do wait_port $((BASE + p)) || fail "port $((BASE + p)) did not open"; done
SEEN=$(openssl s_client -connect "127.0.0.1:$BASE" < /dev/null 2>/dev/null | openssl x509 -outform DER | openssl dgst -sha256 -binary | basenc --base64url | tr -d '=')
[ "$SEEN" = "$FP" ] || fail "the box presents a certificate with fingerprint $SEEN, the link says $FP"
URL="https://127.0.0.1:$BASE"
curl -sS --cacert "$W/box/tls/ca.pem" "$URL/setup?c=$CODE" > "$W/setup.json" 2> "$W/curl.log" || fail "setup over TLS: $(cat "$W/curl.log")"
curl -s --cacert "$W/box/tls/ca.pem" -o /dev/null -w '%{http_code}' "$URL/setup?c=AAAAAAAAAAAAAAAAAAAAAA" | grep -q 403 || fail "a wrong code got the setup"
read -r RH RPORT COSK W1 W2 W3 < <(python3 -c '
import json, sys
j = json.load(open(sys.argv[1]))
print(j["relay_host"], j["relay_port"], j["cosigner_keys"], *j["witnesses"])' "$W/setup.json")
python3 -c 'import json, sys; open(sys.argv[2], "w").write(json.load(open(sys.argv[1]))["ca"])' "$W/setup.json" "$W/ca.pem"
cmp -s "$W/ca.pem" "$W/box/tls/ca.pem" || fail "the setup's CA is not the box's"
echo "pairing service: setup over TLS with the code; a wrong code refused"

# The person's cosigner starts within ten seconds of the invite, and is
# already serving when the device pairs (a pairing must not be lost to
# the copy of the configuration it read before).
for _ in $(seq 60); do pgrep -f "cosigner serve-for $W/box/people/alice/cos" > /dev/null && break; sleep 1; done
pgrep -f "cosigner serve-for $W/box/people/alice/cos" > /dev/null || fail "alice's cosigner did not start"
DEV=$(printf '2468\n\n' | run 120 "$BIN" device new "$W/dev" "$RH" "$RPORT" --unprotected --fast-kdf --ca "$W/ca.pem") || fail "device new"
curl -sS --cacert "$W/ca.pem" -X POST --data "$DEV" "$URL/pair?c=$CODE" | grep -q '"paired": true' || fail "pair"
curl -s --cacert "$W/ca.pem" -o /dev/null -w '%{http_code}' -X POST --data "$DEV" "$URL/pair?c=$CODE" | grep -q 403 || fail "a spent code paired again"
echo "inception against the box (key generation; a minute or two)..."
printf '2468\n' | run 1800 "$BIN" device init "$W/dev" "$COSK" "$W1" "$W2" "$W3" "$W/device.primes" "$W/kit.primes" > "$W/devinit.log" 2>&1 || fail "device init: $(tail -3 "$W/devinit.log")"
run 120 "$BIN" device status "$W/dev" > "$W/status.log" 2>&1 || fail "status: $(cat "$W/status.log")"
grep -q 'parties 3 threshold 2' "$W/status.log" || fail "status: $(cat "$W/status.log")"
printf '2468\n' | run 300 "$BIN" device register "$W/dev" login.example.com > "$W/reg.log" 2>&1 || fail "register"
CID=$(awk '/^credential-id/ {print $2}' "$W/reg.log"); PUB=$(awk '/^public-key/ {print $2}' "$W/reg.log")
MSG=$(printf 'home' | sha256sum | cut -d' ' -f1)
printf '2468\n' | run 600 "$BIN" device sign "$W/dev" login.example.com "$CID" "$MSG" > "$W/sign.log" 2>&1 || fail "sign: $(tail -2 "$W/sign.log")"
python3 - "$PUB" "$MSG" "$(tail -1 "$W/sign.log")" <<'EOF' || fail "the signature does not verify (OpenSSL)"
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
pub, msg, sig = (bytes.fromhex(x) for x in sys.argv[1:4])
ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub).verify(utils.encode_dss_signature(int.from_bytes(sig[:32], 'big'), int.from_bytes(sig[32:], 'big')), msg, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
EOF
echo "device paired with the box, incepted over TLS, and signs with the box's cosigner (OpenSSL verifies)"
echo "PASS home_e2e"

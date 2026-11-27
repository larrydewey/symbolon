#!/usr/bin/env bash
# Symbolon Home end to end on this machine: `home init` makes the box's CA
# and server certificate (checked by OpenSSL, and served to curl over TLS)
# and its one witness, with two witnesses outside the box (on this
# machine's other address, with certificates `home witness-cert` makes),
# and seals the keys to a passphrase; `home invite` a person and a pairing
# link, `home serve` unseals the keys into memory and runs the pairing
# service, relay, the box's witness and the person's cosigner. A device then
# does what the app does with the link: fetches the setup with the code
# (TLS, pinned by the server certificate's fingerprint), pairs with the
# setup's token, and runs the inception against the box (fixture Paillier
# primes, for speed); signs; and the spent code, a second setup, a wrong
# code, a pairing without the token, a wrong passphrase and a box whose
# witnesses would be a majority are refused. No key file on the box's disk
# holds a key in the clear.
set -uo pipefail
cd "$(dirname "$0")/.."
BIN="${BIN:-$PWD/target/symbolon}"
[ -x "$BIN" ] || { echo "build target/symbolon first"; exit 2; }
# The witnesses outside the box listen on this machine's own address (not
# loopback, which `home init` takes for the box itself).
XIP=$(hostname -I 2>/dev/null | awk '{print $1}')
[ -n "$XIP" ] || { echo "SKIP home_e2e: no address but loopback"; exit 0; }
W="$(mktemp -d)"
cleanup() { pkill -f -- "$W/" 2>/dev/null; [ -n "${RUN:-}" ] && rm -rf "$RUN"; [ -n "${KEEP:-}" ] && echo "kept $W" || rm -rf "$W"; }
trap cleanup EXIT
trap "exit 1" INT TERM HUP
run() { ( ulimit -v 40000000; ulimit -s unlimited; timeout "$1" "${@:2}" ); }
fail() { echo "FAIL: $*"; for f in "$W"/*.log; do echo "== $f"; tail -5 "$f"; done; KEEP=1; exit 1; }
wait_port() { for _ in $(seq 150); do (exec 3<>"/dev/tcp/${2:-127.0.0.1}/$1") 2>/dev/null && return 0; sleep 0.2; done; return 1; }
sealed() { [ "$(head -c 8 "$1")" = "SYMBSEAL" ]; }
BASE=$(python3 -c 'import random; print(random.randrange(20000, 60000, 10))')

python3 - "$W" <<'EOF'
import json, os, sys
k = json.load(open(os.path.expanduser('~/git/larry/resid/tests/crypto/cggmp_oracle/keys6.json')))
for name, i in (('device', 0), ('kit', 1)):
    open(f'{sys.argv[1]}/{name}.primes', 'w').write(f"{k[i]['P']} {k[i]['Q']}\n")
EOF

printf 'household passphrase 1\n' > "$W/pass"
printf 'household passphrase 2\n' > "$W/wrong"
X1=$(run 30 "$BIN" witness keygen "$W/x1.key") || fail "witness keygen"
X2=$(run 30 "$BIN" witness keygen "$W/x2.key") || fail "witness keygen"
XW1="$XIP:$((BASE + 7)):$X1"; XW2="$XIP:$((BASE + 8)):$X2"
SEAL=(--seal passphrase --passphrase-file "$W/pass" --fast-kdf)

# One witness outside the box would leave the box's own a majority.
run 60 "$BIN" home init "$W/bad" 127.0.0.1 --ports "$BASE" --bind 127.0.0.1 --witness "$XW1" "${SEAL[@]}" > "$W/bad.log" 2>&1 && fail "home init with one witness outside the box"
grep -q majority "$W/bad.log" || fail "home init with one outside witness: $(cat "$W/bad.log")"
[ -e "$W/bad/home.txt" ] && fail "a refused home init wrote the box"

run 120 "$BIN" home init "$W/box" 127.0.0.1 home.test --ports "$BASE" --bind 127.0.0.1 --witness "$XW1" --witness "$XW2" "${SEAL[@]}" > "$W/init.log" 2>&1 || fail "home init: $(cat "$W/init.log")"
openssl verify -CAfile "$W/box/tls/ca.pem" "$W/box/tls/server.pem" > "$W/verify.log" 2>&1 || fail "OpenSSL does not verify the server certificate: $(cat "$W/verify.log")"
openssl x509 -in "$W/box/tls/server.pem" -noout -text > "$W/x509.txt" 2>&1
grep -q "IP Address:127.0.0.1" "$W/x509.txt" && grep -q "DNS:home.test" "$W/x509.txt" && grep -q "TLS Web Server Authentication" "$W/x509.txt" || fail "server certificate fields: $(cat "$W/x509.txt")"
# Sealed at rest: the CA's, the server's and the witness's keys.
for f in tls/ca.key tls/server.key w1.key; do sealed "$W/box/$f" || fail "$f is not sealed"; done
[ -e "$W/box/w2.key" ] && fail "the box runs a second witness"
echo "home init: CA and server certificate verify in OpenSSL; keys sealed; one witness on the box, two outside it"

# The witnesses outside the box, with certificates under the box's CA.
run 120 "$BIN" home witness-cert "$W/box" "$XIP" "$W/x1tls" --passphrase-file "$W/wrong" > "$W/wcert-bad.log" 2>&1 && fail "witness-cert with a wrong passphrase"
grep -q "wrong passphrase" "$W/wcert-bad.log" || fail "wrong passphrase: $(cat "$W/wcert-bad.log")"
run 120 "$BIN" home witness-cert "$W/box" "$XIP" "$W/x1tls" --passphrase-file "$W/pass" > "$W/wcert.log" 2>&1 || fail "witness-cert: $(cat "$W/wcert.log")"
run 120 "$BIN" home witness-cert "$W/box" "$XIP" "$W/x2tls" --passphrase-file "$W/pass" >> "$W/wcert.log" 2>&1 || fail "witness-cert: $(cat "$W/wcert.log")"
openssl verify -CAfile "$W/box/tls/ca.pem" "$W/x1tls/server.pem" > /dev/null 2>&1 || fail "OpenSSL does not verify the witness certificate"
( setsid "$BIN" witness serve "$W/x1" $((BASE + 7)) "$W/x1.key" 0 --bind "$XIP" --tls "$W/x1tls/server.pem" "$W/x1tls/server.key" > "$W/x1.log" 2>&1 & )
( setsid "$BIN" witness serve "$W/x2" $((BASE + 8)) "$W/x2.key" 0 --bind "$XIP" --tls "$W/x2tls/server.pem" "$W/x2tls/server.key" > "$W/x2.log" 2>&1 & )

LINK=$(run 60 "$BIN" home invite "$W/box" alice 2> "$W/invite.log") || fail "home invite"
grep -q "works once, for a day" "$W/invite.log" || fail "the invite does not say it is a one-day bearer link: $(cat "$W/invite.log")"
CODE=$(sed -n 's/.*[?&]c=\([^&]*\).*/\1/p' <<< "$LINK"); FP=$(sed -n 's/.*[?&]f=\([^&]*\).*/\1/p' <<< "$LINK")
[ "${#CODE}" -eq 22 ] && [ -n "$FP" ] || fail "pairing link: $LINK"
# The fingerprint in the link is the server certificate's SHA-256 (the
# first certificate in server.pem), as a TLS client sees it.
WANT=$(openssl x509 -in "$W/box/tls/server.pem" -outform DER | openssl dgst -sha256 -binary | basenc --base64url | tr -d '=')
[ "$FP" = "$WANT" ] || fail "fingerprint $FP, the server certificate's is $WANT"

# A wrong passphrase starts nothing.
run 120 "$BIN" home serve "$W/box" --passphrase-file "$W/wrong" > "$W/serve-bad.log" 2>&1 && fail "home serve with a wrong passphrase"
grep -q "wrong passphrase" "$W/serve-bad.log" || fail "wrong passphrase: $(cat "$W/serve-bad.log")"
( setsid "$BIN" home serve "$W/box" --passphrase-file "$W/pass" > "$W/serve.log" 2>&1 & )
for p in 0 1 2; do wait_port $((BASE + p)) || fail "port $((BASE + p)) did not open"; done
for p in 7 8; do wait_port $((BASE + p)) "$XIP" || fail "witness port $((BASE + p)) did not open"; done
RUN=$(cat "$W/box/run.path")
case "$RUN" in /dev/shm/symbolon-home-*) ;; *) fail "the keys were unsealed to $RUN, not memory";; esac
openssl ec -in "$RUN/server.key" -check -noout > /dev/null 2>&1 || fail "OpenSSL does not load the unsealed server key"
grep -q "unsealed in memory" "$W/serve.log" || fail "serve: $(cat "$W/serve.log")"
SEEN=$(openssl s_client -connect "127.0.0.1:$BASE" < /dev/null 2>/dev/null | openssl x509 -outform DER | openssl dgst -sha256 -binary | basenc --base64url | tr -d '=')
[ "$SEEN" = "$FP" ] || fail "the box presents a certificate with fingerprint $SEEN, the link says $FP"
URL="https://127.0.0.1:$BASE"
# The person's cosigner is made by `home serve`, within ten seconds.
for _ in $(seq 60); do [ -s "$W/box/people/alice/keys" ] && break; sleep 1; done
[ -s "$W/box/people/alice/keys" ] || fail "alice's cosigner was not made"
curl -s --cacert "$W/box/tls/ca.pem" -o /dev/null -w '%{http_code}' "$URL/setup?c=AAAAAAAAAAAAAAAAAAAAAA" | grep -q 403 || fail "a wrong code got the setup"
curl -sS --cacert "$W/box/tls/ca.pem" "$URL/setup?c=$CODE" > "$W/setup.json" 2> "$W/curl.log" || fail "setup over TLS: $(cat "$W/curl.log")"
curl -s --cacert "$W/box/tls/ca.pem" -o /dev/null -w '%{http_code}' "$URL/setup?c=$CODE" | grep -q 403 || fail "the code gave the setup twice"
read -r RH RPORT COSK W1 W2 W3 TOK SECURE < <(python3 -c '
import json, sys
j = json.load(open(sys.argv[1]))
print(j["relay_host"], j["relay_port"], j["cosigner_keys"], *j["witnesses"], j["pair_token"], j["secure"])' "$W/setup.json")
[ "$W1" = "127.0.0.1:$((BASE + 2)):$(cat "$W/box/w1.pub")" ] && [ "$W2" = "$XW1" ] && [ "$W3" = "$XW2" ] || fail "setup witnesses: $W1 $W2 $W3"
[ "$SECURE" = True ] || fail "a new box is not secure: $(cat "$W/setup.json")"
python3 -c 'import json, sys; open(sys.argv[2], "w").write(json.load(open(sys.argv[1]))["ca"])' "$W/setup.json" "$W/ca.pem"
cmp -s "$W/ca.pem" "$W/box/tls/ca.pem" || fail "the setup's CA is not the box's"
echo "pairing service: setup over TLS with the code, once; a wrong code refused"

sealed "$W/box/people/alice/cos/root" || fail "alice's cosigner's root key is not sealed"
pgrep -f "cosigner serve-for $W/box/people/alice/cos" > /dev/null && fail "alice's cosigner runs before a device paired"
DEV=$(printf '2468\n\n' | run 120 "$BIN" device new "$W/dev" "$RH" "$RPORT" --unprotected --fast-kdf --ca "$W/ca.pem") || fail "device new"
curl -s --cacert "$W/ca.pem" -o /dev/null -w '%{http_code}' -X POST --data "$DEV" "$URL/pair?c=$CODE" | grep -q 403 || fail "paired without the setup's token"
curl -sS --cacert "$W/ca.pem" -X POST --data "$DEV" "$URL/pair?c=$CODE&t=$TOK" | grep -q '"paired": true' || fail "pair"
curl -s --cacert "$W/ca.pem" -o /dev/null -w '%{http_code}' -X POST --data "$DEV" "$URL/pair?c=$CODE&t=$TOK" | grep -q 403 || fail "a spent code paired again"
# The person's cosigner starts within ten seconds of the pairing, and its
# first turn takes the pairing and opens its mailbox for the inception.
for _ in $(seq 60); do pgrep -f "cosigner serve-for $W/box/people/alice/cos" > /dev/null && break; sleep 1; done
pgrep -f "cosigner serve-for $W/box/people/alice/cos" > /dev/null || fail "alice's cosigner did not start"
# It reaches the box's own witness locally and the two outside it where
# they are (the box's key only in its local_host).
[ "$(cat "$W/box/people/alice/cos/local_host")" = "127.0.0.1 $(cat "$W/box/w1.pub")" ] || fail "local_host: $(cat "$W/box/people/alice/cos/local_host")"
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
echo "device paired with the box, incepted over TLS with two witnesses outside the box, and signs with the box's cosigner (OpenSSL verifies)"

# At rest: every secret file of the cosigner is sealed, and the box says
# it is secure.
for f in root cg-1.cfg; do [ -e "$W/box/people/alice/cos/$f" ] || fail "alice's cosigner has no $f"; done
for f in "$W"/box/people/alice/cos/{root,cg-*.cfg,kit-half*,kv-*,kitv-b-*}; do
  [ -e "$f" ] || continue
  sealed "$f" || fail "alice's cosigner's $(basename "$f") is not sealed"
done
run 60 "$BIN" home status "$W/box" > "$W/hstatus.log" 2>&1 || fail "home status"
grep -q '"secure": true' "$W/hstatus.log" || fail "home status: $(cat "$W/hstatus.log")"
echo "at rest: the cosigner's root key, share and kit half are sealed; home status: secure"
echo "PASS home_e2e"

#!/usr/bin/env bash
# The command-line agent end to end on loopback: a relay, three witnesses
# and a cosigner as processes; a device (unprotected profile, fast KDF) set
# up, paired and taken through inception with Paillier primes from the
# Resid CGGMP oracle's fixtures; a credential registered and used; the
# signature checked by Python's cryptography (OpenSSL) under the public key
# the agent printed. Also: a wrong PIN and a credential ID presented for
# another relying party are refused.
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
for name, i in (('device', 0), ('kit', 1), ('devrs', 3), ('dev2', 5), ('dev3', 3)):
    open(f'{sys.argv[1]}/{name}.primes', 'w').write(f"{k[i]['P']} {k[i]['Q']}\n")
# The cosigner: line 1 for key generation, line 2 for the re-share.
open(f'{sys.argv[1]}/cosigner.primes', 'w').write(f"{k[2]['P']} {k[2]['Q']}\n{k[4]['P']} {k[4]['Q']}\n")
EOF

# TLS=1: the relay and the witnesses serve HTTPS with a certificate for
# 127.0.0.1 from a test CA; the device and the cosigner trust that CA.
SERVE_TLS=(); CA=()
if [ -n "${TLS:-}" ]; then
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
grep -q 'RECOVERY KIT' "$W/init.log" || fail "no kit printed"
run 120 "$BIN" device status "$W/dev" > "$W/status.log" 2>&1 || fail "status"
grep -q 'head sequence 0 epoch 1 parties 3 threshold 2' "$W/status.log" || fail "status: $(cat "$W/status.log")"

printf '2468\n' | run 300 "$BIN" device register "$W/dev" login.example.com > "$W/reg.log" 2>&1 || fail "register"
CID=$(awk '/^credential-id/ {print $2}' "$W/reg.log"); PUB=$(awk '/^public-key/ {print $2}' "$W/reg.log")
[ ${#CID} -eq 64 ] && [ ${#PUB} -eq 130 ] || fail "register output"
MSG=$(python3 -c 'import hashlib; print(hashlib.sha256(b"authenticatorData||clientDataHash").hexdigest())')

printf '2468\n' | run 600 "$BIN" device sign "$W/dev" login.example.com "$CID" "$MSG" > "$W/sign.log" 2>&1 || fail "sign"
SIG=$(tail -1 "$W/sign.log")
python3 - "$PUB" "$MSG" "$SIG" <<'EOF' || fail "signature does not verify in OpenSSL"
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
pub, msg, sig = (bytes.fromhex(x) for x in sys.argv[1:4])
k = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub)
k.verify(utils.encode_dss_signature(int.from_bytes(sig[:32], 'big'), int.from_bytes(sig[32:], 'big')), msg, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
print("signature verifies under the credential's key (OpenSSL)")
EOF
# WebAuthn (SPEC 10.4): a registration and an assertion as a site sees
# them, checked with python-fido2: attestation "none", the RP ID hash,
# truthful flags, the credential's COSE key, and an ES256 signature over
# authenticatorData || clientDataHash.
printf '2468\n' | run 300 "$BIN" device webauthn register "$W/dev" webauthn.example.com --uv > "$W/wareg.log" 2>&1 || fail "webauthn register: $(cat "$W/wareg.log")"
WCID=$(awk '/^credential-id/ {print $2}' "$W/wareg.log")
CDH=$(printf '%s' '{"type":"webauthn.get","challenge":"abc","origin":"https://webauthn.example.com"}' | sha256sum | cut -d' ' -f1)
printf '2468\n' | run 600 "$BIN" device webauthn assert "$W/dev" webauthn.example.com "$WCID" "$CDH" --uv > "$W/waget.log" 2>&1 || fail "webauthn assert: $(tail -2 "$W/waget.log")"
printf '2468\n' | run 600 "$BIN" device webauthn assert "$W/dev" evil.example.net "$WCID" "$CDH" > "$W/waevil.log" 2>&1 && fail "a WebAuthn assertion for another RP"
python3 - "$W/wareg.log" "$W/waget.log" "$CDH" <<'PY' || fail "WebAuthn responses do not verify (python-fido2)"
import hashlib, sys
from fido2.webauthn import AttestationObject, AuthenticatorData
from fido2.cose import CoseKey
f = lambda path, k: next(l.split()[1] for l in open(path) if l.startswith(k + " "))
reg, get, cdh = sys.argv[1], sys.argv[2], bytes.fromhex(sys.argv[3])
ao = AttestationObject(bytes.fromhex(f(reg, "attestation-object")))
ad = ao.auth_data
assert ao.fmt == "none" and ao.att_stmt == {}, ao.fmt
assert ad.rp_id_hash == hashlib.sha256(b"webauthn.example.com").digest()
F = AuthenticatorData.FLAG
assert ad.flags & F.UP and ad.flags & F.UV and ad.flags & F.BE and ad.flags & F.BS and ad.flags & F.AT, ad.flags
assert ad.counter == 0
cd = ad.credential_data
assert cd.credential_id.hex() == f(reg, "credential-id")
assert bytes(cd.aaguid).hex() == "5e7b0c1f4a2d4c8e9b316a0d2f87c4e1"
pub = bytes.fromhex(f(reg, "public-key"))
assert cd.public_key[-2] == pub[1:33] and cd.public_key[-3] == pub[33:65] and cd.public_key[3] == -7
gad = AuthenticatorData(bytes.fromhex(f(get, "authenticator-data")))
assert gad.rp_id_hash == ad.rp_id_hash and gad.flags & F.UP and gad.flags & F.UV and not gad.flags & F.AT
CoseKey.parse(dict(cd.public_key)).verify(bytes(gad) + cdh, bytes.fromhex(f(get, "signature-der")))
print("WebAuthn: attestation and assertion verify (python-fido2)")
PY

# Duress (SPEC 9.2, 14): a credential in the duress subset signs under the
# duress PIN; one outside it cannot; while the duress window is open the
# cosigner refuses authority requests (an enrollment) as if unreachable;
# the window ends by witness time.
printf '2468\n' | run 300 "$BIN" device register "$W/dev" login2.example.com --duress > "$W/reg2.log" 2>&1 || fail "register --duress"
CID2=$(awk '/^credential-id/ {print $2}' "$W/reg2.log"); PUB2=$(awk '/^public-key/ {print $2}' "$W/reg2.log")
MSGD=$(python3 -c 'import hashlib; print(hashlib.sha256(b"under duress").hexdigest())')
printf '1357\n' | run 600 "$BIN" device sign "$W/dev" login2.example.com "$CID2" "$MSGD" > "$W/dsign.log" 2>&1 || fail "duress sign: $(tail -2 "$W/dsign.log")"
python3 - "$PUB2" "$MSGD" "$(tail -1 "$W/dsign.log")" <<'PY' || fail "the duress signature does not verify"
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
pub, msg, sig = (bytes.fromhex(x) for x in sys.argv[1:4])
ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub).verify(utils.encode_dss_signature(int.from_bytes(sig[:32], 'big'), int.from_bytes(sig[32:], 'big')), msg, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
PY
printf '1357\n' | run 300 "$BIN" device sign "$W/dev" login.example.com "$CID" "$MSG" > "$W/dsign2.log" 2>&1 && fail "the duress profile signed outside its subset"
grep -q 'not for this relying party' "$W/dsign2.log" || fail "outside the subset: $(cat "$W/dsign2.log")"
DEVX=$(printf '4444\n\n' | run 120 "$BIN" device new "$W/devx" 127.0.0.1 "$RP" --unprotected --fast-kdf "${CA[@]}") || fail "device new (throwaway)"
printf '2468\n' | run 600 "$BIN" device enroll "$W/dev" "$DEVX" "$W/devrs.primes" > "$W/denroll.log" 2>&1 && fail "an enrollment ran during duress"
grep -q 'unreachable' "$W/denroll.log" || fail "enrollment during duress: $(tail -2 "$W/denroll.log")"
for i in 1 2 3; do
  pkill -f -- "witness (serve|child) $W/w$i " 2>/dev/null
  for _ in $(seq 50); do (exec 3<>"/dev/tcp/127.0.0.1/${WPORT[$i]}") 2>/dev/null || break; sleep 0.1; done
  runs 3600 "$BIN" witness serve "$W/w$i" "${WPORT[$i]}" "$W/w$i.key" 4000 "${SERVE_TLS[@]}" > "$W/w$i-duress.log" 2>&1 & PIDS+=($!)
  wait_port "${WPORT[$i]}" || fail "witness $i did not restart"
done
echo "duress: the subset signs (OpenSSL), nothing else does, authority refused as an outage, window ended by witness time"
printf '9999\n' | run 300 "$BIN" device sign "$W/dev" login.example.com "$CID" "$MSG" > "$W/badpin.log" 2>&1 && fail "a wrong PIN signed"
grep -q 'wrong PIN' "$W/badpin.log" || fail "wrong PIN: $(cat "$W/badpin.log")"
printf '2468\n' | run 300 "$BIN" device sign "$W/dev" evil.example.net "$CID" "$MSG" > "$W/otherrp.log" 2>&1 && fail "another RP's request signed"
grep -q 'not for this relying party' "$W/otherrp.log" || fail "other RP: $(cat "$W/otherrp.log")"
# The vault (SPEC 18): put, get, overwrite, list; tampering and rollback at
# the relay are refused.
LOG=$(awk '/^log / {print $2}' "$W/init.log")
# The vault as the relay stores it, through the relay itself (so this
# works whatever the relay's store, RELAY_STORE).
RURL="$([ -n "${TLS:-}" ] && echo https || echo http)://127.0.0.1:$RP/blob/vault-$LOG"
getb() { curl -sS ${TLS:+--cacert "$W/ca.pem"} -o "$1" "$RURL"; }
putb() { curl -sS ${TLS:+--cacert "$W/ca.pem"} -X PUT --data-binary @"$1" "$RURL" > /dev/null; }
printf '2468\nhunter2\n' | run 300 "$BIN" device vault put "$W/dev" mail > "$W/v1.log" 2>&1 || fail "vault put"
getb "$W/vault.v1"
printf '2468\nc0rrect-horse\n' | run 300 "$BIN" device vault put "$W/dev" mail > "$W/v2.log" 2>&1 || fail "vault overwrite"
printf '2468\ns3cret\n' | run 300 "$BIN" device vault put "$W/dev" bank > "$W/v3.log" 2>&1 || fail "vault put 2"
grep -q 'vault version 3, 2 items' "$W/v3.log" || fail "vault versions: $(cat "$W/v3.log")"
[ "$(printf '2468\n' | run 300 "$BIN" device vault get "$W/dev" mail 2>&1)" = "c0rrect-horse" ] || fail "vault get"
[ "$(printf '2468\n' | run 300 "$BIN" device vault list "$W/dev" 2>&1 | sort | tr '\n' ' ')" = "bank mail " ] || fail "vault list"
[ "$(printf '2468\n' | run 300 "$BIN" device vault list "$W/dev" --kinds 2>&1 | sort | tr '\n' ' ')" = "secret bank secret mail " ] || fail "vault list --kinds"
getb "$W/vault.good"
cp "$W/vault.good" "$W/vault.bad"
python3 - "$W/vault.bad" <<'PY'
import sys
b = bytearray(open(sys.argv[1], 'rb').read()); b[len(b) // 2] ^= 1; open(sys.argv[1], 'wb').write(b)
PY
putb "$W/vault.bad"
# A state that does not verify is never accepted: reading falls back to
# this device's copy and says why; changing refuses.
printf '2468\n' | run 300 "$BIN" device vault get "$W/dev" mail > "$W/vt.log" 2> "$W/vt.err" || fail "the local copy after tampering: $(cat "$W/vt.err")"
[ "$(cat "$W/vt.log")" = "c0rrect-horse" ] && grep -q 'local copy:' "$W/vt.err" || fail "a tampered vault was read: $(cat "$W/vt.log" "$W/vt.err")"
printf '2468\nx\n' | run 300 "$BIN" device vault put "$W/dev" other > "$W/vtp.log" 2>&1 && fail "a change was made over a tampered vault"
putb "$W/vault.v1"
printf '2468\n' | run 300 "$BIN" device vault get "$W/dev" mail > "$W/vr.log" 2>&1 || fail "the local copy after rollback"
grep -q 'local copy: .*backwards' "$W/vr.log" && grep -q '^c0rrect-horse$' "$W/vr.log" || fail "rollback: $(cat "$W/vr.log")"
putb "$W/vault.good"
echo "vault: put/get/list, tampering and rollback refused (reads use the device's verified copy)"
# Typed items (SPEC 18.2): set, list --long, show, delete; bad input refused.
hx() { printf '%s' "$1" | od -An -tx1 | tr -d ' \n'; }
printf '2468\nnumber %s\nexpiry %s\ncvv %s\n' "$(hx 4111111111111111)" "$(hx 12/30)" "$(hx 123)" | run 300 "$BIN" device vault set "$W/dev" "my visa" card > "$W/card.log" 2>&1 || fail "vault set card: $(cat "$W/card.log")"
printf '2468\n' | run 300 "$BIN" device vault list "$W/dev" --long > "$W/long.log" 2>&1 || fail "vault list --long"
grep -qx "card $(hx 'my visa') $(hx 1111) -" "$W/long.log" && grep -qx "secret $(hx bank) - -" "$W/long.log" || fail "vault list --long: $(cat "$W/long.log")"
printf '2468\n' | run 300 "$BIN" device vault show "$W/dev" "my visa" > "$W/show.log" 2>&1 || fail "vault show"
grep -qx "type $(hx card)" "$W/show.log" && grep -qx "number $(hx 4111111111111111)" "$W/show.log" && grep -qx "cvv $(hx 123)" "$W/show.log" || fail "vault show: $(cat "$W/show.log")"
printf '2468\nexpiry %s\n' "$(hx 12/30)" | run 300 "$BIN" device vault set "$W/dev" nonum card > "$W/bad1.log" 2>&1 && fail "a card without a number was stored"
printf '2468\nBad-Name %s\n' "$(hx x)" | run 300 "$BIN" device vault set "$W/dev" bad note > "$W/bad2.log" 2>&1 && fail "a bad field name was stored"
printf '2468\ntext zz\n' | run 300 "$BIN" device vault set "$W/dev" bad note > "$W/bad3.log" 2>&1 && fail "a non-hex value was stored"
printf '2468\ntext %s\n' "$(hx hi)" | run 300 "$BIN" device vault set "$W/dev" bad spaceship > "$W/bad4.log" 2>&1 && fail "an unknown type was stored"
printf '2468\n' | run 300 "$BIN" device vault delete "$W/dev" "my visa" > "$W/del.log" 2>&1 || fail "vault delete: $(cat "$W/del.log")"
[ "$(printf '2468\n' | run 300 "$BIN" device vault list "$W/dev" 2>&1 | sort | tr '\n' ' ')" = "bank mail " ] || fail "vault list after delete"
printf '2468\n' | run 300 "$BIN" device vault delete "$W/dev" "my visa" > "$W/del2.log" 2>&1 && fail "deleted a missing item"
echo "vault: typed items set, listed, shown and deleted; bad input refused"
# Importing (SPEC 18.9): a Bitwarden JSON export and a LastPass CSV, each
# as one new vault version; fields mapped, folders kept, clashing names
# numbered; a password-protected export and a stranger's CSV refused.
FX=tests/fixtures/import
field() { # field NAME FIELD: the field's text, from `vault show`
    printf '2468\n' | run 300 "$BIN" device vault show "$W/dev" "$1" 2>/dev/null | python3 -c "
import sys
for l in sys.stdin:
    p = l.split()
    if p and p[0] == sys.argv[1]: print(bytes.fromhex(p[1] if len(p) > 1 else '').decode(), end='')" "$2"
}
run 60 "$BIN" device vault import "$W/dev" $FX/bitwarden.json --dry-run > "$W/imd.log" 2>&1 || fail "import dry run: $(cat "$W/imd.log")"
grep -qx "total 9" "$W/imd.log" && grep -qx "item login $(hx 'GitHub (2)') -" "$W/imd.log" && grep -qx "item card $(hx 'Visa 💳') $(hx Banking)" "$W/imd.log" || fail "import dry run: $(cat "$W/imd.log")"
printf '2468\n' | run 600 "$BIN" device vault import "$W/dev" $FX/bitwarden.json > "$W/imp.log" 2>&1 || fail "import bitwarden: $(cat "$W/imp.log")"
grep -qx "total 9" "$W/imp.log" && grep -q "^warn " "$W/imp.log" || fail "import bitwarden: $(cat "$W/imp.log")"
CA_NAME='Crédit Agricole – compte'
[ "$(field "$CA_NAME" origin)" = "https://www.credit-agricole.fr" ] && [ "$(field "$CA_NAME" current)" = 'S3crét "quoted" pass' ] \
  && [ "$(field "$CA_NAME" folder)" = Banking ] && [ "$(field "$CA_NAME" totp)" = "otpauth://totp/CA:marie?secret=JBSWY3DPEHPK3PXP" ] \
  && [ "$(field "$CA_NAME" custom_0)" = "$(printf 'Security question\0371\037Blue')" ] \
  && [ "$(field "$CA_NAME" custom_3)" = "$(printf 'Website\0370\037https://www.credit-agricole.fr/particulier/acceder.html')" ] \
  && [ "$(field "$CA_NAME" custom_4)" = "$(printf 'Website\0370\037androidapp://fr.ca.app')" ] || fail "imported login: $(printf '2468\n' | "$BIN" device vault show "$W/dev" "$CA_NAME" 2>&1)"
[ "$(field 'Visa 💳' number)" = 4111111111111111 ] && [ "$(field 'Visa 💳' expiry)" = 03/29 ] && [ "$(field 'Visa 💳' cvv)" = 123 ] || fail "imported card"
[ "$(field Me full_name)" = "Dr Marie Curie" ] && [ "$(field Me address)" = "$(printf '1 Rue de la Paix\nParis 75002\nFR')" ] && [ "$(field Me document)" = X1234567 ] || fail "imported identity"
[ "$(field 'Laptop key' type)" = secret ] && [ "$(field portal.acme.example folder)" = "Work/Clients" ] && [ "$(field 'GitHub (2)' current)" = pw2 ] || fail "imported key, folder or renamed login"
printf '2468\n' | run 600 "$BIN" device vault import "$W/dev" $FX/lastpass.csv > "$W/iml.log" 2>&1 || fail "import lastpass: $(cat "$W/iml.log")"
grep -qx "total 8" "$W/iml.log" || fail "import lastpass: $(cat "$W/iml.log")"
[ "$(field Mastercard expiry)" = 01/28 ] && [ "$(field Mastercard notes)" = "$(printf 'Line one\nLine two')" ] && [ "$(field Mastercard folder)" = Finance/Cards ] \
  && [ "$(field Checking routing)" = 021000021 ] && [ "$(field 'Home address' phone)" = 5551234567 ] && [ "$(field 'Home Wi-Fi' ssid)" = HomeNet ] || fail "imported LastPass notes"
printf '2468\n' | run 600 "$BIN" device vault import "$W/dev" $FX/1password.csv > /dev/null 2>&1 || fail "import 1password"
printf '2468\n' | run 600 "$BIN" device vault import "$W/dev" $FX/1password.csv > /dev/null 2>&1 || fail "import 1password again"
[ "$(field 'Dropbox (2)' current)" = oppw ] || fail "a second import did not number the clashing name"
printf '2468\n' | run 300 "$BIN" device vault list "$W/dev" --long > "$W/imlong.log" 2>&1
grep -qx "card $(hx Mastercard) $(hx 4444) $(hx Finance/Cards)" "$W/imlong.log" || fail "list --long folder: $(cat "$W/imlong.log")"
run 60 "$BIN" device vault import "$W/dev" $FX/bitwarden_encrypted.json --dry-run > "$W/ime.log" 2>&1 && fail "a password-protected export was read"
grep -q "password-protected" "$W/ime.log" || fail "encrypted export: $(cat "$W/ime.log")"
run 60 "$BIN" device vault import "$W/dev" $FX/notapm.csv --dry-run > /dev/null 2>&1 && fail "a CSV that is not an export was read"
for f in bitwarden.csv chrome.csv firefox.csv keepassxc.csv; do run 60 "$BIN" device vault import "$W/dev" $FX/$f --dry-run > "$W/im1.log" 2>&1 || fail "dry run $f: $(cat "$W/im1.log")"; done
# What came in is deleted again, so the steps below see the vault as before.
printf '2468\n' | run 300 "$BIN" device vault list "$W/dev" 2>/dev/null | grep -vx 'bank\|mail' | while IFS= read -r n; do printf '2468\n' | run 300 "$BIN" device vault delete "$W/dev" "$n" > /dev/null 2>&1 || fail "delete $n"; done
[ "$(printf '2468\n' | run 300 "$BIN" device vault list "$W/dev" 2>&1 | sort | tr '\n' ' ')" = "bank mail " ] || fail "vault list after the imports were removed"
echo "vault: Bitwarden, LastPass and 1Password exports imported with folders; bad exports refused"
# Enrollment (SPEC 11.1, 11.3): a second device joins; the quorum
# re-shares to epoch 2; both devices sign for the same credential; the new
# one reads the vault.
DEV2=$(printf '1111\n\n' | run 120 "$BIN" device new "$W/dev2" 127.0.0.1 "$RP" --unprotected --fast-kdf "${CA[@]}") || fail "device new (second)"
printf '1111\n' | run 1800 "$BIN" device join "$W/dev2" "$DEV" "$W/dev2.primes" > "$W/join.log" 2>&1 & JP=$!
echo "enrollment (re-share with fresh Paillier keys; a minute or two)..."
printf '2468\n' | run 1800 "$BIN" device enroll "$W/dev" "$DEV2" "$W/devrs.primes" > "$W/enroll.log" 2>&1 || fail "enroll"
wait $JP || fail "join"
run 120 "$BIN" device status "$W/dev2" > "$W/status2.log" 2>&1 || fail "status (second)"
grep -q 'epoch 2 parties 4 threshold 2' "$W/status2.log" || fail "status after enrollment: $(cat "$W/status2.log")"
MSG2=$(python3 -c 'import hashlib; print(hashlib.sha256(b"second device").hexdigest())')
printf '1111\n' | run 600 "$BIN" device sign "$W/dev2" login.example.com "$CID" "$MSG2" > "$W/sign2.log" 2>&1 || fail "sign from the enrolled device"
printf '2468\n' | run 600 "$BIN" device sign "$W/dev" login.example.com "$CID" "$MSG" > "$W/sign3.log" 2>&1 || fail "sign at epoch 2"
for pair in "$MSG2 $(tail -1 "$W/sign2.log")" "$MSG $(tail -1 "$W/sign3.log")"; do
python3 - "$PUB" $pair <<'PY' || fail "epoch-2 signature does not verify"
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
pub, msg, sig = (bytes.fromhex(x) for x in sys.argv[1:4])
ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub).verify(utils.encode_dss_signature(int.from_bytes(sig[:32], 'big'), int.from_bytes(sig[32:], 'big')), msg, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
PY
done
[ "$(printf '1111\n' | run 300 "$BIN" device vault get "$W/dev2" mail 2>&1)" = "c0rrect-horse" ] || fail "vault from the enrolled device"
echo "enrollment: epoch 2, both devices sign under the same credential key (OpenSSL), the new one reads the vault"
# Kit recovery (SPEC 13.2, 13.4) up to the delay: a new device reveals the
# kit; the cosigner refuses to release its half before the delay; a device
# vetoes; the release is still refused.
KIT=$(sed -n 's/^RECOVERY KIT (write it down; it is shown once): //p' "$W/init.log")
DEV3=$(printf '3333\n\n' | run 120 "$BIN" device new "$W/dev3" 127.0.0.1 "$RP" --unprotected --fast-kdf "${CA[@]}") || fail "device new (recovering)"
run 300 "$BIN" device recover "$W/dev3" "$KIT" "$LOG" > "$W/recover.log" 2>&1 || fail "recover: $(cat "$W/recover.log")"
grep -q 'recovery pending: 1' "$W/recover.log" || fail "recover: $(cat "$W/recover.log")"
grep -q 'NEW RECOVERY KIT' "$W/recover.log" || fail "no new kit"
run 120 "$BIN" device status "$W/dev" | grep -q 'pending 1' || fail "status does not show the pending recovery"
printf '3333\n' | run 300 "$BIN" device recover-release "$W/dev3" > "$W/rel1.log" 2>&1 && fail "the kit half was released before the delay"
grep -q 'refused' "$W/rel1.log" || fail "release: $(cat "$W/rel1.log")"
printf '2468\n' | run 300 "$BIN" device veto "$W/dev" > "$W/veto.log" 2>&1 || fail "veto: $(cat "$W/veto.log")"
grep -q 'pending now 0' "$W/veto.log" || fail "veto: $(cat "$W/veto.log")"
printf '3333\n' | run 300 "$BIN" device recover-release "$W/dev3" > "$W/rel2.log" 2>&1 && fail "the kit half was released after a veto"
echo "recovery: pending, release refused before the delay, vetoed, still refused"
# The recovery again, past the delay: the witnesses restart with clocks
# moved forward (the witness majority is trusted for time); the recovered
# device gets the cosigner's half, assembles the kit's share, re-shares
# with the cosigner, and signs for the credential made at the start.
run 300 "$BIN" device recover "$W/dev3" "$KIT" "$LOG" > "$W/recover2.log" 2>&1 || fail "second recover: $(cat "$W/recover2.log")"
for i in 1 2 3; do
  pkill -f -- "witness (serve|child) $W/w$i " 2>/dev/null; wait "${WPID[$i]}" 2>/dev/null
  for _ in $(seq 50); do (exec 3<>"/dev/tcp/127.0.0.1/${WPORT[$i]}") 2>/dev/null || break; sleep 0.1; done
  runs 3600 "$BIN" witness serve "$W/w$i" "${WPORT[$i]}" "$W/w$i.key" 263400 "${SERVE_TLS[@]}" > "$W/w$i-later.log" 2>&1 & PIDS+=($!)
  wait_port "${WPORT[$i]}" || fail "witness $i did not restart"
done
echo "recovery finish (release, kit share, re-share; a minute or two)..."
printf '3333\n' | run 1800 "$BIN" device recover-finish "$W/dev3" "$KIT" "$W/dev3.primes" > "$W/finish.log" 2>&1 || fail "recover-finish: $(tail -3 "$W/finish.log")"
run 120 "$BIN" device status "$W/dev3" > "$W/status3.log" 2>&1 || fail "status (recovered)"
grep -q 'parties 3 threshold 2' "$W/status3.log" || fail "status after recovery: $(cat "$W/status3.log")"
MSG3=$(python3 -c 'import hashlib; print(hashlib.sha256(b"recovered device").hexdigest())')
printf '3333\n' | run 600 "$BIN" device sign "$W/dev3" login.example.com "$CID" "$MSG3" > "$W/sign4.log" 2>&1 || fail "sign from the recovered device: $(tail -2 "$W/sign4.log")"
python3 - "$PUB" "$MSG3" "$(tail -1 "$W/sign4.log")" <<'PY' || fail "the recovered device's signature does not verify"
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
pub, msg, sig = (bytes.fromhex(x) for x in sys.argv[1:4])
ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub).verify(utils.encode_dss_signature(int.from_bytes(sig[:32], 'big'), int.from_bytes(sig[32:], 'big')), msg, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
PY
[ "$(printf '3333\n' | run 300 "$BIN" device vault get "$W/dev3" mail 2>&1)" = "c0rrect-horse" ] || fail "vault from the recovered device"
echo "recovery finished: the recovered device signs under the same credential key (OpenSSL) and reads the vault"
grep -q "(TLS)" "$W/relay.log" || [ -z "${TLS:-}" ] || fail "the relay did not serve TLS"
# Offline (SPEC 18.8): with the relay gone, the vault reads from the
# device's copy; changes are refused.
pkill -f -- "relay (serve|child) $W/relay" 2>/dev/null; sleep 1
printf '3333\n' | run 300 "$BIN" device vault get "$W/dev3" mail > "$W/off.log" 2> "$W/off.err" || fail "offline read: $(cat "$W/off.err")"
[ "$(cat "$W/off.log")" = "c0rrect-horse" ] && grep -q 'local copy:' "$W/off.err" || fail "offline read: $(cat "$W/off.log" "$W/off.err")"
printf '3333\n' | run 300 "$BIN" device vault list "$W/dev3" --long > "$W/offl.log" 2>&1 || fail "offline list"
printf '3333\nx\n' | run 300 "$BIN" device vault put "$W/dev3" other > "$W/offp.log" 2>&1 && fail "an offline change was made"
echo "offline: the vault reads from the device's verified copy; changes wait for the relay"
echo "PASS cli_e2e${TLS:+ (TLS)}"

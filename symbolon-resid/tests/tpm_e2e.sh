#!/usr/bin/env bash
# The TPM profile end to end on this machine's TPM (/dev/tpmrm0; the
# user must be in the tss group): relay, witnesses and cosigner as in
# cli_e2e.sh; one device in the TPM profile (device key gated by the PIN's
# PolicyAuthValue, unlock HMAC keys in the TPM) through inception, a
# credential signed and checked by OpenSSL, a wrong PIN refused, a duress
# PIN sign and the vault. `device forget` removes the TPM keys at the end.
set -uo pipefail
cd "$(dirname "$0")/.."
BIN="${BIN:-$PWD/target/symbolon}"
[ -x "$BIN" ] || { echo "build target/symbolon first"; exit 2; }
[ -r /dev/tpmrm0 ] && [ -w /dev/tpmrm0 ] || { echo "SKIP tpm_e2e: no access to /dev/tpmrm0 (join the tss group)"; exit 0; }
W="$(mktemp -d)"
PIDS=()
cleanup() { [ -d "$W/dev" ] && ( ulimit -v 40000000; timeout 60 "$BIN" device forget "$W/dev" ); for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; pkill -f -- "$W/" 2>/dev/null; [ -n "${KEEP:-}" ] && echo "kept $W" || rm -rf "$W"; }
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
DEV=$(printf '2468\n1357\n' | run 120 "$BIN" device new "$W/dev" 127.0.0.1 "$RP" --fast-kdf) || fail "device new (TPM)"
run 60 "$BIN" cosigner pair "$W/cos" "$DEV" || fail "cosigner pair"
runc 3600 "$BIN" cosigner serve "$W/cos" "$W/cosigner.primes" > "$W/cosigner.log" 2>&1 & PIDS+=($!)

echo "inception (key generation with three parties; a minute or two)..."
printf '2468\n' | run 1800 "$BIN" device init "$W/dev" "$COS" "${WS[0]}" "${WS[1]}" "${WS[2]}" "$W/device.primes" "$W/kit.primes" > "$W/init.log" 2>&1 || fail "device init"
grep -q '^log ' "$W/init.log" || fail "no log id printed"
grep -q 'RECOVERY KIT' "$W/init.log" || fail "no kit printed"
run 120 "$BIN" device status "$W/dev" > "$W/status.log" 2>&1 || fail "status"
grep -q 'head sequence 0 epoch 1 parties 3 threshold 2' "$W/status.log" || fail "status: $(cat "$W/status.log")"
grep -q 'profile TPM' "$W/status.log" || fail "status: not the TPM profile"
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
echo "duress PIN signs its subset through the TPM unlock keys"
printf '9999\n' | run 300 "$BIN" device sign "$W/dev" login.example.com "$CID" "$MSG" > "$W/badpin.log" 2>&1 && fail "a wrong PIN signed"
grep -q 'wrong PIN' "$W/badpin.log" || fail "wrong PIN: $(cat "$W/badpin.log")"
printf '2468\n' | run 300 "$BIN" device sign "$W/dev" evil.example.net "$CID" "$MSG" > "$W/otherrp.log" 2>&1 && fail "another RP's request signed"
grep -q 'not for this relying party' "$W/otherrp.log" || fail "other RP: $(cat "$W/otherrp.log")"
echo "wrong PIN and other relying party refused"
printf '2468\nhunter2\n' | run 300 "$BIN" device vault put "$W/dev" mail > "$W/v1.log" 2>&1 || fail "vault put"
[ "$(printf '2468\n' | run 300 "$BIN" device vault get "$W/dev" mail 2>&1)" = "hunter2" ] || fail "vault get"
echo "vault: put/get under the TPM-held device key"
# Platform attestation of the device key (SPEC 29.5), the whole exchange
# against this machine's TPM: evidence, an administrator's challenge, the
# TPM's answer, the verification. Resid's verifier needs a current CRL for
# every certificate of the EK chain; a TPM maker that publishes none for its
# intermediate gets a stale refusal, which is the expected result there.
read -r ORG FOUNDER < <(printf '2468\n' | run 300 "$BIN" device org new "$W/dev" Solo) || fail "org new"
printf '2468\n' | run 300 "$BIN" device org attest "$W/dev" > "$W/att1.log" 2>&1 || fail "attest evidence: $(cat "$W/att1.log")"
grep -q "evidence sent" "$W/att1.log" || fail "attest: $(cat "$W/att1.log")"
printf '2468\n' | run 600 "$BIN" device org sync "$W/dev" > "$W/async1.log" 2>&1 || fail "sync with evidence: $(cat "$W/async1.log")"
grep -q "^challenged " "$W/async1.log" || fail "no challenge: $(cat "$W/async1.log")"
printf '2468\n' | run 300 "$BIN" device org attest "$W/dev" > "$W/att2.log" 2>&1 || fail "attest answer: $(cat "$W/att2.log")"
grep -q "^answered" "$W/att2.log" || fail "attest answer: $(cat "$W/att2.log")"
printf '2468\n' | run 600 "$BIN" device org sync "$W/dev" > "$W/async2.log" 2>&1 || fail "sync with an answer: $(cat "$W/async2.log")"
if grep -q "^attested " "$W/async2.log"; then
    echo "attestation: the TPM's EK chains to its maker's root, the AK is in it, the device key is fixed to it: attested"
else
    WHY=$(sed -n 's/^refused [0-9a-f]* //p' "$W/async2.log" | head -1 | xxd -r -p)
    case "$WHY" in *stale*|*CRL*) echo "attestation: the exchange completes; refused as expected without a current CRL from the TPM maker ($WHY)" ;; *) fail "attestation refused: $WHY" ;; esac
fi

# A new PIN (TPM2_ObjectChangeAuth on the device key and the real unlock key).
printf '2468\n1357\n' | run 300 "$BIN" device pin "$W/dev" > "$W/pin0.log" 2>&1 && fail "the new PIN was the duress PIN"
printf '2468\n86420\n' | run 300 "$BIN" device pin "$W/dev" > "$W/pin.log" 2>&1 || fail "PIN change: $(cat "$W/pin.log")"
printf '86420\n' | run 300 "$BIN" device sign "$W/dev" login.example.com "$CID" "$MSG" > "$W/sign3.log" 2>&1 || fail "sign with the new PIN: $(tail -2 "$W/sign3.log")"
[ "$(printf '86420\n' | run 300 "$BIN" device vault get "$W/dev" mail 2>&1)" = "hunter2" ] || fail "vault under the new PIN"
printf '1357\n' | run 600 "$BIN" device sign "$W/dev" login2.example.com "$CID2" "$MSGD" > /dev/null 2>&1 || fail "the duress PIN after the change"
echo "PIN change: the TPM keys take the new PIN, the duress PIN stays (the old PIN's refusal is checked in cli_e2e: a wrong try here counts toward the TPM's lockout)"
echo "PASS tpm_e2e"

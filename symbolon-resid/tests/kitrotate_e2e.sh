#!/usr/bin/env bash
# Replacing the recovery kit end to end (SPEC 13.2): a relay, three
# witnesses and a cosigner on loopback; a device set up with a plain kit
# (no passphrase); `device kit renew` makes a new kit under a passphrase,
# publishes the rotate-recovery (in force at once: one device, policy[1] =
# 1) and re-shares with the cosigner to the quorum with the new kit in the
# old one's place. Then the old sheet is dead (the log refuses its
# recover, the cosigner releases nothing to it) and the new sheet recovers
# the identity on another device after the delay (witness clocks moved
# forward, as in cli_e2e.sh), which signs under the credential made first.
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
fail() { echo "FAIL: $*"; for f in "$W"/*.log; do echo "== $f"; tail -5 "$f"; done; KEEP=1; exit 1; }
verify() {
python3 - "$1" "$2" "$3" <<'EOF'
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
pub, msg, sig = (bytes.fromhex(x) for x in sys.argv[1:4])
ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub).verify(utils.encode_dss_signature(int.from_bytes(sig[:32], 'big'), int.from_bytes(sig[32:], 'big')), msg, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
EOF
}

python3 - "$W" <<'EOF'
import json, os, sys
k = json.load(open(os.path.expanduser('~/git/larry/resid/tests/crypto/cggmp_oracle/keys6.json')))
for name, i in (('device', 0), ('kit', 1), ('devrs', 3), ('dev3', 5)):
    open(f'{sys.argv[1]}/{name}.primes', 'w').write(f"{k[i]['P']} {k[i]['Q']}\n")
open(f'{sys.argv[1]}/cosigner.primes', 'w').write(f"{k[2]['P']} {k[2]['Q']}\n{k[4]['P']} {k[4]['Q']}\n")
EOF

RP=$(port)
runs 3600 "$BIN" relay serve "$W/relay" "$RP" --allow-private-witnesses --name "127.0.0.1:$RP" > "$W/relay.log" 2>&1 & PIDS+=($!)
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
LOG=$(awk '/^log / {print $2}' "$W/init.log")
OLD=$(sed -n 's/^RECOVERY KIT (write it down; it is shown once): //p' "$W/init.log")
[ ${#OLD} -eq 64 ] || fail "no plain kit printed"
run 120 "$BIN" device status "$W/dev" > "$W/status1.log" 2>&1 || fail "status after inception"
grep -q 'epoch 1 parties 3 threshold 2' "$W/status1.log" || fail "status after inception: $(cat "$W/status1.log")"

# After the Paillier nonce fix (SPEC 6.2.2): a household made by this build
# needs no key refresh and no rotation.
grep -qx 'security-reshare done' "$W/status1.log" && grep -qx 'rotation none' "$W/status1.log" || fail "status of a household made after the fix: $(cat "$W/status1.log")"
# One made before it has no marker: the refresh is due and the master key
# should be replaced (its signatures were never counted), with a reminder
# after every device command.
mv "$W/dev/nonce-fix" "$W/nonce-fix.born"
run 120 "$BIN" device status "$W/dev" > "$W/status-old.log" 2>&1 || fail "status (before the fix)"
grep -qx 'security-reshare due' "$W/status-old.log" && grep -qx 'rotation strongly-recommended' "$W/status-old.log" && grep -qx 'rotation-rollover ok' "$W/status-old.log" \
  || fail "status of a household from before the fix: $(cat "$W/status-old.log")"
run 60 "$BIN" device kit status "$W/dev" 2>&1 | grep -q "symbolon device security-update $W/dev" || fail "no reminder of the key refresh"
run 120 "$BIN" device security-advice "$W/dev" > "$W/advice.log" 2>&1 || fail "security-advice"
grep -q 'We strongly recommend a new household key.' "$W/advice.log" && grep -q 'did not count signatures before the fix' "$W/advice.log" || fail "advice: $(cat "$W/advice.log")"
echo "key refresh after the nonce fix (a re-share with the cosigner; a minute or two)..."
printf '9999\n\n' | run 300 "$BIN" device security-update "$W/dev" "$W/devrs.primes" > "$W/refresh-pin.log" 2>&1 && fail "the key refresh ran under a wrong PIN"
printf '2468\n\n' | run 1800 "$BIN" device security-update "$W/dev" "$W/devrs.primes" > "$W/refresh.log" 2>&1 || fail "security-update (key refresh): $(tail -3 "$W/refresh.log")"
grep -q '^security re-share: done$' "$W/refresh.log" || fail "key refresh: $(cat "$W/refresh.log")"
run 120 "$BIN" device status "$W/dev" > "$W/status-fixed.log" 2>&1 || fail "status after the key refresh"
grep -q 'epoch 2 parties 3 threshold 2' "$W/status-fixed.log" && grep -qx 'security-reshare done' "$W/status-fixed.log" || fail "status after the key refresh: $(cat "$W/status-fixed.log")"
# Still from before the fix: the refresh does not undo a leaked key.
grep -qx 'rotation strongly-recommended' "$W/status-fixed.log" || fail "the refresh cleared the rotation advice: $(cat "$W/status-fixed.log")"
printf '2468\n\n' | run 300 "$BIN" device security-update "$W/dev" > "$W/refresh2.log" 2>&1 || fail "security-update again"
grep -q '^security re-share: done already$' "$W/refresh2.log" || fail "the key refresh ran twice: $(cat "$W/refresh2.log")"
# A device reported lost: no rollover, each site's own recovery.
run 60 "$BIN" device security-advice "$W/dev" --report lost > "$W/advice-lost.log" 2>&1 || fail "security-advice --report lost"
grep -q "Don't use the rollover browser extension" "$W/advice-lost.log" || fail "advice after a lost device: $(cat "$W/advice-lost.log")"
run 120 "$BIN" device status "$W/dev" > "$W/status-lost.log" 2>&1; grep -qx 'rotation-rollover avoid' "$W/status-lost.log" || fail "rollover still advised after a lost device"
rm "$W/dev/security-reports"; mv "$W/nonce-fix.born" "$W/dev/nonce-fix"
run 120 "$BIN" device status "$W/dev" > "$W/status-born.log" 2>&1; grep -qx 'rotation none' "$W/status-born.log" || fail "the household's inception marker no longer counts"
echo "nonce fix: the key refresh ran once (epoch 2), the advice follows the marker and the reports"
printf '2468\n' | run 300 "$BIN" device register "$W/dev" login.example.com > "$W/reg.log" 2>&1 || fail "register"
CID=$(awk '/^credential-id/ {print $2}' "$W/reg.log"); PUB=$(awk '/^public-key/ {print $2}' "$W/reg.log")
[ ${#CID} -eq 64 ] && [ ${#PUB} -eq 130 ] || fail "register output"

# `device kit status` points at the replacement.
run 60 "$BIN" device kit status "$W/dev" > "$W/kstat.log" 2>&1 || fail "kit status"
[ "$(head -1 "$W/kstat.log")" = "kit: no passphrase" ] && grep -qx "if this kit was lost or seen by someone else: symbolon device kit renew $W/dev" "$W/kstat.log" || fail "kit status: $(cat "$W/kstat.log")"

# The replacement: a wrong PIN changes nothing; mismatched passphrases make nothing.
printf '9999\nx\nx\n' | run 300 "$BIN" device kit renew "$W/dev" > "$W/renew-pin.log" 2>&1 && fail "renewed under a wrong PIN"
printf '2468\nonce\ntwice\n' | run 300 "$BIN" device kit renew "$W/dev" > "$W/renew-mm.log" 2>&1 && fail "renewed with passphrases that differ"
run 120 "$BIN" device status "$W/dev" > "$W/status-refused.log" 2>&1; grep -q 'head sequence 1 ' "$W/status-refused.log" || fail "a refused renewal changed the log: $(cat "$W/status-refused.log")"
KP='lantern orchard pebble'
echo "kit replacement (rotate-recovery, then a re-share; a minute or two)..."
printf '2468\n%s\n%s\n' "$KP" "$KP" | run 1800 "$BIN" device kit renew "$W/dev" "$W/devrs.primes" > "$W/renew.log" 2>&1 || fail "kit renew: $(tail -3 "$W/renew.log")"
NEW=$(sed -n 's/^NEW RECOVERY KIT (write it down; it is shown once): //p' "$W/renew.log")
[ ${#NEW} -eq 136 ] && [ "${NEW:0:2}" = 01 ] || fail "the new kit is not a protected sheet: $NEW"
grep -q '^kit replaced' "$W/renew.log" || fail "kit renew: $(cat "$W/renew.log")"
run 120 "$BIN" device status "$W/dev" > "$W/status2.log" 2>&1 || fail "status"
grep -q 'head sequence 3 epoch 3 parties 3 threshold 2 pending 0' "$W/status2.log" || fail "status after the replacement: $(cat "$W/status2.log")"
[ "$(run 60 "$BIN" device kit status "$W/dev" | head -1)" = "kit: protected by a passphrase" ] || fail "kit status after the replacement"
# Run again: nothing is under way, so it would make another kit; with no
# passphrase lines it makes one without (not wanted here), so it is not run.
MSG=$(python3 -c 'import hashlib; print(hashlib.sha256(b"after the kit was replaced").hexdigest())')
printf '2468\n' | run 600 "$BIN" device sign "$W/dev" login.example.com "$CID" "$MSG" > "$W/sign.log" 2>&1 || fail "sign at epoch 3: $(tail -2 "$W/sign.log")"
verify "$PUB" "$MSG" "$(tail -1 "$W/sign.log")" || fail "the epoch-3 signature does not verify"
echo "kit replaced: rotate-recovery in force, re-shared to epoch 3 with the new kit; the device still signs (OpenSSL)"

# The old sheet is dead: its recover is refused (the witnesses and the
# relay will not take it), and the cosigner has nothing to release to it.
DEV3=$(printf '3333\n\n' | run 120 "$BIN" device new "$W/dev3" 127.0.0.1 "$RP" --unprotected --fast-kdf) || fail "device new (recovering)"
printf '\n' | run 600 "$BIN" device recover "$W/dev3" "$OLD" "$LOG" > "$W/recover-old.log" 2>&1 && fail "the old kit started a recovery"
grep -q 'recover' "$W/recover-old.log" || fail "old kit: $(cat "$W/recover-old.log")"
run 120 "$BIN" device status "$W/dev" | grep -q 'head sequence 3 .*pending 0' || fail "the old kit's recover reached the log"
printf '3333\n' | run 300 "$BIN" device recover-release "$W/dev3" > "$W/rel-old.log" 2>&1 && fail "the cosigner released its half to the old kit"
echo "old sheet: its recover is refused and nothing is released"

# The new sheet recovers, after the delay.
printf 'lantern orchard pebbles\n\n' | run 600 "$BIN" device recover "$W/dev3" "$NEW" "$LOG" > "$W/recover-bad.log" 2>&1 && fail "recovered with a wrong passphrase"
grep -q 'wrong passphrase' "$W/recover-bad.log" || fail "recover (wrong passphrase): $(cat "$W/recover-bad.log")"
printf '%s\n\n' "$KP" | run 600 "$BIN" device recover "$W/dev3" "$NEW" "$LOG" > "$W/recover.log" 2>&1 || fail "recover with the new kit: $(cat "$W/recover.log")"
grep -q 'recovery pending: 1' "$W/recover.log" || fail "recover: $(cat "$W/recover.log")"
for i in 1 2 3; do
  pkill -f -- "witness (serve|child) $W/w$i " 2>/dev/null; wait "${WPID[$i]}" 2>/dev/null
  for _ in $(seq 50); do (exec 3<>"/dev/tcp/127.0.0.1/${WPORT[$i]}") 2>/dev/null || break; sleep 0.1; done
  runs 3600 "$BIN" witness serve "$W/w$i" "${WPORT[$i]}" "$W/w$i.key" 263400 > "$W/w$i-later.log" 2>&1 & PIDS+=($!)
  wait_port "${WPORT[$i]}" || fail "witness $i did not restart"
done
echo "recovery finish with the new kit (release, kit share, re-share; a minute or two)..."
printf '3333\n%s\n' "$KP" | run 1800 "$BIN" device recover-finish "$W/dev3" "$NEW" "$W/dev3.primes" > "$W/finish.log" 2>&1 || fail "recover-finish: $(tail -3 "$W/finish.log")"
run 120 "$BIN" device status "$W/dev3" > "$W/status3.log" 2>&1 || fail "status after recovery"
grep -q 'parties 3 threshold 2' "$W/status3.log" || fail "status after recovery: $(cat "$W/status3.log")"
# A recover is in the log: the passkeys must not be moved by rollover.
grep -qx 'rotation-rollover avoid' "$W/status3.log" || fail "rollover advised after a recovery: $(cat "$W/status3.log")"
MSG3=$(python3 -c 'import hashlib; print(hashlib.sha256(b"recovered with the new kit").hexdigest())')
printf '3333\n' | run 600 "$BIN" device sign "$W/dev3" login.example.com "$CID" "$MSG3" > "$W/sign3.log" 2>&1 || fail "sign from the recovered device: $(tail -2 "$W/sign3.log")"
verify "$PUB" "$MSG3" "$(tail -1 "$W/sign3.log")" || fail "the recovered device's signature does not verify"
echo "new sheet: recovered after the delay; the recovered device signs under the same credential key (OpenSSL)"
echo "PASS kitrotate_e2e"

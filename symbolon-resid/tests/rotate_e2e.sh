#!/usr/bin/env bash
# Credential rotation end to end (SPEC 26.3, 26.4): relay, witnesses,
# cosigner and an unprotected device through inception as in cli_e2e.sh; a
# login saved in the vault for a test site (tests/rotate/site.py); its
# password rotated by a signed, logged recipe (tests/rotate/fixtures.py) in
# headless Chromium, and the site then accepts exactly the vault's password.
# Refused: a recipe with one signature, one still in its hold, a
# destructive click; a refused change leaves the old password current; the
# failed sign-in it cost is rationed. Needs chromium on PATH.
set -uo pipefail
cd "$(dirname "$0")/.."
BIN="${BIN:-$PWD/target/symbolon}"
[ -x "$BIN" ] || { echo "build target/symbolon first"; exit 2; }
command -v chromium >/dev/null || { echo "SKIP rotate_e2e: no chromium"; exit 0; }
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
# The browser needs more address space than the cap allows: soft cap only,
# which its launcher lifts.
runb() { ( ulimit -S -v 40000000; ulimit -s unlimited; timeout "$1" "${@:2}" ); }
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
DEV=$(printf '2468\n1357\n' | run 120 "$BIN" device new "$W/dev" 127.0.0.1 "$RP" --unprotected --fast-kdf) || fail "device new"
run 60 "$BIN" cosigner pair "$W/cos" "$DEV" || fail "cosigner pair"
runc 3600 "$BIN" cosigner serve "$W/cos" "$W/cosigner.primes" > "$W/cosigner.log" 2>&1 & PIDS+=($!)
echo "inception (key generation with three parties; a minute or two)..."
printf '2468\n' | run 1800 "$BIN" device init "$W/dev" "$COS" "${WS[0]}" "${WS[1]}" "${WS[2]}" "$W/device.primes" "$W/kit.primes" > "$W/init.log" 2>&1 || fail "device init"

SP=$(port); SITE="http://127.0.0.1:$SP"
mkdir -p "$W/site"; echo alice > "$W/site/user"; echo 'Initial-pass-1' > "$W/site/password"
python3 tests/rotate/site.py "$W/site" "$SP" > "$W/site.log" 2>&1 & PIDS+=($!)
wait_port "$SP" || fail "site did not start"
python3 tests/rotate/fixtures.py "$W" "$SITE" || fail "fixtures"
printf '2468\nInitial-pass-1\n' | run 300 "$BIN" device vault login "$W/dev" mail "$SITE" alice > "$W/login.log" 2>&1 || fail "vault login: $(cat "$W/login.log")"
[ "$(printf '2468\n' | run 300 "$BIN" device vault list "$W/dev" --kinds 2>&1)" = "login mail" ] || fail "vault list --kinds"
site_pw() { cat "$W/site/password"; }
vault_pw() { printf '2468\n' | run 300 "$BIN" device vault get "$W/dev" mail 2>&1; }
rotate() { printf '2468\n' | runb 600 "$BIN" device rotate "$W/dev" mail "$W/bundle-$1.cbor" "$W/repo.cbor" > "$W/rot-$1.log" 2>&1; }

rotate one-sig && fail "a recipe with one signature ran"
grep -q "threshold" "$W/rot-one-sig.log" || fail "one signature: $(cat "$W/rot-one-sig.log")"
rotate fresh && fail "a recipe in its hold ran"
grep -q "7 days" "$W/rot-fresh.log" || fail "hold: $(cat "$W/rot-fresh.log")"
[ "$(site_pw)" = "Initial-pass-1" ] || fail "the site changed before any recipe ran"
echo "refused: a recipe with one signature, one still in its 7-day hold"

rotate good || fail "rotate: $(tail -5 "$W/rot-good.log")"
grep -q "^rotated" "$W/rot-good.log" || fail "rotate: $(cat "$W/rot-good.log")"
P1=$(site_pw)
[ "$P1" != "Initial-pass-1" ] && [ "$(vault_pw)" = "$P1" ] || fail "the vault ($(vault_pw)) and the site ($P1) disagree"
[ ${#P1} -eq 24 ] || fail "new password length ${#P1}"
echo "rotated: the site now accepts only the vault's new password"

# The same in a shared folder (SPEC 19): the login moved into one, rotated
# there, and moved back.
SID=$(printf '2468\n' | run 300 "$BIN" device share new "$W/dev" Home) || fail "share new"
printf '2468\n' | run 300 "$BIN" device vault move "$W/dev" mail "$SID" > "$W/mv1.log" 2>&1 || fail "move into the folder: $(cat "$W/mv1.log")"
printf '2468\n' | runb 600 "$BIN" device rotate "$W/dev" mail "$W/bundle-good.cbor" "$W/repo.cbor" --share "$SID" > "$W/rot-share.log" 2>&1 || fail "rotate in the folder: $(tail -5 "$W/rot-share.log")"
grep -q "^rotated" "$W/rot-share.log" || fail "rotate in the folder: $(cat "$W/rot-share.log")"
PS=$(site_pw)
SHOWN=$(printf '2468\n' | run 300 "$BIN" device vault show "$W/dev" mail --share "$SID" 2>&1 | sed -n 's/^current //p' | xxd -r -p)
[ "$PS" != "$P1" ] && [ "$SHOWN" = "$PS" ] || fail "the folder ($SHOWN) and the site ($PS) disagree"
printf '2468\n' | run 300 "$BIN" device vault move "$W/dev" mail own --share "$SID" > "$W/mv2.log" 2>&1 || fail "move back: $(cat "$W/mv2.log")"
[ "$(vault_pw)" = "$PS" ] || fail "after moving back the vault has $(vault_pw)"
P1=$PS
echo "rotated in a shared folder: moved in, changed at the site, moved back"

rotate badexpect || fail "rotate (bad expectation): $(tail -5 "$W/rot-badexpect.log")"
grep -q "change procedure stopped" "$W/rot-badexpect.log" && grep -q "^rotated" "$W/rot-badexpect.log" || fail "bad expectation: $(cat "$W/rot-badexpect.log")"
P2=$(site_pw)
[ "$P2" != "$P1" ] && [ "$(vault_pw)" = "$P2" ] || fail "after a failed expectation the vault and the site disagree"
echo "a change whose expectation failed is still verified by signing in, and recorded"

[ -f "$W/site/failed-logins" ] && fail "sign-ins failed during successful rotations"
rotate destructive; [ $? -eq 3 ] || fail "destructive: $(cat "$W/rot-destructive.log")"
grep -q "refused a destructive click" "$W/rot-destructive.log" || fail "destructive: $(cat "$W/rot-destructive.log")"
[ ! -f "$W/site/deleted" ] && [ "$(site_pw)" = "$P2" ] && [ "$(vault_pw)" = "$P2" ] || fail "after a refused click the site or vault changed"
[ "$(wc -l < "$W/site/failed-logins")" -eq 1 ] || fail "failed sign-ins: $(cat "$W/site/failed-logins" | wc -l)"
echo "refused a destructive click; the old password stays current after one rationed failed sign-in"

echo refuse > "$W/site/mode"
rotate good && fail "rotation ran during the backoff"
grep -q "too many failed sign-ins" "$W/rot-good.log" || fail "backoff: $(cat "$W/rot-good.log")"
[ "$(wc -l < "$W/site/failed-logins")" -eq 1 ] || fail "the backoff still tried to sign in"
echo "sign-ins rationed: no attempt during the backoff after a failure"
echo "PASS rotate_e2e"

#!/usr/bin/env bash
# The SSH agent end to end (SPEC 16.1): the stack of cli_e2e.sh with an
# unprotected device; an Ed25519 and an ECDSA key imported from
# ssh-keygen and a threshold key made by the quorum; `symbolon ssh-agent`
# on a Unix socket with a stand-in for the consent window
# (tests/ssh/stub_consent.py), driven by OpenSSH itself:
#   a passphrase-protected key opens only with its passphrase;
#   ssh-add -L lists the four keys without the PIN;
#   ssh-keygen -Y sign makes git signatures with each, ssh-keygen -Y verify
#   accepts them;
#   ssh logs in to a real sshd with each key, and the window was shown the
#   server's host key (session-bind@openssh.com) and the user name;
#   refused: cancel, a signature over other data, ssh-add adding a key.
set -uo pipefail
cd "$(dirname "$0")/.."
BIN="${BIN:-$PWD/target/symbolon}"
[ -x "$BIN" ] || { echo "build target/symbolon first"; exit 2; }
command -v sshd >/dev/null && command -v ssh-keygen >/dev/null || { echo "SKIP ssh_e2e: no OpenSSH"; exit 0; }
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


# --- keys --------------------------------------------------------------
ssh-keygen -q -t ed25519 -N '' -C ed@test -f "$W/k_ed" || fail "ssh-keygen ed25519"
ssh-keygen -q -t ecdsa -b 256 -N '' -C p256@test -f "$W/k_p256" || fail "ssh-keygen ecdsa"
printf '2468\n' | run 300 "$BIN" device ssh import "$W/dev" ed "$W/k_ed" > "$W/imp_ed.log" 2>&1 || fail "import ed25519: $(cat "$W/imp_ed.log")"
printf '2468\n' | run 300 "$BIN" device ssh import "$W/dev" p256 "$W/k_p256" > "$W/imp_p256.log" 2>&1 || fail "import ecdsa: $(cat "$W/imp_p256.log")"
printf '2468\n' | run 300 "$BIN" device ssh new "$W/dev" quorum > "$W/new.log" 2>&1 || fail "ssh new: $(cat "$W/new.log")"
grep "^ecdsa-sha2-nistp256 " "$W/new.log" > "$W/k_quorum.pub"
grep -q '^ecdsa-sha2-nistp256 ' "$W/k_quorum.pub" || fail "threshold key line: $(cat "$W/new.log")"
ssh-keygen -q -t ed25519 -N '' -f "$W/k_other"
cut -d' ' -f1,2 "$W/k_ed.pub" > "$W/want_ed"
printf '2468\n' | run 60 "$BIN" device ssh import "$W/dev" enc "$W/nonexistent" > /dev/null 2>&1 && fail "imported a missing file"
ssh-keygen -q -t ecdsa -b 384 -N 'secret phrase' -C enc@test -f "$W/k_enc"
printf '2468\n' | run 60 "$BIN" device ssh import "$W/dev" enc "$W/k_enc" > "$W/imp_enc.log" 2>&1 && fail "imported a passphrase key without the passphrase"
grep -q "passphrase" "$W/imp_enc.log" || fail "passphrase message: $(cat "$W/imp_enc.log")"
printf '2468\nwrong phrase\n' | run 300 "$BIN" device ssh import "$W/dev" enc "$W/k_enc" > "$W/imp_enc.log" 2>&1 && fail "imported with a wrong passphrase"
grep -q "wrong passphrase" "$W/imp_enc.log" || fail "wrong passphrase message: $(cat "$W/imp_enc.log")"
printf '2468\nsecret phrase\n' | run 300 "$BIN" device ssh import "$W/dev" enc "$W/k_enc" > "$W/imp_enc.log" 2>&1 || fail "import with the passphrase: $(cat "$W/imp_enc.log")"
echo "keys: ed25519 and ECDSA imported, an ECDSA P-384 key opened with its passphrase (bcrypt, aes256-ctr), a threshold key made"

# --- agent -------------------------------------------------------------
export XDG_RUNTIME_DIR="$W/run"; mkdir -m 700 "$W/run"
export SYMBOLON_CONSENT="$PWD/tests/ssh/stub_consent.py" STUB_LOG="$W/consent.log" STUB_MODE="$W/mode" SYMBOLON_BIN="$BIN" SYMBOLON_DIR="$W/dev"
echo sign > "$W/mode"
runs 3600 "$BIN" ssh-agent "$W/dev" > "$W/agent.log" 2>&1 & PIDS+=($!)
SOCK="$W/run/symbolon/ssh-agent.sock"
for _ in $(seq 100); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || fail "the agent did not start: $(cat "$W/agent.log")"
[ "$(stat -c %a "$W/run/symbolon")" = 700 ] && [ "$(stat -c %a "$SOCK")" = 600 ] || fail "socket modes"
export SSH_AUTH_SOCK="$SOCK"
ssh-add -L > "$W/listed" || fail "ssh-add -L"
[ "$(wc -l < "$W/listed")" -eq 4 ] || fail "listed: $(cat "$W/listed")"
for k in ed p256 quorum enc; do grep -qF "$(cut -d' ' -f2 "$W/k_$k.pub")" "$W/listed" || fail "$k not listed"; done
ssh-add "$W/k_other" > "$W/add.log" 2>&1 && fail "ssh-add added a key"
[ "$(ssh-add -L | wc -l)" -eq 4 ] || fail "the list changed after ssh-add"
echo "agent: four keys listed without the PIN; ssh-add refused"

# --- git signatures ------------------------------------------------------
echo "a commit" > "$W/msg"
for k in ed p256 quorum enc; do
    rm -f "$W/msg.sig"
    run 600 ssh-keygen -Y sign -f "$W/k_$k.pub" -n git "$W/msg" > "$W/sig_$k.log" 2>&1 || fail "sign with $k: $(cat "$W/sig_$k.log") $(tail -3 "$W/agent.log")"
    echo "me $(cut -d' ' -f1,2 "$W/k_$k.pub")" > "$W/allowed_$k"
    ssh-keygen -Y verify -f "$W/allowed_$k" -I me -n git -s "$W/msg.sig" < "$W/msg" > /dev/null 2>&1 || fail "the $k signature does not verify"
    python3 -I -c "import json,sys; r=json.loads(open(sys.argv[1]).readlines()[-1]); sys.exit(0 if r['key']==sys.argv[2] and r['what']=={'kind':'sshsig','namespace':'git'} and r['pid']>0 else 1)" "$STUB_LOG" "$k" || fail "the window was not shown a git signature for $k: $(tail -1 "$STUB_LOG")"
done
echo "git signatures: each key signs, ssh-keygen -Y verify accepts, the window saw namespace git"

echo cancel > "$W/mode"
rm -f "$W/msg.sig"
run 120 ssh-keygen -Y sign -f "$W/k_ed.pub" -n git "$W/msg" > /dev/null 2>&1 && fail "signed after cancel"
echo other > "$W/mode"
run 120 ssh-keygen -Y sign -f "$W/k_ed.pub" -n git "$W/msg" > /dev/null 2>&1 && fail "a signature over other data reached the client"
echo sign > "$W/mode"
echo "refused: cancel, and a signature over other data (checked by the agent)"

# --- a real sshd ---------------------------------------------------------
SSHD_PORT=$(port)
ssh-keygen -q -t ed25519 -N '' -f "$W/host_key"
cat "$W/k_ed.pub" "$W/k_p256.pub" "$W/k_quorum.pub" "$W/k_enc.pub" > "$W/authorized_keys"; chmod 600 "$W/authorized_keys"
cat > "$W/sshd_config" <<CFG
Port $SSHD_PORT
ListenAddress 127.0.0.1
HostKey $W/host_key
AuthorizedKeysFile $W/authorized_keys
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
UsePAM no
StrictModes no
PidFile $W/sshd.pid
CFG
"$(command -v sshd)" -D -e -f "$W/sshd_config" > "$W/sshd.log" 2>&1 & PIDS+=($!)
wait_port "$SSHD_PORT" || fail "sshd did not start: $(cat "$W/sshd.log")"
HOSTFP=$(ssh-keygen -l -E sha256 -f "$W/host_key.pub" | cut -d' ' -f2)
for k in ed p256 quorum enc; do
    OUT=$(run 600 ssh -F none -p "$SSHD_PORT" -i "$W/k_$k.pub" -o IdentitiesOnly=yes -o IdentityAgent="$SOCK" -o UserKnownHostsFile="$W/known_hosts" \
        -o StrictHostKeyChecking=accept-new -o BatchMode=yes "$(id -un)@127.0.0.1" echo logged-in-$k 2> "$W/ssh_$k.log")
    [ "$OUT" = "logged-in-$k" ] || fail "ssh with $k: $(tail -3 "$W/ssh_$k.log") $(tail -3 "$W/sshd.log")"
    python3 -I -c "import json,sys; r=json.loads(open(sys.argv[1]).readlines()[-1]); sys.exit(0 if r['key']==sys.argv[2] and r['what']=={'kind':'auth','user':sys.argv[3]} and r['host'] and r['host']['fingerprint']==sys.argv[4] and not r['host']['forwarding'] else 1)" "$STUB_LOG" "$k" "$(id -un)" "$HOSTFP" \
        || fail "the window was not shown the server for $k: $(tail -1 "$STUB_LOG")"
done
echo "sshd: logged in with each key; the window was shown the user and the server's host key ($HOSTFP)"

ls "$W/run/symbolon/" | grep -v '^ssh-agent.sock$' && fail "request files were left behind"
echo "PASS ssh_e2e"

#!/usr/bin/env bash
# The SSH agent end to end (SPEC 16.1): the stack of cli_e2e.sh with an
# unprotected device; an Ed25519 and an ECDSA key imported from
# ssh-keygen and a threshold key made by the quorum; `symbolon ssh-agent`
# on a Unix socket with a stand-in for the consent window
# (tests/ssh/stub_consent.py), driven by OpenSSH itself:
#   a passphrase-protected key opens only with its passphrase;
#   ssh-add -L lists the five keys (an RSA-3072 key among them) without the PIN;
#   ssh-keygen -Y sign makes git signatures with each, ssh-keygen -Y verify
#   accepts them;
#   ssh logs in to a real sshd with each key, and the window was shown the
#   server's host key (session-bind@openssh.com) and the user name;
#   refused: cancel, a signature over other data, ssh-add adding a key;
#   the certificate authority (SPEC 16.1.2): a CA made by the quorum,
#   user certificates for three keys that ssh-keygen -L reads, offered by
#   the agent before their keys, logging in to sshd through
#   cert-authority in authorized_keys and through TrustedUserCAKeys, the
#   window shown the certificate; an expired one not offered; renew,
#   refresh from the vault, and deleting the CA.
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
ssh-keygen -q -t rsa -b 3072 -N '' -C rsa@test -f "$W/k_rsa" || fail "ssh-keygen rsa"
printf '2468\n' | run 300 "$BIN" device ssh import "$W/dev" rsa "$W/k_rsa" > "$W/imp_rsa.log" 2>&1 || fail "import rsa: $(cat "$W/imp_rsa.log")"
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
echo "keys: ed25519 and ECDSA imported, an ECDSA P-384 key opened with its passphrase (bcrypt, aes256-ctr), an RSA-3072 key, a threshold key made"

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
[ "$(wc -l < "$W/listed")" -eq 5 ] || fail "listed: $(cat "$W/listed")"
for k in ed p256 quorum enc rsa; do grep -qF "$(cut -d' ' -f2 "$W/k_$k.pub")" "$W/listed" || fail "$k not listed"; done
ssh-add "$W/k_other" > "$W/add.log" 2>&1 && fail "ssh-add added a key"
[ "$(ssh-add -L | wc -l)" -eq 5 ] || fail "the list changed after ssh-add"
echo "agent: five keys listed without the PIN; ssh-add refused"

# --- git signatures ------------------------------------------------------
echo "a commit" > "$W/msg"
for k in ed p256 quorum enc rsa; do
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
cat "$W/k_ed.pub" "$W/k_p256.pub" "$W/k_quorum.pub" "$W/k_enc.pub" "$W/k_rsa.pub" > "$W/authorized_keys"; chmod 600 "$W/authorized_keys"
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
for k in ed p256 quorum enc rsa; do
    OUT=$(run 600 ssh -F none -p "$SSHD_PORT" -i "$W/k_$k.pub" -o IdentitiesOnly=yes -o IdentityAgent="$SOCK" -o UserKnownHostsFile="$W/known_hosts" \
        -o StrictHostKeyChecking=accept-new -o BatchMode=yes "$(id -un)@127.0.0.1" echo logged-in-$k 2> "$W/ssh_$k.log")
    [ "$OUT" = "logged-in-$k" ] || fail "ssh with $k: $(tail -3 "$W/ssh_$k.log") $(tail -3 "$W/sshd.log")"
    python3 -I -c "import json,sys; r=json.loads(open(sys.argv[1]).readlines()[-1]); sys.exit(0 if r['key']==sys.argv[2] and r['what']=={'kind':'auth','user':sys.argv[3]} and r['host'] and r['host']['fingerprint']==sys.argv[4] and not r['host']['forwarding'] else 1)" "$STUB_LOG" "$k" "$(id -un)" "$HOSTFP" \
        || fail "the window was not shown the server for $k: $(tail -1 "$STUB_LOG")"
done
echo "sshd: logged in with each key; the window was shown the user and the server's host key ($HOSTFP)"

# --- the certificate authority (SPEC 16.1.2) ------------------------------
ME=$(id -un)
printf '2468\n' | run 300 "$BIN" device ssh ca-new "$W/dev" myca > "$W/ca.log" 2>&1 || fail "ca-new: $(cat "$W/ca.log")"
grep "^ecdsa-sha2-nistp256 " "$W/ca.log" > "$W/ca.pub"
grep -q '^ecdsa-sha2-nistp256 ' "$W/ca.pub" || fail "CA line: $(cat "$W/ca.log")"
CAB=$(cut -d' ' -f2 "$W/ca.pub")
CAFP=$(ssh-keygen -l -E sha256 -f "$W/ca.pub" | cut -d' ' -f2)
run 30 "$BIN" device ssh cas "$W/dev" > "$W/cas" || fail "device ssh cas"
grep -qF "$CAB" "$W/cas" || fail "the CA is not in device ssh cas: $(cat "$W/cas")"
run 30 "$BIN" device ssh list "$W/dev" > "$W/keys" || fail "device ssh list"
grep -qF "$CAB" "$W/keys" && fail "the CA is listed with the keys"
[ "$(wc -l < "$W/keys")" -eq 5 ] || fail "device ssh list changed: $(cat "$W/keys")"
ssh-add -L | grep -qF "$CAB" && fail "the agent offers the CA"
printf '2468\n' | run 60 "$BIN" device ssh ca-new "$W/dev" quorum > /dev/null 2>&1 && fail "a CA took a key's name"
printf '2468\n' | run 60 "$BIN" device ssh new "$W/dev" myca > /dev/null 2>&1 && fail "a key took the CA's name"
printf '2468\n64617461\n' | run 300 "$BIN" device ssh sign "$W/dev" myca > "$W/casign.log" 2>&1 && fail "the CA signed data"
grep -q "signs only certificates" "$W/casign.log" || fail "the CA's refusal: $(cat "$W/casign.log")"
for bad in "" "--principal a,b" "--principal $ME --days 400" "--principal $ME --days 0" "--bogus x" "--principal"; do
    printf '2468\n' | run 60 "$BIN" device ssh certify "$W/dev" quorum myca $bad > "$W/bad.log" 2>&1 && fail "certified with '$bad'"
done
printf '2468\n' | run 300 "$BIN" device ssh certify "$W/dev" myca myca --principal "$ME" > /dev/null 2>&1 && fail "certified the CA itself"
printf '2468\n' | run 300 "$BIN" device ssh certify "$W/dev" quorum p256 --principal "$ME" > "$W/bad.log" 2>&1 && fail "a key acted as a CA"
grep -q "not a certificate authority" "$W/bad.log" || fail "a key as CA: $(cat "$W/bad.log")"
echo "CA: made by the quorum, listed apart, not offered by the agent, signs no data; bad options refused"

for k in quorum ed rsa; do
    printf '2468\n' | run 600 "$BIN" device ssh certify "$W/dev" "$k" myca --principal "$ME" --principal deploy --days 7 > "$W/cert_$k.log" 2>&1 || fail "certify $k: $(cat "$W/cert_$k.log")"
    grep -- '-cert-v01@openssh.com ' "$W/cert_$k.log" | tail -1 > "$W/k_$k-cert.pub"
    ssh-keygen -L -f "$W/k_$k-cert.pub" > "$W/cert_$k.txt" 2>&1 || fail "ssh-keygen -L does not read the $k certificate: $(cat "$W/cert_$k.txt") $(cat "$W/cert_$k.log")"
    grep -q "cert-v01@openssh.com user certificate" "$W/cert_$k.txt" || fail "$k: not a user certificate: $(cat "$W/cert_$k.txt")"
    grep -q "Signing CA: ECDSA $CAFP" "$W/cert_$k.txt" || fail "$k: signing CA: $(cat "$W/cert_$k.txt")"
    grep -q "Key ID: \"symbolon:$k\"" "$W/cert_$k.txt" || fail "$k: key id: $(cat "$W/cert_$k.txt")"
    grep -qE "^[[:space:]]+$ME\$" "$W/cert_$k.txt" && grep -qE '^[[:space:]]+deploy$' "$W/cert_$k.txt" || fail "$k: principals: $(cat "$W/cert_$k.txt")"
    grep -q "permit-pty" "$W/cert_$k.txt" && grep -q "permit-port-forwarding" "$W/cert_$k.txt" || fail "$k: extensions: $(cat "$W/cert_$k.txt")"
    grep -qE "permit-agent-forwarding|permit-X11-forwarding|permit-user-rc" "$W/cert_$k.txt" && fail "$k: extra extensions: $(cat "$W/cert_$k.txt")"
    grep -q "Critical Options: (none)" "$W/cert_$k.txt" || fail "$k: critical options: $(cat "$W/cert_$k.txt")"
done
run 30 "$BIN" device ssh certs "$W/dev" > "$W/certs" || fail "device ssh certs"
python3 -I - "$W/certs" "$ME" <<'PY' || fail "device ssh certs: $(cat "$W/certs")"
import sys
ls = [l.split(' ', 6) for l in open(sys.argv[1]).read().splitlines()]
assert sorted(bytes.fromhex(l[0]).decode() for l in ls) == ['ed', 'quorum', 'rsa'], ls
for l in ls:
    assert bytes.fromhex(l[1]).decode() == 'myca' and l[2] == '7' and l[3] == sys.argv[2] + ',deploy', l
    assert int(l[5]) - int(l[4]) == 7 * 86400 + 300, l
    assert '-cert-v01@openssh.com ' in l[6], l
PY
ssh-add -L > "$W/listed2" || fail "ssh-add -L"
[ "$(wc -l < "$W/listed2")" -eq 8 ] || fail "listed with certificates: $(cat "$W/listed2")"
for k in quorum ed rsa; do
    python3 -I -c "import sys; ls=[l.split()[1] for l in open(sys.argv[1])]; c=open(sys.argv[2]).read().split()[1]; k=open(sys.argv[3]).read().split()[1]; sys.exit(0 if ls.index(c) + 1 == ls.index(k) else 1)" \
        "$W/listed2" "$W/k_$k-cert.pub" "$W/k_$k.pub" || fail "the $k certificate is not offered just before its key: $(cat "$W/listed2")"
done
echo "certificates: three issued (ECDSA, Ed25519 and RSA keys), read by ssh-keygen -L as user certificates of the CA; the agent offers each before its key"

# A server that trusts the CA for this user, with no key in authorized_keys.
SSHD2_PORT=$(port)
echo "cert-authority,principals=\"$ME\" $(cat "$W/ca.pub")" > "$W/ak_ca"; chmod 600 "$W/ak_ca"
sed -e "s|^Port .*|Port $SSHD2_PORT|" -e "s|^AuthorizedKeysFile .*|AuthorizedKeysFile $W/ak_ca|" -e "s|^PidFile .*|PidFile $W/sshd2.pid|" "$W/sshd_config" > "$W/sshd2_config"
"$(command -v sshd)" -D -e -f "$W/sshd2_config" > "$W/sshd2.log" 2>&1 & PIDS+=($!)
wait_port "$SSHD2_PORT" || fail "sshd2 did not start: $(cat "$W/sshd2.log")"
for k in quorum ed rsa; do
    OUT=$(run 600 ssh -F none -p "$SSHD2_PORT" -i "$W/k_$k.pub" -o CertificateFile="$W/k_$k-cert.pub" -o IdentitiesOnly=yes -o IdentityAgent="$SOCK" -o UserKnownHostsFile="$W/known_hosts" \
        -o StrictHostKeyChecking=accept-new -o BatchMode=yes "$ME@127.0.0.1" echo cert-$k 2> "$W/ssh_cert_$k.log")
    [ "$OUT" = "cert-$k" ] || fail "ssh with the $k certificate: $(tail -3 "$W/ssh_cert_$k.log") $(tail -5 "$W/sshd2.log")"
    python3 -I -c "import json,sys; r=json.loads(open(sys.argv[1]).readlines()[-1]); c=r.get('certificate'); sys.exit(0 if r['key']==sys.argv[2] and r['what']=={'kind':'auth','user':sys.argv[3]} and c and c['ca']=='myca' and c['principals']==[sys.argv[3],'deploy'] and c['renews'] is False and c['valid_before']>0 else 1)" \
        "$STUB_LOG" "$k" "$ME" || fail "the window was not shown the $k certificate: $(tail -1 "$STUB_LOG")"
done
run 60 ssh -F none -p "$SSHD2_PORT" -i "$W/k_p256.pub" -o IdentitiesOnly=yes -o IdentityAgent="$SOCK" -o UserKnownHostsFile="$W/known_hosts" -o BatchMode=yes "$ME@127.0.0.1" true 2>/dev/null && fail "a key without a certificate logged in to the CA's server"
echo "cert-authority,principals=\"someone-else\" $(cat "$W/ca.pub")" > "$W/ak_ca"
run 60 ssh -F none -p "$SSHD2_PORT" -i "$W/k_ed.pub" -o CertificateFile="$W/k_ed-cert.pub" -o IdentitiesOnly=yes -o IdentityAgent="$SOCK" -o UserKnownHostsFile="$W/known_hosts" -o BatchMode=yes "$ME@127.0.0.1" true 2>/dev/null && fail "a certificate logged in as a principal it does not name"
echo "sshd (cert-authority in authorized_keys): each certificate logs in, the window was shown the CA, the principals and the expiry; no login without a certificate or for another principal"

# The same server trusting the CA system-wide (TrustedUserCAKeys).
SSHD3_PORT=$(port)
cp "$W/ca.pub" "$W/user_ca.pub"
sed -e "s|^Port .*|Port $SSHD3_PORT|" -e "s|^AuthorizedKeysFile .*|AuthorizedKeysFile none|" -e "s|^PidFile .*|PidFile $W/sshd3.pid|" "$W/sshd_config" > "$W/sshd3_config"
echo "TrustedUserCAKeys $W/user_ca.pub" >> "$W/sshd3_config"
"$(command -v sshd)" -D -e -f "$W/sshd3_config" > "$W/sshd3.log" 2>&1 & PIDS+=($!)
wait_port "$SSHD3_PORT" || fail "sshd3 did not start: $(cat "$W/sshd3.log")"
OUT=$(run 600 ssh -F none -p "$SSHD3_PORT" -i "$W/k_ed.pub" -o CertificateFile="$W/k_ed-cert.pub" -o IdentitiesOnly=yes -o IdentityAgent="$SOCK" -o UserKnownHostsFile="$W/known_hosts" \
    -o StrictHostKeyChecking=accept-new -o BatchMode=yes "$ME@127.0.0.1" echo trusted-ca 2> "$W/ssh_tca.log")
[ "$OUT" = "trusted-ca" ] || fail "ssh with TrustedUserCAKeys: $(tail -3 "$W/ssh_tca.log") $(tail -5 "$W/sshd3.log")"
echo "sshd (TrustedUserCAKeys): the certificate logs in"

# Pylon (PYLON=path/to/pylon): it takes the certificate from the agent's
# identity list, where ssh above read it from a file, so the request
# names the certificate's blob itself. sshd3 accepts certificates only.
if [ -n "${PYLON:-}" ] && [ -x "$PYLON" ]; then
    PYH="$W/pylon-home"
    PYLON_HOME="$PYH" run 60 "$PYLON" pin -p "$SSHD3_PORT" 127.0.0.1 "$HOSTFP" > "$W/pylon_pin.log" 2>&1 || fail "pylon pin: $(cat "$W/pylon_pin.log")"
    OUT=$(PYLON_HOME="$PYH" run 600 "$PYLON" -p "$SSHD3_PORT" "$ME@127.0.0.1" echo pylon-cert 2> "$W/pylon_cert.log")
    [ "$OUT" = "pylon-cert" ] || fail "pylon with the agent's certificate: $(tail -5 "$W/pylon_cert.log") $(tail -5 "$W/sshd3.log")"
    grep -q "Accepted publickey.*-CERT" "$W/sshd3.log" || fail "sshd3 did not log a certificate login for pylon"
    echo "pylon: logged in with the certificate the agent lists (TrustedUserCAKeys)"
else
    echo "skip pylon (set PYLON to a pylon binary)"
fi

# An expired certificate is not offered.
ssh-keygen -q -t ed25519 -N '' -f "$W/old_ca"
cp "$W/k_p256.pub" "$W/k_p256_old.pub"
ssh-keygen -q -s "$W/old_ca" -I old -n "$ME" -V -2d:-1d "$W/k_p256_old.pub" 2>/dev/null || fail "ssh-keygen -s"
OLDC=$(cat "$W/k_p256_old-cert.pub")
cp "$W/dev/ssh-certs" "$W/ssh-certs.saved"
echo "$(printf p256 | od -An -tx1 | tr -d ' \n') $(printf old | od -An -tx1 | tr -d ' \n') 1 $ME 1 2 $OLDC" >> "$W/dev/ssh-certs"
ssh-add -L | grep -qF "$(echo "$OLDC" | cut -d' ' -f2)" && fail "the agent offers an expired certificate"
cp "$W/ssh-certs.saved" "$W/dev/ssh-certs"
echo "expired: not offered"

# Renewal by hand, with what the vault remembers.
printf '2468\n' | run 600 "$BIN" device ssh renew "$W/dev" ed > "$W/renew.log" 2>&1 || fail "renew: $(cat "$W/renew.log")"
grep -- '-cert-v01@openssh.com ' "$W/renew.log" | tail -1 > "$W/k_ed-cert2.pub"
[ "$(cut -d' ' -f2 "$W/k_ed-cert2.pub")" != "$(cut -d' ' -f2 "$W/k_ed-cert.pub")" ] || fail "renew gave the same certificate"
ssh-keygen -L -f "$W/k_ed-cert2.pub" > "$W/cert_ed2.txt" 2>&1 && grep -qE '^[[:space:]]+deploy$' "$W/cert_ed2.txt" && grep -q "Signing CA: ECDSA $CAFP" "$W/cert_ed2.txt" || fail "the renewed certificate: $(cat "$W/cert_ed2.txt")"
ssh-add -L > "$W/listed3"
grep -qF "$(cut -d' ' -f2 "$W/k_ed-cert2.pub")" "$W/listed3" && ! grep -qF "$(cut -d' ' -f2 "$W/k_ed-cert.pub")" "$W/listed3" || fail "the agent does not offer the renewed certificate"
printf '2468\n' | run 300 "$BIN" device ssh renew "$W/dev" p256 > "$W/renew.log" 2>&1 && fail "renewed a key with no certificate"
grep -q "no certificate to renew" "$W/renew.log" || fail "renew without a certificate: $(cat "$W/renew.log")"
echo "renew: a new certificate with the same CA and principals, offered in place of the old"

# A signature with a key brings this device's list in line with the vault.
cp "$W/dev/ssh-certs" "$W/ssh-certs.saved"
: > "$W/dev/ssh-certs"
OUT=$(run 600 ssh -F none -p "$SSHD_PORT" -i "$W/k_ed.pub" -o IdentitiesOnly=yes -o IdentityAgent="$SOCK" -o UserKnownHostsFile="$W/known_hosts" -o BatchMode=yes "$ME@127.0.0.1" echo plain 2> "$W/ssh_plain.log")
[ "$OUT" = "plain" ] || fail "ssh with the plain ed key: $(tail -3 "$W/ssh_plain.log")"
run 30 "$BIN" device ssh certs "$W/dev" | grep -qF "$(cut -d' ' -f2 "$W/k_ed-cert2.pub")" || fail "a signature did not restore the key's certificate to the list: $(cat "$W/dev/ssh-certs")"
echo "after a signature: the key's certificate is back in this device's list from the vault"

# The lists rebuilt from the vault (another device's view).
for f in ssh-keys ssh-cas; do sort "$W/dev/$f" > "$W/$f.before"; done
sort "$W/ssh-certs.saved" > "$W/ssh-certs.before"
rm -f "$W/dev/ssh-keys" "$W/dev/ssh-cas" "$W/dev/ssh-certs"
printf '2468\n' | run 600 "$BIN" device ssh refresh "$W/dev" > "$W/refresh.log" 2>&1 || fail "refresh: $(cat "$W/refresh.log")"
grep -q "5 keys, 1 certificate authorities, 3 certificates" "$W/refresh.log" || fail "refresh: $(cat "$W/refresh.log")"
for f in ssh-keys ssh-cas ssh-certs; do sort "$W/dev/$f" | cmp -s - "$W/$f.before" || fail "refresh rebuilt $f differently: $(diff <(sort "$W/dev/$f") "$W/$f.before")"; done
echo "refresh: the keys, the CA and the certificates rebuilt from the vault"

# Deleting the CA drops its certificates here.
printf '2468\n' | run 300 "$BIN" device ssh delete "$W/dev" myca > "$W/delca.log" 2>&1 || fail "delete the CA: $(cat "$W/delca.log")"
[ -z "$(run 30 "$BIN" device ssh cas "$W/dev")" ] && [ -z "$(run 30 "$BIN" device ssh certs "$W/dev")" ] || fail "the CA or its certificates are still listed"
[ "$(ssh-add -L | wc -l)" -eq 5 ] || fail "after the CA was deleted: $(ssh-add -L)"
OUT=$(run 600 ssh -F none -p "$SSHD_PORT" -i "$W/k_ed.pub" -o IdentitiesOnly=yes -o IdentityAgent="$SOCK" -o UserKnownHostsFile="$W/known_hosts" -o BatchMode=yes "$ME@127.0.0.1" echo plain 2> "$W/ssh_plain2.log")
[ "$OUT" = "plain" ] || fail "ssh with the plain ed key after the CA was deleted: $(tail -3 "$W/ssh_plain2.log")"
[ -z "$(run 30 "$BIN" device ssh certs "$W/dev")" ] || fail "a signature listed a deleted CA's certificate again: $(cat "$W/dev/ssh-certs")"
echo "delete: the CA and its certificates are gone, and a signature does not bring them back; the five keys remain"

ls "$W/run/symbolon/" | grep -v '^ssh-agent.sock$' && fail "request files were left behind"

# After co-signing, the cosigner's child keeps the session a while for a
# late abort request, waiting for mail, not turning: it once took a turn
# every 200 ms and kept every turn's memory (about 20 MB a second), and
# never exited, until the kernel's OOM killer ended it.
cpid=$(pgrep -f "cosigner serve-for $W/cos" | head -1)
[ -n "$cpid" ] || fail "no cosigner child after the co-signs"
r0=$(awk '/^VmRSS/{print $2}' "/proc/$cpid/status")
sleep 10
r1=$(awk '/^VmRSS/{print $2}' "/proc/$cpid/status" 2>/dev/null || echo "$r0")
[ $((r1 - r0)) -lt 20480 ] || fail "the cosigner's child grew $(((r1 - r0) / 1024)) MB in 10 s after co-signing"
echo "cosigner: its child after co-signing grew $(((r1 - r0) / 1024)) MB in 10 s"
echo "PASS ssh_e2e"

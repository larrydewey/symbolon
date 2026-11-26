#!/usr/bin/env bash
# Duress alerts (SPEC 14.4) end to end on loopback: two devices and a
# cosigner laid out as on Symbolon Home (BOX/people/larry/cos), the box's
# channels pointed at tests/alert_sinks.py (ntfy and an SMS gateway over
# HTTPS, SMTP over TLS) and a fake `threnody`. A normal unlock beacon sends
# nothing; a duress one sends one alert on every channel, with the location,
# and to the household inbox (Larry is his own household contact here, so
# his device reads it back); settings cannot change during the window; the
# duress device cannot end it; the other device can, and that sends "ended".
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
fail() { echo "FAIL: $*"; for f in "$W"/*.log; do echo "== $f"; tail -6 "$f"; done; ls -la "$W/sink" 2>/dev/null; KEEP=1; exit 1; }
hx() { printf '%s' "$1" | od -An -tx1 | tr -d ' \n'; }
# wait_for PATTERN-GLOB COUNT: until the sinks hold COUNT files matching.
wait_for() { for _ in $(seq 120); do [ "$(ls "$W/sink" 2>/dev/null | grep -c "^$1")" -ge "$2" ] && return 0; sleep 1; done; return 1; }

# ── The sinks ──────────────────────────────────────────────────────────
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$W/ca.key" -out "$W/ca.pem" -days 1 -subj "/CN=alerts CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null || fail "openssl CA"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$W/srv.key" -out "$W/srv.csr" -subj "/CN=localhost" 2>/dev/null
printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n" > "$W/ext"
openssl x509 -req -in "$W/srv.csr" -CA "$W/ca.pem" -CAkey "$W/ca.key" -CAcreateserial -out "$W/srv.pem" -days 1 -extfile "$W/ext" 2>/dev/null || fail "openssl cert"
HP=$(port); SP=$(port)
python3 tests/alert_sinks.py "$HP" "$SP" "$W/srv.pem" "$W/srv.key" "$W/sink" > "$W/sinks.log" 2>&1 & PIDS+=($!)
wait_port "$HP" && wait_port "$SP" || fail "the sinks did not start"
cat > "$W/threnody" <<EOF
#!/bin/sh
echo "\$*" >> "$W/sink/threnody-args"
EOF
chmod +x "$W/threnody"

# ── Two devices and the cosigner, laid out as on Symbolon Home ─────────
python3 - "$W" <<'PY'
import json, os, sys
k = json.load(open(os.path.expanduser('~/git/larry/resid/tests/crypto/cggmp_oracle/keys6.json')))
for name, i in (('device', 0), ('kit', 1), ('devrs', 3), ('dev2', 5)):
    open(f'{sys.argv[1]}/{name}.primes', 'w').write(f"{k[i]['P']} {k[i]['Q']}\n")
open(f'{sys.argv[1]}/cosigner.primes', 'w').write(f"{k[2]['P']} {k[2]['Q']}\n{k[4]['P']} {k[4]['Q']}\n")
PY
BOX="$W/box"; COSD="$BOX/people/larry/cos"
mkdir -p "$BOX/people/larry"; echo "47100" > "$BOX/home.txt"
RP=$(port)
runs 3600 "$BIN" relay serve "$W/relay" "$RP" --allow-private-witnesses --name "127.0.0.1:$RP" > "$W/relay.log" 2>&1 & PIDS+=($!)
WS=()
for i in 1 2 3; do
  P=$(port)
  KEY=$(run 30 "$BIN" witness keygen "$W/w$i.key") || fail "witness keygen"
  runs 3600 "$BIN" witness serve "$W/w$i" "$P" "$W/w$i.key" > "$W/w$i.log" 2>&1 & PIDS+=($!)
  WS+=("127.0.0.1:$P:$KEY")
  wait_port "$P" || fail "witness $i did not start"
done
wait_port "$RP" || fail "relay did not start"
COS=$(run 60 "$BIN" cosigner new "$COSD" 127.0.0.1 "$RP") || fail "cosigner new"
DEV=$(printf '2468\n1357\n' | run 120 "$BIN" device new "$W/dev" 127.0.0.1 "$RP" --unprotected --fast-kdf) || fail "device new"
run 60 "$BIN" cosigner pair "$COSD" "$DEV" || fail "cosigner pair"
runc 3600 "$BIN" cosigner serve "$COSD" "$W/cosigner.primes" >> "$W/cosigner.log" 2>&1 & PIDS+=($!)
echo "inception (a minute or two)..."
printf '2468\n' | run 1800 "$BIN" device init "$W/dev" "$COS" "${WS[0]}" "${WS[1]}" "${WS[2]}" "$W/device.primes" "$W/kit.primes" > "$W/init.log" 2>&1 || fail "device init"
DEV2=$(printf '1111\n\n' | run 120 "$BIN" device new "$W/dev2" 127.0.0.1 "$RP" --unprotected --fast-kdf) || fail "device new (second)"
printf '1111\n' | run 1800 "$BIN" device join "$W/dev2" "$DEV" "$W/dev2.primes" > "$W/join.log" 2>&1 & JP=$!
echo "enrollment of a second device (a minute or two)..."
printf '2468\n' | run 1800 "$BIN" device enroll "$W/dev" "$DEV2" "$W/devrs.primes" > "$W/enroll.log" 2>&1 || fail "enroll"
wait $JP || fail "join"

# ── The box's channels and Larry's contacts ────────────────────────────
H() { run 30 "$BIN" home alerts "$BOX" set "$@" || fail "home alerts set $1"; }
H ntfy_url "https://localhost:$HP"; H ntfy_token tk_test; H ca "$W/ca.pem"; H tz UTC
H smtp_host localhost; H smtp_port "$SP"; H smtp_user user; H smtp_pass secret; H smtp_from home@example.com
H sms_url "https://localhost:$HP/sms"; H sms_auth "Basic dGVzdDp0ZXN0"; H sms_body 'To={to}&From=%2B15550000&Body={text}'
H threnody "$W/threnody"
run 30 "$BIN" home alerts "$BOX" > "$W/conf.log" 2>&1; grep -qx 'smtp_pass (set)' "$W/conf.log" || fail "home alerts shows: $(cat "$W/conf.log")"
printf '2468\nperson %s\ncontact %s 1 %s %s - %s\ncontact %s 0 - - %s -\n\n' "$(hx Larry)" "$(hx Ann)" "$(hx ann@example.com)" "$(hx +15551234567)" "$(hx THRFP123)" "$(hx Me)" "$(hx larry)" \
  | run 300 "$BIN" device alerts set "$W/dev" > "$W/set.log" 2>&1 || fail "alerts set: $(cat "$W/set.log")"
grep -q "^contact $(hx Ann) 1 $(hx ann@example.com) " "$W/set.log" && grep -qx "duress none" "$W/set.log" || fail "alerts set: $(cat "$W/set.log")"
TOPIC=$(awk -v a="$(hx Ann)" '$1 == "contact" && $2 == a {print $8}' "$W/set.log")
[ ${#TOPIC} -gt 8 ] || fail "no ntfy topic: $(cat "$W/set.log")"
printf '2468\n' | run 300 "$BIN" device alerts register "$W/dev" > "$W/reg.log" 2>&1 || fail "register: $(cat "$W/reg.log")"
echo "settings: the box's channels, two contacts, the household alert key"

# ── A normal unlock sends nothing ──────────────────────────────────────
printf '2468\n' | run 300 "$BIN" device beacon "$W/dev" --location 407608000,-1118910000,30,240 > "$W/b1.log" 2>&1 || fail "beacon: $(cat "$W/b1.log")"
sleep 12
[ -z "$(ls "$W/sink" | grep -v '^$')" ] || fail "a normal unlock sent something: $(ls "$W/sink")"
printf '2468\n' | run 300 "$BIN" device alerts "$W/dev" | grep -qx "duress none" || fail "a normal beacon opened a window"
echo "normal unlock: nothing sent"

# ── A duress unlock ────────────────────────────────────────────────────
printf '1357\n' | run 300 "$BIN" device beacon "$W/dev" --location 407608000,-1118910000,30,240 > "$W/b2.log" 2>&1 || fail "duress beacon: $(cat "$W/b2.log")"
[ "$(cat "$W/b1.log")" = "$(cat "$W/b2.log")" ] || fail "the duress beacon's output differs from a normal one's"
wait_for ntfy 1 && wait_for mail 1 && wait_for sms 1 || fail "the alert did not reach every channel: $(ls "$W/sink")"
N=$(cat "$W/sink"/ntfy-*); M=$(cat "$W/sink"/mail-*); S=$(cat "$W/sink"/sms-*)
printf '%s' "$N" | head -1 | grep -qx "$TOPIC" && printf '%s' "$N" | grep -q "Duress alert: Larry" && printf '%s' "$N" | grep -qx urgent || fail "ntfy: $N"
printf '%s' "$N" | grep -q "DURESS: Larry unlocked Symbolon with the duress PIN" && printf '%s' "$N" | grep -q "40.7608, -111.8910 (within 30 m, 4 minutes old)" || fail "ntfy text: $N"
printf '%s' "$M" | head -1 | grep -qx ann@example.com && printf '%s' "$M" | grep -q "Subject: Duress alert: Larry" && printf '%s' "$M" | grep -q "openstreetmap.org/?mlat=40.7608&mlon=-111.8910" || fail "mail: $M"
printf '%s' "$S" | head -1 | grep -qx +15551234567 && printf '%s' "$S" | grep -q "DURESS: Larry" || fail "sms: $S"
for _ in $(seq 30); do [ -s "$W/sink/threnody-args" ] && break; sleep 1; done
grep -qx "ctl /to THRFP123" "$W/sink/threnody-args" && grep -q "^ctl Duress alert: Larry: DURESS: Larry unlocked" "$W/sink/threnody-args" || fail "threnody: $(cat "$W/sink/threnody-args")"
for _ in $(seq 30); do run 120 "$BIN" device alerts inbox "$W/dev" > "$W/inbox.log" 2>&1; grep -q "^alert " "$W/inbox.log" && break; sleep 2; done
grep -q "^alert $(hx 'Duress alert: Larry') " "$W/inbox.log" || fail "household inbox: $(cat "$W/inbox.log")"
run 120 "$BIN" device alerts inbox "$W/dev" | grep -q "^alert " && fail "the inbox showed the same alert twice"
echo "duress unlock: one alert on ntfy, email, SMS, Threnody and the household inbox, with the location"

# ── During the window ──────────────────────────────────────────────────
printf '1111\n' | run 300 "$BIN" device alerts "$W/dev2" > "$W/st.log" 2>&1 || fail "status: $(cat "$W/st.log")"
grep -q "^duress open " "$W/st.log" || fail "status during duress: $(cat "$W/st.log")"
printf '1111\nperson %s\n\n' "$(hx Mallory)" | run 300 "$BIN" device alerts set "$W/dev2" > "$W/set2.log" 2>&1 && fail "settings changed during a duress window"
printf '1357\n' | run 300 "$BIN" device alerts "$W/dev" > "$W/dsh.log" 2>&1 || fail "alerts under the duress PIN: $(cat "$W/dsh.log")"
grep -q "^contact " "$W/dsh.log" && fail "the duress profile showed the contacts"
printf '2468\n' | run 300 "$BIN" device duress end "$W/dev" > "$W/end1.log" 2>&1 && fail "the duress device ended its own window"
echo "during the window: settings locked, hidden under the duress PIN; the duress device cannot end it"

# ── Ended from the other device ────────────────────────────────────────
printf '1111\n' | run 300 "$BIN" device duress end "$W/dev2" > "$W/end2.log" 2>&1 || fail "duress end: $(cat "$W/end2.log")"
grep -qx ended "$W/end2.log" || fail "duress end: $(cat "$W/end2.log")"
wait_for ntfy 2 && wait_for mail 2 && wait_for sms 2 || fail "the end did not reach every channel: $(ls "$W/sink")"
cat "$W/sink"/ntfy-* | grep -q "Larry's duress alert ended at .* (ended from another of their devices)" || fail "ntfy end: $(cat "$W/sink"/ntfy-*)"
printf '1111\n' | run 300 "$BIN" device alerts "$W/dev2" | grep -qx "duress none" || fail "the window is still open"
echo "ended from the other device: everyone told"
echo "PASS duress_alert_e2e"

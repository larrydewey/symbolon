#!/usr/bin/env bash
# A local Symbolon to try the desktop app against: a relay, three witnesses
# and a cosigner on loopback, a device set up and taken through inception,
# and the app pointed at it. Everything lives in $DEMO (default
# ~/.local/share/symbolon/demo); run with --reset to start over.
#
#   tools/demo.sh [--reset] [--no-app]     PIN 2468, duress PIN 1357
#   tools/demo.sh --lan [--reset]          for a phone on the same network:
#       the services listen on the LAN, no device is set up here, and a
#       helper on port 47000 gives the phone what it needs; in the app, enter
#       http://<this machine's address>:47000 under Setup > Join a demo stack.
#
# Demo only: the device uses the unprotected profile (no TPM needed), and
# the Paillier primes come from test fixtures. Each PIN entry runs the real
# Argon2id stretch: allow about 10-20 s per operation.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$HERE/../symbolon-resid/target/symbolon"
DEMO="${DEMO:-$HOME/.local/share/symbolon/demo}"
FLUTTER="${FLUTTER:-$HOME/.local/share/flutter/bin/flutter}"
[ -x "$BIN" ] || { echo "build the agent first: symbolon-resid/target/symbolon"; exit 2; }
RESET=; APP=1; LAN=
for a in "$@"; do case "$a" in --reset) RESET=1 ;; --no-app) APP= ;; --lan) LAN=1; APP= ;; esac; done
[ -n "$LAN" ] && DEMO="${DEMO%/}-lan"
[ -n "$RESET" ] && { pkill -f -- "$DEMO/" 2>/dev/null || true; rm -rf "$DEMO"; }
mkdir -p "$DEMO"
cap() { ( ulimit -v 40000000; ulimit -s unlimited; export RESID_MEM_LIMIT="$1"; shift; "$@" ); }

pkill -f -- "$DEMO/" 2>/dev/null || true
sleep 0.5
RP=47001; WP=(47011 47012 47013)
HOST=127.0.0.1; BIND=()
if [ -n "$LAN" ]; then
  HOST=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") print $(i + 1)}')
  [ -n "$HOST" ] || { echo "cannot find this machine's LAN address"; exit 1; }
  BIND=(--bind 0.0.0.0)
fi
cap 4000 "$BIN" relay serve "$DEMO/relay" $RP "${BIND[@]}" > "$DEMO/relay.log" 2>&1 &
WS=()
for i in 0 1 2; do
  [ -f "$DEMO/w$i.key" ] || cap 4000 "$BIN" witness keygen "$DEMO/w$i.key" > "$DEMO/w$i.pub"
  cap 4000 "$BIN" witness serve "$DEMO/w$i" "${WP[$i]}" "$DEMO/w$i.key" "${BIND[@]}" > "$DEMO/w$i.log" 2>&1 &
  WS+=("$HOST:${WP[$i]}:$(cat "$DEMO/w$i.pub")")
done
sleep 1

if [ -n "$LAN" ]; then
  python3 - "$DEMO" <<'EOF2'
import json, os, sys
k = json.load(open(os.path.expanduser('~/git/larry/resid/tests/crypto/cggmp_oracle/keys6.json')))
open(f'{sys.argv[1]}/cosigner.primes', 'w').write(f"{k[2]['P']} {k[2]['Q']}\n{k[4]['P']} {k[4]['Q']}\n")
EOF2
  [ -d "$DEMO/cos" ] || cap 4000 "$BIN" cosigner new "$DEMO/cos" "$HOST" $RP > "$DEMO/cos.keys"
  cap 16000 "$BIN" cosigner serve "$DEMO/cos" "$DEMO/cosigner.primes" > "$DEMO/cosigner.log" 2>&1 &
  python3 - "$DEMO" "$HOST" "$RP" "$(cat "$DEMO/cos.keys")" "${WS[@]}" <<'EOF2'
import json, os, sys
d, host, rp, cos, ws = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5:]
k = json.load(open(os.path.expanduser('~/git/larry/resid/tests/crypto/cggmp_oracle/keys6.json')))
json.dump({'relay_host': host, 'relay_port': rp, 'cosigner_keys': cos, 'witnesses': ws,
           'device_primes': f"{k[0]['P']} {k[0]['Q']}\n", 'kit_primes': f"{k[1]['P']} {k[1]['Q']}\n"},
          open(f'{d}/setup.json', 'w'))
EOF2
  python3 "$HERE/tools/demo_helper.py" "$DEMO" "$BIN" 47000 "$DEMO/setup.json" > "$DEMO/helper.log" 2>&1 &
  echo "demo stack for a phone: in the app, Setup > Join a demo stack: http://$HOST:47000"
  echo "(the phone must reach this machine on ports 47000-47013; stop with: pkill -f -- \"$DEMO/\")"
  exit 0
fi

if [ ! -f "$DEMO/dev/config.cbor" ] || ! grep -q '^log ' "$DEMO/init.log" 2>/dev/null; then
  echo "setting up the demo device (key generation: a minute or two)..."
  rm -rf "$DEMO/cos" "$DEMO/dev"
  python3 - "$DEMO" <<'EOF'
import json, os, sys
k = json.load(open(os.path.expanduser('~/git/larry/resid/tests/crypto/cggmp_oracle/keys6.json')))
for name, i in (('device', 0), ('kit', 1)):
    open(f'{sys.argv[1]}/{name}.primes', 'w').write(f"{k[i]['P']} {k[i]['Q']}\n")
open(f'{sys.argv[1]}/cosigner.primes', 'w').write(f"{k[2]['P']} {k[2]['Q']}\n{k[4]['P']} {k[4]['Q']}\n")
EOF
  COS=$(cap 4000 "$BIN" cosigner new "$DEMO/cos" 127.0.0.1 $RP)
  DEV=$(printf '2468\n1357\n' | cap 4000 "$BIN" device new "$DEMO/dev" 127.0.0.1 $RP --unprotected)
  cap 4000 "$BIN" cosigner pair "$DEMO/cos" "$DEV"
  cap 16000 "$BIN" cosigner serve "$DEMO/cos" "$DEMO/cosigner.primes" > "$DEMO/cosigner.log" 2>&1 &
  printf '2468\n' | cap 16000 "$BIN" device init "$DEMO/dev" "$COS" "${WS[@]}" "$DEMO/device.primes" "$DEMO/kit.primes" > "$DEMO/init.log" 2>&1 \
    || { echo "inception failed; see $DEMO/init.log"; exit 1; }
  grep 'RECOVERY KIT' "$DEMO/init.log"
else
  cap 16000 "$BIN" cosigner serve "$DEMO/cos" "$DEMO/cosigner.primes" > "$DEMO/cosigner.log" 2>&1 &
fi

CONF="${XDG_CONFIG_HOME:-$HOME/.config}/symbolon-ui"
mkdir -p "$CONF"
[ -f "$CONF/settings.json" ] && cp "$CONF/settings.json" "$CONF/settings.json.before-demo"
python3 - "$CONF/settings.json" "$BIN" "$DEMO/dev" <<'EOF'
import json, os, sys
p, b, d = sys.argv[1:4]
s = json.load(open(p)) if os.path.exists(p) else {}
s.update({'binary': b, 'deviceDir': d, 'chromium': s.get('chromium', 'chromium')})
s.setdefault('credentials', [])
json.dump(s, open(p, 'w'), indent=2)
EOF
echo "services running (logs in $DEMO); PIN 2468, duress PIN 1357"
echo "stop the services afterwards with: pkill -f -- \"$DEMO/\""
[ -n "$APP" ] || exit 0
cd "$HERE" && exec "$FLUTTER" run -d linux

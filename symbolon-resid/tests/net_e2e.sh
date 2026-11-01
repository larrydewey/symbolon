#!/usr/bin/env bash
# Starts a relay and a witness (target/symbolon, built from src/main.resid)
# on loopback in a temporary directory, runs src/net/net_test.resid against
# them, and stops them.
set -euo pipefail
cd "$(dirname "$0")/.."
RC="${RESIDC:-$HOME/git/larry/resid/build/boot/residc}"
BIN=target/symbolon
[ -x "$BIN" ] || { tools/depmap.sh > /dev/null; "$RC" src/main.resid -o "$BIN" --profile debug --verify-lib-dev -depmap target/deps.map > /dev/null; }
W="$(mktemp -d)"
trap 'kill $RP $WP 2>/dev/null; rm -rf "$W"' EXIT
port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
RPORT=$(port); WPORT=$(port)
KEY=$("$BIN" witness keygen "$W/wkey")
"$BIN" relay serve "$W/relay" "$RPORT" > "$W/relay.log" 2>&1 & RP=$!
"$BIN" witness serve "$W/witness" "$WPORT" "$W/wkey" > "$W/witness.log" 2>&1 & WP=$!
for _ in $(seq 50); do (exec 3<>"/dev/tcp/127.0.0.1/$RPORT") 2>/dev/null && (exec 3<>"/dev/tcp/127.0.0.1/$WPORT") 2>/dev/null && break; sleep 0.1; done
SYM_RELAY_PORT=$RPORT SYM_WITNESS_PORT=$WPORT SYM_WITNESS_KEY=$KEY "$RC" test src/net/net_test.resid --verify-lib-dev 2>&1 | grep -v '^OK\|typecheck OK\|^note\|warning\|-->'

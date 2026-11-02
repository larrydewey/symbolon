#!/usr/bin/env bash
# The browser extension end to end (SPEC 22.2, 22.5): headless Chromium
# with the unpacked extension (../symbolon-extension), the agent registered
# as its native messaging host (install.sh), and a stand-in for the consent
# window (tests/browser/stub_consent.py). Test sites keep their real
# origins (tests/browser/site.py).
#   card: the page's cc-name and the payment processor's frame are filled;
#         the ad frame and every password field are not.
#   login: filled on its own site.
#   refused: cancel, a login for another site, a wrong token, no answer.
# Needs chromium and Node's playwright (mise npm-playwright).
set -uo pipefail
cd "$(dirname "$0")/.."
BIN="${BIN:-$PWD/target/symbolon}"
EXT="$(cd ../symbolon-extension && pwd)"
[ -x "$BIN" ] || { echo "build target/symbolon first"; exit 2; }
command -v chromium >/dev/null || { echo "SKIP browser_e2e: no chromium"; exit 0; }
PW="${PLAYWRIGHT_MODULES:-$HOME/.local/share/mise/installs/npm-playwright/latest/node_modules}"
[ -d "$PW/playwright" ] || { echo "SKIP browser_e2e: no playwright"; exit 0; }
W="$(mktemp -d)"
cleanup() { [ -n "${SITE:-}" ] && kill "$SITE" 2>/dev/null; pkill -f -- "$W/" 2>/dev/null; [ -n "${KEEP:-}" ] && echo "kept $W" || rm -rf "$W"; }
trap cleanup EXIT
trap "exit 1" INT TERM HUP
fail() { echo "FAIL: $*"; KEEP=1; exit 1; }

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=test \
    -keyout "$W/key.pem" -out "$W/cert.pem" 2>/dev/null || fail "openssl"
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
python3 -I tests/browser/site.py "$PORT" "$W/cert.pem" "$W/key.pem" > "$W/site.log" 2>&1 &
SITE=$!
for _ in $(seq 50); do grep -q ready "$W/site.log" && break; sleep 0.1; done

XDG_DATA_HOME="$W/data" SYMBOLON_PROFILES="$W/profile" "$EXT/install.sh" "$BIN" "$PWD/tests/browser/stub_consent.py" > /dev/null || fail "install.sh"

# One fill: ANSWER is what the consent window does; prints the driver's JSON.
fill() {
    STUB_ANSWER="$1" STUB_LOG="$W/consent.log" NODE_PATH="$PW" XDG_RUNTIME_DIR="$W" \
        timeout 120 node tests/browser/fill.cjs "$W/profile" "$EXT" "$PORT" "$2" 2> "$W/node.log"
}
check() { python3 -I -c "import json,sys; d=json.loads(sys.argv[1]); sys.exit(0 if ($2) else 1)" "$1" || fail "$3: $1"; }

R=$(fill card https://shop.example/checkout)
check "$R" "d['frames']['js.stripe.com'] == {'num': '4111111111111111', 'exp': '08/29', 'cvc': '123', 'pw': ''}" "card into the processor's frame"
check "$R" "d['frames']['shop.example'] == {'name': 'Ada Lovelace'}" "cardholder on the page"
check "$R" "'https://ads.example cc-number,current-password' in d['scanned'] and 'https://js.stripe.com cc-number,cc-exp,cc-csc,current-password' in d['scanned']" "the extension offered every frame (the host chose)"
check "$R" "d['frames']['ads.example'] == {'num': '', 'pw': ''}" "nothing into the ad frame"
check "$(tail -1 "$W/consent.log")" "d['top'] == 'https://shop.example' and d['want'] == 'card' and [f['origin'] for f in d['frames']] == ['https://shop.example', 'https://js.stripe.com']" "the consent window was shown the page and the processor only"

R=$(fill login https://shop.example/login)
check "$R" "d['frames']['shop.example'] == {'user': 'ada@example.com', 'pw': 'pa\"ss\\\\w0rd é'}" "login on its own site"

R=$(fill cancel https://shop.example/login)
check "$R" "d['frames']['shop.example'] == {'user': '', 'pw': ''}" "cancel fills nothing"

R=$(fill other-login https://shop.example/login)
check "$R" "d['frames']['shop.example'] == {'user': '', 'pw': ''} and 'another site' in d['title']" "a login for another site is refused"

R=$(fill wrong-token https://shop.example/checkout)
check "$R" "d['frames']['js.stripe.com']['num'] == '' and 'did not answer' in d['title']" "an answer without the token is refused"

R=$(fill squat https://shop.example/checkout)
check "$R" "d['frames']['js.stripe.com']['num'] == '4111111111111111'" "a connection without the token does not block the window"

# Run directly, not by the browser for the extension: refused before reading anything.
printf '\x10\x00\x00\x00{"type":"hello"}' | timeout 10 "$BIN" browser host > "$W/direct.out" 2>&1
[ $? -eq 2 ] && grep -q "Symbolon extension only" "$W/direct.out" || fail "a direct run of the host was not refused"
printf '\x10\x00\x00\x00{"type":"hello"}' | timeout 10 "$BIN" browser host chrome-extension://kkhginlcfndkhicoihlaccmmahljipjp/ | tail -c +5 | grep -q '"version":1' || fail "hello"
# No per-user runtime directory: no request file in a shared place, no window.
M='{"type":"fill","id":1,"top":"https://shop.example","frames":[{"frame":0,"origin":"https://shop.example","fields":["username"]}]}'
python3 -I -c "import struct,sys; m=sys.argv[1].encode(); sys.stdout.buffer.write(struct.pack('<I',len(m))+m)" "$M" \
    | env -u XDG_RUNTIME_DIR SYMBOLON_CONSENT="$PWD/tests/browser/stub_consent.py" STUB_LOG="$W/consent2.log" timeout 20 "$BIN" browser host chrome-extension://x/ \
    | tail -c +5 | grep -q 'did not answer' || fail "a fill without XDG_RUNTIME_DIR was not refused"
[ -e "$W/consent2.log" ] && fail "the window was opened without XDG_RUNTIME_DIR"

ls "$W"/symbolon-fill-* >/dev/null 2>&1 && fail "the request or launcher file was left behind"
echo "PASS browser_e2e"

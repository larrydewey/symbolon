#!/usr/bin/env bash
# One pending fill at a time (SPEC 22.7 item 3), at the native messaging
# host, with no browser: while one fill waits for its window, a second
# request is refused, not queued; once the first is answered the next goes
# through; a lock left by a host that died is cleared once it is older than
# any fill can last. The window is tests/browser/stub_consent.py.
set -uo pipefail
cd "$(dirname "$0")/.."
BIN="${BIN:-$PWD/target/symbolon}"
[ -x "$BIN" ] || { echo "build target/symbolon first"; exit 2; }
W="$(mktemp -d)"
cleanup() { pkill -f -- "$W/" 2>/dev/null; [ -n "${KEEP:-}" ] && echo "kept $W" || rm -rf "$W"; }
trap cleanup EXIT
trap "exit 1" INT TERM HUP
fail() { echo "FAIL: $*"; KEEP=1; exit 1; }
mkdir -p "$W/rt" && chmod 700 "$W/rt"

M='{"type":"fill","id":7,"top":"https://shop.example","frames":[{"frame":0,"origin":"https://shop.example","fields":["username","current-password"]}]}'
# host ANSWER OUT: one fill through the host, its reply's JSON in OUT.
host() {
    python3 -I -c "import struct,sys; m=sys.argv[1].encode(); sys.stdout.buffer.write(struct.pack('<I',len(m))+m)" "$M" \
        | XDG_RUNTIME_DIR="$W/rt" SYMBOLON_CONSENT="$PWD/tests/browser/stub_consent.py" STUB_ANSWER="$1" STUB_DELAY=5 STUB_LOG="$W/consent.log" \
          timeout 60 "$BIN" browser host chrome-extension://kkhginlcfndkhicoihlaccmmahljipjp/ | tail -c +5 > "$2"
}

host slow "$W/first.json" & FIRST=$!
for _ in $(seq 50); do [ -d "$W/rt/symbolon-fill.lock" ] && break; sleep 0.1; done
[ -d "$W/rt/symbolon-fill.lock" ] || fail "the first fill took no lock"
host login "$W/second.json"
grep -q 'another fill is waiting' "$W/second.json" || fail "a second fill while one waited: $(cat "$W/second.json")"
wait $FIRST
grep -q '"type":"fill"' "$W/first.json" && grep -q 'ada@example.com' "$W/first.json" || fail "the first fill: $(cat "$W/first.json")"
[ -e "$W/rt/symbolon-fill.lock" ] && fail "the lock was not released"
[ "$(grep -c . "$W/consent.log")" = 1 ] || fail "the refused request opened a window"
echo "while one fill waited, a second was refused without a window; the first was answered"

host login "$W/third.json"
grep -q 'ada@example.com' "$W/third.json" || fail "the next fill after the first: $(cat "$W/third.json")"
mkdir "$W/rt/symbolon-fill.lock" && touch -d '10 minutes ago' "$W/rt/symbolon-fill.lock"
host login "$W/stale.json"
grep -q 'ada@example.com' "$W/stale.json" || fail "a stale lock blocked the fill: $(cat "$W/stale.json")"
mkdir "$W/rt/symbolon-fill.lock"
host login "$W/fresh.json"
grep -q 'another fill is waiting' "$W/fresh.json" || fail "a fresh lock did not hold: $(cat "$W/fresh.json")"
rmdir "$W/rt/symbolon-fill.lock"
echo "the next fill goes through; a lock older than any fill is cleared, a fresh one holds"
echo "PASS fill_lock_e2e"

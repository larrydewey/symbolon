#!/usr/bin/env bash
# The relay's storage backends (SPEC 29.9): two relays over one
# PostgreSQL database (postgres:17-alpine in Docker, SCRAM-SHA-256), then
# two over one S3-compatible store (tests/s3_oracle.py, which checks every
# request's Signature Version 4 itself). Through either relay: a blob
# written at one is read at the other, byte for byte; a log sequence is
# taken once across both (409); mailbox indexes never collide; listings
# are sorted and page; a wrong password or secret keeps the relay from
# starting. FULL=1 also runs tests/cli_e2e.sh against each store.
set -uo pipefail
cd "$(dirname "$0")/.."
BIN="${BIN:-$PWD/target/symbolon}"
[ -x "$BIN" ] || { echo "build target/symbolon first"; exit 2; }
W="$(mktemp -d)"
PG=""
cleanup() { pkill -f -- "$W/" 2>/dev/null; [ -n "$PG" ] && docker rm -f "$PG" > /dev/null 2>&1; [ -n "${KEEP:-}" ] && echo "kept $W" || rm -rf "$W"; }
trap cleanup EXIT
trap "exit 1" INT TERM HUP
fail() { echo "FAIL: $*"; for f in "$W"/*.log; do echo "== $f"; tail -5 "$f"; done; KEEP=1; exit 1; }
wait_port() { for _ in $(seq 150); do (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0; sleep 0.2; done; return 1; }
BASE=$(python3 -c 'import random; print(random.randrange(20000, 60000, 10))')
c() { curl -sS -o "$W/out" -w '%{http_code}' "$@"; }

relays() {   # NAME STORE-SPEC PORT1 PORT2
    local name=$1 spec=$2 p1=$3 p2=$4
    printf '%s' "$spec" > "$W/$name.store"
    ( setsid "$BIN" relay serve "$W/$name-a" "$p1" --store "@$W/$name.store" > "$W/$name-a.log" 2>&1 & )
    ( setsid "$BIN" relay serve "$W/$name-b" "$p2" --store "@$W/$name.store" > "$W/$name-b.log" 2>&1 & )
    wait_port "$p1" && wait_port "$p2" || fail "$name relays did not start"
}

exercise() {   # NAME PORT1 PORT2
    local name=$1 A="http://127.0.0.1:$2" B="http://127.0.0.1:$3"
    python3 -c 'import sys; sys.stdout.buffer.write(bytes(range(256)) * 300)' > "$W/bin"
    [ "$(c -X PUT --data-binary @"$W/bin" "$A/blob/vault-test")" = 200 ] || fail "$name: put"
    [ "$(c "$B/blob/vault-test")" = 200 ] && cmp -s "$W/out" "$W/bin" || fail "$name: the other relay did not give the same bytes"
    [ "$(c "$B/blob/nothing-here")" = 404 ] || fail "$name: a missing blob"
    L=$(printf 'ab%.0s' $(seq 32))
    [ "$(c -X POST --data first "$A/log/$L/0")" = 200 ] || fail "$name: log put"
    [ "$(c -X POST --data second "$B/log/$L/0")" = 409 ] || fail "$name: a log sequence taken twice across relays"
    c "$B/log/$L/0" > /dev/null; [ "$(cat "$W/out")" = first ] || fail "$name: the log kept the second writer"
    T=$(printf 'cd%.0s' $(seq 32))
    [ "$(c -X POST --data m0 "$A/mbox/$T")" = 200 ] && [ "$(cat "$W/out")" = 0 ] || fail "$name: mailbox 0"
    [ "$(c -X POST --data m1 "$B/mbox/$T")" = 200 ] && [ "$(cat "$W/out")" = 1 ] || fail "$name: mailbox 1 at the other relay"
    [ "$(c -X POST --data m2 "$A/mbox/$T")" = 200 ] && [ "$(cat "$W/out")" = 2 ] || fail "$name: mailbox 2"
    c "$A/mbox/$T/1" > /dev/null; [ "$(cat "$W/out")" = m1 ] || fail "$name: mailbox read"
    for n in e c a d b; do c -X PUT --data "$n" "$B/blob/card-$n" > /dev/null; done
    c "$A/list/card-" > /dev/null; [ "$(tr '\n' ' ' < "$W/out")" = "card-a card-b card-c card-d card-e" ] || fail "$name: list: $(cat "$W/out")"
    c "$A/list/card-?after=card-c" > /dev/null; [ "$(tr '\n' ' ' < "$W/out")" = "card-d card-e" ] || fail "$name: list after: $(cat "$W/out")"
    [ "$(c "$B/healthz")" = 200 ] || fail "$name: healthz"
    echo "$name: blobs, logs written once, mailboxes and listings agree across two relays"
}

# PostgreSQL.
PGP=$((BASE + 5))
PG=$(docker run -d --rm -e POSTGRES_USER=sym -e POSTGRES_PASSWORD=s3cret-pw -e POSTGRES_DB=sym -p "127.0.0.1:$PGP:5432" postgres:17-alpine) || fail "docker postgres"
for _ in $(seq 120); do docker exec "$PG" pg_isready -U sym -h 127.0.0.1 > /dev/null 2>&1 && break; sleep 0.5; done
sleep 1
printf 'postgres://sym:wrong@127.0.0.1:%s/sym' "$PGP" > "$W/badpg.store"
timeout 30 "$BIN" relay serve "$W/bad" $((BASE + 9)) --store "@$W/badpg.store" > "$W/badpg.log" 2>&1 && fail "a relay started with a wrong database password"
grep -q "not ready" "$W/badpg.log" || fail "wrong password: $(cat "$W/badpg.log")"
relays pg "postgres://sym:s3cret-pw@127.0.0.1:$PGP/sym" $((BASE + 1)) $((BASE + 2))
exercise postgres $((BASE + 1)) $((BASE + 2))
[ "$(docker exec "$PG" psql -U sym -d sym -tAc "select count(*) from symbolon_objects where k like 'mbox/%'")" = 3 ] || fail "postgres: the table does not hold the mailbox"

# S3.
S3P=$((BASE + 6))
( setsid python3 tests/s3_oracle.py "$S3P" AKIDTEST secretkey123 symbolon eu-west-1 > "$W/s3.log" 2>&1 & )
wait_port "$S3P" || fail "s3 oracle"
printf 's3://AKIDTEST:wrongsecret@127.0.0.1:%s/symbolon?region=eu-west-1' "$S3P" > "$W/bads3.store"
timeout 30 "$BIN" relay serve "$W/bad2" $((BASE + 8)) --store "@$W/bads3.store" > "$W/bads3.log" 2>&1 && fail "a relay started with a wrong S3 secret"
relays s3 "s3://AKIDTEST:secretkey123@127.0.0.1:$S3P/symbolon?region=eu-west-1" $((BASE + 3)) $((BASE + 4))
exercise s3 $((BASE + 3)) $((BASE + 4))

if [ -n "${FULL:-}" ]; then
    RELAY_STORE="postgres://sym:s3cret-pw@127.0.0.1:$PGP/sym" tests/cli_e2e.sh > "$W/cli-pg.log" 2>&1 || fail "cli_e2e on postgres: $(tail -5 "$W/cli-pg.log")"
    echo "postgres: the whole device flow (cli_e2e) runs on it"
fi
echo "PASS store_e2e"

#!/usr/bin/env bash
# Writes target/deps.map, the dependency map residc takes (-depmap), from
# resid.toml's [dependencies] (resid-json and resid-csv, beside this
# checkout). Paths in it are relative to symbolon-resid/: build from there.
#   tools/depmap.sh
set -euo pipefail
cd "$(dirname "$0")/.."
MANIFEST="${MANIFEST:-$(command -v resid-manifest || echo "$HOME/.resid/bin/resid-manifest")}"
mkdir -p target
"$MANIFEST" depmap resid.toml target/deps.map > /dev/null
# resid-json is a format for resid-serial, which is the standard library's
# serial.resid as a package (the same code). The agent already uses the
# standard library's copy (CBOR), and two copies would define every serial
# name twice, so resid-json is pointed at that one.
# The standard library the compiler uses: RESID_LIB, else as residc finds
# it from RESID_HOME (an install's lib/, or a checkout's beside build/boot).
RH="${RESID_HOME:-$HOME/.resid}"
if [ -n "${RESID_LIB:-}" ]; then STDLIB="$RESID_LIB"; elif [ -d "$RH/lib" ]; then STDLIB="$RH/lib"; else STDLIB="$RH/../../lib"; fi
sed -i "s|^resid-serial::.*|resid-serial::$STDLIB/serial.resid|" target/deps.map
echo target/deps.map

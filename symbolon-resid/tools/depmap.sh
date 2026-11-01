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
STDLIB="${RESID_LIB:-$HOME/git/larry/resid/lib}"
sed -i "s|^resid-serial::.*|resid-serial::$STDLIB/serial.resid|" target/deps.map
echo target/deps.map

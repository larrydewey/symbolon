#!/usr/bin/env bash
# Builds the agent for Android (aarch64 for phones, x86_64 for the
# emulator), optimized, and puts it in the app as lib/<abi>/libsymbolon.so.
#   tools/bundle-agent.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$HERE/../symbolon-resid"
RC="${RESIDC:-$HOME/git/larry/resid/build/boot/residc}"
# Release builds (-O2, about ten times faster than debug) are signed: with
# RESID_SIGNING_KEY, else the Resid install's key.
export RESID_SIGNING_KEY="${RESID_SIGNING_KEY:-$HOME/.resid/keys/resid-ed25519.key}"
[ -f "$RESID_SIGNING_KEY" ] || { echo "no signing key: set RESID_SIGNING_KEY or run residc keygen"; exit 2; }
"$SRC/tools/depmap.sh" > /dev/null
build() {
  ( cd "$SRC" && ulimit -v 40000000 && ulimit -s unlimited && export RESID_MEM_LIMIT=10000 &&
    timeout 3000 "$RC" src/main.resid -o "$1" --verify-lib-dev -depmap target/deps.map "${@:2}" 2>&1 | grep -E "^error|wrote" )
}
build target/symbolon-aarch64 --target aarch64
build target/symbolon-x86_64
for abi in arm64-v8a x86_64; do mkdir -p "$HERE/android/app/src/main/jniLibs/$abi"; done
cp "$SRC/target/symbolon-aarch64" "$HERE/android/app/src/main/jniLibs/arm64-v8a/libsymbolon.so"
cp "$SRC/target/symbolon-x86_64" "$HERE/android/app/src/main/jniLibs/x86_64/libsymbolon.so"
ls -la "$HERE"/android/app/src/main/jniLibs/*/libsymbolon.so

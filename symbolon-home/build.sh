#!/usr/bin/env bash
# Builds the Symbolon Home image from the agent binaries
# (symbolon-resid/target/symbolon-x86_64 and -aarch64, release builds).
#   ./build.sh            the image for this machine, tagged symbolon-home
#   ./build.sh --multi    amd64 and arm64 (docker buildx), e.g. for a NAS
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
T="$HERE/../symbolon-resid/target"
mkdir -p "$HERE/bin"
cp "$T/symbolon-x86_64" "$HERE/bin/symbolon-amd64"
cp "$T/symbolon-aarch64" "$HERE/bin/symbolon-arm64"
if [ "${1:-}" = "--multi" ]; then
  docker buildx build --platform linux/amd64,linux/arm64 -t symbolon-home "$HERE"
else
  docker build -t symbolon-home "$HERE"
fi

#!/usr/bin/env bash
# Registers the Symbolon agent as the extension's native messaging host for
# the current user (SPEC 22.5), for Chromium-based browsers and Firefox.
#
#   install.sh AGENT UI [CHROMIUM_EXTENSION_ID]
#
# AGENT is the `symbolon` binary, UI the Symbolon app (the consent window).
# The default extension ID is the one the unpacked extension gets from the
# key in manifest.json. Run again after moving either binary.
set -euo pipefail

AGENT=$(readlink -f "$1")
UI=$(readlink -f "$2")
EXT_ID="${3:-kkhginlcfndkhicoihlaccmmahljipjp}"
FIREFOX_ID="browser@symbolon.dev"
NAME="dev.symbolon.browser"

for p in "$AGENT" "$UI"; do
    [ -x "$p" ] || { echo "not an executable: $p" >&2; exit 2; }
    case "$p" in *"'"*) echo "a path with a quote is not supported: $p" >&2; exit 2 ;; esac
done

DATA="${XDG_DATA_HOME:-$HOME/.local/share}/symbolon"
mkdir -p "$DATA"
WRAPPER="$DATA/browser-host"
cat > "$WRAPPER" <<EOF
#!/bin/sh
# Started by the browser for the Symbolon extension (install.sh).
export SYMBOLON_CONSENT='$UI'
exec '$AGENT' browser host "\$@"
EOF
chmod 755 "$WRAPPER"

chromium_manifest() {
    cat <<EOF
{
  "name": "$NAME",
  "description": "Symbolon agent",
  "path": "$WRAPPER",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://$EXT_ID/"]
}
EOF
}

firefox_manifest() {
    cat <<EOF
{
  "name": "$NAME",
  "description": "Symbolon agent",
  "path": "$WRAPPER",
  "type": "stdio",
  "allowed_extensions": ["$FIREFOX_ID"]
}
EOF
}

CONF="${XDG_CONFIG_HOME:-$HOME/.config}"
# SYMBOLON_PROFILES (space-separated browser profile directories) replaces
# the defaults and skips Firefox; the tests use it.
if [ -n "${SYMBOLON_PROFILES:-}" ]; then
    for d in $SYMBOLON_PROFILES; do
        mkdir -p "$d/NativeMessagingHosts"
        chromium_manifest > "$d/NativeMessagingHosts/$NAME.json"
        echo "registered for $d"
    done
    exit 0
fi
for d in "$CONF/chromium" "$CONF/google-chrome" "$CONF/google-chrome-beta" "$CONF/BraveSoftware/Brave-Browser" \
         "$CONF/microsoft-edge" "$CONF/vivaldi"; do
    # Chromium and Chrome always; the others only where they are installed.
    case "$d" in */chromium|*/google-chrome) ;; *) [ -d "$d" ] || continue ;; esac
    mkdir -p "$d/NativeMessagingHosts"
    chromium_manifest > "$d/NativeMessagingHosts/$NAME.json"
    echo "registered for $d"
done
mkdir -p "$HOME/.mozilla/native-messaging-hosts"
firefox_manifest > "$HOME/.mozilla/native-messaging-hosts/$NAME.json"
echo "registered for Firefox"

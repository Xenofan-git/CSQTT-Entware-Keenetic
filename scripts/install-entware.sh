#!/bin/sh
set -eu

PREFIX=/opt
APP="$PREFIX/etc/csqtt"
WPE_AUTH_REPO="${WPE_AUTH_REPO:-Xenofan-git/WPE-Auth-Entware}"
WPE_AUTH_REF="${WPE_AUTH_REF:-main}"

mkdir -p "$APP"
echo "[CSQTT] Installing ARM64 Entware manager..."
install -m 0755 ./CSQTT-Keenetic "$APP/CSQTT-Keenetic"
install -m 0644 ./config.example.json "$APP/config.example.json"

cat > "$APP/README-ARM64.txt" <<EOF
CSQTT ARM64/Entware
Manager: $APP/CSQTT-Keenetic
WPE auth source: https://github.com/$WPE_AUTH_REPO @ $WPE_AUTH_REF
CAPTCHA fallback: CSQTT Web Panel -> /captcha
EOF

echo "[CSQTT] Installed."
echo "[CSQTT] WPE remains a separate browser/auth component; install its published ARM64 artifact when available."
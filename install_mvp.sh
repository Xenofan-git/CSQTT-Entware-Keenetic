#!/bin/sh
set -eu
BASE=/opt/etc/csqtt
mkdir -p "$BASE"
cp CSQTT-Keenetic "$BASE/CSQTT-Keenetic"
chmod 755 "$BASE/CSQTT-Keenetic"
cp config.example.json "$BASE/config.json" 2>/dev/null || true
echo "Installed $BASE/CSQTT-Keenetic"

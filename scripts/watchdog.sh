#!/bin/sh
# CSQTT-Keenetic watchdog.
# The web panel is part of the manager process. If the manager dies OR
# TCP/2001 disappears after the startup grace period, restart the service.

BASE=/opt/etc/csqtt
INIT=/opt/etc/init.d/S99csqtt
PIDFILE="$BASE/manager.pid"
LOG="$BASE/watchdog.log"

sleep 15

while :; do
    sleep 30

    manager_ok=0
    if [ -f "$PIDFILE" ]; then
        pid=`cat "$PIDFILE" 2>/dev/null`
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            manager_ok=1
        fi
    fi

    panel_ok=0
    if command -v curl >/dev/null 2>&1; then
        code=`curl -sS -m 3 -o /dev/null -w '%{http_code}' http://127.0.0.1:2001/ 2>/dev/null || echo 000`
        case "$code" in
            2*|3*|401|403|405) panel_ok=1 ;;
        esac
    fi

    if [ "$manager_ok" -eq 0 ] || [ "$panel_ok" -eq 0 ]; then
        echo "`date '+%Y-%m-%d %H:%M:%S'` watchdog: manager_ok=$manager_ok panel_ok=$panel_ok; restarting" >>"$LOG"
        "$INIT" restart >>"$LOG" 2>&1
    fi
done

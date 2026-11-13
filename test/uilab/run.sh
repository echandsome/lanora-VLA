#!/usr/bin/env bash
# Runs inside the lanora-uilab container (see shots.sh). Builds the window
# for Linux, starts a server, a daemon and some room members, then walks the
# window through its screens, saving a screenshot of each to /out.
set -euo pipefail

export PATH=/go/bin:$PATH GOTOOLCHAIN=local GOMODCACHE=/gomod GOCACHE=/cache/gobuild GOFLAGS=-mod=readonly GOPROXY=off
THEME=${THEME:-light}
cd /src

echo "building…"
CGO_ENABLED=1 go build -tags lanoraui,nowayland,novulkan -o /tmp/lanora-ui ./cmd/lanora
for b in lanora-server lanora-cli lanora-bench; do CGO_ENABLED=0 go build -o /tmp/$b ./cmd/$b; done

SRV=http://127.0.0.1:18490
export LANORA_SOCKET=/tmp/lanora.sock DISPLAY=:99
Xvfb :99 -screen 0 400x660x24 -nolisten tcp >/dev/null 2>&1 &
LANORA_DATA_DIR=/tmp/srv LANORA_LISTEN=127.0.0.1:18490 LANORA_RELAY_LISTEN=127.0.0.1:18490 LANORA_TLS=off \
    LANORA_ADMIN_PASSWORD=uilab-admin-pw LANORA_TRUSTED_PROXIES=127.0.0.1 LANORA_LOG_LEVEL=warn /tmp/lanora-server &
for _ in $(seq 50); do curl -s -o /dev/null $SRV/healthz && break; sleep 0.2; done
curl -s -c /tmp/jar -o /dev/null $SRV/api/admin/login -H 'Content-Type: application/json' \
    -d '{"username":"admin","password":"uilab-admin-pw"}'
ROOM=$(curl -s -b /tmp/jar $SRV/api/admin/rooms -H 'Content-Type: application/json' \
    -d '{"name":"Friday LAN party","capacity":16,"password":"correct-horse-battery"}' | jq -r .room.public_id)
DISPLAY_ID=${ROOM:0:3}-${ROOM:3:3}-${ROOM:6:3}

shot() { sleep "${2:-0.8}"; import -window root "/out/$THEME-$1.png"; echo "  $1"; }
# A pause after each action: the window handles input once per frame, and a
# key arriving in the same frame as the previous text can be lost.
key()  { xdotool key --delay 40 "$@"; sleep 0.3; }
type_() { xdotool type --delay 15 "$1"; sleep 0.3; }

echo "screens ($THEME):"
LANORA_THEME=$THEME /tmp/lanora-ui >/tmp/ui.log 2>&1 &
shot 01-service-not-running 4
# With no window manager on the virtual display, nothing gives the window
# keyboard focus; do it by hand.
xdotool windowfocus "$(xdotool search --name Lanora | head -1)"

/tmp/lanora-cli daemon -state /tmp/state >/tmp/daemon.log 2>&1 &
shot 02-join-empty 3

# Other members: three that connect directly and two that only relay.
/tmp/lanora-bench -server $SRV -room "$ROOM" -room-password correct-horse-battery -mode full -clients 3 \
    -names "Mei,Jonas,阿明" -duration 30m >/dev/null 2>&1 &
/tmp/lanora-bench -server $SRV -room "$ROOM" -room-password correct-horse-battery -mode full -clients 2 \
    -names "Priya,Tomás" -relay-only -duration 30m >/dev/null 2>&1 &

type_ "$SRV"                           # the first field has the focus
key Tab; type_ "$DISPLAY_ID"
key Tab; type_ "wrong-password"
shot 03-join-filled
key Return
shot 04-join-wrong-password 3

type_ "correct-horse-battery"          # focus is back on the password
key Return
shot 05-room-just-joined 1.5
shot 06-room 9

xdotool mousemove 60 330 click 1      # a member row: copies its address
shot 07-room-address-copied 0.4

xdotool mousemove 374 30 click 1      # the settings button
shot 08-settings 1
xdotool mousemove 200 400; for _ in 1 2 3 4 5 6; do xdotool click 5; done
shot 09-settings-scrolled 1
xdotool mousemove 200 400; for _ in $(seq 20); do xdotool click 5; done
shot 10-settings-end 1
xdotool mousemove 30 30 click 1       # back

xdotool mousemove 200 630 click 1     # Leave room
shot 11-after-leaving 2

echo "daemon log tail:"; tail -5 /tmp/daemon.log || true
echo "ui log:"; cat /tmp/ui.log || true

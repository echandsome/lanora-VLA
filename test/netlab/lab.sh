#!/usr/bin/env bash
# Lanora network lab.
#
# Builds a small internet out of containers and runs the real server and the
# real headless client over real kernel network interfaces:
#
#     client-a ── lan-a ── nat-a ──┐
#                                  ├── wan ── server
#     client-b ── lan-b ── nat-b ──┘      └── client-c (public address)
#
# Each client sits behind its own NAT router on its own private network, so
# the two can only meet by hole punching or through the relay, exactly as two
# homes on the internet would. The NAT behaviour, packet loss and outages are
# then changed underneath the running clients.
#
# Usage:  test/netlab/lab.sh [scenario ...]     (default: all scenarios)
#         test/netlab/lab.sh down               (remove everything it created)
#
# Needs Docker and the binaries in dist/ (make build). Every container and
# network it creates is named lanora-lab-*; nothing else is touched.

set -euo pipefail
cd "$(dirname "$0")/../.."

P=lanora-lab
IMG=$P-node
WAN=10.250.0
LAN_A=192.168.110
LAN_B=192.168.120
SERVER_IP=$WAN.10
ADMIN_PW=lab-admin-password
ROOM_PW=lab-room-password

red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
step()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
info()  { printf '   %s\n' "$*"; }

PASSED=() FAILED=()

in_() { local c=$1; shift; docker exec "$P-$c" "$@"; }
sh_() { local c=$1; shift; docker exec "$P-$c" bash -c "$*"; }

down() {
    docker ps -aq --filter "name=^$P-" | xargs -r docker rm -f >/dev/null 2>&1 || true
    docker network ls -q --filter "name=^$P-" | xargs -r docker network rm >/dev/null 2>&1 || true
    docker volume ls -q --filter "name=^$P-" | xargs -r docker volume rm >/dev/null 2>&1 || true
}

node() { # node <name> <network> <ip> [docker run args...]
    local name=$1 net=$2 ip=$3; shift 3
    docker run -d --name "$P-$name" --hostname "$name" --network "$P-$net" --ip "$ip" \
        -v "$PWD/dist:/lanora:ro" "$@" "$IMG" sleep infinity >/dev/null
}

# nat_mode <router> cone|symmetric
#   cone:      one public port per client socket, whatever the destination
#              (what most home routers do; hole punching works).
#   symmetric: a different random public port for every destination
#              (carrier-grade and some corporate NATs; hole punching cannot
#              work and the relay must be used).
nat_mode() {
    local r=$1 mode=$2 flag=""
    [ "$mode" = symmetric ] && flag="--random-fully"
    # Like a real home router, the lab router also firewalls its public
    # side: only replies to traffic that started inside get in. (Without
    # this the router itself would accept an early probe from the other
    # side, and connection tracking would then move the client's mapping to
    # another port.)
    sh_ "$r" "wan=\$(ip -o -4 addr show | awk '/$WAN\\./{print \$2}'); \
        iptables -t nat -F POSTROUTING; iptables -F INPUT; iptables -F FORWARD; \
        iptables -t nat -A POSTROUTING -o \$wan -j MASQUERADE $flag; \
        for chain in INPUT FORWARD; do \
            iptables -A \$chain -i \$wan -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; \
            iptables -A \$chain -i \$wan -j DROP; \
        done; \
        conntrack -F >/dev/null 2>&1 || true"
}

api() { # api <method> <path> [json]  — administrator API, from inside the server container
    local method=$1 path=$2 body=${3:-}
    if [ -n "$body" ]; then
        in_ server curl -sk -b /tmp/jar -X "$method" "https://127.0.0.1:8443$path" -H 'Content-Type: application/json' -d "$body"
    else
        in_ server curl -sk -b /tmp/jar -X "$method" "https://127.0.0.1:8443$path"
    fi
}

up() {
    [ -x dist/lanora-server ] && [ -x dist/lanora-cli ] || { red "dist/lanora-server and dist/lanora-cli are missing; run: make build"; exit 1; }
    down
    step "building the lab"
    docker build -q -t "$IMG" test/netlab >/dev/null
    docker network create --subnet $WAN.0/24 "$P-wan" >/dev/null
    docker network create --internal --subnet $LAN_A.0/24 "$P-lan-a" >/dev/null
    docker network create --internal --subnet $LAN_B.0/24 "$P-lan-b" >/dev/null
    docker volume create "$P-data" >/dev/null

    docker run -d --name "$P-server" --hostname server --network "$P-wan" --ip $SERVER_IP \
        -v "$PWD/dist:/lanora:ro" -v "$P-data:/data" \
        -e LANORA_DATA_DIR=/data -e LANORA_ADMIN_PASSWORD=$ADMIN_PW -e LANORA_LOG_LEVEL=info \
        "$IMG" /lanora/lanora-server >/dev/null

    for r in a b; do
        local lan=LAN_${r^^}
        node "nat-$r" wan "$WAN.$([ $r = a ] && echo 2 || echo 3)" --cap-add NET_ADMIN --sysctl net.ipv4.ip_forward=1
        docker network connect --ip "${!lan}.2" "$P-lan-$r" "$P-nat-$r"
        nat_mode "nat-$r" cone
        node "client-$r" "lan-$r" "${!lan}.10" --cap-add NET_ADMIN --device /dev/net/tun
        in_ "client-$r" ip route replace default via "${!lan}.2"
    done
    node client-c wan $WAN.20 --cap-add NET_ADMIN --device /dev/net/tun

    for _ in $(seq 50); do in_ server curl -sk -o /dev/null https://127.0.0.1:8443/healthz && break; sleep 0.2; done
    PIN=$(in_ server env LANORA_DATA_DIR=/data /lanora/lanora-server pin)
    SERVER_URL="https://$SERVER_IP:8443/#pin=$PIN"
    in_ server curl -sk -c /tmp/jar -o /dev/null https://127.0.0.1:8443/api/admin/login \
        -H 'Content-Type: application/json' -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PW\"}"
    ROOM_JSON=$(api POST /api/admin/rooms "{\"name\":\"lab\",\"capacity\":8,\"password\":\"$ROOM_PW\"}")
    ROOM=$(jq -r .room.public_id <<<"$ROOM_JSON"); ROOM_DB=$(jq -r .room.id <<<"$ROOM_JSON")
    ROOM2=$(api POST /api/admin/rooms "{\"name\":\"other\",\"capacity\":8,\"password\":\"$ROOM_PW\"}" | jq -r .room.public_id)
    info "server $SERVER_URL"
    info "rooms  $ROOM (lab), $ROOM2 (other)"
}

start_client() { # start_client <name> [room] [extra lanora-cli args...]
    local c=$1 room=${2:-$ROOM}; shift; shift || true
    sh_ "client-$c" "pkill lanora-cli 2>/dev/null; sleep 0.3; : > /var/log/lanora.json"
    docker exec -d -e LANORA_PASSWORD=$ROOM_PW "$P-client-$c" bash -c \
        "/lanora/lanora-cli up -server '$SERVER_URL' -room $room -nickname $c -state /state -json $* >>/var/log/lanora.json 2>>/var/log/lanora.err"
}

state() { in_ "client-$1" tail -n 1 /var/log/lanora.json 2>/dev/null || true; }
vip()   { state "$1" | jq -r '.ip // empty'; }

# wait_for <client> <seconds> <jq filter that must become true> <description>
wait_for() {
    local c=$1 secs=$2 filter=$3 what=$4 deadline=$((SECONDS + $2))
    while [ $SECONDS -lt $deadline ]; do
        if state "$c" | jq -e "$filter" >/dev/null 2>&1; then return 0; fi
        sleep 0.3
    done
    red "   $c: timed out after ${secs}s waiting for $what"
    info "last state: $(state "$c")"
    return 1
}
via() { echo ".phase==\"connected\" and ([.peers[] | select(.ip==\"$1\") | .via] == [\"$2\"])"; }

ping_ok() { # ping_ok <from> <to-ip> [count]
    in_ "client-$1" ping -q -c "${3:-3}" -i 0.2 -W 2 "$2" >/dev/null
}

relay_bytes() { api GET /api/admin/overview | jq -r '.live.relay.bytes'; }

run() { # run <scenario function>
    step "$1"
    if "$1"; then green "   PASS $1"; PASSED+=("$1"); else red "   FAIL $1"; FAILED+=("$1"); fi
}

# --- scenarios ---------------------------------------------------------------

# Two homes with ordinary routers: the clients must find a direct path.
direct_path() {
    nat_mode nat-a cone; nat_mode nat-b cone
    start_client a; start_client b
    wait_for a 30 '.phase=="connected"' "connect" && wait_for b 30 '.phase=="connected"' "connect" || return 1
    A=$(vip a); B=$(vip b)
    info "virtual addresses: a=$A b=$B"
    wait_for a 30 "$(via "$B" direct)" "a direct path to b" && wait_for b 30 "$(via "$A" direct)" "a direct path to a" || return 1
    info "a reaches b at $(state a | jq -r '.peers[0].addr'), b reaches a at $(state b | jq -r '.peers[0].addr')"
    ping_ok a "$B" 5 && ping_ok b "$A" 5 || { red "   ping across the overlay failed"; return 1; }
    local rtt; rtt=$(in_ client-a ping -q -c 10 -i 0.1 "$B" | awk -F/ '/rtt|round-trip/{print $5}')
    info "overlay round trip: ${rtt} ms"
}

# Bulk transfer over the direct path must not touch the relay.
throughput_and_file_transfer() {
    local before after mbps sum_a sum_b
    before=$(relay_bytes)
    sh_ client-b "pkill iperf3 2>/dev/null; iperf3 -s -D -B $B >/dev/null"
    sleep 1
    mbps=$(in_ client-a iperf3 -c "$B" -t 5 -J | jq -r '.end.sum_received.bits_per_second/1e6 | floor')
    info "TCP throughput a→b through the tunnel: ${mbps} Mbit/s"
    [ "$mbps" -gt 20 ] || { red "   throughput is implausibly low"; return 1; }

    sh_ client-a "head -c 67108864 /dev/urandom > /tmp/payload.bin"
    sum_a=$(sh_ client-a "sha256sum /tmp/payload.bin | cut -d' ' -f1")
    docker exec -d "$P-client-a" bash -c "cd /tmp && exec python3 -m http.server 8000 --bind $A >/dev/null 2>&1"
    for _ in $(seq 50); do sh_ client-b "curl -s -o /dev/null --max-time 2 -I http://$A:8000/" && break; sleep 0.2; done
    sum_b=$(sh_ client-b "curl -s --max-time 120 http://$A:8000/payload.bin | sha256sum | cut -d' ' -f1")
    in_ client-a pkill python3 || true
    [ "$sum_a" = "$sum_b" ] || { red "   the 64 MB file arrived corrupted or incomplete"; return 1; }
    info "64 MB file transferred b←a, SHA-256 matches"

    after=$(relay_bytes)
    info "bytes through the relay during the transfers: $((after - before))"
    [ $((after - before)) -lt 1000000 ] || { red "   bulk traffic went through the relay although a direct path existed"; return 1; }
}

# LAN discovery: what a game lobby or mDNS sends must reach the other member.
broadcast_and_multicast() {
    local listener='
import socket, struct, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("", 4445))
mreq = struct.pack("4s4s", socket.inet_aton("224.0.2.60"), socket.inet_aton(sys.argv[1]))
s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
s.settimeout(15)
seen = set()
try:
    while len(seen) < 3:
        data, addr = s.recvfrom(2000)
        seen.add(data.decode())
        print(data.decode(), "from", addr[0], flush=True)
except socket.timeout:
    pass
'
    local sender='
import socket, sys
me = sys.argv[1]
def send(dst, text, opts=()):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    for o in opts: s.setsockopt(*o)
    s.bind((me, 0))
    s.sendto(text.encode(), (dst, 4445))
for _ in range(3):
    send(sys.argv[2], "subnet-broadcast")
    send("255.255.255.255", "limited-broadcast", [(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"lanora0")])
    send("224.0.2.60", "multicast", [(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(me))])
'
    docker exec -d "$P-client-b" bash -c "python3 -c '$listener' $B > /tmp/heard.txt 2>&1"
    sleep 1
    in_ client-a python3 -c "$sender" "$A" "${A%.*}.255"
    sleep 2
    local heard; heard=$(in_ client-b cat /tmp/heard.txt)
    for kind in subnet-broadcast limited-broadcast multicast; do
        grep -q "^$kind from $A" <<<"$heard" || { red "   b never received the $kind packet from a"; info "heard: $heard"; return 1; }
    done
    info "b received a's subnet broadcast, limited broadcast and multicast, each from $A"
}

# Signalling must not be a single point of failure for members already
# connected, and they must come back by themselves when the server returns.
server_restart() {
    docker stop -t 5 "$P-server" >/dev/null
    info "server stopped"
    wait_for a 20 '.phase=="reconnecting"' "notice the server is gone" || return 1
    ping_ok a "$B" 5 || { red "   members lost each other when the server went away"; return 1; }
    info "a and b still reach each other with the server down"
    docker start "$P-server" >/dev/null
    for _ in $(seq 50); do in_ server curl -sk -o /dev/null https://127.0.0.1:8443/healthz && break; sleep 0.2; done
    in_ server curl -sk -c /tmp/jar -o /dev/null https://127.0.0.1:8443/api/admin/login \
        -H 'Content-Type: application/json' -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PW\"}"
    # While the clients find the server again, one at a time, they must stay
    # connected to each other: ping throughout and count what is lost.
    docker exec -d "$P-client-a" bash -c "ping -q -i 0.2 -w 40 $B > /tmp/restart-ping.txt 2>&1"
    local t0=$SECONDS
    wait_for a 60 '.phase=="connected"' "reconnect" && wait_for b 60 '.phase=="connected"' "reconnect" || return 1
    info "both clients reconnected $((SECONDS - t0))s after the server came back"
    sleep 3
    in_ client-a pkill -INT ping || true
    sleep 0.5
    local loss; loss=$(in_ client-a grep -o '[0-9.]*% packet loss' /tmp/restart-ping.txt | cut -d% -f1)
    info "packets lost between a and b while reconnecting: ${loss}%"
    [ -n "$loss" ] && [ "${loss%.*}" -le 2 ] || { red "   members lost each other while reconnecting to the restarted server"; return 1; }
    ping_ok a "$B" 3
}

# A router that loses all its state (reboot, or the mapping simply expires).
nat_rebinding() {
    in_ nat-a conntrack -F >/dev/null 2>&1
    info "nat-a forgot every mapping"
    local ok=0
    for _ in $(seq 40); do if ping_ok a "$B" 1; then ok=1; break; fi; sleep 0.5; done
    [ $ok = 1 ] || { red "   connectivity did not come back"; return 1; }
    wait_for a 40 "$(via "$B" direct)" "the direct path again" || return 1
    info "connectivity restored, direct path re-established"
}

# The line goes dead for a while, then comes back.
outage_and_recovery() {
    sh_ nat-a "iptables -I FORWARD -j DROP"
    info "a's uplink cut"
    sleep 12
    if ping_ok a "$B" 1; then red "   traffic still flows through a dead link?"; return 1; fi
    sh_ nat-a "iptables -D FORWARD -j DROP"
    local t0=$SECONDS ok=0
    for _ in $(seq 80); do if ping_ok a "$B" 1; then ok=1; break; fi; sleep 0.5; done
    [ $ok = 1 ] || { red "   connectivity did not come back after the outage"; return 1; }
    info "traffic resumed $((SECONDS - t0))s after the uplink returned"
    wait_for a 60 '.phase=="connected"' "signalling to reconnect" || return 1
    wait_for a 60 "$(via "$B" direct)" "the direct path again"
}

# Both sides behind NATs that defeat hole punching: the relay must carry it.
symmetric_nat_uses_relay() {
    nat_mode nat-a symmetric; nat_mode nat-b symmetric
    start_client a; start_client b
    wait_for a 30 '.phase=="connected"' "connect" && wait_for b 30 '.phase=="connected"' "connect" || return 1
    wait_for a 40 "$(via "$B" relay)" "the relay path to b" && wait_for b 40 "$(via "$A" relay)" "the relay path to a" || return 1
    ping_ok a "$B" 5 || { red "   ping through the relay failed"; return 1; }
    local before after mbps
    before=$(relay_bytes)
    sh_ client-b "pkill iperf3 2>/dev/null; iperf3 -s -D -B $B >/dev/null"; sleep 1
    mbps=$(in_ client-a iperf3 -c "$B" -t 4 -J | jq -r '.end.sum_received.bits_per_second/1e6 | floor')
    after=$(relay_bytes)
    info "TCP throughput through the relay: ${mbps} Mbit/s ($(( (after - before) / 1000000 )) MB relayed)"
    [ "$mbps" -gt 5 ] && [ $((after - before)) -gt 1000000 ]
}

# One side cannot send UDP at all: the relay's TCP transport must take over,
# and UDP must be picked up again once it works.
udp_blocked_falls_back_to_tcp() {
    sh_ nat-a "iptables -I FORWARD -p udp -j DROP"
    start_client a
    wait_for a 30 '.phase=="connected"' "connect" || return 1
    wait_for a 40 '.relay=="tcp"' "the TCP relay" || return 1
    wait_for a 40 "$(via "$B" relay)" "the relay path to b" || return 1
    ping_ok a "$B" 5 || { red "   ping over the TCP relay failed"; return 1; }
    info "a is relaying over TCP and reaches b"
    sh_ nat-a "iptables -D FORWARD -p udp -j DROP"
    wait_for a 60 '.relay=="udp"' "UDP relaying to resume" || return 1
    info "a switched back to UDP once it worked again"
    ping_ok a "$B" 3
}

# A member of another room must not be able to reach this one's members.
rooms_are_isolated() {
    nat_mode nat-a cone; nat_mode nat-b cone
    start_client a; start_client b; start_client c "$ROOM2"
    wait_for a 30 '.phase=="connected"' "connect" && wait_for b 30 '.phase=="connected"' "connect" &&
        wait_for c 30 '.phase=="connected"' "connect" || return 1
    A=$(vip a); B=$(vip b); local C; C=$(vip c)
    info "room 1: a=$A b=$B   room 2: c=$C"
    [ "${A%.*}" != "${C%.*}" ] || { red "   two rooms share a subnet"; return 1; }
    wait_for a 30 "$(via "$B" direct)" "a direct path to b" || return 1
    ping_ok a "$B" 3 || return 1
    [ "$(state c | jq '.peers | length')" = 0 ] || { red "   c sees members of another room"; return 1; }
    if ping_ok c "$A" 2; then red "   c reached a member of another room"; return 1; fi
    info "c cannot reach room 1"
}

# Removing a member from the dashboard takes effect immediately.
kick_and_ban() {
    local member; member=$(api GET "/api/admin/rooms/$ROOM_DB" | jq -r '.members[] | select(.nickname=="b") | .id')
    api POST "/api/admin/rooms/$ROOM_DB/members/$member/ban" '{"reason":"lab test"}' >/dev/null
    wait_for b 15 '.phase=="stopped" and .error_code=="banned"' "b to be told it is banned" || return 1
    wait_for a 15 '.peers | length == 0' "a to see b leave" || return 1
    if ping_ok a "$B" 2; then red "   a still reaches the banned member"; return 1; fi
    start_client b
    wait_for b 20 '.phase=="stopped" and .error_code=="banned"' "the rejoin to be refused" || return 1
    info "b was disconnected, cannot rejoin, and is unreachable from a"
    api POST "/api/admin/rooms/$ROOM_DB/members/$member/unban" >/dev/null
}

ALL=(direct_path throughput_and_file_transfer broadcast_and_multicast server_restart nat_rebinding
     outage_and_recovery symmetric_nat_uses_relay udp_blocked_falls_back_to_tcp rooms_are_isolated kick_and_ban)

if [ "${1:-}" = down ]; then down; exit 0; fi
trap 'if [ "${KEEP:-0}" != 1 ]; then down; fi' EXIT
up
if [ $# -gt 0 ]; then SCENARIOS=("$@"); else SCENARIOS=("${ALL[@]}"); fi
for s in "${SCENARIOS[@]}"; do run "$s"; done

step "summary"
green "   passed: ${#PASSED[@]}  ${PASSED[*]:-}"
if [ ${#FAILED[@]} -gt 0 ]; then red "   failed: ${#FAILED[@]}  ${FAILED[*]}"; exit 1; fi

# Node image for the network lab: routers, the server and the clients all
# run from it. The Lanora binaries are mounted in, not baked in.
FROM alpine:3.20
RUN apk add --no-cache bash iproute2 iptables iputils iperf3 socat conntrack-tools python3 curl jq coreutils

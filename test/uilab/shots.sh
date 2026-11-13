#!/usr/bin/env bash
# Builds the Lanora window for Linux in a container, runs it against a real
# server, daemon and room members on a virtual display, and saves a
# screenshot of every screen.
#
# Usage: test/uilab/shots.sh <output directory> [light|dark]
#
# The window is a Windows program; this is how its layout is checked on a
# development machine without one. Fonts differ from Windows (Inter stands
# in for Segoe UI); everything else is drawn by the same code.
set -euo pipefail
cd "$(dirname "$0")/../.."
OUT=$(mkdir -p "${1:?output directory}" && cd "$1" && pwd)
THEME=${2:-light}
GOSDK=$(dirname "$(dirname "$(command -v go)")")
docker build -q -t lanora-uilab test/uilab >/dev/null
docker run --rm --name lanora-uilab --cap-add NET_ADMIN --device /dev/net/tun \
    -v "$PWD:/src:ro" -v "$GOSDK:/go:ro" -v "$(go env GOMODCACHE):/gomod:ro" \
    -v lanora-uilab-cache:/cache -v "$OUT:/out" -e THEME="$THEME" \
    lanora-uilab bash /src/test/uilab/run.sh

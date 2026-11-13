#!/usr/bin/env bash
# Runs the Windows builds of Lanora under Wine, in a container.
#
# Usage: test/winelab/lab.sh [scenario ...]        (no arguments: all of them)
#        VERBOSE=1 test/winelab/lab.sh ...         (show each scenario's output)
#
# Nothing here stands in for a test on Windows: Wine is a reimplementation,
# it has no network drivers, and it does not enforce Windows' permissions.
# What it does offer is a place where the Windows-only code runs at all, and
# above all a place to load the real wintun.dll against a planted adapter of
# the kind Astrill VPN has, with and without Lanora's safeguards, and see
# what happens to it. docs/TESTING.md says what each scenario shows.
set -euo pipefail
cd "$(dirname "$0")/../.."
command -v go >/dev/null || { echo "go must be on PATH" >&2; exit 1; }

IN=$(mktemp -d)
trap 'rm -rf "$IN"' EXIT
echo "building…"
export GOFLAGS=-mod=readonly CGO_ENABLED=0
GOOS=windows GOARCH=amd64 go test -c -o "$IN/netcfg.test.exe" ./internal/client/netcfg
GOOS=windows GOARCH=amd64 go test -c -o "$IN/ipc.test.exe" ./internal/client/ipc
GOOS=windows GOARCH=amd64 go build -o "$IN/lanora-cli.exe" ./cmd/lanora-cli
GOOS=windows GOARCH=amd64 go build -ldflags "-H windowsgui" -o "$IN/Lanora.exe" ./cmd/lanora
go build -o "$IN/lanora-server" ./cmd/lanora-server
chmod -R a+rX "$IN"

docker build -q -t lanora-winelab test/winelab >/dev/null
docker run --rm --name lanora-winelab -e VERBOSE="${VERBOSE:-}" -v "$IN:/in:ro" -v "$PWD/test/winelab:/lab:ro" \
    lanora-winelab bash /lab/run.sh "$@"

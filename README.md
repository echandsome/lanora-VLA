# Lanora

Lanora puts computers in different places on one virtual LAN. People join a
**room** with an ID and a password; from then on their PCs can reach each
other as if they shared a home network: LAN games find each other, shared
folders open, anything that works on a LAN works.

It is a self-hosted alternative to Radmin VPN, written in Go. You run the
server; your players run a single Windows `.exe`. Developed by Jack.

- **Peer to peer first.** Members connect directly through their routers
  (UDP hole punching). A relay carries traffic only for pairs that cannot,
  with a TCP fallback for networks that block UDP.
- **Behaves like a LAN.** Broadcast and multicast reach every member, so
  discovery works, not just connections by address.
- **Encrypted end to end** with WireGuard. The relay never sees content.
- **Built to run next to another VPN**, Astrill in particular: one adapter
  with one address, no default route, no DNS changes, nothing left behind
  when you leave a room.
- **A dashboard** for rooms, members, live connections, logs and settings.

## Status

| | |
|---|---|
| Server, relay, protocol, client engine | Tested on Linux: unit, security, end-to-end, real NAT traversal in a container lab, 5,000-client load |
| Dashboard | Every page and action driven in a headless browser against a live server |
| Windows app | **Never run on Windows.** Its window has run on Linux, and the rest under Wine as far as Wine allows (not as far as creating the adapter) |
| Astrill coexistence | **Never run next to Astrill.** The way other Wintun programs delete Astrill's adapter, and Lanora's defence, have been reproduced under Wine with the real `wintun.dll` |

The Windows side needs testing on real machines before this is finished.
[docs/TESTING.md](docs/TESTING.md) has the procedure. Its first step,
`lanora-cli.exe doctor`, checks a PC without creating or loading anything,
so it is safe to run next to Astrill.

## Quick start

**Server** (any Linux host with Docker):

```sh
cp .env.example .env      # set LANORA_ADMIN_PASSWORD
docker compose up -d
docker compose logs lanora    # shows the address clients must use
```

Open `https://<host>:8443/`, sign in as `admin`, create a room. See
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md), including the simpler set-up with a
domain name.

**Windows app:**

```sh
make windows SERVER='https://<host>:8443/#pin=sha256:...'    # dist/Lanora.exe
```

Give `Lanora.exe` to your players. They start it, approve the one-time
installation, enter the room ID and password. See
[docs/WINDOWS.md](docs/WINDOWS.md).

**Linux client** (headless, as root):

```sh
make build
LANORA_PASSWORD='...' dist/lanora-cli up -server 'https://...' -room 7KQ-2MX-9DW
```

## Building and testing

Requires Go 1.27 or later. Docker is needed only for the image and the
labs.

```sh
make build        # dist/lanora-server, lanora-cli, lanora-bench
make windows      # dist/Lanora.exe, Lanora-arm64.exe, lanora-cli.exe
make test         # unit and end-to-end tests
make test-race    # the same under the race detector
make lab          # real networking behind NAT, in containers
make winelab      # the Windows builds under Wine, in a container
make ui-shots     # screenshots of every screen of the window
make docker       # the server image
```

## Documentation

| | |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | How it works and why, including the Astrill analysis |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Running the server: Docker, TLS, configuration, scaling, backups |
| [docs/WINDOWS.md](docs/WINDOWS.md) | Installing, using, building and distributing the Windows app |
| [docs/TESTING.md](docs/TESTING.md) | What was tested, results, and what you still need to test |
| [docs/SECURITY.md](docs/SECURITY.md) | What is protected, how, and what is not |

## Layout

```
cmd/            lanora-server, lanora (Windows app), lanora-cli, lanora-bench
internal/proto  the wire protocol shared by server and clients
internal/server store (SQLite), auth, hub (signalling), relay, api
internal/client engine, transport, vnet, netcfg, daemon, ipc, winsvc, ui
internal/e2e    end-to-end tests
web/admin       the dashboard
test/netlab     container network lab
test/winelab    the Windows builds under Wine
test/uilab      window screenshots on a virtual display
deploy/         Compose files for a domain name and for relay nodes
build/windows   icon and resource definitions for the .exe
docs/           documentation
```

## Licence and contributing

Lanora is released under the [MIT licence](LICENSE): anyone may use, change
and redistribute it, provided the copyright notice is kept.

Pull requests are welcome. By opening one you agree that your contribution is
licensed under the same MIT licence. Please run `make test` and `make vet`
first, and describe what you tested; changes to how the Windows adapter is
set up need a note on how they were checked next to another VPN.

## Third-party software

Lanora builds on WireGuard's Go implementation and Wintun (WireGuard LLC),
Gio (UI), systray, go-winio, the Go extended libraries, coder/websocket and
modernc.org/sqlite. `Lanora.exe` contains the unmodified, signed Wintun
library; its licence is in `internal/client/netcfg/wintun/LICENSE.txt` and
must accompany redistribution. The dashboard vendors Preact (MIT) and htm
(Apache-2.0); both licences are in `web/admin/vendor/`.

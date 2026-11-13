# Deploying the Lanora server

The server is one program, `lanora-server`, with one data directory. It
serves the client API, the dashboard and the relay.

## What you need

- A Linux host with a public IP address. A small VPS is enough: plan about
  50 KB of memory per connected client, plus up to 19 MiB per CPU core while
  people are joining.
- Docker with Compose, or just the `lanora-server` binary.
- Two open ports of the **same number**, one TCP and one UDP (default 8443).
  TCP carries HTTPS: the API, the dashboard and the relay's TCP fallback. UDP
  carries the relay. If the host or cloud provider has a firewall, open both.

## Quick start with Docker

```sh
cp .env.example .env          # set LANORA_ADMIN_PASSWORD (10+ characters)
docker compose up -d
docker compose logs lanora
```

The log shows the address clients must use:

```
self-signed certificate in use: clients must add this pin to the server address
example="https://<this-host>:8443/#pin=sha256:UM1MrE7p..."
```

Replace `<this-host>` with the server's IP address or name. That whole
string, including the part after `#`, is the **server address** to enter in
the Lanora app (or to build into it, see [WINDOWS.md](WINDOWS.md)). The pin is
the fingerprint of the server's certificate; it lets clients trust exactly
this server without a certificate authority. `docker compose exec lanora
/usr/local/bin/lanora-server pin` prints it again.

Then open `https://<this-host>:8443/` in a browser (the browser will warn
about the self-signed certificate; that is expected in this mode), sign in as
`admin`, and create a room. The room's ID and password are what you give to
players.

If you left `LANORA_ADMIN_PASSWORD` empty, a password was generated and
printed once in the log at first start.

## With a domain name (recommended)

With a host name pointing at the server, Lanora gets a certificate from Let's
Encrypt and renews it by itself. Browsers show no warning and clients need no
pin: the server address is just `https://lan.example.com`.

```sh
LANORA_DOMAIN=lan.example.com docker compose -f deploy/docker-compose.domain.yml up -d
```

This needs TCP 80, TCP 443 and UDP 443 reachable from the internet.

## Without Docker

```sh
make build
LANORA_DATA_DIR=/var/lib/lanora LANORA_ADMIN_PASSWORD='...' dist/lanora-server
```

A systemd unit:

```ini
[Unit]
Description=Lanora server
After=network-online.target
Wants=network-online.target

[Service]
User=lanora
Environment=LANORA_DATA_DIR=/var/lib/lanora
EnvironmentFile=/etc/lanora.env
ExecStart=/usr/local/bin/lanora-server
Restart=on-failure
LimitNOFILE=65536
# Needed only to listen on ports below 1024:
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

## Configuration

Everything that needs a restart is an environment variable. `lanora-server
help` prints this list.

| Variable | Default | Meaning |
|---|---|---|
| `LANORA_MODE` | `server` | `server`, or `relay` for a stand-alone relay node |
| `LANORA_DATA_DIR` | `./data` | Database and generated certificates |
| `LANORA_LISTEN` | `:8443` | TCP address for HTTPS |
| `LANORA_TLS` | `selfsigned` | `selfsigned`, `autocert` (Let's Encrypt), `files`, or `off` (only behind a TLS-terminating proxy) |
| `LANORA_TLS_DOMAINS` | | Host names for `autocert`, comma-separated |
| `LANORA_TLS_CERT`, `LANORA_TLS_KEY` | | Certificate chain and key for `files` |
| `LANORA_ACME_LISTEN` | `:80` | HTTP address for certificate challenges (`autocert`) |
| `LANORA_ACME_EMAIL` | | Contact address given to Let's Encrypt (optional) |
| `LANORA_RELAY_LISTEN` | port of `LANORA_LISTEN` | UDP address of the built-in relay |
| `LANORA_RELAY_PUBLIC` | | Relay address told to clients, as `host:port` or `:port`, when it differs from how they reach the API |
| `LANORA_RELAYS` | | Stand-alone relay nodes, `host:port` comma-separated; replaces the built-in relay |
| `LANORA_RELAY_SECRET` | | Secret shared with stand-alone relays (16+ characters) |
| `LANORA_SECRET` | generated | Master signing secret. Stored in the database when not set |
| `LANORA_ADMIN_USER`, `LANORA_ADMIN_PASSWORD` | `admin`, generated | The first administrator, created on an empty database only |
| `LANORA_TRUSTED_PROXIES` | | CIDRs of reverse proxies whose `X-Forwarded-For` is believed |
| `LANORA_METRICS_TOKEN` | | Enables `GET /metrics` (Prometheus format) for requests carrying this bearer token |
| `LANORA_DEBUG_LISTEN` | | Address for Go's profiling endpoints. Unauthenticated: bind to `127.0.0.1` only |
| `LANORA_LOG_LEVEL`, `LANORA_LOG_FORMAT` | `info`, `text` | `debug`/`info`/`warn`/`error`; `text`/`json` |

Settings that can change while running are in the dashboard under Settings:
server name, the address pool rooms are carved from, MTU, default room
capacity, the room limit, session lifetimes, the per-client relay rate limit,
log retention and the minimum client version.

### The address pool

Each room gets a `/24` from the pool (default `10.214.0.0/16`, 256 rooms; a
`/12` gives 4,096). Changing the pool affects new rooms only. A room can also
be given a specific `/24` when it is created.

Do not use `198.18.0.0/15` (Astrill's tunnel uses it), and avoid ranges your
players' home routers use (`192.168.0.0/16`, `10.0.0.0/24`). If a player's
network does overlap a room's range, their Lanora app refuses to connect and
says why, rather than breaking their network.

## Behind a reverse proxy

Set `LANORA_TLS=off`, bind to a local address, and list the proxy in
`LANORA_TRUSTED_PROXIES` so rate limits and the log see real client
addresses. The proxy must pass WebSocket upgrades for `/api/v1/session` and
`/api/v1/relay`, and must not buffer `/api/admin/stream`. **The UDP relay
cannot go through an HTTP proxy**: publish it directly and set
`LANORA_RELAY_PUBLIC` if its address differs from the proxy's.

## More relay capacity

Relaying is the only part whose cost grows with traffic, and it only carries
traffic for members who cannot reach each other directly. Relay nodes hold no
data and can be added at any time:

```sh
# on each relay host
LANORA_RELAY_SECRET='the same long random string everywhere' \
    docker compose -f deploy/docker-compose.relay.yml up -d

# on the control server, in .env, then restart it
LANORA_RELAY_SECRET=the same long random string everywhere
LANORA_RELAYS=relay1.example.com:8443,relay2.example.com:8443
```

Each room is assigned to one node. The control server probes the nodes every
10 seconds, stops assigning rooms to one that fails three probes, and moves
its rooms. On a stand-alone node a removed member's relay access ends when
its ticket expires (within 30 minutes) rather than immediately as with the
built-in relay; this matters little, since other members have already dropped
its key.

For the relay's TCP fallback to work on a stand-alone node, the node needs a
certificate clients trust (`LANORA_TLS=autocert` or `files`).

## Operations

**Health.** `GET /healthz` answers when the process is up; `GET /readyz`
also checks the database. The container image has a health check built in.

**Logs.** The process logs to standard error. Joins, departures, failed
sign-ins, lockouts and administrator actions are also in the dashboard under
Logs, kept for the configured number of days.

**Backup.** The only state is the data directory. To copy the database while
the server runs:

```sh
docker compose exec lanora /usr/local/bin/lanora-server backup /data/backup-$(date +%F).db
```

Keep `tls/` too if you use the self-signed mode: clients pin that key, and
replacing it means giving every client a new server address.

**Upgrade.** Replace the binary or image and restart. Schema changes are
applied at start. Connected members keep their connections to each other
during the restart and reconnect to the server by themselves.

**Lost administrator password.**

```sh
docker compose exec lanora /usr/local/bin/lanora-server reset-password admin
```

**Memory.** Resident memory can sit well above what the server is using after
a burst of joins. Set `GOMEMLIMIT` (for example `400MiB`) to cap it.

**File descriptors.** One per connected client. The Compose files raise the
limit to 65,536.

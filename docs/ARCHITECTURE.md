# Lanora architecture

Lanora puts computers in different places on one virtual LAN. This document
explains how it is built and why, starting with the requirement that shaped
the Windows side most: running next to Astrill VPN without disturbing it.

Contents

1. [The parts](#1-the-parts)
2. [Coexisting with Astrill VPN](#2-coexisting-with-astrill-vpn)
3. [The data plane](#3-the-data-plane)
4. [Finding a path: direct, relayed, relayed over TCP](#4-finding-a-path)
5. [Behaving like a LAN](#5-behaving-like-a-lan)
6. [The control plane](#6-the-control-plane)
7. [The Windows client](#7-the-windows-client)
8. [Scaling](#8-scaling)
9. [Limits and things deliberately left out](#9-limits)
10. [Source map](#10-source-map)

Security has its own document: [SECURITY.md](SECURITY.md).

## 1. The parts

```
                      ┌───────────────────────────────────────────────┐
                      │                 lanora-server                 │
   administrator ───▶ │  dashboard + admin API   (HTTPS)              │
   (browser)          │  client API: hello, join (HTTPS)              │
                      │  signalling             (WebSocket)           │
                      │  relay                  (UDP, TCP fallback)   │
                      │  SQLite: rooms, members, admins, log, settings│
                      └───────▲───────────────────────────▲───────────┘
                    signalling│                           │signalling
                    + relay   │                           │+ relay
             ┌────────────────┴───┐                 ┌─────┴──────────────┐
             │ Lanora client  (A) │◀═══ WireGuard ═▶│ Lanora client  (B) │
             │ virtual adapter    │   direct UDP     │ virtual adapter    │
             │ 10.214.0.1/24      │   when possible  │ 10.214.0.2/24      │
             └────────────────────┘                 └────────────────────┘
```

| Part | What it is | Where |
|---|---|---|
| `lanora-server` | Control server: API, signalling, dashboard, built-in relay. One static binary, one SQLite file. Also runs as a stand-alone relay node (`LANORA_MODE=relay`). | `cmd/lanora-server`, `internal/server` |
| `Lanora.exe` | The Windows app. One executable that is the window, the notification-area icon, the background service and its own installer. | `cmd/lanora`, `internal/client` |
| `lanora-cli` | The same client engine without a window, for Linux and for diagnosing Windows from a console. | `cmd/lanora-cli` |
| `lanora-bench` | Load generator. | `cmd/lanora-bench` |
| Dashboard | Static web app embedded in the server. | `web/admin` |

A **room** is a virtual LAN: a `/24` subnet, a password, a capacity. A
**member** is a device's standing in a room: its identity key and the virtual
address leased to it. A device gets the same address every time it returns.

## 2. Coexisting with Astrill VPN

Astrill was researched before any Windows code was written. The conclusion
changed the design, so it comes first. Sources are listed at the end of this
section.

How far this has been checked: the first mechanism below, and Lanora's
defence against it, have been reproduced with the real `wintun.dll` under
Wine (the "Wine lab", see [TESTING.md](TESTING.md)). **Nothing here has been
confirmed on Windows itself, or on a machine running Astrill.** That test is
still to be done, and TESTING.md says how to do it without putting Astrill
at risk.

### What actually conflicts

The usual suspects (routes, DNS, metrics) turned out not to be the problem.
Three other mechanisms are.

**1. The Wintun library deletes Astrill's network adapter.**
Astrill keeps a permanent adapter named "Astrill VPN". It is a Wintun
adapter, but Astrill creates it with OpenVPN's `tapctl` tool, which makes an
old-style device node (`ROOT\NET\000x`, hardware ID `Wintun`). The Wintun
library that nearly every modern VPN tool ships, `wintun.dll`, has this in its
entry point:

```c
case DLL_PROCESS_ATTACH:
    ...
    AdapterCleanupLegacyDevices();   /* api/main.c */
```

`AdapterCleanupLegacyDevices` lists the devices under `ROOT\NET` with
`SetupDiGetClassDevsExW` and removes every one whose hardware ID is `Wintun`
with `SetupDiCallClassInstaller(DIF_REMOVE)`. It runs whenever a process with
administrator rights loads the DLL. So starting Tailscale, Clash, or any
other Wintun-based tool silently deletes Astrill's adapter, and Astrill
cannot connect until it is repaired. Radmin VPN does not use Wintun (it ships
its own driver), which is why it coexists.

**2. The Wintun library replaces an older Wintun driver.**
There is one Wintun kernel driver per machine, shared by every program that
uses it. When the library creates an adapter and finds an installed driver
older than the one it carries, it waits up to 75 seconds for the old driver
to unload, deletes the old driver package even if it is in use, and installs
its own (`DriverInstall` in `api/driver.c`). An adapter that another program
created the old way keeps the old driver loaded, so on such a machine the
wait runs its full length and the other program's driver is pulled out from
under it.

**3. Astrill injects a socket hook into ordinary programs.**
Astrill installs a Winsock layered service provider, `ASProxy64.dll`. Windows
loads it into every ordinary process that creates a socket, whether or not
Astrill is running. It implements Astrill's per-application filtering, it
dates from 2015, and it has crashed many unrelated programs on recent Windows
11 builds. Microsoft's documentation says an uncategorised provider like this
one "will not be loaded in services or system processes". Radmin VPN's
networking lives in a service.

### What Lanora does about it

| Mechanism | Measure | Code |
|---|---|---|
| Wintun's clean-up removes Astrill's adapter | When old-style Wintun adapters exist on the machine (and only then), the library is loaded under three safeguards, described below the table. If the first cannot be put in place, the library is not loaded at all. | `internal/client/netcfg/wintun_windows.go` |
| The library would replace the driver Astrill is using | The embedded library is Wintun 0.14.1, whose driver is version 0.14.0.0, the same one Astrill installs; the library then reports "using existing driver" and replaces nothing. This is checked, not assumed: before anything is loaded, the driver version of every old-style Wintun adapter is read from the registry, and if one is older (or cannot be read) Lanora stops with a message saying which adapter and what to do. `WintunDeleteDriver` is never called. | `wintun_windows.go`, `wintun_driver.go` |
| Astrill's socket hook | Every socket Lanora opens belongs to the Lanora **service**, where the hook is not loaded. The window has no sockets; it talks to the service over a named pipe. The installer also registers `Lanora.exe` with Winsock as accepting only system-certified providers, which covers the other ways the program can be started. | `internal/client/winsvc`, `internal/client/ipc` |
| Astrill's tunnel addresses (198.18.0.0/15) | Rooms are allocated from `10.214.0.0/16` by default, and never from that range. | `internal/server/api/settings.go` |
| An extra default route confuses VPN clients that look for "the" default gateway (seen with ZeroTier and OpenVPN) | Lanora adds no default route, real or fake. | `internal/client/netcfg/netcfg_windows.go` |
| Astrill's TCP-only OpenWeb mode, or anything else that drops UDP | The relay has a TCP transport on the HTTPS port; clients fall back to it by themselves and return to UDP when it works. | `internal/client/transport/relayclient.go` |
| The room's subnet might overlap something already in use | Before the adapter is created, the subnet is checked against the system's routes. An existing route for addresses inside it, or a gateway inside it (another VPN's tunnel gateway, say), stops the connection with an explanation. | `internal/client/netcfg/netcfg.go` |

### Loading the Wintun library safely

The three safeguards, in the order they act:

1. **The clean-up cannot find or remove anything.** For the few milliseconds
   the load takes, the two Windows functions it works through are made to
   fail inside the Lanora process: `SetupDiGetClassDevsExW` returns "no
   list" and `SetupDiCallClassInstaller` returns failure. This is done the
   way a debugger places a breakpoint, by overwriting the first instructions
   of each function with "return the failure value", and undone afterwards.
   Before the library is loaded, Lanora makes the clean-up's own first call
   and confirms that it fails. The library file is not modified, nothing
   outside the process is affected, and the Wintun API is used exactly as
   documented. Either of the two blocks is sufficient alone.
2. **The load has no administrator rights.** It runs on a thread that, for
   its duration, impersonates a copy of the process token with the
   Administrators group disabled and every privilege removed, so a removal
   attempt would also lack the rights for it. If the library will not start
   that way, it is loaded with the first safeguard only.
3. **The result is checked.** The old-style Wintun adapters present before
   the load must all be present after it. If one is missing, Lanora stops
   and says which, and how to restore it.

Lanora also checks that the Wintun binding, which later asks for the library
by name, is given the module that was loaded this way and not a second copy
whose clean-up would run unguarded.

On a machine with no such adapters there is nothing to protect, and the
library is loaded the ordinary way, as by any other program that uses it.

`lanora-cli doctor` runs every check short of loading the library (which
adapters exist, their driver versions, whether the two functions can be
blocked and restored on this machine) and creates nothing, so it is safe as
the first thing to run on a machine with Astrill.

**What the Wine lab showed** (real `wintun.dll`, an old-style Wintun adapter
planted in the registry; one function Wine lacks is filled in by the test,
see TESTING.md):

| Experiment | The adapter afterwards |
|---|---|
| The library loaded the ordinary way | **deleted** |
| Loaded with only the removal call blocked | present |
| Loaded the way Lanora loads it | present |
| Adapter planted with driver 0.8.1 | present; Lanora refused to load the library |

### Lanora's whole footprint in Windows networking

While a room is joined:

- one Wintun adapter named "Lanora", with a fixed GUID;
- one IPv4 address on it, and the on-link route for the room's `/24` that
  Windows adds for any address;
- interface metric 1 on that adapter (optional, see below);
- the adapter's network category set to Private (optional);
- one firewall rule allowing ICMP echo from the room's subnet to the room
  address.

Not touched: other adapters, the default route, any other route, DNS servers,
the DNS resolution policy table, Windows Filtering Platform filters, proxy
settings. When the room is left, the adapter is removed and the rule deleted.
Installing adds the service, one firewall rule allowing inbound UDP to
`Lanora.exe`, and a Start menu shortcut.

### Interface metric

Windows sends a broadcast or multicast that a program did not pin to an
adapter out of the single interface with the lowest metric. LAN games
announce themselves exactly that way, so for members to see each other's
games the room's adapter has to be that interface. Radmin VPN sets its
adapter's metric to 1 for this reason, and so does Lanora (setting "Prefer
the room for LAN games", on by default).

The metric only ranks routes to the same destination. Lanora's adapter has
routes for the room's subnet, broadcast and multicast, and nothing else, so
unicast traffic, the default route and DNS are unaffected. The side effect is
the intended one: while in a room, un-pinned broadcasts go to the room and
not to the physical LAN. Unlike Radmin, whose adapter and metric are
permanent, this lasts only while a room is joined.

### Sources

- Wintun source: `api/main.c`, `api/adapter_win7.h`, `api/driver.c` at
  <https://git.zx2c4.com/wintun/> (the clean-up and the driver upgrade path).
- Tailscale issue 7937 (Astrill's adapter deleted when Tailscale starts; a
  maintainer's explanation); Clash Verge issue 7839 (same symptom).
- Microsoft Learn, "Categorizing layered service providers and apps" (which
  processes load which providers).
- Astrill's wiki and changelog (Wintun as its adapter since build 3.9.0.2161,
  the 198.18.0.0/24 tunnel range, default MTU 1446, protocol modes).
- Pasted `route print` and `ipconfig` output for Radmin VPN (26.0.0.0/8,
  interface metric 1, gateway 26.0.0.1 at metric 9257), Hamachi and ZeroTier;
  OpenVPN issue 133 (the fake default route picked as gateway).

## 3. The data plane

Traffic between members is carried by **WireGuard**, using the reference
userspace implementation (`golang.zx2c4.com/wireguard`) on a **Wintun**
adapter on Windows and a kernel TUN device on Linux. Lanora contains no
cryptographic code of its own design: encryption, authentication, key
exchange and replay protection are WireGuard's.

What Lanora adds around it:

```
 operating system
        │  IP packets
 ┌──────▼─────────┐
 │ virtual adapter│  Wintun / TUN                      internal/client/netcfg
 ├────────────────┤
 │ vnet           │  address filter; broadcast fan-out internal/client/vnet
 ├────────────────┤
 │ WireGuard      │  encrypt, authenticate             (library)
 ├────────────────┤
 │ transport      │  per peer: direct UDP or relay     internal/client/transport
 └──────┬─────────┘
        │  UDP (or a WebSocket to the relay)
```

**Keys.** A device has one long-lived Ed25519 identity key (protected with
DPAPI on Windows). It never encrypts anything; it signs the join request so
that a room member cannot claim another member's identity. For each
connection the client makes a fresh WireGuard key pair and a fresh discovery
key pair, and sends the public halves to the server, which distributes them
to the room. Nothing long-lived protects traffic.

**One endpoint per peer.** WireGuard is configured with each peer's virtual
address as its "endpoint". The transport implements WireGuard's `conn.Bind`
interface and resolves that handle, per packet, to wherever the peer can
currently be reached. WireGuard's own roaming is switched off so that it
never overrides the transport's choice.

**MTU.** 1280 by default. A full packet is then 1340 bytes on the wire (1346
relayed), which fits inside PPPoE and inside the tunnel of another VPN that
Lanora's traffic may itself be travelling through (Astrill's default tunnel
MTU is 1446). It is a server setting.

## 4. Finding a path

A client uses one UDP socket (plus an IPv6 one when available) for
everything. Three kinds of path exist, tried in this order of preference:

1. **Direct.** Each client publishes its candidate addresses through the
   signalling channel: its local interface addresses, and its public address
   as seen by the relay. Peers probe each other's candidates with small
   authenticated pings (NaCl box under the peers' discovery keys). Because
   both sides send at the same moment (the server forwards a "punch" request
   to synchronise them), each one's outgoing packet opens its NAT for the
   other's. A candidate that answers becomes the path. An address a valid
   ping arrives from is also learned as a candidate, which covers NATs that
   use a different port for every destination on one side.
2. **Relay over UDP.** Until a direct path is verified, and whenever one
   stops answering, packets go through the room's relay. The relay sees only
   WireGuard ciphertext.
3. **Relay over TCP.** If the relay does not answer over UDP for five
   seconds, the client opens a WebSocket to it on the HTTPS port and relays
   over that. It keeps trying UDP and switches back when it works.

Paths are checked continuously: every 1.5 seconds to a peer there is traffic
with, every 12 seconds otherwise (often enough to keep NAT mappings open). A
direct path that misses its answers for 5 seconds is dropped. While an answer
is overdue, packets are sent both ways (WireGuard discards the duplicates),
so a dying path costs little or nothing. When the local network changes, all
paths are re-verified at once.

The relay binding is a four-message exchange (`internal/proto/wire.go`) that
proves the client receives at the address it sends from (a stateless cookie)
and that the server authorised it for the room (a MAC keyed by a ticket).
Because the cookie is bound to the sender's address, a captured exchange
replayed from elsewhere is refused.

## 5. Behaving like a LAN

WireGuard routes each packet to one peer by destination address. It has no
notion of broadcast, which is what LAN software uses to find other machines.
`vnet` supplies it: a broadcast or multicast packet leaving the adapter
(`255.255.255.255`, the subnet's broadcast address, `224.0.0.0/4`) is copied
to every member. Each copy is wrapped in an IPv4-in-IPv4 header addressed to
one member, so WireGuard can route it, and unwrapped on arrival. The receiving
adapter gets the original packet, byte for byte, with its broadcast or
multicast destination intact. Game lobby announcements, mDNS, SSDP, NetBIOS
name queries and Windows network discovery all work this way.

`vnet` is also the adapter's packet filter. In both directions, only IPv4
between this machine's room address and the room's subnet passes. A member
can reach your room address and nothing else on your machine, and a wrapped
packet must contain a broadcast from the same member that sent it.

Broadcast copies are limited to 100 packets per second per client, which is
far above discovery traffic and stops a misbehaving program from flooding the
room.

## 6. The control plane

**API** (`internal/server/api`). `GET /api/v1/hello` returns the server's
version and a nonce. `POST /api/v1/join` checks the room password and returns
a signed session token and the room's network parameters. `GET
/api/v1/session` upgrades to the signalling WebSocket. `GET /api/v1/relay` is
the relay's TCP transport. `/api/admin/*` serves the dashboard.

**Hub** (`internal/server/hub`). Presence and endpoints live in memory,
partitioned by room. Nothing real-time touches the database. A client that
cannot keep up with its message queue is disconnected and resynchronises on
reconnect. What one member can make the server send to others is rate
limited.

**Store** (`internal/server/store`). SQLite in WAL mode with one writer
connection and a pool of readers. It holds administrators, rooms, members
(address leases), bans, settings and the event log. The event log is written
in batches from a queue; when the queue is full, events are dropped and
counted rather than slowing anything down.

**Relay** (`internal/server/relay`). The forwarding path is two lock-free map
lookups and one send, rewriting six header bytes in place, with no
allocation. On Linux several sockets share the port so the kernel spreads
flows over cores.

**Session tokens** are self-contained and signed, so a client can resume
after a server restart without the server remembering anything. They are
still checked against the database on every use: the membership must exist,
belong to the device the token was issued to and not be banned; the room
must be enabled, and its password must not have changed since the token was
issued.

A token names its room and membership by database id, so an id must never
come to mean another room or member. SQLite hands the id of the newest row
to the next one once that row is deleted, which would have let a token from
a deleted room open a session in the room created to replace it. Every id
column is therefore `AUTOINCREMENT` (never reused), and the token also
carries the device's identity key, which the membership it names must match.

**Failure independence.** Once members know each other, their traffic does
not involve the server. If the server restarts, members keep talking and
reconnect their signalling in the background. A restarted server starts with
empty rooms and learns of members as they return, so a client that is told a
peer is missing right after a restart (it recognises one by the server's
epoch changing) keeps that peer for 30 seconds instead of dropping a working
connection. This is tested in process and in the network lab, where a
continuous ping between two members loses nothing across a restart.

## 7. The Windows client

```
  Lanora.exe (window, per user, unprivileged)
       │  named pipe \\.\pipe\Lanora  (JSON lines)
  Lanora.exe --service (LocalSystem)
       ├─ daemon: settings, connection lifecycle       internal/client/daemon
       ├─ engine: join, signalling, reconnect          internal/client/engine
       └─ adapter, WireGuard, transport
```

- The **service** starts with Windows, restarts if it crashes, and rejoins
  the remembered room if asked to. It holds the device identity and the
  remembered password, encrypted with DPAPI.
- The **window** is drawn with Gio (GPU-rendered, no runtime to install). It
  holds no window at all while in the notification area. Closing or
  minimising it leaves the room connected.
- **Installation** is the same executable run elevated with `--install`: it
  copies itself to `Program Files\Lanora`, registers the service and starts
  it. The window offers this on first run and Windows asks for approval once.
  The helper programs it then runs for the firewall rule and the Start menu
  entry each get a limited time, and a failure is also written to
  `install.log`. Removal ends a service that will not stop rather than
  giving up, and clears the program folder once the uninstaller itself has
  closed.
- Every step of setting up the adapter, and what the Wintun library itself
  reports while doing it, goes to `service.log`. On a machine nobody can
  look at, that log is what there is to go on.

On Linux, `lanora-cli daemon` plays the service's part and the window (built
with `-tags lanoraui`) connects to it over a Unix socket. That is how the
window is exercised in tests.

## 8. Scaling

- **Signalling.** One process, about 50 KB and two goroutines per connected
  client. Measured: 5,000 clients in 100 rooms on a shared 8-core VM, joining
  at 40 per second, median join 130 ms, none failed.
- **Joins** cost one Argon2id verification (19 MiB, about 50 ms of CPU). They
  are limited to one per core at a time; beyond what can be served within 4
  seconds the server answers "busy, try again" instead of queueing. A restart
  does not cause a join storm, because clients resume with their tokens.
- **Relay.** Stateless apart from the session table, so relay nodes can be
  added freely: `LANORA_RELAYS` lists them, each room is pinned to one by
  rendezvous hashing, and the control server probes them and moves rooms off
  one that stops answering. See [DEPLOYMENT.md](DEPLOYMENT.md).
- **Signalling beyond one host** is not implemented. The natural split is by
  room (a room's members must share a hub); tokens are already stateless, so
  what is missing is a router in front and a shared store.

## 9. Limits

- **IPv4 only inside rooms.** IPv6 is used between clients when available,
  but the virtual LAN itself carries IPv4.
- **Layer 3.** Non-IP protocols (raw Ethernet, IPX) are not carried.
- **253 members per room**, a `/24`. Broadcast fan-out is the reason for the
  cap.
- **One room at a time** per device.
- **No file transfer or chat in the app.** Members share files the way they
  would on a LAN (Windows file sharing, or any tool that works on a LAN).
- **The server is trusted** to hand out the right keys. A compromised server
  could put itself between members. The relay is not trusted with content.
- **An unsigned executable.** Windows SmartScreen will warn about
  `Lanora.exe` until it is signed with a code-signing certificate. The
  network driver inside it is signed by its authors.

## 10. Source map

| Path | Contents |
|---|---|
| `internal/proto` | Everything client and server must agree on: API payloads, signalling messages, UDP frames |
| `internal/server/store` | SQLite schema, migrations, queries |
| `internal/server/auth` | Password hashing, signed tokens, rate limiting, lockout |
| `internal/server/hub` | Live rooms, presence, signalling fan-out |
| `internal/server/relay` | UDP and TCP relay, relay directory |
| `internal/server/api` | HTTP handlers, settings, event log |
| `internal/client/engine` | One room connection from join to leave |
| `internal/client/transport` | Path selection, hole punching, relay client |
| `internal/client/vnet` | Broadcast fan-out and the adapter's address filter |
| `internal/client/netcfg` | Adapter creation and configuration per operating system |
| `internal/client/daemon`, `ipc` | The service's logic and its channel to the window |
| `internal/client/winsvc` | Windows service, install and uninstall |
| `internal/client/ui` | The window |
| `internal/e2e` | End-to-end tests of server and clients in one process |
| `test/netlab` | The container network lab |
| `test/uilab` | Screenshots of the window on a virtual display |
| `test/winelab` | The Windows builds under Wine: the Wintun loading experiments, the console client, install and removal |

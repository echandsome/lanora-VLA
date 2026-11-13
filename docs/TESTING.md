# Testing Lanora

This document says what has been tested, how to run each test, and what has
**not** been tested and must be before Lanora is called finished.

## Status at a glance

| Area | State |
|---|---|
| Server: storage, authentication, API, signalling, relay | Tested on Linux (unit tests, security tests, race detector) |
| Client engine: join, WireGuard, hole punching, relay fallback, broadcast | Tested on Linux, in-process and over real kernel networking behind NAT |
| Client daemon and its channel to the window | Tested on Linux |
| The window | Run on Linux on a virtual display against a real daemon and server; every screen captured and inspected |
| The dashboard | Every page and action driven in a headless browser against a real server with live members, in both themes and at phone width |
| Docker deployment | Built and run; health check, API and relay exercised through published ports |
| Load | 5,000 concurrent clients on one server |
| **Windows adapter, service, window** | **Never run on Windows.** The Windows programs have run under Wine as far as Wine allows: up to the point of creating the adapter, and through install and removal |
| **Coexistence with Astrill VPN** | **Never run on Windows or next to Astrill.** The way Wintun deletes an adapter like Astrill's, and Lanora's defence against it, have been reproduced under Wine with the real `wintun.dll` |
| **LAN games, Windows file sharing** | **Not run** (the Linux equivalents, broadcast delivery and bulk TCP, are) |

The development machine was Linux with no access to a Windows computer. The
last three rows need you. The procedure is in
[Windows and Astrill](#windows-and-astrill-what-you-need-to-run) below, in the
order that finds problems soonest, and it starts with a check that cannot
harm Astrill.

## Automated tests

Everything in this section runs with `make test` (about a minute) except the
network lab.

### Unit tests

`go test ./...` covers, package by package:

- **`internal/proto`**: room ID normalisation; every wire frame's encoding;
  that the bind challenge is never larger than the request (no amplification);
  that a discovery frame cannot be opened or forged by a third party.
- **`internal/server/store`**: migrations are idempotent; subnet allocation,
  reuse and exhaustion; address leases (stable across returns, recycled only
  from members who are offline, unique under 60 concurrent admissions);
  sessions, bans, log paging, settings; that the id of a deleted room,
  member, administrator or ban is never given to a new one.
- **`internal/server/auth`**: Argon2id hashing and parsing, including hostile
  parameters; token forgery (every single-character change is rejected; a
  token of one kind is not accepted as another); rate limiter and lockout
  arithmetic; refusal when the hashing queue is full.
- **`internal/server/hub`**: presence and signalling; rooms cannot see each
  other; a member cannot flood another member's queue; a slow client is
  dropped without blocking the room.
- **`internal/server/relay`**: binding, forwarding, room isolation; expired,
  forged and altered tickets; a replayed bind from another address; address
  change; revocation; rate limit; the TCP transport and bridging between TCP
  and UDP members; malformed input.
- **`internal/client/vnet`**: broadcast and multicast fan-out (limited
  broadcast, subnet broadcast, multicast), outer header and checksum,
  rate limit; the address filter in both directions; that a wrapper cannot
  smuggle a unicast or spoofed packet.
- **`internal/client/netcfg`**: the subnet conflict rules, including a VPN
  gateway inside the room's range; which Wintun driver versions count as
  older than the embedded one; that the embedded `wintun.dll` files are
  byte for byte the official Wintun 0.14.1 release.
- **`internal/client/settings`**: identity and password persistence.

### End-to-end tests (`internal/e2e`)

The real server and real client engines in one process. Each client has a
userspace TCP/IP stack in place of an operating-system adapter, so real TCP
connections run across real WireGuard tunnels with no privileges.

| Test | What it shows |
|---|---|
| `TestDirectConnection` | Two members find a direct path and move 1 MB over it; nothing goes through the relay |
| `TestRelayFallback` | With direct paths disabled, the same works through the relay |
| `TestMixedPaths` | Three members, one relay-only, every pair exchanges data |
| `TestStreamRelayFallback` | With the UDP relay unreachable, clients switch to the TCP relay |
| `TestBroadcastReachesEveryMember` | A broadcast, a subnet broadcast and a multicast packet arrive at every member byte for byte; a unicast reply reaches only its destination |
| `TestRoomsAreSeparate` | Members of different rooms get different subnets and cannot connect to each other |
| `TestJoinFailures` | Wrong password and unknown room are indistinguishable; malformed ID; full room |
| `TestAdminActions` | Kick, return with the same address, ban, password change, disable |
| `TestSignallingLossKeepsPeersConnected` | Traffic continues while signalling is down; clients reconnect |
| `TestServerRestartDoesNotInterruptMembers` | The server is stopped and a new one started on the same address and database while two members exchange data continuously: no exchange fails and neither member ever loses sight of the other |
| `TestPeerRestart` | A member returns with new keys; others pick them up; address unchanged |
| `TestSelfSignedTLSWithPin` | Pinned TLS works; without the pin, or with the wrong one, the client sends nothing |
| `TestDaemonOverIPC` | The daemon driven through its local channel: connect, errors in plain words, remembered password, settings, reconnect at start, forgetting a password that stopped working |
| `TestAdminAuthentication`, `TestAdminLoginLockout`, `TestAdminRoles` | Sessions, cookie attributes, cross-origin requests refused, lockout, what each role may do, the last owner cannot be removed |
| `TestRoomAdministrationRules` | Input validation; the password is shown once and never appears in any other response |
| `TestJoinIsAuthenticatedAndRateLimited` | Join signatures; lockout after five wrong passwords; a spoofed `X-Forwarded-For` does not escape it |
| `TestServerWideBans`, `TestSessionTokensCannotBeForged` | Bans by device and by address range; altered tokens; tokens die with a password change; the metrics endpoint |
| `TestTokensDoNotOutliveTheirRoom` | A room is deleted and another created, which takes over its subnet and addresses: a token from the old room does not open a session in the new one, and a token naming another device's membership is refused |

All of these also pass under the race detector (`make test-race`).

### Network lab (`make lab`)

`test/netlab/lab.sh` builds a small internet from containers and runs the real
server and `lanora-cli` over real kernel network interfaces:

```
client-a ── lan-a ── nat-a ──┐
                             ├── wan ── server
client-b ── lan-b ── nat-b ──┘      └── client-c
```

Each client is behind its own NAT router (with a firewall, like a home
router) on its own private network. Results of the last run:

| Scenario | Result |
|---|---|
| `direct_path` | Both clients punch through their NATs and reach each other directly (round trip about 2 ms in the lab) |
| `throughput_and_file_transfer` | 175 Mbit/s TCP through the tunnel; a 64 MB file arrives with the same SHA-256; **0 bytes** through the relay |
| `broadcast_and_multicast` | Subnet broadcast, limited broadcast and multicast from one client all arrive at the other |
| `server_restart` | Clients still reach each other with the server stopped, reconnect 1 s after it returns, and lose 0% of a continuous ping between them while doing so |
| `nat_rebinding` | After a router forgets all its mappings, connectivity and the direct path come back |
| `outage_and_recovery` | After a 12 s uplink cut, traffic resumes as soon as the link does |
| `symmetric_nat_uses_relay` | With NATs that defeat hole punching, the relay carries traffic (139 Mbit/s) |
| `udp_blocked_falls_back_to_tcp` | With UDP dropped, the client relays over TCP, and returns to UDP when it works |
| `rooms_are_isolated` | A client in another room cannot reach this room's members |
| `kick_and_ban` | A banned member is disconnected, cannot rejoin, and is unreachable |

The throughput figures are from a slow shared virtual machine where one
system call costs several microseconds; they are a floor, not a measure of
the Windows client.

The lab found problems the in-process tests had not, all fixed: the relay
kept sending to a client's stale UDP address after it had fallen back to TCP;
and after a server restart, the first client to reconnect was told the room
was empty and dropped its working connections to members who had simply not
reconnected yet. (It also taught the lab something: routers without a
firewall behave unlike real ones, so the lab's routers now have one.)

### Wine lab (`make winelab`)

`test/winelab/lab.sh` cross-compiles the Windows programs and runs them under
Wine in a container. Wine is a reimplementation of Windows: it has no network
drivers, does not enforce Windows' permissions, and differs in many details.
So this is not a test on Windows. It is the one place on a Linux machine
where the Windows-only code runs at all, and it allows one experiment that
matters a great deal: loading the real `wintun.dll` against an old-style
Wintun adapter planted in the registry (the kind Astrill has) and seeing
whether the adapter survives.

| Scenario | Result of the last run |
|---|---|
| `device_functions_can_be_blocked` | The two Windows functions the library's clean-up needs are made to fail, confirmed, and restored, twice over |
| `ordinary_load_removes_adapter` | **Control.** The library loaded the ordinary way: the planted adapter is deleted. This is what other Wintun programs do to Astrill |
| `removal_block_alone_keeps_adapter` | Same load with only the removal call blocked: the adapter stays |
| `lanora_load_keeps_adapter` | The library loaded the way Lanora loads it: it ends up loaded, the adapter stays |
| `older_driver_is_refused` | Adapter planted with Wintun driver 0.8.1: Lanora stops before loading anything, with a message naming the adapter |
| `pipe_rules_are_valid` | The access rules of the service's named pipe are accepted |
| `doctor_reports` | `lanora-cli doctor` passes with a current adapter present, fails with an old one, reaches the server, and leaves nothing behind |
| `client_joins_and_stops_at_the_adapter` | The real console client joins a room on a real server, loads the library through the safeguards (planted adapter intact), then reports that the adapter cannot be created, which is as far as Wine goes |
| `install_registers_service` | `Lanora.exe --install` copies itself to Program Files and registers the service (automatic start, LocalSystem, `--service`) and the "Installed apps" entry |
| `uninstall_removes_everything` | `Lanora.exe --uninstall` removes the service, the entry and the program folder |

Two things to know when reading these:

- Wine does not implement `SetupDiSetClassInstallParamsW`, one of the two
  calls the library uses to remove an adapter, so on Wine the clean-up would
  stop one step short whatever Lanora did. The tests make that one call
  succeed (on Wine only), so that the clean-up runs to its end and the
  control really deletes the adapter. The call that deletes, and the call
  that lists, are Wine's own.
- The second safeguard, loading with administrator rights removed, runs
  under Wine but proves nothing there, because Wine does not enforce those
  rights. Only Windows can show whether it holds. The first safeguard does
  not depend on it.

Not possible under Wine: creating the adapter (no drivers); the service's
pipe (Wine lacks what the pipe library uses), and therefore the service
staying up and the window talking to it; the window itself (Wine lacks a
pointer-input call the toolkit requires).

Running the Windows code for the first time, even there, found real faults,
all fixed: the service decided how it had been started by inspecting its
surroundings instead of by the `--service` argument it is registered with;
the installer ran `netsh` and PowerShell with no time limit, and before
starting the service, so one hung helper would have left the installation
waiting for ever; the command that clears the program folder after removal
was quoted in a way `cmd.exe` does not understand, ran once while the
uninstaller was still on screen holding its own file, and ran from inside
the folder it was deleting; removal and update gave up if the service would
not stop; and a window that could not be created would have ended the
program without a word.

### The dashboard

The dashboard was driven in headless Chromium against a real server with a
load generator keeping members connected. Checked: every page at 1280 and
390 pixels wide in the light and dark themes; no sideways scrolling from 320
pixels up; create, edit, disable, delete and reset the password of a room,
with the one-time password dialog; kick, ban, unban and remove members while
they were connected; server-wide bans by device and by address range; log
filters and paging; settings, including the server's validation errors;
administrator accounts and roles (a viewer sees no controls that change
anything, and the server refuses if it tries); expired sessions, lockout and
a lost live connection; keyboard order and focus; about 2,000 connected
clients. No request violated the Content-Security-Policy. Only Chromium was
used; Firefox, Safari, touch devices and screen readers were not.

Writing it found one fault that mattered: database ids were reused after
deletion, which with self-contained session tokens meant a token from a
deleted room could be accepted for the room that replaced it. Fixed twice
over; see [SECURITY.md](SECURITY.md).

### The window (`make ui-shots`)

`test/uilab/shots.sh` builds the window for Linux in a container, starts a
server, a daemon and five room members, drives the window with synthetic
keyboard and mouse input through every screen in both themes, and saves a
screenshot of each. The screens were inspected by eye. This found and fixed
text misaligned in input fields, Chinese nicknames rendered as boxes in bold
text, a notification covering the Leave button, and missing keyboard focus
indicators.

Fonts differ from Windows (Inter stands in for Segoe UI). Everything else is
drawn by the same code that runs on Windows.

### Load (`lanora-bench`)

On a shared 8-core virtual machine, server and load generator on the same
host:

| Test | Result |
|---|---|
| 5,000 clients in 100 rooms, joining at 40 per second, held for 40 s | All joined. Join time: median 130 ms, 95th percentile 1.4 s, 99th 1.9 s. Server: 10,020 goroutines, 5,032 open files |
| Idle cost of 2,000 connected clients | About 16% of one core, all of it keepalive traffic |
| Memory per connected client | About 31 KB of live heap (measured after a garbage collection), plus two goroutine stacks |
| 2,000 clients arriving at 1,000 per second | 359 admitted; the rest refused within 4 s with "The server is busy. Try again in a moment." instead of timing out |

Joins are bounded by password hashing, on purpose (see
[SECURITY.md](SECURITY.md)). Resident memory runs well above live heap after a
burst of joins, because each hash in flight uses 19 MiB that the runtime
returns to the system lazily; `GOMEMLIMIT` caps it.

To repeat:

```
LANORA_TRUSTED_PROXIES=127.0.0.1 LANORA_ADMIN_PASSWORD=... dist/lanora-server &
dist/lanora-bench -server 'https://127.0.0.1:8443/#pin=...' -admin-password ... \
    -rooms 100 -clients 50 -ramp 40 -duration 60s
```

`-mode full` runs the real client engine for each simulated client
(WireGuard, hole punching, relay binding) instead of only signalling.

## Windows and Astrill: what you need to run

None of this has been run on Windows. Treat the first run as the first
contact between this code and Windows, and expect to find things. Please
report what you see at each step, including the ones that pass.

You need two Windows 10 or 11 PCs on **different networks** (two homes, or
one on a phone hotspot), Astrill installed on at least one, and a server
reachable from both. From `dist/` you need `Lanora.exe` and `lanora-cli.exe`.

### Step 0. Record Astrill's adapter before running anything

On the PC with Astrill, in PowerShell:

```powershell
Get-NetAdapter -IncludeHidden | Where-Object InterfaceDescription -like '*Wintun*' |
    Format-List Name, InterfaceDescription, Status, PnPDeviceID
```

You should see an adapter named "Astrill VPN" with a `PnPDeviceID` starting
`ROOT\NET\`. Keep this output: it is what must still be there after every
later step. If its `PnPDeviceID` starts with `SWD\` instead, tell me; the
research would then be out of date (and the risk lower).

### Step 1. Check the PC without risking anything

This step creates no adapter and does not load the network driver library,
so it cannot disturb Astrill whatever it finds. Open an **administrator**
Command Prompt (Start, type `cmd`, right-click, "Run as administrator"), go
to the folder with `lanora-cli.exe`, and run:

```
lanora-cli.exe doctor -server <your server address>
```

On the PC with Astrill, expect:

```
[ ok ] Administrator rights
[ ok ] Other programs' Wintun adapters
       Found "Astrill VPN", Wintun Userspace Tunnel [ROOT\NET\0001, driver 0.14.0.0]. ...
[ ok ] Wintun driver version
[ ok ] Protection of other programs' adapters
       The functions the Wintun library would use to remove another program's adapter
       were blocked, confirmed to fail, and restored.
[ ok ] Loading with reduced rights
[ ok ] Server
...
All checks passed.
```

followed by a list of adapters and routes. Please send me the whole output
either way. What a failure means:

| Failed check | Meaning | Do |
|---|---|---|
| Wintun driver version | Astrill's adapter runs an older Wintun driver than Lanora's. Lanora will refuse to connect rather than replace it | Update Astrill to its current version, restart, run `doctor` again |
| Protection of other programs' adapters | The first safeguard cannot be set up on this PC (security software may be preventing it). Lanora will refuse to connect while Astrill's adapter exists | Stop here and send me the output |
| Other programs' Wintun adapters | Part of the device registry could not be read | Stop here and send me the output |

If "Other programs' Wintun adapters" says **None** on a PC that has Astrill
installed, also stop and tell me: either Astrill no longer uses that kind of
adapter, or Lanora is not seeing it.

### Step 2. Install and join (the step that matters most)

1. Start `Lanora.exe`. Windows SmartScreen will warn that it is unsigned:
   "More info", then "Run anyway".
2. Choose **Install** and approve the Windows prompt.
3. Open Settings (the cog) and choose **Copy diagnostics**; paste into a text
   file. Check "Astrill socket hook loaded into this Lanora process: **no**".
4. Join a room. The Wintun library is loaded at this moment.
5. Run the PowerShell command from step 0 again. **Astrill's adapter must
   still be listed.** Then connect Astrill and confirm it works.
6. Open `C:\ProgramData\Lanora\service.log` and send it to me. Around the
   time you joined it should contain, in this order:
   - `old-style Wintun adapters are present; loading the Wintun library
     without letting it remove them`
   - `device listing and removal are blocked in this process for the
     duration of the load`
   - `the Wintun library was loaded with reduced rights` (or a warning that
     this did not work and it was loaded with removal blocked only; both are
     acceptable, and I want to know which)
   - `the Wintun library is loaded and every old-style Wintun adapter is
     still present`
   - lines marked `part=driver`, which are the Wintun library's own account;
     look for `Using existing driver 0.14`
   - `the adapter has its address; nothing else on this computer was changed`

If Astrill's adapter is gone, Lanora will have said so in a red message.
Stop, restore it (Astrill: Help, Repair), and send me the diagnostics and the
log. That would mean the safeguards described in
[ARCHITECTURE.md](ARCHITECTURE.md#2-coexisting-with-astrill-vpn) do not hold
on your Windows build, and the adapter back end needs a different approach.

### Step 3. Basic virtual LAN, no Astrill

With Astrill disconnected on both PCs:

| Check | How | Expected |
|---|---|---|
| Both join | Same room ID and password on both | Each shows the other in the member list within a few seconds |
| Path | Member row | "Direct" on ordinary home routers; "Relayed" if either side is behind a strict NAT. Both are fine |
| Ping | `ping <the other's address>` in a terminal | Replies. (Lanora adds the firewall rule that allows this) |
| File sharing | Share a folder on one PC; on the other open `\\10.214.x.y` in Explorer | The share opens. Needs "Treat the room as a private network" on (default) |
| A LAN game | Host on one, look for LAN games on the other | The game appears. If not, try connecting by address, and tell me which game |
| Leave and rejoin | Leave room, join again | Same address as before |
| Adapter is gone after leaving | `Get-NetAdapter` | No "Lanora" adapter |

### Step 4. With Astrill

Repeat the checks of step 3 in each of these states. "A" is the PC with
Astrill.

| State | What to watch |
|---|---|
| Astrill connected (OpenWeb) on A **before** Lanora joins | Lanora joins; path to the other PC |
| Astrill connected (StealthVPN or OpenVPN) on A before Lanora joins | Lanora joins; expect "Relayed" more often, and higher latency, because Lanora's packets now travel inside Astrill |
| Astrill connected (WireGuard) on A before Lanora joins | Same |
| Lanora joined first, **then** connect Astrill | Astrill connects normally. Lanora shows "Reconnecting" briefly and recovers; member paths come back within about 10 s |
| Both connected, then **disconnect Astrill** | Astrill disconnects normally; Lanora recovers as above |
| Both connected, then **leave the Lanora room** | Astrill stays connected and keeps working (browse a site) |
| Both connected, Astrill's kill switch on | Note whether Lanora still works; some kill switches block every other adapter |
| Astrill on both PCs | Works, relayed |

For each state please note: did Astrill stay connected; could you browse
through Astrill; did Lanora's members stay reachable; any error message. After
the whole run, repeat the PowerShell command from step 0 one last time.

Also useful, with both connected: the output of `route print -4` and
`Get-NetIPInterface -AddressFamily IPv4 | Sort-Object InterfaceMetric`.

### Step 5. Start-up and shutdown

| Check | Expected |
|---|---|
| Turn on "Rejoin automatically", restart Windows | After signing in, the room is already connected (the service joined at boot) |
| Turn on "Open Lanora when I sign in", sign out and in | The icon appears in the notification area; the window stays closed until clicked |
| Close the window while connected | The room stays connected; the icon remains |
| Close the window, then open it again from the icon, several times | It opens every time |
| Sleep the PC for a minute, wake it | Lanora reconnects by itself within about 15 s |
| Shut down Windows while connected | No delay or error at shutdown |
| Task Manager while connected and idle | Note the memory and CPU of the two `Lanora.exe` processes |
| Uninstall (Settings in Lanora, or Windows "Installed apps") | Service, Start menu entry and `C:\Program Files\Lanora` are gone a few seconds after you close the "Lanora was removed" message; Astrill unaffected |

### If something fails

What tells me most:

1. The diagnostics text (Settings, Copy diagnostics, or `lanora-cli.exe
   doctor`), taken while the problem is happening.
2. `C:\ProgramData\Lanora\service.log`, and `install.log` next to it if
   installing or removing went wrong.
3. For connectivity problems, the same scenario with `lanora-cli.exe` from an
   administrator prompt, which prints what it is doing. Stop the service
   first (`sc stop Lanora`):
   `lanora-cli.exe up -v -server <address> -room <id> -password <password>`

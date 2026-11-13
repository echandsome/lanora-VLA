# Lanora on Windows

> The Windows app has **not been run on Windows**. Its window has been run on
> Linux, and its other parts under Wine as far as Wine allows. Follow
> [TESTING.md](TESTING.md) the first time, and expect to find problems.

## For the people who will use it

Requirements: Windows 10 or 11, 64-bit (there is also an ARM64 build), and
the right to approve an administrator prompt once.

1. Start `Lanora.exe`. Windows may show "Windows protected your PC" because
   the file is not code-signed: choose **More info**, then **Run anyway**.
2. Choose **Install** and answer **Yes** when Windows asks. This installs
   Lanora's background service. It happens once.
3. Enter the server address if the app asks for it (the person who runs the
   server gives you this, or has built it into the app), then the **room ID**
   and **password**, and choose **Join room**.
4. The window shows your address in the room and the other members. Click a
   member to copy their address. Use those addresses the way you would on a
   home network: in a game's "connect to IP" box, in a LAN lobby, or as
   `\\10.214.0.2` in File Explorer.

Closing or minimising the window leaves you connected; Lanora stays in the
notification area next to the clock. **Leave room** disconnects. **Quit** in
the icon's menu closes the window and icon but not the connection.

### Settings

| Setting | What it does |
|---|---|
| Server address | Where your rooms live. For a server with a self-signed certificate, paste the whole address including the part after `#` |
| Rejoin automatically | Joins the remembered room when the computer starts, before anyone signs in |
| Open Lanora when I sign in | Shows the icon in the notification area at sign-in |
| Prefer the room for LAN games | Lets games that search "the local network" find room members. While you are in a room, such games will not find devices on your own home network |
| Treat the room as a private network | Lets Windows file sharing and games you host accept connections from room members |
| Always use the relay | Hides your internet address from other members, at the cost of speed |
| Copy diagnostics | Copies a report for troubleshooting |

### Using Lanora with another VPN

Lanora is designed to run next to another VPN, Astrill in particular. It adds
one adapter with one address while you are in a room and changes nothing
else: no default route, no DNS, no firewall filters. If you connect or
disconnect the other VPN while in a room, Lanora shows "Reconnecting" for a
few seconds and recovers.

If the other VPN has a "kill switch" that blocks everything outside its
tunnel, it may block Lanora's adapter too. That is the other VPN doing what
it was asked to.

Astrill's own adapter is of a kind that the network driver library Lanora
uses would normally delete. Lanora loads that library in a way that prevents
this and checks afterwards that the adapter is still there. If it ever
cannot do so safely, it does not connect and says why.

### Uninstalling

Settings, **Uninstall Lanora**, or Windows Settings, Apps, Installed apps,
Lanora. This removes the service, the program and the Start menu entry (the
program folder goes a few seconds after you close the last message). Your
device identity is kept in `C:\ProgramData\Lanora` so that reinstalling gives
you the same addresses; delete that folder to forget it.

### Troubleshooting

| Symptom | Try |
|---|---|
| "The Lanora service is not running" | Choose **Start the service**. If it will not start, look at `C:\ProgramData\Lanora\service.log` |
| Members stay on "Connecting…" | Both sides need the server reachable. Check the relay line under your address: "Relay not reachable" means a firewall is blocking the server's port |
| Ping works but a game does not see the other player | Allow the game through Windows Firewall on private networks; make sure "Treat the room as a private network" is on; try connecting by address |
| "This room uses the address range … already in use on this computer" | Your own network uses the same addresses as the room. Ask the server's administrator to create the room with a different range |
| Everything is "Relayed" | One of you is behind a strict NAT (mobile data, some ISPs, or another VPN). It works, with more latency |
| "Another program's virtual adapter (…) uses version … of the Wintun network driver" | Another VPN on this PC (Astrill, for instance) has an older network driver than Lanora needs, and Lanora will not replace it. Update that program to its current version, restart the PC, and try again |
| "Lanora could not start its network driver safely" | Lanora could not rule out harming another VPN's adapter, so it did nothing. Security software may be interfering. Send the administrator the output of `lanora-cli.exe doctor` |
| "Lanora could not show its window" | Windows refused to create the window (usually a graphics driver problem). The room connection is not affected; update the graphics driver, or use Remote Desktop to reach the PC |

## For the person distributing it

### Building

```sh
make windows                                   # dist/Lanora.exe, dist/Lanora-arm64.exe, dist/lanora-cli.exe
make windows SERVER='https://lan.example.com'  # with your server address built in
```

With `SERVER` set, the app starts with that server and only asks for a room
ID and password. For a self-signed server, include the pin and quote it:

```sh
make windows SERVER='https://203.0.113.5:8443/#pin=sha256:UM1MrE7p...'
```

The build is a cross-compile and needs only Go; no Windows machine and no C
compiler. `Lanora.exe` is everything: the window, the service, the installer
and the network driver library.

### What installing does

Run with `--install` (the window does this for the user), `Lanora.exe`:

- copies itself to `C:\Program Files\Lanora\Lanora.exe`;
- registers the service **Lanora** (automatic start, restarted on failure),
  running that copy with `--service` as LocalSystem;
- adds a firewall rule allowing inbound UDP to `Lanora.exe`, so other members
  can connect to it directly;
- registers the program with Winsock so third-party socket hooks are not
  loaded into it;
- adds a Start menu shortcut and an entry under Installed apps.

The first time a room is joined, the service writes `wintun.dll` (the Wintun
network driver library, unmodified, signed by its authors) next to itself and
uses it to create the adapter. Wintun installs its driver into Windows on
first use; Windows does not prompt, because the driver is signed.

Running a newer `Lanora.exe` and choosing Install again updates the installed
copy and restarts the service.

If installing or removing fails, the reason is shown and also written to
`C:\ProgramData\Lanora\install.log`.

### Code signing

Unsigned, `Lanora.exe` triggers SmartScreen on every new PC, and some
antivirus products are suspicious of an unsigned program that installs a
service. For distribution beyond people who trust you, sign it with an
Authenticode certificate (`signtool sign /fd sha256 /tr <timestamp URL> /td
sha256 Lanora.exe`).

### Command line

`lanora-cli.exe`, run from an administrator prompt, is the same engine with
text output.

```
lanora-cli.exe doctor -server <address>
```

checks a PC before anything is installed or joined: whether another VPN's
adapter is present and which driver it runs, whether Lanora's protection of
it works on this PC, whether the server answers, and what the adapters and
routes look like. It creates no adapter and loads no driver, so it is safe
to run next to any VPN, and its output is the first thing to ask a user for.

```
lanora-cli.exe up -v -server <address> -room <id> -password <password>
```

joins a room and prints what it is doing. It is the quickest way to see what
is happening on a machine where the app misbehaves. Stop the Lanora service
first (`sc stop Lanora`); only one of them can own the adapter. The console
client has its own device identity, so it appears in the room as a separate
member with its own address.

### Files

| Path | Contents |
|---|---|
| `C:\Program Files\Lanora\` | `Lanora.exe`, `wintun.dll` |
| `C:\ProgramData\Lanora\client.json` | Settings; the device identity and remembered password, encrypted with DPAPI |
| `C:\ProgramData\Lanora\service.log` | The service's log, including every step of setting up the adapter and what the driver library reports |
| `C:\ProgramData\Lanora\install.log` | Written only if installing or removing failed |

# Lanora security

What Lanora protects, against whom, and how. Each claim names the code that
implements it and, where there is one, the test that checks it.

## Who is trusted with what

| Party | Trusted to | Not trusted with |
|---|---|---|
| The server | Tell members which keys belong to which room member; enforce room passwords, capacity and bans | (see "What the server can do" below) |
| The relay | Deliver packets | Their content: it only ever sees WireGuard ciphertext |
| Room members | Reach your **room address** | Anything else on your machine or network |
| The network between everyone | Nothing | |
| Other local users of a Windows PC | Join and leave rooms through the Lanora window | The saved device identity and room password |

## Traffic between members

- **Encryption and authentication** are WireGuard's (Noise IK,
  ChaCha20-Poly1305, Curve25519), from the reference Go implementation.
  Lanora adds no cryptography of its own design.
- **Replay protection** is WireGuard's sliding window.
- **Fresh keys per connection.** The WireGuard key pair is generated when a
  room is joined and discarded when it is left
  (`internal/client/engine/engine.go`, `buildStack`). A key that leaks later
  cannot decrypt earlier sessions.
- **Members only.** A client configures a WireGuard peer for exactly the
  members the server lists for its room, and removes it when the server says
  the member left. Someone who is not a current member cannot complete a
  handshake with anyone.
- **Room address only.** The adapter passes only IPv4 between your room
  address and the room's subnet, in both directions
  (`internal/client/vnet`). A member cannot use the tunnel to reach your
  other addresses, your home network or the internet through you. *Tested:*
  `TestInboundFilterAndDecapsulation`.
- **Path probes** are authenticated and encrypted with NaCl box under
  per-connection discovery keys, so an outsider cannot steer a member's
  traffic to an address of their choosing. *Tested:* `TestDiscoSealOpen`.

## Joining a room

- **Transport.** Everything to the server is HTTPS (TLS 1.2 or later). With a
  self-signed server the client pins the server's public key and refuses
  anything else, before sending anything. *Tested:* `TestSelfSignedTLSWithPin`.
- **Room passwords** are stored as Argon2id hashes (19 MiB, 2 passes, per the
  OWASP recommendation), with parameters recorded in the hash so they can be
  raised later. A generated password has about 79 bits of entropy. It is
  shown once, when the room is created or its password reset, and cannot be
  retrieved afterwards. *Tested:* `TestRoomAdministrationRules` checks no API
  response ever contains it again.
- **An unknown room and a wrong password are indistinguishable**, in message
  and in time: the server does a dummy hash for rooms that do not exist.
  *Tested:* `TestJoinFailures`.
- **Guessing is throttled three ways**: a per-address rate limit on join
  requests; a lockout after five wrong passwords for one room from one
  address, doubling from 30 seconds to 15 minutes; and a cap on concurrent
  hash computations so a flood cannot exhaust memory. The lockout is per room
  as well as per address because many people can share one public address
  (the exit of a commercial VPN, for instance), and one person's mistyped
  password must not lock strangers out of other rooms. *Tested:*
  `TestJoinIsAuthenticatedAndRateLimited`, `TestHasherBoundsConcurrency`.
- **Device identity.** A join is signed with the device's Ed25519 key over a
  server-issued nonce, so one member cannot claim another member's identity
  (and with it their address, or evade a ban by impersonation). *Tested:*
  same test.
- **Session tokens** are HMAC-signed, expire, and are re-checked against the
  database on every use: a ban, a removed membership, a disabled room or a
  changed room password each invalidate them at once. Keys for different
  token kinds are derived separately, so one kind cannot be passed off as
  another. *Tested:* `TestSessionTokens`, `TestSessionTokensCannotBeForged`.
- **A token cannot outlive its room or change hands.** It names the room and
  the membership by database id, and carries the device's identity key. Ids
  are never reused (every id column is `AUTOINCREMENT`), and the membership
  a token names must belong to the device it names. Without the first, a
  token from a deleted room would have been accepted for the room created to
  replace it, which is precisely what an administrator does to get rid of
  people who know a password; this was found while the dashboard was being
  tested and is fixed both ways. *Tested:* `TestIDsAreNeverReused`,
  `TestTokensDoNotOutliveTheirRoom`.

## Rooms are separate

Separation is enforced independently at every layer, so a mistake in one does
not join two rooms:

| Layer | Enforcement |
|---|---|
| Signalling | The hub is partitioned by room; a punch request names a member of the sender's own room or goes nowhere |
| Keys | A client only ever learns the keys of its own room's members |
| Relay | A relay ticket names one room and one member; the relay forwards only within that room |
| Addressing | Rooms have disjoint subnets; the adapter filter drops anything outside the room's subnet |

*Tested:* `TestRoomsDoNotSeeEachOther`, `TestRoomsAreIsolated` (relay),
`TestRoomsAreSeparate` (end to end), `rooms_are_isolated` (network lab).

## The relay

- A client must prove two things before the relay forwards for it: that it
  receives packets at the address it sends from (a cookie bound to that
  address) and that the server authorised it for the room (a MAC under a
  per-ticket key). A captured bind replayed from another address is refused.
  *Tested:* `TestReplayedConfirmFromAnotherAddressIsRefused`,
  `TestBindRejections`.
- The relay never sends more bytes than it received in reply to an
  unauthenticated packet, so it cannot be used to amplify traffic at a
  spoofed address. *Tested:* `TestBindFrames`, `TestProbe`.
- Removing a member (kick, ban, room closed) revokes its relay access
  immediately on the built-in relay, including tickets it still holds.
  *Tested:* `TestRevokeAndExpiry`.
- Optional per-client rate limit (dashboard, Settings).

## The dashboard

- **Passwords** are Argon2id, minimum 10 characters.
- **Sessions** are random 256-bit tokens in a cookie that is `HttpOnly`,
  `SameSite=Strict` and, over HTTPS, `Secure`. The database stores only the
  token's SHA-256, so a copy of the database cannot be used to sign in.
  Signing out, disabling an account or changing its password ends its
  sessions on the server.
- **Cross-site requests** are refused by origin (Go's
  `http.CrossOriginProtection`) in addition to the cookie's `SameSite`.
- **Lockout** after five failed sign-ins, per address and per account name.
- **Roles.** Viewers can only read; administrators manage rooms, members,
  bans and settings; only owners manage administrator accounts. The last
  active owner cannot be removed, demoted or disabled.
- **Headers.** A strict Content-Security-Policy (no inline script or style,
  no third-party origins), `X-Frame-Options: DENY`, `nosniff`, HSTS over TLS.
- **Audit.** Sign-ins, failures, lockouts and every administrative action
  are recorded with who, when and from where.

*Tested:* `TestAdminAuthentication`, `TestAdminLoginLockout`,
`TestAdminRoles`.

## Abuse within a room

A member is someone you gave the password to, but may still misbehave:

- What one member can make the server send to others is rate limited (punch
  requests once per second per target, endpoint updates in small bursts), and
  advisory messages are never allowed to fill another member's queue.
  *Tested:* `TestEndpointsAndPunch`, `TestAdvisoryMessagesNeverDisconnect`.
- Broadcast fan-out is limited to 100 packets per second per client.
- Members can be kicked or banned from a room, and devices or address ranges
  banned from the server.

## On the Windows PC

- The **device identity and any remembered room password** are encrypted with
  DPAPI under the service's account. Other users of the PC can read the file
  but not decrypt it.
- The **window is unprivileged** and has no network access of its own. It
  reaches the service through a named pipe that refuses connections from the
  network and admits only interactive users.
- The **network driver library** (`wintun.dll`) is the unmodified, signed
  file from the official Wintun release, embedded in the program, written
  next to it and checked against its hash before every load; it is loaded by
  full path, with anything it needs taken from the system directory only.
  How it is loaded on a machine that has another VPN's adapter is described
  in [ARCHITECTURE.md](ARCHITECTURE.md#loading-the-wintun-library-safely).
- **Membership of a room makes your room address reachable by its members.**
  With "Treat the room as a private network" on (the default), whatever you
  have allowed on private networks (file sharing, a game server) is reachable
  from the room. Join only rooms whose members you would let onto your home
  network, or turn that setting off.
- Lanora adds two firewall rules: inbound UDP to `Lanora.exe` (so members can
  connect directly), and ICMP echo from the room's subnet to your room
  address while in a room.

## What the server can do

The server introduces members to each other. A compromised or malicious
server could give members keys of its own and sit between them. This is the
same trust that Radmin VPN, Hamachi, Tailscale and ZeroTier place in their
coordination servers; the difference is that you run this one. Protect it
accordingly: keep the dashboard password strong, keep the host patched, and
prefer a real certificate (or guard the pin) so clients cannot be pointed at
an impostor.

The server also sees room passwords in transit when members join (inside
TLS), as any password-checking server does. It stores only hashes.

## Not covered

- **Denial of service by volume** against the server's network link.
- **A hostile room member** can send you any traffic your own firewall allows
  from the room.
- **Code signing.** `Lanora.exe` is unsigned; users are asked to trust the
  file you give them. Sign it before distributing widely.
- **Two-factor authentication** for the dashboard is not implemented.

## Reporting

Security-relevant events to watch in the dashboard's Logs: `auth.fail`,
`auth.lockout`, `auth.banned`, `admin.login.fail`.

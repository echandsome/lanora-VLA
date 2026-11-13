-- Lanora schema, revision 1.
--
-- SQLite holds only durable application data: administrators, rooms, room
-- membership (which device owns which virtual address), bans, settings and
-- the audit/event log. Presence, endpoints and relay sessions live in memory
-- and never touch the database, so it is not on the path of any real-time
-- traffic.
--
-- All timestamps are Unix milliseconds (UTC).
--
-- Every numeric id is AUTOINCREMENT, which in SQLite means "never reused":
-- without it, deleting the newest row hands its id to the next one. Session
-- tokens, relay tickets and log entries all refer to rooms and members by
-- id, so an id must never come to mean a different room or member.

CREATE TABLE admins (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL CHECK (role IN ('owner', 'admin', 'viewer')),
    disabled      INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
    created_at    INTEGER NOT NULL,
    last_login_at INTEGER
) STRICT;

-- Dashboard sessions. Only the SHA-256 of the session token is stored, so a
-- copy of the database cannot be used to impersonate a signed-in admin.
CREATE TABLE admin_sessions (
    token_hash   BLOB    PRIMARY KEY,
    admin_id     INTEGER NOT NULL REFERENCES admins (id) ON DELETE CASCADE,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    addr         TEXT    NOT NULL DEFAULT '',
    user_agent   TEXT    NOT NULL DEFAULT ''
) STRICT, WITHOUT ROWID;

CREATE INDEX admin_sessions_admin   ON admin_sessions (admin_id);
CREATE INDEX admin_sessions_expires ON admin_sessions (expires_at);

CREATE TABLE rooms (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    public_id        TEXT    NOT NULL UNIQUE,
    name             TEXT    NOT NULL,
    description      TEXT    NOT NULL DEFAULT '',
    password_hash    TEXT    NOT NULL,
    -- Bumped whenever the password changes; session tokens carry the value
    -- they were issued under, so a password change signs everyone out.
    password_version INTEGER NOT NULL DEFAULT 1,
    subnet           TEXT    NOT NULL UNIQUE,
    capacity         INTEGER NOT NULL CHECK (capacity BETWEEN 2 AND 253),
    enabled          INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at       INTEGER NOT NULL,
    updated_at       INTEGER NOT NULL,
    created_by       INTEGER REFERENCES admins (id) ON DELETE SET NULL
) STRICT;

-- One row per device that has ever joined a room. It is the address lease:
-- a device keeps the same virtual IP every time it comes back.
CREATE TABLE members (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id        INTEGER NOT NULL REFERENCES rooms (id) ON DELETE CASCADE,
    identity       BLOB    NOT NULL CHECK (length(identity) = 32),
    nickname       TEXT    NOT NULL,
    ip             TEXT    NOT NULL,
    banned         INTEGER NOT NULL DEFAULT 0 CHECK (banned IN (0, 1)),
    ban_reason     TEXT    NOT NULL DEFAULT '',
    first_seen_at  INTEGER NOT NULL,
    last_seen_at   INTEGER NOT NULL,
    last_addr      TEXT    NOT NULL DEFAULT '',
    platform       TEXT    NOT NULL DEFAULT '',
    client_version TEXT    NOT NULL DEFAULT '',
    UNIQUE (room_id, identity),
    UNIQUE (room_id, ip)
) STRICT;

CREATE INDEX members_identity  ON members (identity);
CREATE INDEX members_last_seen ON members (room_id, last_seen_at);

-- Server-wide bans, by device identity (hex) or by source IP / CIDR.
CREATE TABLE bans (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    kind       TEXT    NOT NULL CHECK (kind IN ('identity', 'ip')),
    value      TEXT    NOT NULL,
    reason     TEXT    NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    created_by INTEGER REFERENCES admins (id) ON DELETE SET NULL,
    UNIQUE (kind, value)
) STRICT;

-- Connection, security and administration log shown in the dashboard.
CREATE TABLE events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        INTEGER NOT NULL,
    level     TEXT    NOT NULL CHECK (level IN ('info', 'warn', 'error')),
    kind      TEXT    NOT NULL,
    room_id   INTEGER,
    member_id INTEGER,
    admin_id  INTEGER,
    actor     TEXT    NOT NULL DEFAULT '',
    addr      TEXT    NOT NULL DEFAULT '',
    message   TEXT    NOT NULL
) STRICT;

CREATE INDEX events_ts    ON events (ts);
CREATE INDEX events_room  ON events (room_id, ts);
CREATE INDEX events_level ON events (level, ts);

CREATE TABLE settings (
    key        TEXT    PRIMARY KEY,
    value      TEXT    NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT, WITHOUT ROWID;

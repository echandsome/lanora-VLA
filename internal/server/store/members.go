package store

import (
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"lanora/internal/proto"
)

// Member is a device's standing in a room: its identity, the virtual address
// leased to it, and whether it has been banned from the room.
type Member struct {
	ID            int64
	RoomID        int64
	Identity      proto.Key32
	Nickname      string
	IP            netip.Addr
	Banned        bool
	BanReason     string
	FirstSeenAt   time.Time
	LastSeenAt    time.Time
	LastAddr      string
	Platform      string
	ClientVersion string
}

const memberColumns = `id, room_id, identity, nickname, ip, banned, ban_reason,
	first_seen_at, last_seen_at, last_addr, platform, client_version`

func scanMember(row interface{ Scan(...any) error }) (Member, error) {
	var (
		m        Member
		identity []byte
		ip       string
		banned   int
		first    int64
		last     int64
	)
	if err := row.Scan(&m.ID, &m.RoomID, &identity, &m.Nickname, &ip, &banned, &m.BanReason,
		&first, &last, &m.LastAddr, &m.Platform, &m.ClientVersion); err != nil {
		return Member{}, mapErr(err)
	}
	if len(identity) != len(m.Identity) {
		return Member{}, fmt.Errorf("store: member %d has a %d-byte identity", m.ID, len(identity))
	}
	copy(m.Identity[:], identity)
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return Member{}, fmt.Errorf("store: member %d has invalid address %q: %w", m.ID, ip, err)
	}
	m.IP = addr
	m.Banned = banned != 0
	m.FirstSeenAt, m.LastSeenAt = msTime(first), msTime(last)
	return m, nil
}

// Admission holds the inputs for AdmitMember.
type Admission struct {
	RoomID        int64
	Subnet        netip.Prefix
	Identity      proto.Key32
	Nickname      string
	Addr          string
	Platform      string
	ClientVersion string

	// Online reports whether a virtual address is held by a connected
	// member. When the subnet is full, the lease of the member that has been
	// away longest is recycled; an address that is in use never is.
	Online func(netip.Addr) bool
}

// AdmitMember records that a device is joining a room and returns its
// membership, creating it (and leasing a virtual address) on first contact.
// A banned member is returned unchanged with Banned set; the caller must
// refuse it.
func (s *Store) AdmitMember(ctx context.Context, in Admission) (m Member, created bool, err error) {
	err = s.tx(ctx, func(tx *sql.Tx) error {
		existing, err := scanMember(tx.QueryRowContext(ctx,
			"SELECT "+memberColumns+" FROM members WHERE room_id = ? AND identity = ?", in.RoomID, in.Identity[:]))
		switch {
		case err == nil:
			if existing.Banned {
				m = existing
				return nil
			}
			now := nowMs()
			if _, err := tx.ExecContext(ctx, `UPDATE members
				SET nickname = ?, last_seen_at = ?, last_addr = ?, platform = ?, client_version = ?
				WHERE id = ?`, in.Nickname, now, in.Addr, in.Platform, in.ClientVersion, existing.ID); err != nil {
				return err
			}
			existing.Nickname, existing.LastSeenAt = in.Nickname, msTime(now)
			existing.LastAddr, existing.Platform, existing.ClientVersion = in.Addr, in.Platform, in.ClientVersion
			m = existing
			return nil
		case !errors.Is(err, ErrNotFound):
			return err
		}

		ip, err := leaseAddress(ctx, tx, in)
		if err != nil {
			return err
		}
		now := nowMs()
		res, err := tx.ExecContext(ctx, `INSERT INTO members
			(room_id, identity, nickname, ip, first_seen_at, last_seen_at, last_addr, platform, client_version)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			in.RoomID, in.Identity[:], in.Nickname, ip.String(), now, now, in.Addr, in.Platform, in.ClientVersion)
		if err != nil {
			return mapErr(err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			return err
		}
		created = true
		m = Member{
			ID: id, RoomID: in.RoomID, Identity: in.Identity, Nickname: in.Nickname, IP: ip,
			FirstSeenAt: msTime(now), LastSeenAt: msTime(now),
			LastAddr: in.Addr, Platform: in.Platform, ClientVersion: in.ClientVersion,
		}
		return nil
	})
	return m, created, err
}

// leaseAddress picks the lowest free host address in the room's subnet. If
// every address is leased it reclaims the one whose owner has been offline
// the longest.
func leaseAddress(ctx context.Context, tx *sql.Tx, in Admission) (netip.Addr, error) {
	if !in.Subnet.Addr().Is4() || in.Subnet.Bits() > 30 {
		return netip.Addr{}, fmt.Errorf("store: unusable room subnet %s", in.Subnet)
	}
	rows, err := tx.QueryContext(ctx, "SELECT ip FROM members WHERE room_id = ?", in.RoomID)
	if err != nil {
		return netip.Addr{}, err
	}
	used := map[netip.Addr]bool{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			rows.Close()
			return netip.Addr{}, err
		}
		if a, err := netip.ParseAddr(s); err == nil {
			used[a] = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return netip.Addr{}, err
	}

	base := binary.BigEndian.Uint32(in.Subnet.Masked().Addr().AsSlice())
	hosts := uint32(1)<<(32-in.Subnet.Bits()) - 2 // minus network and broadcast
	for i := uint32(1); i <= hosts; i++ {
		var a [4]byte
		binary.BigEndian.PutUint32(a[:], base+i)
		if ip := netip.AddrFrom4(a); !used[ip] {
			return ip, nil
		}
	}

	// Full: recycle the stalest lease that is neither banned nor online.
	stale, err := tx.QueryContext(ctx,
		"SELECT id, ip FROM members WHERE room_id = ? AND banned = 0 ORDER BY last_seen_at ASC", in.RoomID)
	if err != nil {
		return netip.Addr{}, err
	}
	var (
		victim   int64
		victimIP netip.Addr
	)
	for stale.Next() {
		var (
			id int64
			s  string
		)
		if err := stale.Scan(&id, &s); err != nil {
			stale.Close()
			return netip.Addr{}, err
		}
		ip, err := netip.ParseAddr(s)
		if err != nil || (in.Online != nil && in.Online(ip)) {
			continue
		}
		victim, victimIP = id, ip
		break
	}
	stale.Close()
	if err := stale.Err(); err != nil {
		return netip.Addr{}, err
	}
	if victim == 0 {
		return netip.Addr{}, fmt.Errorf("%w: every address in %s is in use", ErrNoSpace, in.Subnet)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM members WHERE id = ?", victim); err != nil {
		return netip.Addr{}, err
	}
	return victimIP, nil
}

// Member returns a membership by ID.
func (s *Store) Member(ctx context.Context, id int64) (Member, error) {
	return scanMember(s.r.QueryRowContext(ctx, "SELECT "+memberColumns+" FROM members WHERE id = ?", id))
}

// ListMembers returns every membership of a room ordered by virtual address.
func (s *Store) ListMembers(ctx context.Context, roomID int64) ([]Member, error) {
	rows, err := s.r.QueryContext(ctx, "SELECT "+memberColumns+" FROM members WHERE room_id = ?", roomID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Member
	for rows.Next() {
		m, err := scanMember(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP.Less(out[j].IP) })
	return out, rows.Err()
}

// SetMemberBan bans or unbans a member from its room.
func (s *Store) SetMemberBan(ctx context.Context, id int64, banned bool, reason string) (Member, error) {
	if !banned {
		reason = ""
	}
	res, err := s.w.ExecContext(ctx, "UPDATE members SET banned = ?, ban_reason = ? WHERE id = ?", boolInt(banned), reason, id)
	if err != nil {
		return Member{}, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return Member{}, ErrNotFound
	}
	return scanMember(s.w.QueryRowContext(ctx, "SELECT "+memberColumns+" FROM members WHERE id = ?", id))
}

// DeleteMember removes a membership, releasing its virtual address.
func (s *Store) DeleteMember(ctx context.Context, id int64) error {
	res, err := s.w.ExecContext(ctx, "DELETE FROM members WHERE id = ?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchMember records that a member was just seen (on disconnect, so that
// "last seen" reflects when it was last online).
func (s *Store) TouchMember(ctx context.Context, id int64) error {
	_, err := s.w.ExecContext(ctx, "UPDATE members SET last_seen_at = ? WHERE id = ?", nowMs(), id)
	return err
}

// CountMembers returns the number of membership records.
func (s *Store) CountMembers(ctx context.Context) (int, error) {
	var n int
	err := s.r.QueryRowContext(ctx, "SELECT COUNT(*) FROM members").Scan(&n)
	return n, err
}

// CountDevices returns the number of distinct devices that are a member of
// at least one room.
func (s *Store) CountDevices(ctx context.Context) (int, error) {
	var n int
	err := s.r.QueryRowContext(ctx, "SELECT COUNT(DISTINCT identity) FROM members").Scan(&n)
	return n, err
}

// MemberCounts returns the number of membership records per room.
func (s *Store) MemberCounts(ctx context.Context) (map[int64]int, error) {
	rows, err := s.r.QueryContext(ctx, "SELECT room_id, COUNT(*) FROM members GROUP BY room_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]int{}
	for rows.Next() {
		var id int64
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

// Device summarises one device identity across every room it has joined.
type Device struct {
	Identity      proto.Key32
	Nickname      string
	Rooms         int
	BannedRooms   int
	FirstSeenAt   time.Time
	LastSeenAt    time.Time
	LastAddr      string
	Platform      string
	ClientVersion string
}

// DeviceFilter narrows ListDevices.
type DeviceFilter struct {
	Search string
	Limit  int
	Offset int
}

// ListDevices returns known devices, most recently seen first, and the total
// number matching the filter.
func (s *Store) ListDevices(ctx context.Context, f DeviceFilter) ([]Device, int, error) {
	where, args := "", []any{}
	if f.Search != "" {
		where = ` WHERE m.nickname LIKE ? ESCAPE '\' OR m.last_addr LIKE ? ESCAPE '\' OR hex(m.identity) LIKE ? ESCAPE '\'`
		p := likePattern(f.Search)
		args = append(args, p, p, p)
	}
	var total int
	if err := s.r.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM (SELECT 1 FROM members m"+where+" GROUP BY m.identity)", args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	// The newest membership of each device supplies its descriptive fields.
	rows, err := s.r.QueryContext(ctx, `
		SELECT m.identity, COUNT(*), SUM(m.banned), MIN(m.first_seen_at), MAX(m.last_seen_at),
		       (SELECT x.nickname       FROM members x WHERE x.identity = m.identity ORDER BY x.last_seen_at DESC LIMIT 1),
		       (SELECT x.last_addr      FROM members x WHERE x.identity = m.identity ORDER BY x.last_seen_at DESC LIMIT 1),
		       (SELECT x.platform       FROM members x WHERE x.identity = m.identity ORDER BY x.last_seen_at DESC LIMIT 1),
		       (SELECT x.client_version FROM members x WHERE x.identity = m.identity ORDER BY x.last_seen_at DESC LIMIT 1)
		FROM members m`+where+`
		GROUP BY m.identity
		ORDER BY MAX(m.last_seen_at) DESC
		LIMIT ? OFFSET ?`, append(args, limit, max(f.Offset, 0))...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		var (
			d        Device
			identity []byte
			first    int64
			last     int64
		)
		if err := rows.Scan(&identity, &d.Rooms, &d.BannedRooms, &first, &last,
			&d.Nickname, &d.LastAddr, &d.Platform, &d.ClientVersion); err != nil {
			return nil, 0, err
		}
		copy(d.Identity[:], identity)
		d.FirstSeenAt, d.LastSeenAt = msTime(first), msTime(last)
		out = append(out, d)
	}
	return out, total, rows.Err()
}

// DeviceMembership is one room a device belongs to.
type DeviceMembership struct {
	Member
	RoomPublicID string
	RoomName     string
}

// DeviceMemberships returns every room membership of a device.
func (s *Store) DeviceMemberships(ctx context.Context, identity proto.Key32) ([]DeviceMembership, error) {
	rows, err := s.r.QueryContext(ctx, `
		SELECT m.id, m.room_id, m.identity, m.nickname, m.ip, m.banned, m.ban_reason,
		       m.first_seen_at, m.last_seen_at, m.last_addr, m.platform, m.client_version,
		       r.public_id, r.name
		FROM members m JOIN rooms r ON r.id = m.room_id
		WHERE m.identity = ?
		ORDER BY m.last_seen_at DESC`, identity[:])
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DeviceMembership
	for rows.Next() {
		var dm DeviceMembership
		m, err := scanMember(scanTail{rows, []any{&dm.RoomPublicID, &dm.RoomName}})
		if err != nil {
			return nil, err
		}
		dm.Member = m
		out = append(out, dm)
	}
	return out, rows.Err()
}

// scanTail lets scanMember be reused for queries that select extra trailing
// columns: the extra destinations are appended to scanMember's own.
type scanTail struct {
	rows  *sql.Rows
	extra []any
}

func (s scanTail) Scan(dest ...any) error { return s.rows.Scan(append(dest, s.extra...)...) }

// Ban is a server-wide ban on a device identity or a source address range.
type Ban struct {
	ID        int64
	Kind      string // BanIdentity or BanIP
	Value     string
	Reason    string
	CreatedAt time.Time
	CreatedBy int64
}

// Ban kinds.
const (
	BanIdentity = "identity"
	BanIP       = "ip"
)

// NormalizeBan validates a ban value and returns its canonical form: 64 hex
// digits for an identity, a masked prefix for an address or range.
func NormalizeBan(kind, value string) (string, error) {
	switch kind {
	case BanIdentity:
		if k, err := proto.ParseKey32(value); err == nil {
			return k.Hex(), nil
		}
		b, err := hex.DecodeString(value)
		if err != nil || len(b) != 32 {
			return "", errors.New("identity must be a 32-byte key in hex or base64")
		}
		return hex.EncodeToString(b), nil
	case BanIP:
		if a, err := netip.ParseAddr(value); err == nil {
			a = a.Unmap()
			return netip.PrefixFrom(a, a.BitLen()).String(), nil
		}
		p, err := netip.ParsePrefix(value)
		if err != nil {
			return "", errors.New("address must be an IP address or a CIDR range")
		}
		return p.Masked().String(), nil
	}
	return "", errors.New("ban kind must be identity or ip")
}

// AddBan records a server-wide ban. value must already be normalised.
func (s *Store) AddBan(ctx context.Context, kind, value, reason string, by int64) (Ban, error) {
	var createdBy any
	if by != 0 {
		createdBy = by
	}
	now := nowMs()
	res, err := s.w.ExecContext(ctx,
		"INSERT INTO bans (kind, value, reason, created_at, created_by) VALUES (?, ?, ?, ?, ?)",
		kind, value, reason, now, createdBy)
	if err != nil {
		return Ban{}, mapErr(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Ban{}, err
	}
	return Ban{ID: id, Kind: kind, Value: value, Reason: reason, CreatedAt: msTime(now), CreatedBy: by}, nil
}

// RemoveBan deletes a server-wide ban.
func (s *Store) RemoveBan(ctx context.Context, id int64) error {
	res, err := s.w.ExecContext(ctx, "DELETE FROM bans WHERE id = ?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ListBans returns all server-wide bans, newest first.
func (s *Store) ListBans(ctx context.Context) ([]Ban, error) {
	rows, err := s.r.QueryContext(ctx,
		"SELECT id, kind, value, reason, created_at, COALESCE(created_by, 0) FROM bans ORDER BY created_at DESC, id DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Ban
	for rows.Next() {
		var b Ban
		var created int64
		if err := rows.Scan(&b.ID, &b.Kind, &b.Value, &b.Reason, &created, &b.CreatedBy); err != nil {
			return nil, err
		}
		b.CreatedAt = msTime(created)
		out = append(out, b)
	}
	return out, rows.Err()
}

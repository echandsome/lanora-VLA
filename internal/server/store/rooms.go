package store

import (
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"lanora/internal/proto"
)

// RoomPrefixBits is the size of every room's virtual subnet. A /24 gives 254
// host addresses, mirrors what people expect from a home LAN, and keeps the
// broadcast domain small enough for discovery traffic to stay cheap.
const RoomPrefixBits = 24

// MaxRoomCapacity is the largest number of simultaneously connected members
// a room may be configured for: one host address stays spare so a returning
// device can always be given its lease back.
const MaxRoomCapacity = 253

// Room is a virtual LAN.
type Room struct {
	ID              int64
	PublicID        string
	Name            string
	Description     string
	PasswordHash    string
	PasswordVersion int
	Subnet          netip.Prefix
	Capacity        int
	Enabled         bool
	CreatedAt       time.Time
	UpdatedAt       time.Time
	CreatedBy       int64
}

// NewRoom holds the inputs for CreateRoom.
type NewRoom struct {
	Name         string
	Description  string
	PasswordHash string
	Capacity     int
	CreatedBy    int64

	// Pool is the range room subnets are carved from. Subnet, when set,
	// requests a specific /24 instead of the next free one.
	Pool   netip.Prefix
	Subnet netip.Prefix
}

const roomColumns = `id, public_id, name, description, password_hash, password_version,
	subnet, capacity, enabled, created_at, updated_at, COALESCE(created_by, 0)`

func scanRoom(row interface{ Scan(...any) error }) (Room, error) {
	var (
		r       Room
		subnet  string
		enabled int
		created int64
		updated int64
	)
	if err := row.Scan(&r.ID, &r.PublicID, &r.Name, &r.Description, &r.PasswordHash, &r.PasswordVersion,
		&subnet, &r.Capacity, &enabled, &created, &updated, &r.CreatedBy); err != nil {
		return Room{}, mapErr(err)
	}
	p, err := netip.ParsePrefix(subnet)
	if err != nil {
		return Room{}, fmt.Errorf("store: room %d has invalid subnet %q: %w", r.ID, subnet, err)
	}
	r.Subnet = p
	r.Enabled = enabled != 0
	r.CreatedAt, r.UpdatedAt = msTime(created), msTime(updated)
	return r, nil
}

// ValidatePool checks that p can serve as the pool room subnets are carved
// from: IPv4, no wider than /8 and at least one /24.
func ValidatePool(p netip.Prefix) error {
	if !p.IsValid() || !p.Addr().Is4() {
		return errors.New("address pool must be an IPv4 prefix")
	}
	if p != p.Masked() {
		return fmt.Errorf("address pool %s has host bits set (did you mean %s?)", p, p.Masked())
	}
	if p.Bits() < 8 || p.Bits() > RoomPrefixBits {
		return fmt.Errorf("address pool must be between /8 and /%d", RoomPrefixBits)
	}
	return nil
}

// ValidateRoomSubnet checks an explicitly requested room subnet.
func ValidateRoomSubnet(p netip.Prefix) error {
	if !p.IsValid() || !p.Addr().Is4() || p.Bits() != RoomPrefixBits {
		return fmt.Errorf("room subnet must be an IPv4 /%d", RoomPrefixBits)
	}
	if p != p.Masked() {
		return fmt.Errorf("room subnet %s has host bits set (did you mean %s?)", p, p.Masked())
	}
	return nil
}

// CreateRoom inserts a room, assigning it a unique public ID and a subnet
// that overlaps no other room.
func (s *Store) CreateRoom(ctx context.Context, in NewRoom) (Room, error) {
	var room Room
	err := s.tx(ctx, func(tx *sql.Tx) error {
		used, err := roomSubnets(ctx, tx)
		if err != nil {
			return err
		}
		subnet := in.Subnet
		if subnet.IsValid() {
			for _, u := range used {
				if u.Overlaps(subnet) {
					return fmt.Errorf("%w: subnet %s is used by another room", ErrConflict, subnet)
				}
			}
		} else if subnet, err = nextFreeSubnet(in.Pool, used); err != nil {
			return err
		}

		now := nowMs()
		var createdBy any
		if in.CreatedBy != 0 {
			createdBy = in.CreatedBy
		}
		for attempt := 0; ; attempt++ {
			res, err := tx.ExecContext(ctx, `INSERT INTO rooms
				(public_id, name, description, password_hash, subnet, capacity, created_at, updated_at, created_by)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				proto.NewRoomID(), in.Name, in.Description, in.PasswordHash, subnet.String(), in.Capacity, now, now, createdBy)
			if err != nil {
				// The subnet was chosen inside this transaction, so a
				// uniqueness failure can only be a public ID collision.
				if errors.Is(mapErr(err), ErrConflict) && attempt < 8 {
					continue
				}
				return mapErr(err)
			}
			id, err := res.LastInsertId()
			if err != nil {
				return err
			}
			room, err = scanRoom(tx.QueryRowContext(ctx, "SELECT "+roomColumns+" FROM rooms WHERE id = ?", id))
			return err
		}
	})
	return room, err
}

func roomSubnets(ctx context.Context, tx *sql.Tx) ([]netip.Prefix, error) {
	rows, err := tx.QueryContext(ctx, "SELECT subnet FROM rooms")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []netip.Prefix
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p)
		}
	}
	return out, rows.Err()
}

// nextFreeSubnet returns the lowest /24 inside pool that overlaps none of
// the used prefixes.
func nextFreeSubnet(pool netip.Prefix, used []netip.Prefix) (netip.Prefix, error) {
	if err := ValidatePool(pool); err != nil {
		return netip.Prefix{}, err
	}
	taken := make(map[netip.Prefix]bool, len(used))
	var foreign []netip.Prefix // used subnets that are not plain /24s
	for _, u := range used {
		if u.Bits() == RoomPrefixBits {
			taken[u] = true
		} else {
			foreign = append(foreign, u)
		}
	}
	base := binary.BigEndian.Uint32(pool.Addr().AsSlice())
	count := uint32(1) << (RoomPrefixBits - pool.Bits())
next:
	for i := uint32(0); i < count; i++ {
		var a [4]byte
		binary.BigEndian.PutUint32(a[:], base+i<<8)
		cand := netip.PrefixFrom(netip.AddrFrom4(a), RoomPrefixBits)
		if taken[cand] {
			continue
		}
		for _, f := range foreign {
			if f.Overlaps(cand) {
				continue next
			}
		}
		return cand, nil
	}
	return netip.Prefix{}, fmt.Errorf("%w: no free /%d subnet left in pool %s", ErrNoSpace, RoomPrefixBits, pool)
}

// Room returns a room by its internal ID.
func (s *Store) Room(ctx context.Context, id int64) (Room, error) {
	return scanRoom(s.r.QueryRowContext(ctx, "SELECT "+roomColumns+" FROM rooms WHERE id = ?", id))
}

// RoomByPublicID returns a room by the ID users type to join it.
func (s *Store) RoomByPublicID(ctx context.Context, publicID string) (Room, error) {
	return scanRoom(s.r.QueryRowContext(ctx, "SELECT "+roomColumns+" FROM rooms WHERE public_id = ?", publicID))
}

// RoomFilter narrows ListRooms.
type RoomFilter struct {
	Search string
	Limit  int
	Offset int
}

// ListRooms returns rooms, newest first, and the total number matching the
// filter.
func (s *Store) ListRooms(ctx context.Context, f RoomFilter) ([]Room, int, error) {
	where, args := "", []any{}
	if term := strings.TrimSpace(f.Search); term != "" {
		where = ` WHERE name LIKE ? ESCAPE '\' OR description LIKE ? ESCAPE '\' OR public_id LIKE ? ESCAPE '\'`
		p := likePattern(term)
		// Room IDs are searched without the display dashes.
		args = append(args, p, p, likePattern(strings.ToUpper(strings.ReplaceAll(term, "-", ""))))
	}
	var total int
	if err := s.r.QueryRowContext(ctx, "SELECT COUNT(*) FROM rooms"+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	rows, err := s.r.QueryContext(ctx,
		"SELECT "+roomColumns+" FROM rooms"+where+" ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?",
		append(args, limit, max(f.Offset, 0))...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Room
	for rows.Next() {
		r, err := scanRoom(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}

// CountRooms returns the number of rooms.
func (s *Store) CountRooms(ctx context.Context) (int, error) {
	var n int
	err := s.r.QueryRowContext(ctx, "SELECT COUNT(*) FROM rooms").Scan(&n)
	return n, err
}

// RoomPatch lists the room fields to change; nil fields are left alone.
type RoomPatch struct {
	Name        *string
	Description *string
	Capacity    *int
	Enabled     *bool
}

// UpdateRoom applies a patch and returns the updated room.
func (s *Store) UpdateRoom(ctx context.Context, id int64, p RoomPatch) (Room, error) {
	var room Room
	err := s.tx(ctx, func(tx *sql.Tx) error {
		sets, args := []string{"updated_at = ?"}, []any{nowMs()}
		if p.Name != nil {
			sets, args = append(sets, "name = ?"), append(args, *p.Name)
		}
		if p.Description != nil {
			sets, args = append(sets, "description = ?"), append(args, *p.Description)
		}
		if p.Capacity != nil {
			sets, args = append(sets, "capacity = ?"), append(args, *p.Capacity)
		}
		if p.Enabled != nil {
			sets, args = append(sets, "enabled = ?"), append(args, boolInt(*p.Enabled))
		}
		res, err := tx.ExecContext(ctx, "UPDATE rooms SET "+strings.Join(sets, ", ")+" WHERE id = ?", append(args, id)...)
		if err != nil {
			return mapErr(err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		room, err = scanRoom(tx.QueryRowContext(ctx, "SELECT "+roomColumns+" FROM rooms WHERE id = ?", id))
		return err
	})
	return room, err
}

// SetRoomPassword replaces a room's password hash and bumps its password
// version, which invalidates every session token issued under the old one.
func (s *Store) SetRoomPassword(ctx context.Context, id int64, hash string) (Room, error) {
	var room Room
	err := s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			"UPDATE rooms SET password_hash = ?, password_version = password_version + 1, updated_at = ? WHERE id = ?",
			hash, nowMs(), id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		room, err = scanRoom(tx.QueryRowContext(ctx, "SELECT "+roomColumns+" FROM rooms WHERE id = ?", id))
		return err
	})
	return room, err
}

// DeleteRoom removes a room and, by cascade, its membership records.
func (s *Store) DeleteRoom(ctx context.Context, id int64) error {
	res, err := s.w.ExecContext(ctx, "DELETE FROM rooms WHERE id = ?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

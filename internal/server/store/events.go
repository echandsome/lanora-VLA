package store

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

// Event levels.
const (
	LevelInfo  = "info"
	LevelWarn  = "warn"
	LevelError = "error"
)

// Event is one entry of the connection / security / administration log.
type Event struct {
	ID       int64
	Time     time.Time
	Level    string
	Kind     string // dotted category, e.g. "room.join", "auth.fail", "admin.login"
	RoomID   int64
	MemberID int64
	AdminID  int64
	Actor    string // display name of whoever caused the event
	Addr     string // source network address, when known
	Message  string
}

// InsertEvents appends a batch of events in one transaction.
func (s *Store) InsertEvents(ctx context.Context, events []Event) error {
	if len(events) == 0 {
		return nil
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		stmt, err := tx.PrepareContext(ctx, `INSERT INTO events
			(ts, level, kind, room_id, member_id, admin_id, actor, addr, message)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return err
		}
		defer stmt.Close()
		for _, e := range events {
			if _, err := stmt.ExecContext(ctx, e.Time.UnixMilli(), e.Level, e.Kind,
				nullID(e.RoomID), nullID(e.MemberID), nullID(e.AdminID), e.Actor, e.Addr, e.Message); err != nil {
				return err
			}
		}
		return nil
	})
}

func nullID(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}

// EventFilter narrows ListEvents. BeforeID pages backwards through the log:
// pass the ID of the oldest event already shown.
type EventFilter struct {
	Level    string // exact level, or "" for all
	Kind     string // kind prefix ("room." matches room.join, room.leave, ...)
	RoomID   int64
	Search   string
	BeforeID int64
	Limit    int
}

// ListEvents returns events, newest first.
func (s *Store) ListEvents(ctx context.Context, f EventFilter) ([]Event, error) {
	var conds []string
	var args []any
	if f.Level != "" {
		conds, args = append(conds, "level = ?"), append(args, f.Level)
	}
	if f.Kind != "" {
		conds, args = append(conds, `kind LIKE ? ESCAPE '\'`), append(args, likePrefix(f.Kind))
	}
	if f.RoomID != 0 {
		conds, args = append(conds, "room_id = ?"), append(args, f.RoomID)
	}
	if term := strings.TrimSpace(f.Search); term != "" {
		p := likePattern(term)
		conds = append(conds, `(message LIKE ? ESCAPE '\' OR actor LIKE ? ESCAPE '\' OR addr LIKE ? ESCAPE '\')`)
		args = append(args, p, p, p)
	}
	if f.BeforeID > 0 {
		conds, args = append(conds, "id < ?"), append(args, f.BeforeID)
	}
	q := `SELECT id, ts, level, kind, COALESCE(room_id, 0), COALESCE(member_id, 0), COALESCE(admin_id, 0),
		actor, addr, message FROM events`
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.r.QueryContext(ctx, q+" ORDER BY id DESC LIMIT ?", append(args, limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var ts int64
		if err := rows.Scan(&e.ID, &ts, &e.Level, &e.Kind, &e.RoomID, &e.MemberID, &e.AdminID,
			&e.Actor, &e.Addr, &e.Message); err != nil {
			return nil, err
		}
		e.Time = msTime(ts)
		out = append(out, e)
	}
	return out, rows.Err()
}

// PurgeEvents deletes events older than before and then trims the log to at
// most keep rows. It returns the number of rows removed.
func (s *Store) PurgeEvents(ctx context.Context, before time.Time, keep int) (int64, error) {
	var removed int64
	res, err := s.w.ExecContext(ctx, "DELETE FROM events WHERE ts < ?", before.UnixMilli())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	removed += n
	if keep > 0 {
		res, err = s.w.ExecContext(ctx,
			"DELETE FROM events WHERE id <= (SELECT id FROM events ORDER BY id DESC LIMIT 1 OFFSET ?)", keep)
		if err != nil {
			return removed, err
		}
		n, _ = res.RowsAffected()
		removed += n
	}
	return removed, nil
}

// Setting returns one stored setting, or "" and false when it is not set.
func (s *Store) Setting(ctx context.Context, key string) (string, bool, error) {
	var v string
	err := s.r.QueryRowContext(ctx, "SELECT value FROM settings WHERE key = ?", key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	return v, err == nil, err
}

// Settings returns every stored setting.
func (s *Store) Settings(ctx context.Context) (map[string]string, error) {
	rows, err := s.r.QueryContext(ctx, "SELECT key, value FROM settings")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

// SetSettings upserts a group of settings atomically.
func (s *Store) SetSettings(ctx context.Context, values map[string]string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		now := nowMs()
		for k, v := range values {
			if _, err := tx.ExecContext(ctx, `INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
				ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`, k, v, now); err != nil {
				return err
			}
		}
		return nil
	})
}

// SettingOrInit returns the stored value of key, first storing the result of
// init when the key is not set. It is used for values that must be generated
// once and then stay stable, such as the server's signing secret.
func (s *Store) SettingOrInit(ctx context.Context, key string, init func() string) (string, error) {
	var value string
	err := s.tx(ctx, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, "SELECT value FROM settings WHERE key = ?", key).Scan(&value)
		if err == nil {
			return nil
		}
		if err != sql.ErrNoRows {
			return err
		}
		value = init()
		_, err = tx.ExecContext(ctx, "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)", key, value, nowMs())
		return err
	})
	return value, err
}

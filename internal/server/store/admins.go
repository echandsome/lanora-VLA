package store

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

// Administrator roles, from most to least privileged.
const (
	RoleOwner  = "owner"  // everything, including managing other administrators
	RoleAdmin  = "admin"  // manage rooms, members, bans and settings
	RoleViewer = "viewer" // read-only access to the dashboard
)

// ValidRole reports whether role is a known administrator role.
func ValidRole(role string) bool {
	return role == RoleOwner || role == RoleAdmin || role == RoleViewer
}

// Admin is a dashboard account.
type Admin struct {
	ID           int64
	Username     string
	PasswordHash string
	Role         string
	Disabled     bool
	CreatedAt    time.Time
	LastLoginAt  time.Time // zero if the account has never signed in
}

const adminColumns = "id, username, password_hash, role, disabled, created_at, last_login_at"

func scanAdmin(row interface{ Scan(...any) error }) (Admin, error) {
	var (
		a        Admin
		disabled int
		created  int64
		last     sql.NullInt64
	)
	if err := row.Scan(&a.ID, &a.Username, &a.PasswordHash, &a.Role, &disabled, &created, &last); err != nil {
		return Admin{}, mapErr(err)
	}
	a.Disabled = disabled != 0
	a.CreatedAt, a.LastLoginAt = msTime(created), nullMsTime(last)
	return a, nil
}

// CreateAdmin adds a dashboard account.
func (s *Store) CreateAdmin(ctx context.Context, username, passwordHash, role string) (Admin, error) {
	res, err := s.w.ExecContext(ctx,
		"INSERT INTO admins (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
		username, passwordHash, role, nowMs())
	if err != nil {
		return Admin{}, mapErr(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Admin{}, err
	}
	return scanAdmin(s.w.QueryRowContext(ctx, "SELECT "+adminColumns+" FROM admins WHERE id = ?", id))
}

// Admin returns an account by ID.
func (s *Store) Admin(ctx context.Context, id int64) (Admin, error) {
	return scanAdmin(s.r.QueryRowContext(ctx, "SELECT "+adminColumns+" FROM admins WHERE id = ?", id))
}

// AdminByUsername returns an account by its (case-insensitive) username.
func (s *Store) AdminByUsername(ctx context.Context, username string) (Admin, error) {
	return scanAdmin(s.r.QueryRowContext(ctx, "SELECT "+adminColumns+" FROM admins WHERE username = ?", username))
}

// ListAdmins returns all accounts ordered by username.
func (s *Store) ListAdmins(ctx context.Context) ([]Admin, error) {
	rows, err := s.r.QueryContext(ctx, "SELECT "+adminColumns+" FROM admins ORDER BY username")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Admin
	for rows.Next() {
		a, err := scanAdmin(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// CountAdmins returns the number of accounts.
func (s *Store) CountAdmins(ctx context.Context) (int, error) {
	var n int
	err := s.r.QueryRowContext(ctx, "SELECT COUNT(*) FROM admins").Scan(&n)
	return n, err
}

// CountActiveOwners returns the number of enabled owner accounts. The API
// uses it to refuse changes that would leave the server without one.
func (s *Store) CountActiveOwners(ctx context.Context) (int, error) {
	var n int
	err := s.r.QueryRowContext(ctx, "SELECT COUNT(*) FROM admins WHERE role = 'owner' AND disabled = 0").Scan(&n)
	return n, err
}

// AdminPatch lists the account fields to change; nil fields are left alone.
type AdminPatch struct {
	Role         *string
	Disabled     *bool
	PasswordHash *string
}

// UpdateAdmin applies a patch. Changing the password or disabling the
// account also ends all of its dashboard sessions.
func (s *Store) UpdateAdmin(ctx context.Context, id int64, p AdminPatch) (Admin, error) {
	var admin Admin
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var sets []string
		var args []any
		if p.Role != nil {
			sets, args = append(sets, "role = ?"), append(args, *p.Role)
		}
		if p.Disabled != nil {
			sets, args = append(sets, "disabled = ?"), append(args, boolInt(*p.Disabled))
		}
		if p.PasswordHash != nil {
			sets, args = append(sets, "password_hash = ?"), append(args, *p.PasswordHash)
		}
		if len(sets) > 0 {
			res, err := tx.ExecContext(ctx, "UPDATE admins SET "+strings.Join(sets, ", ")+" WHERE id = ?", append(args, id)...)
			if err != nil {
				return mapErr(err)
			}
			if n, _ := res.RowsAffected(); n == 0 {
				return ErrNotFound
			}
		}
		if p.PasswordHash != nil || (p.Disabled != nil && *p.Disabled) {
			if _, err := tx.ExecContext(ctx, "DELETE FROM admin_sessions WHERE admin_id = ?", id); err != nil {
				return err
			}
		}
		var err error
		admin, err = scanAdmin(tx.QueryRowContext(ctx, "SELECT "+adminColumns+" FROM admins WHERE id = ?", id))
		return err
	})
	return admin, err
}

// DeleteAdmin removes an account and, by cascade, its sessions.
func (s *Store) DeleteAdmin(ctx context.Context, id int64) error {
	res, err := s.w.ExecContext(ctx, "DELETE FROM admins WHERE id = ?", id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// AdminSession is a signed-in dashboard session.
type AdminSession struct {
	Admin     Admin
	CreatedAt time.Time
	ExpiresAt time.Time
}

// CreateAdminSession stores a session keyed by the hash of its token and
// stamps the account's last sign-in time.
func (s *Store) CreateAdminSession(ctx context.Context, tokenHash []byte, adminID int64, ttl time.Duration, addr, userAgent string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		now := time.Now()
		if _, err := tx.ExecContext(ctx, `INSERT INTO admin_sessions
			(token_hash, admin_id, created_at, expires_at, last_seen_at, addr, user_agent)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			tokenHash, adminID, now.UnixMilli(), now.Add(ttl).UnixMilli(), now.UnixMilli(), addr, userAgent); err != nil {
			return mapErr(err)
		}
		_, err := tx.ExecContext(ctx, "UPDATE admins SET last_login_at = ? WHERE id = ?", now.UnixMilli(), adminID)
		return err
	})
}

// AdminSession looks up an unexpired session by token hash.
func (s *Store) AdminSession(ctx context.Context, tokenHash []byte) (AdminSession, error) {
	var (
		sess     AdminSession
		created  int64
		expires  int64
		disabled int
		aCreated int64
		aLast    sql.NullInt64
	)
	err := s.r.QueryRowContext(ctx, `
		SELECT s.created_at, s.expires_at,
		       a.id, a.username, a.password_hash, a.role, a.disabled, a.created_at, a.last_login_at
		FROM admin_sessions s JOIN admins a ON a.id = s.admin_id
		WHERE s.token_hash = ? AND s.expires_at > ?`, tokenHash, nowMs()).Scan(
		&created, &expires,
		&sess.Admin.ID, &sess.Admin.Username, &sess.Admin.PasswordHash, &sess.Admin.Role, &disabled, &aCreated, &aLast)
	if err != nil {
		return AdminSession{}, mapErr(err)
	}
	sess.CreatedAt, sess.ExpiresAt = msTime(created), msTime(expires)
	sess.Admin.Disabled = disabled != 0
	sess.Admin.CreatedAt, sess.Admin.LastLoginAt = msTime(aCreated), nullMsTime(aLast)
	return sess, nil
}

// ExtendAdminSession pushes a session's expiry out to ttl from now (sliding
// expiry for sessions that are in use).
func (s *Store) ExtendAdminSession(ctx context.Context, tokenHash []byte, ttl time.Duration) error {
	now := time.Now()
	_, err := s.w.ExecContext(ctx,
		"UPDATE admin_sessions SET expires_at = ?, last_seen_at = ? WHERE token_hash = ?",
		now.Add(ttl).UnixMilli(), now.UnixMilli(), tokenHash)
	return err
}

// DeleteAdminSession signs a session out.
func (s *Store) DeleteAdminSession(ctx context.Context, tokenHash []byte) error {
	_, err := s.w.ExecContext(ctx, "DELETE FROM admin_sessions WHERE token_hash = ?", tokenHash)
	return err
}

// DeleteAdminSessionsExcept signs out every session of an account apart from
// the one identified by keep (used after a password change).
func (s *Store) DeleteAdminSessionsExcept(ctx context.Context, adminID int64, keep []byte) error {
	_, err := s.w.ExecContext(ctx, "DELETE FROM admin_sessions WHERE admin_id = ? AND token_hash <> ?", adminID, keep)
	return err
}

// PurgeAdminSessions removes expired sessions.
func (s *Store) PurgeAdminSessions(ctx context.Context) error {
	_, err := s.w.ExecContext(ctx, "DELETE FROM admin_sessions WHERE expires_at <= ?", nowMs())
	return err
}

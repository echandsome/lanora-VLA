// Package store is Lanora's persistence layer on SQLite.
//
// Two connection pools are opened on the same database file: a single
// writer connection, so writes are serialised in-process instead of
// colliding on SQLite's file lock, and a pool of read-only connections that
// WAL mode lets run concurrently with the writer.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	sqlite "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Sentinel errors returned by store operations.
var (
	ErrNotFound = errors.New("store: not found")
	ErrConflict = errors.New("store: already exists")
	ErrNoSpace  = errors.New("store: address space exhausted")
)

// Store is a handle to the database. It is safe for concurrent use.
type Store struct {
	w    *sql.DB
	r    *sql.DB
	path string
}

// Open opens (creating if necessary) the database at path and brings its
// schema up to date.
func Open(ctx context.Context, path string) (*Store, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("store: resolve %q: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		return nil, fmt.Errorf("store: create data directory: %w", err)
	}

	common := []string{
		"busy_timeout(5000)",
		"foreign_keys(1)",
		"synchronous(NORMAL)",
		"temp_store(MEMORY)",
	}
	w, err := sql.Open("sqlite", dsn(abs, append([]string{"journal_mode(WAL)"}, common...), true))
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	w.SetMaxOpenConns(1)
	w.SetMaxIdleConns(1)

	if err := w.PingContext(ctx); err != nil {
		w.Close()
		return nil, fmt.Errorf("store: open %s: %w", abs, err)
	}

	r, err := sql.Open("sqlite", dsn(abs, append([]string{"query_only(1)"}, common...), false))
	if err != nil {
		w.Close()
		return nil, fmt.Errorf("store: open reader: %w", err)
	}
	readers := max(4, runtime.GOMAXPROCS(0))
	r.SetMaxOpenConns(readers)
	r.SetMaxIdleConns(readers)

	s := &Store{w: w, r: r, path: abs}
	if err := s.migrate(ctx); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func dsn(path string, pragmas []string, immediate bool) string {
	q := url.Values{}
	for _, p := range pragmas {
		q.Add("_pragma", p)
	}
	if immediate {
		// Take the write lock when a transaction begins rather than at its
		// first write, so a transaction can never fail half-way with BUSY.
		q.Set("_txlock", "immediate")
	}
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: q.Encode()}
	return u.String()
}

// Close checkpoints the write-ahead log and closes the database.
func (s *Store) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.w.ExecContext(ctx, "PRAGMA optimize")
	s.w.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)")
	return errors.Join(s.r.Close(), s.w.Close())
}

// Ping reports whether the database answers queries.
func (s *Store) Ping(ctx context.Context) error {
	var one int
	return s.r.QueryRowContext(ctx, "SELECT 1").Scan(&one)
}

// Path returns the database file location.
func (s *Store) Path() string { return s.path }

// Backup writes a consistent copy of the database to dst, which must not
// exist. It is safe to call while the server is running.
func (s *Store) Backup(ctx context.Context, dst string) error {
	if _, err := os.Stat(dst); err == nil {
		return fmt.Errorf("store: backup target %s already exists", dst)
	}
	_, err := s.w.ExecContext(ctx, "VACUUM INTO ?", dst)
	return err
}

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.w.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		name       TEXT    NOT NULL,
		applied_at INTEGER NOT NULL
	) STRICT`); err != nil {
		return fmt.Errorf("store: create migrations table: %w", err)
	}

	files, err := fs.Glob(migrationFS, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(files)

	var current int
	if err := s.w.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&current); err != nil {
		return fmt.Errorf("store: read schema version: %w", err)
	}

	for _, f := range files {
		name := filepath.Base(f)
		prefix, _, _ := strings.Cut(name, "_")
		version, err := strconv.Atoi(prefix)
		if err != nil {
			return fmt.Errorf("store: migration %q has no numeric prefix", name)
		}
		if version <= current {
			continue
		}
		body, err := migrationFS.ReadFile(f)
		if err != nil {
			return err
		}
		err = s.tx(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, string(body)); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx,
				"INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
				version, name, nowMs())
			return err
		})
		if err != nil {
			return fmt.Errorf("store: apply migration %s: %w", name, err)
		}
		current = version
	}
	return nil
}

// SchemaVersion returns the revision of the applied schema.
func (s *Store) SchemaVersion(ctx context.Context) (int, error) {
	var v int
	err := s.r.QueryRowContext(ctx, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations").Scan(&v)
	return v, err
}

// tx runs fn inside a write transaction, committing if it returns nil.
func (s *Store) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// SQLite extended result codes for uniqueness violations.
const (
	sqliteConstraintPrimaryKey = 1555
	sqliteConstraintUnique     = 2067
)

// mapErr translates driver errors into the package's sentinel errors.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	var se *sqlite.Error
	if errors.As(err, &se) {
		switch se.Code() {
		case sqliteConstraintUnique, sqliteConstraintPrimaryKey:
			return ErrConflict
		}
	}
	return err
}

func nowMs() int64 { return time.Now().UnixMilli() }

func msTime(ms int64) time.Time { return time.UnixMilli(ms).UTC() }

func nullMsTime(ms sql.NullInt64) time.Time {
	if !ms.Valid {
		return time.Time{}
	}
	return msTime(ms.Int64)
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// likePattern escapes a user-supplied search term for use with
// "LIKE ? ESCAPE '\'" and wraps it for substring matching.
func likePattern(term string) string { return "%" + likeEscaper.Replace(term) + "%" }

// likePrefix is likePattern for prefix matching.
func likePrefix(term string) string { return likeEscaper.Replace(term) + "%" }

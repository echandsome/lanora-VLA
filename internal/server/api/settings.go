package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"lanora/internal/proto"
	"lanora/internal/server/store"
	"lanora/internal/version"
)

// DefaultAddressPool is the range room subnets are carved from unless an
// administrator chooses another. See docs/ARCHITECTURE.md ("Addressing") for
// why this block was picked.
const DefaultAddressPool = "10.214.0.0/16"

// DefaultMTU is the MTU of the virtual adapter. 1280 fits inside every
// common path, including PPPoE links and the tunnel of another VPN that
// Lanora's own packets may be travelling through, without fragmentation.
const DefaultMTU = 1280

// Settings are the options an administrator can change from the dashboard
// while the server is running.
type Settings struct {
	ServerName        string `json:"server_name"`
	AddressPool       string `json:"address_pool"`
	MTU               int    `json:"mtu"`
	DefaultCapacity   int    `json:"default_capacity"`
	MaxRooms          int    `json:"max_rooms"`           // 0 = unlimited
	SessionHours      int    `json:"session_hours"`       // lifetime of a room session token
	AdminSessionHours int    `json:"admin_session_hours"` // idle lifetime of a dashboard session
	RelayLimitKbps    int    `json:"relay_limit_kbps"`    // per client; 0 = unlimited
	LogRetentionDays  int    `json:"log_retention_days"`
	MinClientVersion  string `json:"min_client_version"`
}

// DefaultSettings returns the settings of a fresh installation.
func DefaultSettings() Settings {
	return Settings{
		ServerName:        "Lanora",
		AddressPool:       DefaultAddressPool,
		MTU:               DefaultMTU,
		DefaultCapacity:   16,
		MaxRooms:          0,
		SessionHours:      24,
		AdminSessionHours: 12,
		RelayLimitKbps:    0,
		LogRetentionDays:  30,
		MinClientVersion:  version.MinClient,
	}
}

// Validate normalises the settings and reports the first problem found.
func (s *Settings) Validate() error {
	s.ServerName = proto.CleanText(s.ServerName, 48)
	if s.ServerName == "" {
		return errors.New("server name must not be empty")
	}
	pool, err := netip.ParsePrefix(strings.TrimSpace(s.AddressPool))
	if err != nil {
		return errors.New("address pool must be an IPv4 range in CIDR form, for example 10.214.0.0/16")
	}
	if err := store.ValidatePool(pool); err != nil {
		return err
	}
	s.AddressPool = pool.String()
	if s.MTU < 576 || s.MTU > 1400 {
		return errors.New("MTU must be between 576 and 1400")
	}
	if s.DefaultCapacity < 2 || s.DefaultCapacity > store.MaxRoomCapacity {
		return fmt.Errorf("default room capacity must be between 2 and %d", store.MaxRoomCapacity)
	}
	if s.MaxRooms < 0 || s.MaxRooms > 1_000_000 {
		return errors.New("maximum number of rooms must be between 0 (unlimited) and 1000000")
	}
	if s.SessionHours < 1 || s.SessionHours > 24*30 {
		return errors.New("room session lifetime must be between 1 hour and 30 days")
	}
	if s.AdminSessionHours < 1 || s.AdminSessionHours > 24*30 {
		return errors.New("dashboard session lifetime must be between 1 hour and 30 days")
	}
	if s.RelayLimitKbps < 0 || s.RelayLimitKbps > 10_000_000 {
		return errors.New("relay limit must be between 0 (unlimited) and 10000000 kbit/s")
	}
	if s.LogRetentionDays < 1 || s.LogRetentionDays > 3650 {
		return errors.New("log retention must be between 1 and 3650 days")
	}
	s.MinClientVersion = strings.TrimSpace(s.MinClientVersion)
	if s.MinClientVersion == "" {
		s.MinClientVersion = version.MinClient
	}
	if version.Compare(s.MinClientVersion, version.MinClient) < 0 {
		return fmt.Errorf("minimum client version cannot be lower than %s, the oldest this server supports", version.MinClient)
	}
	return nil
}

// Pool returns the address pool as a prefix.
func (s Settings) Pool() netip.Prefix { return netip.MustParsePrefix(s.AddressPool) }

// SessionTTL returns the lifetime of room session tokens.
func (s Settings) SessionTTL() time.Duration { return time.Duration(s.SessionHours) * time.Hour }

// AdminSessionTTL returns the idle lifetime of dashboard sessions.
func (s Settings) AdminSessionTTL() time.Duration {
	return time.Duration(s.AdminSessionHours) * time.Hour
}

// RelayLimitBytes returns the per-client relay budget in bytes per second.
func (s Settings) RelayLimitBytes() int64 { return int64(s.RelayLimitKbps) * 1000 / 8 }

const settingsKey = "settings"

// settingsCache holds the current settings for lock-free reads on hot paths.
type settingsCache struct {
	v atomic.Pointer[Settings]
}

func (c *settingsCache) get() Settings { return *c.v.Load() }

// loadSettings reads the stored settings, filling in defaults for anything
// missing (a fresh database, or fields added by a newer version).
func loadSettings(ctx context.Context, st *store.Store) (Settings, error) {
	s := DefaultSettings()
	raw, ok, err := st.Setting(ctx, settingsKey)
	if err != nil {
		return s, err
	}
	if ok {
		if err := json.Unmarshal([]byte(raw), &s); err != nil {
			return s, fmt.Errorf("stored settings are corrupt: %w", err)
		}
	}
	if err := s.Validate(); err != nil {
		return s, fmt.Errorf("stored settings are invalid: %w", err)
	}
	return s, nil
}

func saveSettings(ctx context.Context, st *store.Store, s Settings) error {
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return st.SetSettings(ctx, map[string]string{settingsKey: string(raw)})
}

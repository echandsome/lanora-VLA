// Package config loads the server's process-level configuration from the
// environment. Everything here needs a restart to change; settings that can
// be edited from the dashboard live in the database instead (see package
// api, Settings).
package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// Modes a server process can run in.
const (
	ModeServer = "server" // control plane, dashboard and built-in relay
	ModeRelay  = "relay"  // stand-alone relay node
)

// TLS modes.
const (
	TLSSelfSigned = "selfsigned" // generate and persist a certificate; clients pin it
	TLSFiles      = "files"      // certificate and key from files
	TLSAutocert   = "autocert"   // Let's Encrypt via ACME
	TLSOff        = "off"        // plain HTTP, for use behind a TLS-terminating proxy
)

// Config is the process configuration.
type Config struct {
	Mode    string
	DataDir string

	Listen     string // TCP: HTTPS API, dashboard and stream relay
	TLSMode    string
	TLSCert    string
	TLSKey     string
	TLSDomains []string
	ACMEListen string // TCP: HTTP-01 challenges and redirect to HTTPS
	ACMEEmail  string

	RelayListen string   // UDP listen address of the built-in relay
	RelayPublic string   // "host:port" advertised to clients; host may be empty
	Relays      []string // stand-alone relay nodes ("host:port"); replaces the built-in relay
	RelaySecret string
	Secret      string

	AdminUser     string
	AdminPassword string

	TrustedProxies []netip.Prefix
	MetricsToken   string
	AdminDir       string // serve the dashboard from disk instead of the embedded copy
	DebugListen    string // TCP address for Go's profiling endpoints; empty disables them

	LogLevel  string
	LogFormat string
}

// Var documents one environment variable.
type Var struct {
	Name    string
	Default string
	Help    string
}

// Vars lists every environment variable the server reads, for --help and
// the deployment documentation.
var Vars = []Var{
	{"LANORA_MODE", ModeServer, "server (control plane + dashboard + built-in relay) or relay (stand-alone relay node)"},
	{"LANORA_DATA_DIR", "./data", "directory for the database and generated certificates"},
	{"LANORA_LISTEN", ":8443", "TCP address for the HTTPS API, dashboard and TCP-fallback relay"},
	{"LANORA_TLS", TLSSelfSigned, "selfsigned, files, autocert, or off (only behind a TLS-terminating reverse proxy)"},
	{"LANORA_TLS_CERT", "", "certificate chain file (LANORA_TLS=files)"},
	{"LANORA_TLS_KEY", "", "private key file (LANORA_TLS=files)"},
	{"LANORA_TLS_DOMAINS", "", "comma-separated host names to obtain certificates for (LANORA_TLS=autocert)"},
	{"LANORA_ACME_LISTEN", ":80", "TCP address for ACME HTTP-01 challenges and the HTTP→HTTPS redirect (LANORA_TLS=autocert)"},
	{"LANORA_ACME_EMAIL", "", "contact address given to the certificate authority (optional)"},
	{"LANORA_RELAY_LISTEN", "", "UDP address of the built-in relay (default: the port of LANORA_LISTEN)"},
	{"LANORA_RELAY_PUBLIC", "", "relay address advertised to clients as host:port, when it differs from how clients reach the API (for example behind port mapping)"},
	{"LANORA_RELAYS", "", "comma-separated host:port list of stand-alone relay nodes; when set they are used instead of the built-in relay"},
	{"LANORA_RELAY_SECRET", "", "secret shared between the control server and stand-alone relay nodes (required when LANORA_RELAYS is set or LANORA_MODE=relay)"},
	{"LANORA_SECRET", "", "master signing secret; generated and stored in the database when unset"},
	{"LANORA_ADMIN_USER", "admin", "user name of the administrator created on first start"},
	{"LANORA_ADMIN_PASSWORD", "", "password of that administrator; a random one is generated and printed once when unset"},
	{"LANORA_TRUSTED_PROXIES", "", "comma-separated CIDRs of reverse proxies whose X-Forwarded-For header is trusted"},
	{"LANORA_METRICS_TOKEN", "", "bearer token that enables GET /metrics (Prometheus format); disabled when unset"},
	{"LANORA_ADMIN_DIR", "", "serve dashboard files from this directory instead of the embedded copy (development)"},
	{"LANORA_DEBUG_LISTEN", "", "address (use 127.0.0.1:6060) for Go's /debug/pprof profiling endpoints; they are unauthenticated, so never expose this port"},
	{"LANORA_LOG_LEVEL", "info", "debug, info, warn or error"},
	{"LANORA_LOG_FORMAT", "text", "text or json"},
}

func defaultOf(name string) string {
	for _, v := range Vars {
		if v.Name == name {
			return v.Default
		}
	}
	return ""
}

// Load reads the configuration from the environment.
func Load() (*Config, error) { return FromEnv(os.Getenv) }

// FromEnv builds a configuration from a lookup function.
func FromEnv(getenv func(string) string) (*Config, error) {
	get := func(name string) string {
		if v := strings.TrimSpace(getenv(name)); v != "" {
			return v
		}
		return defaultOf(name)
	}
	c := &Config{
		Mode:          strings.ToLower(get("LANORA_MODE")),
		DataDir:       get("LANORA_DATA_DIR"),
		Listen:        get("LANORA_LISTEN"),
		TLSMode:       strings.ToLower(get("LANORA_TLS")),
		TLSCert:       get("LANORA_TLS_CERT"),
		TLSKey:        get("LANORA_TLS_KEY"),
		TLSDomains:    splitList(get("LANORA_TLS_DOMAINS")),
		ACMEListen:    get("LANORA_ACME_LISTEN"),
		ACMEEmail:     get("LANORA_ACME_EMAIL"),
		RelayListen:   get("LANORA_RELAY_LISTEN"),
		RelayPublic:   get("LANORA_RELAY_PUBLIC"),
		Relays:        splitList(get("LANORA_RELAYS")),
		RelaySecret:   get("LANORA_RELAY_SECRET"),
		Secret:        get("LANORA_SECRET"),
		AdminUser:     get("LANORA_ADMIN_USER"),
		AdminPassword: getenv("LANORA_ADMIN_PASSWORD"), // not trimmed: spaces may be intended
		MetricsToken:  get("LANORA_METRICS_TOKEN"),
		AdminDir:      get("LANORA_ADMIN_DIR"),
		DebugListen:   get("LANORA_DEBUG_LISTEN"),
		LogLevel:      strings.ToLower(get("LANORA_LOG_LEVEL")),
		LogFormat:     strings.ToLower(get("LANORA_LOG_FORMAT")),
	}

	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if c.Mode != ModeServer && c.Mode != ModeRelay {
		fail("LANORA_MODE must be %q or %q, not %q", ModeServer, ModeRelay, c.Mode)
	}
	_, port, err := net.SplitHostPort(c.Listen)
	if err != nil {
		fail("LANORA_LISTEN %q is not a host:port address: %v", c.Listen, err)
	}
	if c.RelayListen == "" && port != "" {
		c.RelayListen = ":" + port
	}
	if _, _, err := net.SplitHostPort(c.RelayListen); err != nil && c.RelayListen != "" {
		fail("LANORA_RELAY_LISTEN %q is not a host:port address: %v", c.RelayListen, err)
	}
	if c.RelayPublic != "" {
		if _, _, err := net.SplitHostPort(c.RelayPublic); err != nil {
			fail("LANORA_RELAY_PUBLIC %q is not a host:port address: %v", c.RelayPublic, err)
		}
	}
	for _, r := range c.Relays {
		if host, _, err := net.SplitHostPort(r); err != nil || host == "" {
			fail("LANORA_RELAYS entry %q must be host:port", r)
		}
	}

	switch c.TLSMode {
	case TLSSelfSigned, TLSOff:
	case TLSFiles:
		if c.TLSCert == "" || c.TLSKey == "" {
			fail("LANORA_TLS=files needs LANORA_TLS_CERT and LANORA_TLS_KEY")
		}
	case TLSAutocert:
		if len(c.TLSDomains) == 0 {
			fail("LANORA_TLS=autocert needs LANORA_TLS_DOMAINS")
		}
	default:
		fail("LANORA_TLS must be selfsigned, files, autocert or off, not %q", c.TLSMode)
	}

	if (len(c.Relays) > 0 || c.Mode == ModeRelay) && len(c.RelaySecret) < 16 {
		fail("LANORA_RELAY_SECRET (at least 16 characters) is required with stand-alone relay nodes")
	}
	if c.Secret != "" && len(c.Secret) < 16 {
		fail("LANORA_SECRET must be at least 16 characters")
	}

	for _, p := range splitList(get("LANORA_TRUSTED_PROXIES")) {
		prefix, err := parsePrefixOrAddr(p)
		if err != nil {
			fail("LANORA_TRUSTED_PROXIES entry %q: %v", p, err)
			continue
		}
		c.TrustedProxies = append(c.TrustedProxies, prefix)
	}

	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		fail("LANORA_LOG_LEVEL must be debug, info, warn or error, not %q", c.LogLevel)
	}
	if c.LogFormat != "text" && c.LogFormat != "json" {
		fail("LANORA_LOG_FORMAT must be text or json, not %q", c.LogFormat)
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return c, nil
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func parsePrefixOrAddr(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, errors.New("not an IP address or CIDR range")
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// DatabasePath returns the location of the SQLite database.
func (c *Config) DatabasePath() string { return filepath.Join(c.DataDir, "lanora.db") }

// RelayPort returns the UDP port of the built-in relay.
func (c *Config) RelayPort() string {
	_, port, _ := net.SplitHostPort(c.RelayListen)
	return port
}

// Usage returns the environment variable reference as text.
func Usage() string {
	var b strings.Builder
	for _, v := range Vars {
		def := v.Default
		if def == "" {
			def = "(unset)"
		}
		fmt.Fprintf(&b, "  %-24s %s\n  %-24s default: %s\n", v.Name, v.Help, "", def)
	}
	return b.String()
}

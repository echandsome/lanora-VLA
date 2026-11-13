// Package settings stores what the client must remember between runs: the
// device identity, the user's preferences and, if asked to, the last room.
package settings

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Settings are the user-editable client options.
type Settings struct {
	Server   string `json:"server"`
	RoomID   string `json:"room_id"`
	Nickname string `json:"nickname"`

	// Remember keeps the room password (protected, see protect) so the
	// room can be rejoined without typing it again. AutoConnect rejoins it
	// when the client starts.
	Remember    bool `json:"remember"`
	AutoConnect bool `json:"auto_connect"`

	// LANPriority makes the virtual adapter the preferred interface for
	// broadcast and multicast, so LAN games find the room's members.
	LANPriority bool `json:"lan_priority"`
	// PrivateNetwork lets programs allowed on private networks accept
	// connections from the room.
	PrivateNetwork bool `json:"private_network"`
	// RelayOnly never connects directly to other members.
	RelayOnly bool `json:"relay_only"`
}

// DefaultServer is the server address a fresh installation starts with. It
// is empty unless set when the app is built (make windows SERVER=...), which
// lets an operator hand out an app that only asks for a room ID and
// password.
var DefaultServer = ""

// Defaults returns the settings of a fresh installation.
func Defaults() Settings {
	return Settings{Server: DefaultServer, LANPriority: true, PrivateNetwork: true}
}

// file is the on-disk form. Secrets are stored protected.
type file struct {
	Settings
	Identity []byte `json:"identity"`
	Password []byte `json:"password,omitempty"`
}

// Store reads and writes the client's state file.
type Store struct {
	path string
	mu   sync.Mutex
	data file
}

// DefaultDir returns the directory the Lanora service keeps its state in.
func DefaultDir() (string, error) { return defaultDir() }

// UserDir returns a state directory for running the client by hand as the
// current user. On Windows it is separate from the service's, whose secrets
// are encrypted for the service's account and unreadable to anyone else.
func UserDir() (string, error) { return userDir() }

// Open loads the state in dir, creating a device identity on first use.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating %s: %w", dir, err)
	}
	s := &Store{path: filepath.Join(dir, "client.json"), data: file{Settings: Defaults()}}
	raw, err := os.ReadFile(s.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(raw, &s.data); err != nil {
			return nil, fmt.Errorf("%s is corrupt: %w", s.path, err)
		}
	}
	if _, err := s.identity(); err != nil {
		if len(s.data.Identity) > 0 {
			// There is an identity, but this account cannot read it: it was
			// saved by another account (the Lanora service, say) or on
			// another computer. Replacing it would silently throw away the
			// device's addresses in every room, so refuse instead.
			return nil, fmt.Errorf("the device identity saved in %s cannot be read by this account; "+
				"use a different state directory, or delete that file to start over with a new identity", s.path)
		}
		// A new installation.
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		protected, err := protect(key.Seed())
		if err != nil {
			return nil, err
		}
		s.data.Identity, s.data.Password = protected, nil
		if err := s.save(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) identity() (ed25519.PrivateKey, error) {
	if len(s.data.Identity) == 0 {
		return nil, errors.New("no identity")
	}
	seed, err := unprotect(s.data.Identity)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("identity cannot be read")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// Identity returns the device's long-lived signing key. It identifies this
// installation to servers, which is how a device gets the same virtual
// address every time it returns to a room.
func (s *Store) Identity() ed25519.PrivateKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, err := s.identity()
	if err != nil {
		panic("settings: identity vanished after Open: " + err.Error())
	}
	return key
}

// Settings returns the current settings.
func (s *Store) Settings() Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data.Settings
}

// Password returns the remembered room password, or "".
func (s *Store) Password() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.data.Password) == 0 {
		return ""
	}
	pw, err := unprotect(s.data.Password)
	if err != nil {
		return ""
	}
	return string(pw)
}

// Update changes the settings and, when password is not nil, the remembered
// password (an empty string forgets it).
func (s *Store) Update(fn func(*Settings), password *string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(&s.data.Settings)
	if !s.data.Remember {
		s.data.Password = nil
	} else if password != nil {
		if *password == "" {
			s.data.Password = nil
		} else {
			protected, err := protect([]byte(*password))
			if err != nil {
				return err
			}
			s.data.Password = protected
		}
	}
	return s.save()
}

// save writes the state atomically, so a crash never leaves half a file.
func (s *Store) save() error {
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

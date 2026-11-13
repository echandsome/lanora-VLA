//go:build !windows

package settings

import (
	"os"
	"path/filepath"
)

// On Unix-like systems secrets are protected by file permissions: the state
// file is readable only by its owner.

func protect(b []byte) ([]byte, error)   { return b, nil }
func unprotect(b []byte) ([]byte, error) { return b, nil }

func defaultDir() (string, error) {
	if os.Geteuid() == 0 {
		return "/var/lib/lanora", nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "lanora"), nil
}

func userDir() (string, error) { return defaultDir() }

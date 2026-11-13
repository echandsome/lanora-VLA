//go:build !linux && !windows

package netcfg

import (
	"errors"
	"runtime"
)

// Open is not implemented for this operating system.
func Open(Config) (Adapter, error) {
	return nil, errors.New("Lanora does not support creating a virtual network adapter on " + runtime.GOOS)
}

//go:build !windows

package netcfg

// Preflight has nothing to check on this system; see preflight_windows.go.
func Preflight() []Check { return nil }

// Diagnostics has nothing to report on this system; see diag_windows.go.
func Diagnostics() string { return "" }

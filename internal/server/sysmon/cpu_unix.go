//go:build unix

package sysmon

import (
	"syscall"
	"time"
)

// processCPU returns the CPU time (user + system) the process has consumed.
func processCPU() time.Duration {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

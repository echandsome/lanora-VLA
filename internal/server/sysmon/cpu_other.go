//go:build !unix

package sysmon

import "time"

// processCPU is not implemented on this platform; CPU usage reads as zero.
func processCPU() time.Duration { return 0 }

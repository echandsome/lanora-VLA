package netcfg

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// driverVersion identifies a build of the Wintun kernel driver the way
// Windows does: by the date and the version in its package.
type driverVersion struct {
	date    time.Time
	version [4]uint16
}

// embeddedDriver is the driver inside the Wintun library this program
// carries (Wintun 0.14.1: "DriverVer = 10/13/2021,0.14.0.0"). The files are
// pinned by hash in wintun_test.go; change the two together.
var embeddedDriver = driverVersion{
	date:    time.Date(2021, time.October, 13, 0, 0, 0, 0, time.UTC),
	version: [4]uint16{0, 14, 0, 0},
}

func (v driverVersion) String() string {
	return fmt.Sprintf("%d.%d.%d.%d", v.version[0], v.version[1], v.version[2], v.version[3])
}

// olderThan reports whether the Wintun library would treat v as out of date
// next to ref and replace it. It mirrors IsNewer in Wintun's api/driver.c:
// the date decides, and the version only breaks a tie.
func (v driverVersion) olderThan(ref driverVersion) bool {
	if !v.date.Equal(ref.date) {
		return v.date.Before(ref.date)
	}
	for i := range v.version {
		if v.version[i] != ref.version[i] {
			return v.version[i] < ref.version[i]
		}
	}
	return false
}

// parseDriverVersion reads a version as Windows records it for an installed
// driver, for example "0.14.0.0".
func parseDriverVersion(s string) ([4]uint16, bool) {
	var v [4]uint16
	parts := strings.Split(strings.TrimSpace(s), ".")
	if len(parts) != len(v) {
		return v, false
	}
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return v, false
		}
		v[i] = uint16(n)
	}
	return v, true
}

// parseDriverDate reads a driver date as Windows records it in the
// registry, for example "10-13-2021".
func parseDriverDate(s string) (time.Time, bool) {
	t, err := time.Parse("1-2-2006", strings.TrimSpace(s))
	return t, err == nil
}

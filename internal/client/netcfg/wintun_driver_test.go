package netcfg

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"time"
)

func TestDriverVersionOrdering(t *testing.T) {
	day := func(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }
	ours := embeddedDriver
	cases := []struct {
		name  string
		v     driverVersion
		older bool
	}{
		{"the same driver", ours, false},
		{"Wintun 0.8.1, as OpenVPN 2.5 shipped it", driverVersion{day(2020, 4, 6), [4]uint16{0, 8, 1, 0}}, true},
		{"an earlier date wins over a higher version", driverVersion{day(2021, 10, 12), [4]uint16{9, 0, 0, 0}}, true},
		{"a later date wins over a lower version", driverVersion{day(2021, 10, 14), [4]uint16{0, 1, 0, 0}}, false},
		{"same date, lower version", driverVersion{ours.date, [4]uint16{0, 13, 9, 9}}, true},
		{"same date, higher version", driverVersion{ours.date, [4]uint16{0, 14, 0, 1}}, false},
	}
	for _, c := range cases {
		if got := c.v.olderThan(ours); got != c.older {
			t.Errorf("%s: olderThan = %v, want %v", c.name, got, c.older)
		}
	}
}

func TestParseDriverVersionAndDate(t *testing.T) {
	if v, ok := parseDriverVersion("0.14.0.0"); !ok || v != embeddedDriver.version {
		t.Errorf("version: %v %v", v, ok)
	}
	for _, bad := range []string{"", "0.14", "0.14.0.0.1", "a.b.c.d", "0.14.0.70000"} {
		if _, ok := parseDriverVersion(bad); ok {
			t.Errorf("version %q accepted", bad)
		}
	}
	if d, ok := parseDriverDate("10-13-2021"); !ok || !d.Equal(embeddedDriver.date) {
		t.Errorf("date: %v %v", d, ok)
	}
	if d, ok := parseDriverDate("4-6-2020"); !ok || d.Month() != time.April || d.Day() != 6 {
		t.Errorf("date: %v %v", d, ok)
	}
	if _, ok := parseDriverDate("2021-10-13"); ok {
		t.Error("an ISO date was accepted")
	}
	if embeddedDriver.String() != "0.14.0.0" {
		t.Errorf("String() = %s", embeddedDriver.String())
	}
}

// The embedded libraries must be exactly the files of the official Wintun
// 0.14.1 release. embeddedDriver, the way the library is loaded and the
// Astrill analysis in docs/ARCHITECTURE.md all describe that release; a
// different file needs all three looked at again.
func TestEmbeddedWintunIsTheOfficialRelease(t *testing.T) {
	want := map[string]string{
		"wintun/amd64/wintun.dll": "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce",
		"wintun/arm64/wintun.dll": "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80",
	}
	for path, sum := range want {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		got := sha256.Sum256(data)
		if hex.EncodeToString(got[:]) != sum {
			t.Errorf("%s: SHA-256 %x, want %s", path, got, sum)
		}
	}
}

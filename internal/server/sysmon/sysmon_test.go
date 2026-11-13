package sysmon

import (
	"testing"
	"time"
)

func TestMonitor(t *testing.T) {
	m := New(time.Second, 4)
	first := m.Latest()
	if first.Goroutines == 0 || first.CPUs == 0 || first.RSSBytes == 0 {
		t.Fatalf("empty first sample: %+v", first)
	}
	// Burn some CPU so the next sample shows usage.
	deadline := time.Now().Add(60 * time.Millisecond)
	x := 0
	for time.Now().Before(deadline) {
		x++
	}
	_ = x
	s := m.measure(time.Now())
	if s.CPUPercent <= 0 {
		t.Fatalf("CPU usage not measured: %+v", s)
	}
	for i := 0; i < 6; i++ {
		s.Goroutines = 100 + i
		m.record(s)
	}
	h := m.History()
	if len(h) != 4 || h[0].Goroutines != 102 || h[3].Goroutines != 105 {
		t.Fatalf("history window: %d samples, first %d, last %d", len(h), h[0].Goroutines, h[len(h)-1].Goroutines)
	}
	if m.Latest().Goroutines != 105 {
		t.Fatalf("latest = %d", m.Latest().Goroutines)
	}
}

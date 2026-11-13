// Package sysmon samples the server's resource usage for the dashboard.
package sysmon

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Sample is one measurement of process and host resource usage.
type Sample struct {
	Time time.Time `json:"time"`

	// Process.
	CPUPercent float64 `json:"cpu_percent"` // of one core; can exceed 100 on multi-core hosts
	RSSBytes   uint64  `json:"rss_bytes"`
	HeapBytes  uint64  `json:"heap_bytes"`
	Goroutines int     `json:"goroutines"`
	OpenFDs    int     `json:"open_fds"`

	// Host. Zero where the platform does not expose them.
	Load1         float64 `json:"load1"`
	MemTotalBytes uint64  `json:"mem_total_bytes"`
	MemAvailBytes uint64  `json:"mem_avail_bytes"`
	CPUs          int     `json:"cpus"`
}

// Monitor keeps a rolling window of samples.
type Monitor struct {
	interval time.Duration

	mu      sync.RWMutex
	samples []Sample // ring buffer
	next    int
	full    bool

	// measureMu serialises measurements: the periodic sampler and a request
	// for the latest sample before the first tick can both take one.
	measureMu sync.Mutex
	lastCPU   time.Duration
	lastWall  time.Time
}

// New returns a monitor that samples every interval and remembers the last
// window samples.
func New(interval time.Duration, window int) *Monitor {
	return &Monitor{interval: interval, samples: make([]Sample, window), lastCPU: processCPU(), lastWall: time.Now()}
}

// Run samples until ctx is cancelled.
func (m *Monitor) Run(ctx context.Context) {
	tick := time.NewTicker(m.interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			m.record(m.measure(now))
		}
	}
}

func (m *Monitor) measure(now time.Time) Sample {
	m.measureMu.Lock()
	defer m.measureMu.Unlock()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	s := Sample{
		Time:       now.UTC(),
		HeapBytes:  ms.HeapAlloc,
		Goroutines: runtime.NumGoroutine(),
		CPUs:       runtime.NumCPU(),
	}

	cpu := processCPU()
	if wall := now.Sub(m.lastWall); wall > 0 && cpu >= m.lastCPU {
		s.CPUPercent = float64(cpu-m.lastCPU) / float64(wall) * 100
	}
	m.lastCPU, m.lastWall = cpu, now

	s.RSSBytes = processRSS()
	if s.RSSBytes == 0 {
		s.RSSBytes = ms.Sys
	}
	s.OpenFDs = openFDs()
	s.Load1 = loadAverage()
	s.MemTotalBytes, s.MemAvailBytes = hostMemory()
	return s
}

func (m *Monitor) record(s Sample) {
	m.mu.Lock()
	m.samples[m.next] = s
	m.next = (m.next + 1) % len(m.samples)
	if m.next == 0 {
		m.full = true
	}
	m.mu.Unlock()
}

// Latest returns the most recent sample, taking one immediately if none has
// been recorded yet.
func (m *Monitor) Latest() Sample {
	m.mu.RLock()
	if m.next > 0 || m.full {
		s := m.samples[(m.next-1+len(m.samples))%len(m.samples)]
		m.mu.RUnlock()
		return s
	}
	m.mu.RUnlock()
	s := m.measure(time.Now())
	m.record(s)
	return s
}

// History returns the remembered samples, oldest first.
func (m *Monitor) History() []Sample {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.full {
		return append([]Sample(nil), m.samples[:m.next]...)
	}
	out := make([]Sample, 0, len(m.samples))
	out = append(out, m.samples[m.next:]...)
	return append(out, m.samples[:m.next]...)
}

// The host-level readers below use Linux's /proc. On other systems the
// files do not exist and the values are reported as zero.

func processRSS() uint64 {
	b, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(b))
	if len(fields) < 2 {
		return 0
	}
	pages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0
	}
	return pages * uint64(os.Getpagesize())
}

func openFDs() int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0
	}
	return len(entries)
}

func loadAverage() float64 {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(b))
	if len(fields) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(fields[0], 64)
	return v
}

func hostMemory() (total, avail uint64) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		kb, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			total = kb << 10
		case "MemAvailable:":
			avail = kb << 10
		}
	}
	return total, avail
}

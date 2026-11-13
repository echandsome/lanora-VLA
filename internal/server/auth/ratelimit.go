package auth

import (
	"math"
	"sync"
	"time"
)

// Limiter is a token-bucket rate limiter keyed by an arbitrary string
// (typically a client IP address). Each key may make burst requests at once
// and then rate requests per second. Idle keys are forgotten, so memory use
// follows the number of recently active clients, not the number ever seen.
type Limiter struct {
	rate  float64
	burst float64

	mu      sync.Mutex
	buckets map[string]*bucket
	swept   time.Time
	now     func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewLimiter returns a limiter allowing burst requests immediately and
// perMinute requests per minute thereafter, per key.
func NewLimiter(perMinute float64, burst int) *Limiter {
	return &Limiter{
		rate:    perMinute / 60,
		burst:   float64(burst),
		buckets: make(map[string]*bucket),
		now:     time.Now,
	}
}

// Allow reports whether key may proceed. When it may not, retry is how long
// to wait before the next attempt can succeed.
func (l *Limiter) Allow(key string) (ok bool, retry time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.sweep(now)

	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	} else {
		b.tokens = math.Min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
		b.last = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	return false, time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
}

// sweep drops buckets that have been idle long enough to be full again; a
// full bucket is indistinguishable from a missing one.
func (l *Limiter) sweep(now time.Time) {
	if now.Sub(l.swept) < time.Minute {
		return
	}
	l.swept = now
	idle := time.Duration(l.burst / l.rate * float64(time.Second))
	for k, b := range l.buckets {
		if now.Sub(b.last) > idle {
			delete(l.buckets, k)
		}
	}
}

// Lockout slows down password guessing. After threshold consecutive
// failures a key is locked for base, and the lock doubles with every further
// failure up to max. A success clears the key's history.
type Lockout struct {
	threshold int
	base      time.Duration
	max       time.Duration

	mu      sync.Mutex
	entries map[string]*lockEntry
	swept   time.Time
	now     func() time.Time
}

type lockEntry struct {
	failures int
	until    time.Time
	last     time.Time
}

// NewLockout returns a Lockout with the given policy.
func NewLockout(threshold int, base, max time.Duration) *Lockout {
	return &Lockout{threshold: threshold, base: base, max: max, entries: make(map[string]*lockEntry), now: time.Now}
}

// Locked returns how much longer key is locked, or zero if it is not.
func (l *Lockout) Locked(key string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if e := l.entries[key]; e != nil && now.Before(e.until) {
		return e.until.Sub(now)
	}
	return 0
}

// Fail records a failed attempt and returns the resulting lock duration
// (zero while the key is still under the threshold).
func (l *Lockout) Fail(key string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.sweep(now)

	e := l.entries[key]
	if e == nil {
		e = &lockEntry{}
		l.entries[key] = e
	}
	e.failures++
	e.last = now
	if e.failures < l.threshold {
		return 0
	}
	lock := l.max
	if shift := e.failures - l.threshold; shift < 20 {
		if d := l.base << shift; d > 0 && d < l.max {
			lock = d
		}
	}
	e.until = now.Add(lock)
	return lock
}

// Success clears key's failure history.
func (l *Lockout) Success(key string) {
	l.mu.Lock()
	delete(l.entries, key)
	l.mu.Unlock()
}

func (l *Lockout) sweep(now time.Time) {
	if now.Sub(l.swept) < time.Minute {
		return
	}
	l.swept = now
	for k, e := range l.entries {
		// Forget a key once its lock has expired and it has stayed quiet
		// for a further full lock period.
		if now.After(e.until) && now.Sub(e.last) > 2*l.max {
			delete(l.entries, k)
		}
	}
}

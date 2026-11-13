package api

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"lanora/internal/server/store"
)

// EventLog collects audit and connection events and writes them to the
// database in batches from a single goroutine. Callers never wait on the
// database: Add only places the event on a bounded queue, and when the
// queue is full (a flood of failed logins, say) events are dropped and
// counted instead of slowing the server down.
type EventLog struct {
	store *store.Store
	log   *slog.Logger
	queue chan store.Event

	dropped atomic.Uint64
	wg      sync.WaitGroup
}

const (
	eventQueueSize  = 4096
	eventBatchSize  = 256
	eventFlushEvery = 500 * time.Millisecond
)

// NewEventLog returns an event log writing to st. log must not itself feed
// the event log, or a failing database would generate events about its own
// failures.
func NewEventLog(st *store.Store, log *slog.Logger) *EventLog {
	return &EventLog{store: st, log: log, queue: make(chan store.Event, eventQueueSize)}
}

// Add queues an event. It never blocks.
func (l *EventLog) Add(e store.Event) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	select {
	case l.queue <- e:
	default:
		l.dropped.Add(1)
	}
}

// Record is a convenience wrapper matching hub.EventFunc.
func (l *EventLog) Record(level, kind string, roomID, memberID int64, actor, addr, message string) {
	l.Add(store.Event{Level: level, Kind: kind, RoomID: roomID, MemberID: memberID, Actor: actor, Addr: addr, Message: message})
}

// Dropped returns how many events were discarded because the queue was full.
func (l *EventLog) Dropped() uint64 { return l.dropped.Load() }

// Start begins writing queued events in the background. When ctx is
// cancelled the remaining events are flushed; Wait returns once that is
// done.
func (l *EventLog) Start(ctx context.Context) {
	l.wg.Add(1)
	go l.run(ctx)
}

func (l *EventLog) run(ctx context.Context) {
	defer l.wg.Done()

	tick := time.NewTicker(eventFlushEvery)
	defer tick.Stop()
	batch := make([]store.Event, 0, eventBatchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		// Use a fresh context: the final flush runs after ctx is cancelled.
		wctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := l.store.InsertEvents(wctx, batch); err != nil {
			l.log.Error("writing event log", "err", err, "events", len(batch))
		}
		cancel()
		batch = batch[:0]
	}
	for {
		select {
		case e := <-l.queue:
			batch = append(batch, e)
			if len(batch) >= eventBatchSize {
				flush()
			}
		case <-tick.C:
			flush()
		case <-ctx.Done():
			for {
				select {
				case e := <-l.queue:
					batch = append(batch, e)
					if len(batch) >= eventBatchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}
		}
	}
}

// Wait blocks until the writer started by Start has flushed and stopped.
func (l *EventLog) Wait() { l.wg.Wait() }

// LogHandler wraps a slog.Handler so that warnings and errors logged by the
// server also appear in the dashboard's log view.
type LogHandler struct {
	slog.Handler
	events *EventLog
}

// NewLogHandler returns a handler that forwards records at warn level and
// above to events in addition to passing every record to next.
func NewLogHandler(next slog.Handler, events *EventLog) *LogHandler {
	return &LogHandler{Handler: next, events: events}
}

// Handle implements slog.Handler.
func (h *LogHandler) Handle(ctx context.Context, r slog.Record) error {
	if r.Level >= slog.LevelWarn {
		level := store.LevelWarn
		if r.Level >= slog.LevelError {
			level = store.LevelError
		}
		msg := r.Message
		r.Attrs(func(a slog.Attr) bool {
			msg += " " + a.Key + "=" + a.Value.String()
			return len(msg) < 600
		})
		h.events.Add(store.Event{Time: r.Time, Level: level, Kind: "server.log", Message: msg})
	}
	return h.Handler.Handle(ctx, r)
}

// WithAttrs implements slog.Handler.
func (h *LogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &LogHandler{Handler: h.Handler.WithAttrs(attrs), events: h.events}
}

// WithGroup implements slog.Handler.
func (h *LogHandler) WithGroup(name string) slog.Handler {
	return &LogHandler{Handler: h.Handler.WithGroup(name), events: h.events}
}

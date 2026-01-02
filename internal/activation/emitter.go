package activation

import (
	"context"
	"sync"
	"time"

	"github.com/straja-ai/straja/internal/redact"
)

// Sink consumes activation events (file, webhook, etc.).
type Sink interface {
	Name() string
	Deliver(context.Context, *Event) error
	Close(context.Context) error
}

// Metrics holds counters for activation delivery.
type Metrics struct {
	enqueued uint64
	dropped  uint64

	sinkSuccess map[string]uint64
	sinkFailure map[string]uint64
}

// Snapshot copies the counters for observation/testing.
func (m *Metrics) Snapshot() Metrics {
	if m == nil {
		return Metrics{}
	}
	out := Metrics{
		enqueued:    m.enqueued,
		dropped:     m.dropped,
		sinkSuccess: make(map[string]uint64, len(m.sinkSuccess)),
		sinkFailure: make(map[string]uint64, len(m.sinkFailure)),
	}
	for k, v := range m.sinkSuccess {
		out.sinkSuccess[k] = v
	}
	for k, v := range m.sinkFailure {
		out.sinkFailure[k] = v
	}
	return out
}

// Public accessors for metrics.
func (m *Metrics) Enqueued() uint64 { return m.enqueued }
func (m *Metrics) Dropped() uint64  { return m.dropped }
func (m *Metrics) SinkSuccess(name string) uint64 {
	if m == nil {
		return 0
	}
	return m.sinkSuccess[name]
}
func (m *Metrics) SinkFailure(name string) uint64 {
	if m == nil {
		return 0
	}
	return m.sinkFailure[name]
}

// Emitter buffers and delivers activation events to sinks.
type Emitter struct {
	queue           chan *Event
	sinks           []Sink
	workers         int
	metrics         *Metrics
	shutdownTimeout time.Duration

	mu        sync.RWMutex
	metricsMu sync.Mutex
	closed    bool
	wg        sync.WaitGroup
}

// EmitterConfig controls worker and queue sizing.
type EmitterConfig struct {
	QueueSize       int
	Workers         int
	ShutdownTimeout time.Duration
}

// NewEmitter starts background workers to deliver events to the provided sinks.
func NewEmitter(cfg EmitterConfig, sinks []Sink) *Emitter {
	queueSize := cfg.QueueSize
	if queueSize <= 0 {
		queueSize = 1000
	}
	workerCount := cfg.Workers
	if workerCount <= 0 {
		workerCount = 1
	}
	shutdownTimeout := cfg.ShutdownTimeout
	if shutdownTimeout <= 0 {
		shutdownTimeout = 2 * time.Second
	}

	m := &Metrics{
		sinkSuccess: make(map[string]uint64, len(sinks)),
		sinkFailure: make(map[string]uint64, len(sinks)),
	}
	for _, s := range sinks {
		m.sinkSuccess[s.Name()] = 0
		m.sinkFailure[s.Name()] = 0
	}

	em := &Emitter{
		queue:           make(chan *Event, queueSize),
		sinks:           sinks,
		workers:         workerCount,
		metrics:         m,
		shutdownTimeout: shutdownTimeout,
	}

	for i := 0; i < workerCount; i++ {
		em.wg.Add(1)
		go em.worker()
	}

	return em
}

// Emit attempts to enqueue the event without blocking the request path.
func (e *Emitter) Emit(ctx context.Context, ev *Event) {
	if e == nil || ev == nil {
		return
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.closed {
		e.metricsMu.Lock()
		e.metrics.dropped++
		e.metricsMu.Unlock()
		return
	}

	select {
	case e.queue <- ev:
		e.metricsMu.Lock()
		e.metrics.enqueued++
		e.metricsMu.Unlock()
	default:
		e.metricsMu.Lock()
		e.metrics.dropped++
		e.metricsMu.Unlock()
	}
}

// Close stops accepting new events and waits briefly to drain the queue.
func (e *Emitter) Close(ctx context.Context) {
	if e == nil {
		return
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	e.closed = true
	close(e.queue)
	e.mu.Unlock()

	done := make(chan struct{})
	go func() {
		e.wg.Wait()
		close(done)
	}()

	waitCtx := ctx
	if waitCtx == nil {
		waitCtx = context.Background()
	}
	if e.shutdownTimeout > 0 {
		var cancel context.CancelFunc
		waitCtx, cancel = context.WithTimeout(waitCtx, e.shutdownTimeout)
		defer cancel()
	}

	select {
	case <-done:
	case <-waitCtx.Done():
	}

	for _, s := range e.sinks {
		if err := s.Close(waitCtx); err != nil {
			redact.Logf("activation: sink %s close error: %v", s.Name(), err)
		}
	}
}

// MetricsSnapshot safely copies current counters.
func (e *Emitter) MetricsSnapshot() Metrics {
	if e == nil || e.metrics == nil {
		return Metrics{}
	}
	e.metricsMu.Lock()
	defer e.metricsMu.Unlock()
	return e.metrics.Snapshot()
}

func (e *Emitter) worker() {
	defer e.wg.Done()
	for ev := range e.queue {
		e.deliver(ev)
	}
}

func (e *Emitter) deliver(ev *Event) {
	for _, s := range e.sinks {
		if err := s.Deliver(context.Background(), ev); err != nil {
			redact.Logf("activation: sink %s failed: %v", s.Name(), err)
			e.metricsMu.Lock()
			e.metrics.sinkFailure[s.Name()]++
			e.metricsMu.Unlock()
			continue
		}
		e.metricsMu.Lock()
		e.metrics.sinkSuccess[s.Name()]++
		e.metricsMu.Unlock()
	}
}

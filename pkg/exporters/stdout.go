package exporters

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strconv"

	"github.com/castai/ko/pkg/tracer"
	"github.com/castai/logging"
)

const queueSize = 1024

// StdoutExporter logs events in logfmt via the logging lib, one line per
// event. The field-based format is meant to be ingested by Loki later.
type StdoutExporter struct {
	log    *logging.Logger
	events chan Event
}

type Option func(*StdoutExporter)

// WithOutput replaces the logfmt output target. Intended for tests.
func WithOutput(w io.Writer) Option {
	return func(e *StdoutExporter) {
		e.log = logging.New(logging.NewTextHandler(logging.TextHandlerConfig{
			Level:  slog.LevelInfo,
			Output: w,
		}))
	}
}

func NewStdoutExporter(opts ...Option) *StdoutExporter {
	e := &StdoutExporter{
		log:    logging.New(),
		events: make(chan Event, queueSize),
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// Push enqueues an event without blocking. When the queue is full the
// event is dropped: delivery must never stall the tracer.
func (e *StdoutExporter) Push(event Event) {
	select {
	case e.events <- event:
	default:
	}
}

func (e *StdoutExporter) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case event := <-e.events:
			e.logEvent(event)
		}
	}
}

func (e *StdoutExporter) logEvent(ev Event) {
	log := e.log.With(
		"type", ev.Type,
		"comm", ev.Comm,
		"pid", ev.Pid,
		"cgroup_id", ev.CgroupID,
		"local_addr", addr(ev.LocalIP, ev.LocalPort),
		"remote_addr", addr(ev.RemoteIP, ev.RemotePort),
		"conn_rate", ev.ConnRate,
		"conn_total", ev.ConnCount,
		"rtt_avg_us", ev.RTTAvgUS,
		"life_avg_us", ev.LifeAvgUS,
	)
	// Only connect failures carry an errno: retransmit and reset events
	// leave it zero, so the field is omitted for them.
	if ev.Type == tracer.EventTypeConnectFailed {
		log = log.WithField("error", tracer.ErrnoString(ev.Errno))
	}
	if c := ev.Container; c != nil {
		log = log.With(
			"runtime", c.Runtime,
			"container_id", c.ContainerID,
			"container", c.ContainerName,
			"pod", c.PodName,
			"namespace", c.PodNamespace,
		)
	}
	log.Info("tcp_event")
}

func addr(ip net.IP, port uint16) string {
	if ip == nil {
		return ""
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
}

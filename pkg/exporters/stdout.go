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
		"ko_type", ev.Type,
		"ko_comm", ev.Comm,
		"ko_pid", ev.Pid,
		"ko_cgroup_id", ev.CgroupID,
		"ko_local_addr", addr(ev.LocalIP, ev.LocalPort),
		"ko_remote_addr", addr(ev.RemoteIP, ev.RemotePort),
		"ko_conn_rate", ev.ConnRate,
		"ko_conn_total", ev.ConnCount,
		"ko_rtt_avg_us", ev.RTTAvgUS,
		"ko_life_avg_us", ev.LifeAvgUS,
		"ko_retrans_ratio_pm", ev.RetransRatioPM,
	)
	// Only connect failures carry an errno: retransmit and reset events
	// leave it zero, so the field is omitted for them.
	if ev.Type == tracer.EventTypeConnectFailed {
		log = log.WithField("ko_error", tracer.ErrnoString(ev.Errno))
	}
	if ev.Type == tracer.EventTypeRetransmit {
		log = log.With(
			"ko_ca_state", ev.CaState.String(),
			"ko_seg_len", ev.SegLen,
			"ko_snd_wnd", ev.SndWnd,
			"ko_packets_out", ev.PacketsOut,
		)
	}
	if ev.Type == tracer.EventTypeRetransmit || ev.Type == tracer.EventTypeRetransmitSynack {
		log = log.With("ko_retrans_count", ev.RetransmitCount)
	}
	if c := ev.Container; c != nil {
		log = log.With(
			"ko_runtime", c.Runtime,
			"ko_container_id", c.ContainerID,
			"ko_container", c.ContainerName,
			"ko_pod", c.PodName,
			"ko_namespace", c.PodNamespace,
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

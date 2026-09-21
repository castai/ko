package tracer

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"runtime"
	"syscall"

	"github.com/castai/logging"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate env NIX_HARDENING_ENABLE= go tool bpf2go -target arm64 -type conn_event_t -cc clang -strip llvm-strip tracer c/tracer.bpf.c -- -Ic/headers -O2 -g
//go:generate env NIX_HARDENING_ENABLE= go tool bpf2go -target amd64 -type conn_event_t -cc clang -strip llvm-strip tracer c/tracer.bpf.c -- -Ic/headers -O2 -g

const (
	afInet  = 2
	afInet6 = 10
)

type EventType uint16

const (
	EventTypeConnectFailed EventType = iota + 1
	EventTypeRetransmit
	EventTypeRetransmitSynack
	EventTypeSendReset
	EventTypeReceiveReset
)

func (t EventType) String() string {
	switch t {
	case EventTypeConnectFailed:
		return "connect_failed"
	case EventTypeRetransmit:
		return "retransmit"
	case EventTypeRetransmitSynack:
		return "retransmit_synack"
	case EventTypeSendReset:
		return "send_reset"
	case EventTypeReceiveReset:
		return "receive_reset"
	default:
		return fmt.Sprintf("unknown(%d)", uint16(t))
	}
}

type Option func(*Tracer)

// WithEvents subscribes a channel to decoded connection events.
func WithEvents(events chan<- ConnEvent) Option {
	return func(t *Tracer) {
		t.events = events
	}
}

func New(log *logging.Logger, opts ...Option) *Tracer {
	t := &Tracer{log: log}
	for _, opt := range opts {
		opt(t)
	}
	return t
}

type Tracer struct {
	log    *logging.Logger
	events chan<- ConnEvent
}

// ConnEvent is a TCP connection problem observed on the node.
type ConnEvent struct {
	Type        EventType
	TimestampNS uint64
	Pid         uint32
	Comm        string
	LocalIP     net.IP
	LocalPort   uint16
	RemoteIP    net.IP
	RemotePort  uint16
	Family      uint16
	CgroupID    uint64
	// Aggregates for this event's stats key
	// (cgroup+pid+src_ip+dst_ip+dst_port), giving single events their
	// baseline: ConnRate is connect attempts in the current 1s window,
	// ConnCount the total; RTTAvgUS and LifeAvgUS are averages across
	// previously established connections of the same key.
	ConnCount uint64
	ConnRate  uint32
	RTTAvgUS  uint32
	LifeAvgUS uint64
	// Errno is the kernel error the connection failed with
	// (e.g. ECONNREFUSED, ETIMEDOUT). Zero means the socket was
	// aborted locally before the handshake resolved. Only set for
	// EventTypeConnectFailed.
	Errno uint32
}

// StatsSummary renders the aggregate context carried on the event.
func (e ConnEvent) StatsSummary() string {
	s := fmt.Sprintf("rate=%d/s total=%d", e.ConnRate, e.ConnCount)
	if e.RTTAvgUS > 0 {
		s += fmt.Sprintf(" rtt_avg=%s", formatMicros(float64(e.RTTAvgUS)))
	}
	if e.LifeAvgUS > 0 {
		s += fmt.Sprintf(" life_avg=%s", formatMicros(float64(e.LifeAvgUS)))
	}
	return s
}

func formatMicros(us float64) string {
	switch {
	case us >= 1e6:
		return fmt.Sprintf("%.1fs", us/1e6)
	case us >= 1e3:
		return fmt.Sprintf("%.1fms", us/1e3)
	default:
		return fmt.Sprintf("%.0fus", us)
	}
}

func (t *Tracer) Run(ctx context.Context) error {
	t.log.Info("started tracer")
	defer t.log.Info("finished tracer")

	if runtime.GOOS != "linux" {
		return fmt.Errorf("tracer: eBPF requires Linux, got %s", runtime.GOOS)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	objs := tracerObjects{}
	if err := loadTracerObjects(&objs, nil); err != nil {
		return fmt.Errorf("load bpf objects: %w", err)
	}
	defer objs.Close()

	rtps := []struct {
		name string
		prog *ebpf.Program
	}{
		{"inet_sock_set_state", objs.KoSockState},
		{"tcp_destroy_sock", objs.KoDestroySock},
		{"tcp_retransmit_skb", objs.KoRtxSkb},
		{"tcp_retransmit_synack", objs.KoRtxSynack},
		{"tcp_send_reset", objs.KoSendReset},
		{"tcp_receive_reset", objs.KoRecvReset},
	}
	for _, rtp := range rtps {
		l, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: rtp.name, Program: rtp.prog})
		if err != nil {
			return fmt.Errorf("attach raw tracepoint %s: %w", rtp.name, err)
		}
		defer l.Close()
	}

	rd, err := ringbuf.NewReader(objs.KoEvents)
	if err != nil {
		return fmt.Errorf("open ringbuf reader: %w", err)
	}
	defer rd.Close()

	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	t.log.Info("listening for tcp connection failures")
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read ringbuf: %w", err)
		}

		var raw tracerConnEventT
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			t.log.Errorf("decode conn event: %v", err)
			continue
		}

		event := decodeConnEvent(raw)
		// With a sink configured the consumer owns event presentation.
		if t.events == nil {
			t.logEvent(event)
		}
		if t.events != nil {
			select {
			case t.events <- event:
			case <-ctx.Done():
				return nil
			}
		}
	}
}

func (t *Tracer) logEvent(event ConnEvent) {
	msg := fmt.Sprintf("tcp %s comm=%s pid=%d local=%s remote=%s",
		event.Type, event.Comm, event.Pid,
		net.JoinHostPort(event.LocalIP.String(), fmt.Sprint(event.LocalPort)),
		net.JoinHostPort(event.RemoteIP.String(), fmt.Sprint(event.RemotePort)))
	if event.Type == EventTypeConnectFailed {
		msg += " error=" + ErrnoString(event.Errno)
	}
	t.log.Info(msg + " " + event.StatsSummary())
}

func decodeConnEvent(raw tracerConnEventT) ConnEvent {
	event := ConnEvent{
		Type:        EventType(raw.Type),
		TimestampNS: raw.Ts,
		Pid:         raw.Pid,
		Comm:        cString(raw.Comm[:]),
		LocalPort:   raw.LocalPort,
		RemotePort:  raw.RemotePort,
		Family:      raw.Family,
		CgroupID:    raw.CgroupId,
		ConnCount:   raw.ConnCount,
		ConnRate:    raw.ConnRate,
		RTTAvgUS:    raw.RttAvgUs,
		LifeAvgUS:   raw.LifeAvgUs,
		Errno:       raw.Error,
	}
	switch raw.Family {
	case afInet:
		event.LocalIP = net.IP(append([]byte(nil), raw.LocalIp[:4]...))
		event.RemoteIP = net.IP(append([]byte(nil), raw.RemoteIp[:4]...))
	case afInet6:
		event.LocalIP = net.IP(append([]byte(nil), raw.LocalIp[:]...))
		event.RemoteIP = net.IP(append([]byte(nil), raw.RemoteIp[:]...))
	}
	return event
}

func cString(b []int8) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		out = append(out, byte(c))
	}
	return string(out)
}

func ErrnoString(errno uint32) string {
	if errno == 0 {
		return "aborted locally"
	}
	return syscall.Errno(errno).Error()
}

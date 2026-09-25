package tracer

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
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

// CaState is the socket's congestion control state at retransmit time:
// the discriminator between RTO and fast retransmits.
type CaState uint8

const (
	CaOpen CaState = iota
	CaDisorder
	CaCWR
	CaRecovery // fast retransmit (ordinary loss)
	CaLoss     // RTO fired (stall/blackhole)
)

func (c CaState) String() string {
	switch c {
	case CaOpen:
		return "open"
	case CaDisorder:
		return "disorder"
	case CaCWR:
		return "cwr"
	case CaRecovery:
		return "fast_retransmit"
	case CaLoss:
		return "rto"
	default:
		return fmt.Sprintf("ca(%d)", uint8(c))
	}
}

type Option func(*Tracer)

// WithEvents subscribes a channel to decoded connection events.
func WithEvents(events chan<- ConnEvent) Option {
	return func(t *Tracer) {
		t.events = events
	}
}

// Filter selects which connections the tracer reports.
type Filter struct {
	// IgnoreLoopback skips connections whose peer is on the same host
	// (loopback destinations): self-connects, local health probes and
	// other traffic that never touches the network. Filtering happens in
	// the eBPF program, so ignored connections also skip the stats and
	// context maps.
	IgnoreLoopback bool `yaml:"ignoreLoopback"`
}

// WithFilter sets the tracer's connection filters.
func WithFilter(f Filter) Option {
	return func(t *Tracer) {
		t.filter = f
	}
}

func New(log *logging.Logger, opts ...Option) *Tracer {
	t := &Tracer{log: log, eventsReady: make(chan struct{})}
	for _, opt := range opts {
		opt(t)
	}
	return t
}

type Tracer struct {
	log         *logging.Logger
	events      chan<- ConnEvent
	filter      Filter
	eventsReady chan struct{}
	readyOnce   sync.Once
}

// EventsReady is closed once the tracer has read its first event from
// the ring buffer. Connections established before that moment are not
// tracked: components whose own connections must be observed (the
// conntest mesh) wait for it before connecting.
func (t *Tracer) EventsReady() <-chan struct{} {
	return t.eventsReady
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
	// baseline: ConnRate is connect attempts per second in the current
	// or the last completed 1s window (whichever shows the higher rate),
	// ConnCount the total; RTTAvgUS, LifeAvgUS and RetransRatioPM are
	// aggregates across previously established connections of the same
	// key.
	ConnCount uint64
	ConnRate  uint32
	RTTAvgUS  uint32
	LifeAvgUS uint64
	// Errno is the kernel error the connection failed with
	// (e.g. ECONNREFUSED, ETIMEDOUT). Zero means the socket was
	// aborted locally before the handshake resolved. Only set for
	// EventTypeConnectFailed.
	Errno uint32
	// Retransmit payload, only set for EventTypeRetransmit.
	CaState    CaState // Loss (rto) vs Recovery (fast_retransmit)
	SegLen     uint32  // retransmitted segment size in bytes
	SndWnd     uint32  // peer's advertised window: zero means a stuck receiver
	PacketsOut uint32
	// RetransmitCount is the retransmits the connection (or, for
	// EventTypeRetransmitSynack, the handshake) already had before this
	// event. Only retransmits that look like incidents are emitted at all:
	// RTO-driven, zero-window or repeated ones, and the second SYN-ACK retry.
	RetransmitCount uint8
	// RetransRatioPM is retransmitted/sent segments in per-mille over
	// the same stats key as the averages above.
	RetransRatioPM uint32
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
	if e.RetransRatioPM > 0 {
		s += fmt.Sprintf(" retrans=%.1f%%", float64(e.RetransRatioPM)/10)
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

	spec, err := loadTracer()
	if err != nil {
		return fmt.Errorf("load bpf spec: %w", err)
	}
	v, ok := spec.Variables["ko_filter_ignore_loopback"]
	if !ok {
		return fmt.Errorf("bpf spec missing filter variable")
	}
	if err := v.Set(t.filter.IgnoreLoopback); err != nil {
		return fmt.Errorf("set ignore_loopback filter: %w", err)
	}
	objs := tracerObjects{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
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
		t.readyOnce.Do(func() { close(t.eventsReady) })

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
	if event.Type == EventTypeRetransmit {
		msg += fmt.Sprintf(" cause=%s seg=%d inflight=%d retransmits=%d", event.CaState, event.SegLen, event.PacketsOut, event.RetransmitCount)
		if event.SndWnd == 0 {
			msg += " snd_wnd=0"
		}
	}
	t.log.Info(msg + " " + event.StatsSummary())
}

func decodeConnEvent(raw tracerConnEventT) ConnEvent {
	event := ConnEvent{
		Type:            EventType(raw.Type),
		TimestampNS:     raw.Ts,
		Pid:             raw.Pid,
		Comm:            cString(raw.Comm[:]),
		LocalPort:       raw.LocalPort,
		RemotePort:      raw.RemotePort,
		Family:          raw.Family,
		CgroupID:        raw.CgroupId,
		ConnCount:       raw.ConnCount,
		ConnRate:        raw.ConnRate,
		RTTAvgUS:        raw.RttAvgUs,
		LifeAvgUS:       raw.LifeAvgUs,
		Errno:           raw.Error,
		CaState:         CaState(raw.CaState),
		SegLen:          raw.SegLen,
		SndWnd:          raw.SndWnd,
		PacketsOut:      raw.PacketsOut,
		RetransRatioPM:  raw.RtxRatioPm,
		RetransmitCount: raw.RtxCount,
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

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

	celfilter "github.com/castai/ko/pkg/filter"
)

//go:generate env NIX_HARDENING_ENABLE= go tool bpf2go -target arm64 -type conn_event_t -cc clang -strip llvm-strip tracer c/tracer.bpf.c -- -Ic/headers -O2 -g
//go:generate env NIX_HARDENING_ENABLE= go tool bpf2go -target amd64 -type conn_event_t -cc clang -strip llvm-strip tracer c/tracer.bpf.c -- -Ic/headers -O2 -g

const (
	afInet  = 2
	afInet6 = 10
)

type EventType uint16

const (
	EventTypeConnFailed EventType = iota + 1
	EventTypeConnClosed
)

func (t EventType) String() string {
	switch t {
	case EventTypeConnFailed:
		return "conn_failed"
	case EventTypeConnClosed:
		return "conn_closed"
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

// Filter selects which connections the tracer reports.
type Filter struct {
	// Cel is an ordered list of named CEL expressions. An event matching
	// one carries the filter's index and name; events matching none are
	// dropped, as early as the eBPF program when the expression decides
	// from event fields and known cgroup verdicts.
	Cel []CelFilter `yaml:"cel"`
	// Verify re-evaluates every eBPF-decided filter in userspace and
	// counts disagreements on ko_filter_verify_mismatches_total. Off by
	// default: it costs one CEL evaluation per event.
	Verify bool `yaml:"verify"`
}

// WithFilter sets the tracer's connection filters.
func WithFilter(f Filter) Option {
	return func(t *Tracer) {
		t.filter = f
	}
}

// WithAttrSource sets the resolver the CEL filters use to map cgroup IDs
// to namespace, container and pod names.
func WithAttrSource(s celfilter.AttrSource) Option {
	return func(t *Tracer) {
		t.attrs = s
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
	attrs       celfilter.AttrSource
	filterSet   *celfilter.Set
	verdictMap  *ebpf.Map
	eventsReady chan struct{}
	readyOnce   sync.Once
}

func (t *Tracer) EventsReady() <-chan struct{} {
	return t.eventsReady
}

// ConnEvent is a TCP connection lifecycle event observed on the node,
// carrying the connection's final stats.
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
	// LifeUS is the duration from the connect attempt to the event.
	LifeUS uint64
	// RTTUS is the kernel's smoothed RTT at the end of the connection;
	// zero on failed attempts (no sample was ever taken).
	RTTUS uint32
	// Retransmits is the connection's retransmit count: handshake SYN
	// retries plus data retransmits on conn_closed events, just the SYN
	// retries on connect_failed ones. SegsOut is the total segments sent
	// over the same period, giving the count its denominator.
	Retransmits uint32
	SegsOut     uint32
	// Errno is the socket error at event time: the failure reason on
	// connect_failed (e.g. ECONNREFUSED, ETIMEDOUT), the reset or abort
	// cause on conn_closed, zero on clean closes.
	Errno uint32
	// FilterIdx is the index of the first matching CEL filter, FilterName
	// its name. Zero when no CEL filters are configured.
	FilterIdx  uint16
	FilterName string
}

// StatsSummary renders the per-connection stats carried on the event.
func (e ConnEvent) StatsSummary() string {
	s := fmt.Sprintf("life=%s", formatMicros(float64(e.LifeUS)))
	if e.RTTUS > 0 {
		s += fmt.Sprintf(" rtt=%s", formatMicros(float64(e.RTTUS)))
	}
	return s + fmt.Sprintf(" retrans=%d/%d", e.Retransmits, e.SegsOut)
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
	if err := t.initFilters(); err != nil {
		return err
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	spec, err := loadTracer()
	if err != nil {
		return fmt.Errorf("load bpf spec: %w", err)
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

	stopDrops := make(chan struct{})
	defer close(stopDrops)
	if m := objs.KoRingbufDrops; m != nil {
		go trackRingbufDrops(m, stopDrops)
	}
	if m := objs.KoFilterDrops; m != nil && t.filterSet != nil {
		go trackFilterDrops(m, stopDrops)
	}
	// Kernel-side program runtime accounting is opt-in because it adds a
	// small per-run cost to every BPF program on the node; it stays armed
	// only while the agent runs.
	stats, err := enableProgStats()
	if err != nil {
		t.log.Warnf("bpf program stats unavailable (needs Linux 5.8+): %v", err)
	} else {
		defer stats.Close()
		go trackProgStats(stopDrops)
	}
	if err := t.startFilters(&objs, stopDrops); err != nil {
		return err
	}

	t.log.Info("listening for tcp connection events")
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read ringbuf: %w", err)
		}
		t.readyOnce.Do(func() { close(t.eventsReady) })
		eventsTotal.Inc()

		var raw tracerConnEventT
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			decodeErrorsTotal.Inc()
			t.log.Errorf("decode conn event: %v", err)
			continue
		}

		event := decodeConnEvent(raw)
		if t.filterSet != nil {
			names := t.filterSet.Names()
			if event.FilterIdx < uint16(len(names)) {
				event.FilterName = names[event.FilterIdx]
				filterEvents.WithLabelValues("passed_bpf").Inc()
				if t.filter.Verify {
					t.verifyBpfDecision(raw, event.FilterIdx)
				}
			} else {
				idx, matched := t.resolveFilter(raw)
				if !matched {
					filterEvents.WithLabelValues("dropped_userspace").Inc()
					continue
				}
				event.FilterIdx = idx
				event.FilterName = names[idx]
				filterEvents.WithLabelValues("passed_userspace").Inc()
			}
			filterMatched.WithLabelValues(event.FilterName).Inc()
		}
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
	if event.Errno != 0 {
		msg += " error=" + ErrnoString(event.Errno)
	}
	if event.FilterName != "" {
		msg += " filter=" + event.FilterName
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
		LifeUS:      raw.LifeUs,
		RTTUS:       raw.RttUs,
		Retransmits: raw.Retransmits,
		SegsOut:     raw.SegsOut,
		Errno:       raw.Error,
		FilterIdx:   raw.FilterIdx,
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

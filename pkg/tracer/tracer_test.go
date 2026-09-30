package tracer

import (
	"context"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"

	celfilter "github.com/castai/ko/pkg/filter"
	"github.com/castai/logging"
	"github.com/davecgh/go-spew/spew"
)

func TestDecodeConnEvent(t *testing.T) {
	raw := tracerConnEventT{
		Ts:          123,
		Pid:         42,
		Error:       111,
		Comm:        [16]int8{'c', 'u', 'r', 'l', 0},
		Family:      afInet,
		LocalPort:   54321,
		RemotePort:  80,
		Type:        uint16(EventTypeConnFailed),
		LifeUs:      2500000,
		RttUs:       1200,
		Retransmits: 7,
		SegsOut:     120,
		FilterIdx:   1,
	}
	raw.LocalIp = [16]byte{127, 0, 0, 1}
	raw.RemoteIp = [16]byte{10, 0, 0, 1}

	e := decodeConnEvent(raw)

	if e.Comm != "curl" || e.Pid != 42 || e.Errno != 111 {
		t.Fatalf("unexpected basic fields: %+v", e)
	}
	if e.FilterIdx != 1 {
		t.Fatalf("unexpected filter index: %+v", e)
	}
	if e.LifeUS != 2500000 || e.RTTUS != 1200 || e.Retransmits != 7 || e.SegsOut != 120 {
		t.Fatalf("unexpected stats fields: %+v", e)
	}
	if s := e.StatsSummary(); s != "life=2.5s rtt=1.2ms retrans=7/120" {
		t.Fatalf("unexpected stats summary: %s", s)
	}
	if e.Type != EventTypeConnFailed || e.Type.String() != "conn_failed" {
		t.Fatalf("unexpected event type: %+v", e.Type)
	}
	if EventTypeConnClosed.String() != "conn_closed" {
		t.Fatalf("unexpected event type string: %s", EventTypeConnClosed)
	}
	if e.LocalIP.String() != "127.0.0.1" || e.RemoteIP.String() != "10.0.0.1" {
		t.Fatalf("unexpected ips: local=%s remote=%s", e.LocalIP, e.RemoteIP)
	}
	if e.LocalPort != 54321 || e.RemotePort != 80 {
		t.Fatalf("unexpected ports: %+v", e)
	}
	if ErrnoString(e.Errno) != "connection refused" {
		t.Fatalf("unexpected errno string: %s", ErrnoString(e.Errno))
	}
}

func freeTCPPort(network, host string) (int, error) {
	l, err := net.Listen(network, net.JoinHostPort(host, "0"))
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func nonLoopbackIPv4() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ip := ipnet.IP.To4(); ip != nil && !ip.IsLoopback() {
					return ip.String()
				}
			}
		}
	}
	return ""
}

func TestTracerReportsConnectionFailures(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping: requires Linux to load eBPF programs")
	}
	if os.Geteuid() != 0 {
		t.Skip("skipping: requires root to load eBPF programs")
	}

	events := make(chan ConnEvent, 64)
	tr := New(logging.New(), WithEvents(events), WithFilter(Filter{Cel: []CelFilter{
		{Name: "lifecycle", Expr: `ko_type in [ko_type_conn_failed, ko_type_conn_closed]`},
	}}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- tr.Run(ctx)
	}()

	port4, err := freeTCPPort("tcp", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	port6, err := freeTCPPort("tcp", "::1")
	if err != nil {
		t.Fatal(err)
	}

	// A successful short-lived connection to the same destination produces
	// a conn_closed event with the full per-connection stats: rtt sampled,
	// lifetime recorded. Re-primed each iteration because the first
	// attempts may race the tracer startup.
	prime := func(network, host string, port int) {
		l, err := net.Listen(network, net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			return
		}
		if conn, err := net.DialTimeout(network, l.Addr().String(), time.Second); err == nil {
			conn.Close()
		}
		l.Close()
		time.Sleep(150 * time.Millisecond)
	}

	var (
		gotV4, gotV6, gotClosed bool
		deadline                = time.Now().Add(15 * time.Second)
	)
	for time.Now().Before(deadline) && !(gotV4 && gotV6 && gotClosed) {
		prime("tcp", "127.0.0.1", port4)
		prime("tcp", "::1", port6)

		if conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port4)), time.Second); err == nil {
			conn.Close()
		}
		if conn, err := net.DialTimeout("tcp", net.JoinHostPort("::1", strconv.Itoa(port6)), time.Second); err == nil {
			conn.Close()
		}

	wait:
		for {
			select {
			case e := <-events:
				switch {
				case e.Type == EventTypeConnClosed && e.RemoteIP.Equal(net.ParseIP("127.0.0.1")) && e.RemotePort == uint16(port4):
					// The primed successful connection: rtt sampled, full
					// lifetime recorded, clean close with no errno.
					if e.Errno != 0 || e.Pid != uint32(os.Getpid()) || e.RTTUS == 0 || e.LifeUS == 0 || e.SegsOut == 0 {
						t.Fatalf("unexpected conn_closed event: %+v", e)
					}
					gotClosed = true
				case e.Type == EventTypeConnFailed && e.RemoteIP.Equal(net.ParseIP("127.0.0.1")) && e.RemotePort == uint16(port4):
					if e.Errno != uint32(syscall.ECONNREFUSED) || e.Pid != uint32(os.Getpid()) || e.LocalPort == 0 {
						t.Fatalf("unexpected ipv4 event: %+v", e)
					}
					gotV4 = e.LifeUS > 0
				case e.Type == EventTypeConnFailed && e.RemoteIP.Equal(net.ParseIP("::1")) && e.RemotePort == uint16(port6):
					if e.Errno != uint32(syscall.ECONNREFUSED) || e.Family != afInet6 {
						t.Fatalf("unexpected ipv6 event: %+v", e)
					}
					gotV6 = e.LifeUS > 0
				}
			case <-time.After(300 * time.Millisecond):
				break wait
			}
		}

		select {
		case err := <-errCh:
			t.Fatalf("tracer exited: %v", err)
		default:
		}
	}

	select {
	case <-tr.EventsReady():
	default:
		t.Fatal("expected tracer to report readiness after receiving events")
	}

	if !gotV4 {
		t.Errorf("no ipv4 connection failure event received")
	}
	if !gotV6 {
		t.Errorf("no ipv6 connection failure event received")
	}
	if !gotClosed {
		t.Errorf("no conn_closed event received")
	}
}

// Loopback peers must not produce events (from any process) when the
// filter list only matches non-loopback remotes, while a same-host
// non-loopback peer still does: that is the positive control proving the
// filter matches addresses, not a broken tracer.
func TestTracerIgnoresLoopback(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping: requires Linux to load eBPF programs")
	}
	if os.Geteuid() != 0 {
		t.Skip("skipping: requires root to load eBPF programs")
	}

	host := nonLoopbackIPv4()
	if host == "" {
		t.Skip("skipping: no non-loopback interface to test with")
	}

	events := make(chan ConnEvent, 64)
	tr := New(logging.New(), WithEvents(events), WithFilter(Filter{Cel: []CelFilter{
		{Name: "non-loopback", Expr: `!ip_in(ko_remote_addr, ko_loopback_cidrs)`},
	}}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- tr.Run(ctx)
	}()

	port4, err := freeTCPPort("tcp", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	port6, err := freeTCPPort("tcp", "::1")
	if err != nil {
		t.Fatal(err)
	}
	portHost, err := freeTCPPort("tcp", host)
	if err != nil {
		t.Fatal(err)
	}

	var gotHost bool
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && !gotHost {
		if conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port4)), time.Second); err == nil {
			conn.Close()
		}
		if conn, err := net.DialTimeout("tcp", net.JoinHostPort("::1", strconv.Itoa(port6)), time.Second); err == nil {
			conn.Close()
		}
		if conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(portHost)), time.Second); err == nil {
			conn.Close()
		}

	wait:
		for {
			select {
			case e := <-events:
				if e.FilterName != "non-loopback" {
					t.Fatalf("unexpected filter attribution: %+v", e)
				}
				if e.RemoteIP.IsLoopback() {
					t.Fatalf("loopback event leaked through the filter: %+v", e)
				}
				if e.Type == EventTypeConnFailed && e.RemotePort == uint16(portHost) && e.RemoteIP.Equal(net.ParseIP(host)) {
					gotHost = true
				}
			case <-time.After(300 * time.Millisecond):
				break wait
			}
		}

		select {
		case err := <-errCh:
			t.Fatalf("tracer exited: %v", err)
		default:
		}
	}

	if !gotHost {
		t.Errorf("no connect_failed event for non-loopback peer %s", host)
	}
}

// Program runtime accounting must be explicitly enabled; once it is,
// every loaded program shows up in the node-wide snapshot with its
// kernel-reported runtime and run count.
func TestProgStats(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping: requires Linux to load eBPF programs")
	}
	if os.Geteuid() != 0 {
		t.Skip("skipping: requires root to load eBPF programs")
	}

	stats, err := enableProgStats()
	if err != nil {
		t.Skipf("skipping: bpf stats unsupported: %v", err)
	}
	defer stats.Close()

	spec, err := loadTracer()
	if err != nil {
		t.Fatal(err)
	}
	objs := tracerObjects{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		t.Fatal(err)
	}
	defer objs.Close()

	samples, err := snapshotProgStats()
	if err != nil {
		t.Fatal(err)
	}
	ko := 0
	for _, s := range samples {
		if s.Name != "ko_sock_state" && s.Name != "ko_destroy_sock" {
			continue
		}
		if s.Tag == "" || s.Type == "" {
			t.Fatalf("program %s missing tag or type: %+v", s.Name, s)
		}
		ko++
	}
	if ko != 2 {
		t.Fatalf("expected both ko programs in the snapshot, got %d of %d programs", ko, len(samples))
	}
}

// A filter selecting only retransmits must drop every other event type,
// while SYN retries towards an unroutable TEST-NET address produce
// retransmit events for the tracked connection.
func TestTracerRetransmits(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping: requires Linux to load eBPF programs")
	}
	if os.Geteuid() != 0 {
		t.Skip("skipping: requires root to load eBPF programs")
	}

	events := make(chan ConnEvent, 64)
	tr := New(logging.New(), WithEvents(events), WithFilter(Filter{Cel: []CelFilter{
		{Name: "retrans", Expr: `ko_type == ko_type_retransmit`},
	}}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- tr.Run(ctx)
	}()

	var gotRetrans bool
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && !gotRetrans {
		conn, err := net.DialTimeout("tcp", "192.0.2.1:81", 4*time.Second)
		if err == nil {
			conn.Close()
			t.Fatal("unexpected successful dial to TEST-NET address")
		}

	wait:
		for {
			select {
			case e := <-events:
				if e.Type != EventTypeRetransmit || e.FilterName != "retrans" {
					t.Fatalf("unexpected event through retransmit filter: %+v", e)
				}
				if e.RemoteIP.Equal(net.ParseIP("192.0.2.1")) {
					gotRetrans = true
				}
			case <-time.After(300 * time.Millisecond):
				break wait
			}
		}

		select {
		case err := <-errCh:
			t.Fatalf("tracer exited: %v", err)
		default:
		}
	}

	if !gotRetrans {
		t.Errorf("no retransmit event for 192.0.2.1")
	}
}

// A filter selecting only probes must see periodic congestion samples
// while data flows, carrying the sender's cwnd and windows.
func TestTracerProbes(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping: requires Linux to load eBPF programs")
	}
	if os.Geteuid() != 0 {
		t.Skip("skipping: requires root to load eBPF programs")
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go io.Copy(io.Discard, c)
		}
	}()

	events := make(chan ConnEvent, 64)
	tr := New(logging.New(), WithEvents(events), WithFilter(Filter{Cel: []CelFilter{
		{Name: "probes", Expr: `ko_type == ko_type_probe`},
	}}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- tr.Run(ctx)
	}()

	buf := make([]byte, 4096)
	var gotProbe bool
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && !gotProbe {
		conn, err := net.DialTimeout("tcp", l.Addr().String(), time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		for i := 0; i < 10 && !gotProbe; i++ {
			if _, err := conn.Write(buf); err != nil {
				t.Fatalf("write: %v", err)
			}

			select {
			case e := <-events:
				if e.Type != EventTypeProbe || e.FilterName != "probes" {
					t.Fatalf("unexpected event through probe filter: %+v", e)
				}
				if e.RemotePort == uint16(port) && e.SndCwnd > 0 && e.SndWnd > 0 {
					gotProbe = true
				}
			case <-time.After(100 * time.Millisecond):
			}
		}
		conn.Close()

		select {
		case err := <-errCh:
			t.Fatalf("tracer exited: %v", err)
		default:
		}
	}

	if !gotProbe {
		t.Errorf("no probe event for streaming connection")
	}
}

type staticAttrs struct{}

func (staticAttrs) Attrs(uint64) (celfilter.CgroupAttrs, bool) {
	return celfilter.CgroupAttrs{Namespace: "ns-a"}, true
}

func (staticAttrs) AttrsSnapshot() map[uint64]celfilter.CgroupAttrs {
	return map[uint64]celfilter.CgroupAttrs{}
}

func TestTracerCelFilters(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping: requires Linux to load eBPF programs")
	}
	if os.Geteuid() != 0 {
		t.Skip("skipping: requires root to load eBPF programs")
	}

	events := make(chan ConnEvent, 64)
	tr := New(logging.New(), WithEvents(events), WithAttrSource(staticAttrs{}), WithFilter(Filter{Cel: []CelFilter{
		{Name: "degraded", Expr: "ko_retransmits > 3"},
		{Name: "prod-ns", Expr: `ko_namespace == "ns-a" && ip_in(ko_remote_addr, ko_loopback_cidrs)`},
	}}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- tr.Run(ctx)
	}()

	port4, err := freeTCPPort("tcp", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	port6, err := freeTCPPort("tcp", "::1")
	if err != nil {
		t.Fatal(err)
	}

	var gotV4, gotV6 bool
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && !(gotV4 && gotV6) {
		prime := func(network, host string, port int) {
			l, err := net.Listen(network, net.JoinHostPort(host, strconv.Itoa(port)))
			if err != nil {
				return
			}
			if conn, err := net.DialTimeout(network, l.Addr().String(), time.Second); err == nil {
				conn.Close()
			}
			l.Close()
		}
		prime("tcp", "127.0.0.1", port4)
		prime("tcp", "::1", port6)

	wait:
		for {
			select {
			case e := <-events:
				if e.FilterName != "prod-ns" || e.FilterIdx != 1 {
					t.Fatalf("unexpected filter attribution: %+v", e)
				}
				if e.RemoteIP.Equal(net.ParseIP("127.0.0.1")) {
					gotV4 = true
				}
				if e.RemoteIP.Equal(net.ParseIP("::1")) {
					gotV6 = true
				}
			case <-time.After(300 * time.Millisecond):
				break wait
			}
		}

		select {
		case err := <-errCh:
			t.Fatalf("tracer exited: %v", err)
		default:
		}
	}

	if !gotV4 {
		t.Errorf("no filtered ipv4 event received")
	}
	if !gotV6 {
		t.Errorf("no filtered ipv6 event received")
	}
}

func TestTracerCelFiltersDrop(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping: requires Linux to load eBPF programs")
	}
	if os.Geteuid() != 0 {
		t.Skip("skipping: requires root to load eBPF programs")
	}

	events := make(chan ConnEvent, 64)
	tr := New(logging.New(), WithEvents(events), WithAttrSource(staticAttrs{}), WithFilter(Filter{Cel: []CelFilter{
		{Name: "nope", Expr: `ko_namespace == "nope"`},
	}}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- tr.Run(ctx)
	}()

	port4, err := freeTCPPort("tcp", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port4)))
		if err != nil {
			t.Fatal(err)
		}
		if conn, err := net.DialTimeout("tcp", l.Addr().String(), time.Second); err == nil {
			conn.Close()
		}
		l.Close()
		time.Sleep(200 * time.Millisecond)
	}

	select {
	case err := <-errCh:
		t.Fatalf("tracer exited: %v", err)
	default:
	}

	select {
	case e := <-events:
		t.Fatalf("expected no events, got %+v", e)
	default:
	}
}

// Playground test: run manually with
//
//	go test -run TestTracer -v -timeout 5m
//
// to watch the raw event stream while reproducing scenarios by hand.
func TestTracer(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping: requires Linux to load eBPF programs")
	}
	if os.Geteuid() != 0 {
		t.Skip("skipping: requires root to load eBPF programs")
	}

	events := make(chan ConnEvent, 64)
	tr := New(logging.New(), WithEvents(events), WithFilter(Filter{Cel: []CelFilter{
		{Name: "all", Expr: `ko_type in [ko_type_conn_failed, ko_type_conn_closed, ko_type_retransmit]`},
	}}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- tr.Run(ctx)
	}()

	for {
		select {
		case e := <-events:
			spew.Dump(e)
		case err := <-errCh:
			t.Fatalf("tracer exited: %v", err)
		}
	}
}

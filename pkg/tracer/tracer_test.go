package tracer

import (
	"context"
	"net"
	"os"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/castai/logging"
	"github.com/davecgh/go-spew/spew"
)

func TestDecodeConnEvent(t *testing.T) {
	raw := tracerConnEventT{
		Ts:         123,
		Pid:        42,
		Error:      111,
		Comm:       [16]int8{'c', 'u', 'r', 'l', 0},
		Family:     afInet,
		LocalPort:  54321,
		RemotePort: 80,
		Type:       uint16(EventTypeConnectFailed),
		ConnCount:  7,
		ConnRate:   3,
		RttAvgUs:   1200,
		LifeAvgUs:  2500000,
		SegLen:     1448,
		SndWnd:     0,
		PacketsOut: 12,
		RtxRatioPm: 25,
		CaState:    uint8(CaLoss),
		RtxCount:   7,
	}
	raw.LocalIp = [16]byte{127, 0, 0, 1}
	raw.RemoteIp = [16]byte{10, 0, 0, 1}

	e := decodeConnEvent(raw)

	if e.Comm != "curl" || e.Pid != 42 || e.Errno != 111 {
		t.Fatalf("unexpected basic fields: %+v", e)
	}
	if e.ConnCount != 7 || e.ConnRate != 3 || e.RTTAvgUS != 1200 || e.LifeAvgUS != 2500000 {
		t.Fatalf("unexpected stats fields: %+v", e)
	}
	if e.CaState != CaLoss || e.CaState.String() != "rto" || e.SegLen != 1448 || e.SndWnd != 0 || e.PacketsOut != 12 || e.RetransRatioPM != 25 || e.RetransmitCount != 7 {
		t.Fatalf("unexpected retransmit fields: %+v", e)
	}
	if s := e.StatsSummary(); s != "rate=3/s total=7 rtt_avg=1.2ms life_avg=2.5s retrans=2.5%" {
		t.Fatalf("unexpected stats summary: %s", s)
	}
	if e.Type != EventTypeConnectFailed || e.Type.String() != "connect_failed" {
		t.Fatalf("unexpected event type: %+v", e.Type)
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
	tr := New(logging.New(), WithEvents(events))

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

	// A successful short-lived connection to the same destination primes the
	// stats (connection count, RTT, life) so failure events carry a
	// baseline. Re-primed each iteration because the first attempts may race
	// the tracer startup.
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
		gotV4, gotV6, gotRX bool
		deadline            = time.Now().Add(15 * time.Second)
	)
	for time.Now().Before(deadline) && !(gotV4 && gotV6 && gotRX) {
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
				case e.Type == EventTypeConnectFailed && e.RemoteIP.Equal(net.ParseIP("127.0.0.1")) && e.RemotePort == uint16(port4):
					if e.Errno != uint32(syscall.ECONNREFUSED) || e.Pid != uint32(os.Getpid()) || e.LocalPort == 0 {
						t.Fatalf("unexpected ipv4 event: %+v", e)
					}
					gotV4 = e.ConnCount >= 2 && e.ConnRate >= 1 && e.RTTAvgUS > 0 && e.LifeAvgUS > 0
				case e.Type == EventTypeConnectFailed && e.RemoteIP.Equal(net.ParseIP("::1")) && e.RemotePort == uint16(port6):
					if e.Errno != uint32(syscall.ECONNREFUSED) || e.Family != afInet6 {
						t.Fatalf("unexpected ipv6 event: %+v", e)
					}
					gotV6 = e.ConnCount >= 2 && e.ConnRate >= 1 && e.RTTAvgUS > 0 && e.LifeAvgUS > 0
				case e.Type == EventTypeReceiveReset && e.RemoteIP.Equal(net.ParseIP("127.0.0.1")) && e.RemotePort == uint16(port4):
					// RSTs on sockets whose context is already gone (e.g. reset
					// accept-queued connections) carry no pid: only an attributed
					// one proves the sock context path.
					if e.Pid != 0 {
						gotRX = e.Pid == uint32(os.Getpid())
						if !gotRX {
							t.Fatalf("unexpected receive_reset event: %+v", e)
						}
					}
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
	if !gotRX {
		t.Errorf("no receive_reset event received")
	}
}

// With IgnoreLoopback set, loopback peers must not produce events at all
// (from any process), while a same-host non-loopback peer still does: that
// is the positive control proving the filter matches addresses, not a
// broken tracer.
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
	tr := New(logging.New(), WithEvents(events), WithFilter(Filter{IgnoreLoopback: true}))

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
				if e.RemoteIP.IsLoopback() {
					t.Fatalf("loopback event leaked through the filter: %+v", e)
				}
				if e.Type == EventTypeConnectFailed && e.RemotePort == uint16(portHost) && e.RemoteIP.Equal(net.ParseIP(host)) {
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
	tr := New(logging.New(), WithEvents(events))

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

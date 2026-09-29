package nodeagent

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/castai/ko/pkg/exporters"
	"github.com/castai/ko/pkg/tracer"
	"github.com/castai/logging"
)

// syncBuffer is a concurrency safe log sink for the stdout exporter.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestApp(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping: requires Linux to load eBPF programs")
	}
	if os.Geteuid() != 0 {
		t.Skip("skipping: requires root to load eBPF programs")
	}

	var out syncBuffer
	exp := exporters.NewStdoutExporter(exporters.WithOutput(&out))

	events := make(chan tracer.ConnEvent, 256)
	tr := tracer.New(logging.New(), tracer.WithEvents(events))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	instance := New(logging.New(), tr, nil, events, "127.0.0.1:0", exp)
	errCh := make(chan error, 1)
	go func() {
		errCh <- instance.Run(ctx)
	}()

	metricsDeadline := time.Now().Add(10 * time.Second)
	for instance.MetricsAddr() == "" && time.Now().Before(metricsDeadline) {
		select {
		case err := <-errCh:
			t.Fatalf("app exited: %v", err)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	if instance.MetricsAddr() == "" {
		t.Fatal("metrics endpoint did not start")
	}
	resp, err := http.Get("http://" + instance.MetricsAddr() + "/metrics")
	if err != nil {
		t.Fatalf("scraping metrics: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics status: %s", resp.Status)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	want := []string{
		"msg=tcp_event",
		"type=conn_failed",
		"remote_addr=127.0.0.1:" + strconv.Itoa(port),
		"pid=" + strconv.Itoa(os.Getpid()),
		"life_us=",
		"retransmits=",
		"segs_out=",
	}

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second); err == nil {
			conn.Close()
		}

		select {
		case err := <-errCh:
			t.Fatalf("app exited: %v", err)
		default:
		}

		for _, line := range strings.Split(out.String(), "\n") {
			if containsAll(line, want) {
				assertTracerMetrics(t, instance.MetricsAddr())
				return
			}
		}

		time.Sleep(300 * time.Millisecond)
	}

	t.Fatalf("no exported event found in output:\n%s", out.String())
}

func containsAll(line string, want []string) bool {
	for _, w := range want {
		if !strings.Contains(line, w) {
			return false
		}
	}
	return true
}

func assertTracerMetrics(t *testing.T, addr string) {
	t.Helper()
	resp, err := http.Get("http://" + addr + "/metrics")
	if err != nil {
		t.Fatalf("scraping metrics: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading metrics: %v", err)
	}
	lines := strings.Split(string(body), "\n")
	for _, metric := range []string{
		"ko_ebpf_events_total",
		"ko_ebpf_decode_error_total",
		"ko_ebpf_ringbuf_dropped_total",
	} {
		if !metricHasValue(lines, metric) {
			t.Fatalf("metric %s not exposed with a value", metric)
		}
	}
	// Events flowed through the read loop by the time the exported line was
	// seen: the counter must have moved off zero.
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "ko_ebpf_events_total" {
			if v, err := strconv.ParseFloat(fields[1], 64); err != nil || v == 0 {
				t.Fatalf("ko_ebpf_events_total not counted: %s", line)
			}
			break
		}
	}
}

func metricHasValue(lines []string, metric string) bool {
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == metric {
			return true
		}
	}
	return false
}

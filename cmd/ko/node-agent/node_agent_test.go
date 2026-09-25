package nodeagent

import (
	"bytes"
	"context"
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

	instance := New(logging.New(), tr, nil, events, nil, "127.0.0.1:0", exp)
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
		"type=connect_failed",
		"remote_addr=127.0.0.1:" + strconv.Itoa(port),
		"pid=" + strconv.Itoa(os.Getpid()),
		"conn_total=",
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

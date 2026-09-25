package conntest

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/castai/logging"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"gopkg.in/yaml.v3"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("condition not met in time")
}

type fakeKubeAPI struct {
	mu     sync.Mutex
	pods   []Pod
	events chan WatchEvent
}

func (f *fakeKubeAPI) setPods(pods []Pod) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pods = pods
}

func (f *fakeKubeAPI) GetPod(_ context.Context, name string) (Pod, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.pods {
		if p.Name == name {
			return p, nil
		}
	}
	return Pod{}, fmt.Errorf("pod %q not found", name)
}

func (f *fakeKubeAPI) ListPods(_ context.Context, _ string) ([]Pod, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	pods := make([]Pod, len(f.pods))
	copy(pods, f.pods)
	return pods, "1", nil
}

func (f *fakeKubeAPI) WatchPods(ctx context.Context, _, _ string) (<-chan WatchEvent, error) {
	out := make(chan WatchEvent)
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-f.events:
				select {
				case out <- ev:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out, nil
}

func scrapeMetrics(h http.Handler) string {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	return rec.Body.String()
}

func TestMeshRunProbesPeersAndServesMetrics(t *testing.T) {
	port := freePort(t)
	kube := &fakeKubeAPI{events: make(chan WatchEvent, 16)}
	kube.setPods([]Pod{
		{Name: "self", IP: "127.0.0.1", NodeName: "node-a", Phase: "Running"},
		{Name: "peer", IP: "127.0.0.1", NodeName: "node-b", Phase: "Running"},
	})

	registry := prometheus.NewRegistry()
	mesh := New(logging.New(), Config{
		ListenPort: port,
		Interval:   Duration(50 * time.Millisecond),
		Timeout:    Duration(time.Second),
	}, WithKubeAPI(kube), WithIdentity("self", "node-a"), WithRegisterer(registry))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- mesh.Run(ctx)
	}()

	waitFor(t, func() bool {
		return mesh.ListenAddr() != ""
	})

	scrape := func() string {
		return scrapeMetrics(promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	}

	waitFor(t, func() bool {
		v, ok := metricValue(t, scrape(), "ko_conntest_state", map[string]string{"state": stateConnected, "target_pod": "peer"})
		return ok && v == 1
	})

	waitFor(t, func() bool {
		body := scrape()
		pings, okP := metricValue(t, body, "ko_conntest_pings_total", map[string]string{"target_pod": "peer"})
		rtt, okR := metricValue(t, body, "ko_conntest_rtt_seconds", map[string]string{"target_pod": "peer"})
		return okP && pings >= 2 && okR && rtt > 0
	})

	body := scrape()
	if strings.Contains(body, `target_pod="self"`) {
		t.Fatalf("self pod must not be probed:\n%s", body)
	}
	if !strings.Contains(body, `source_pod="self"`) || !strings.Contains(body, `source_node="node-a"`) {
		t.Fatalf("missing source labels:\n%s", body)
	}
	if !strings.Contains(body, "# HELP ko_conntest_state") {
		t.Fatalf("missing metrics exposition:\n%s", body)
	}

	kube.events <- WatchEvent{Type: "DELETED", Pod: Pod{Name: "peer"}}
	waitFor(t, func() bool {
		return !strings.Contains(scrape(), `target_pod="peer"`)
	})

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("mesh exited with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("mesh did not exit after context cancellation")
	}
}

func metricValue(t *testing.T, body, name string, want map[string]string) (float64, bool) {
	t.Helper()
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, name+"{") {
			continue
		}
		closeIdx := strings.LastIndexByte(line, '}')
		if closeIdx < 0 {
			continue
		}
		labels := map[string]string{}
		for _, pair := range strings.Split(line[len(name)+1:closeIdx], ",") {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) == 2 {
				labels[kv[0]] = strings.Trim(kv[1], `"`)
			}
		}
		matched := true
		for k, v := range want {
			if labels[k] != v {
				matched = false
				break
			}
		}
		if !matched {
			continue
		}
		var value float64
		if _, err := fmt.Sscanf(strings.TrimSpace(line[closeIdx+1:]), "%g", &value); err != nil {
			t.Fatalf("parsing value of %q: %v", line, err)
		}
		return value, true
	}
	return 0, false
}

type pongServer struct {
	listener net.Listener
	mu       sync.Mutex
	conns    []net.Conn
}

func (s *pongServer) serve(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, len(pingMsg))
	for {
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		if _, err := conn.Write([]byte(pongMsg)); err != nil {
			return
		}
	}
}

func (s *pongServer) Close() {
	s.listener.Close()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, conn := range s.conns {
		conn.Close()
	}
}

func startPongServer(t *testing.T, port int) *pongServer {
	t.Helper()
	l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port)))
	if err != nil {
		t.Fatal(err)
	}
	s := &pongServer{listener: l}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			s.mu.Lock()
			s.conns = append(s.conns, conn)
			s.mu.Unlock()
			go s.serve(conn)
		}
	}()
	return s
}

func TestProberReconnects(t *testing.T) {
	port := freePort(t)
	registry := prometheus.NewRegistry()
	mesh := New(logging.New(), Config{
		ListenPort: port,
		Interval:   Duration(50 * time.Millisecond),
		Timeout:    Duration(time.Second),
	}, WithIdentity("self", "node-a"), WithRegisterer(registry))
	target := Pod{Name: "peer", IP: "127.0.0.1", NodeName: "node-b", Phase: "Running"}
	mesh.metrics.addTarget(target)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		mesh.runProber(ctx, target)
		close(done)
	}()
	render := func() string {
		return scrapeMetrics(promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	}

	waitFor(t, func() bool {
		v, ok := metricValue(t, render(), "ko_conntest_state", map[string]string{"state": stateFailed})
		return ok && v == 1
	})

	peer := startPongServer(t, port)
	waitFor(t, func() bool {
		body := render()
		v, ok := metricValue(t, body, "ko_conntest_state", map[string]string{"state": stateConnected})
		pings, okP := metricValue(t, body, "ko_conntest_pings_total", nil)
		return ok && v == 1 && okP && pings >= 1
	})

	peer.Close()
	waitFor(t, func() bool {
		v, ok := metricValue(t, render(), "ko_conntest_state", map[string]string{"state": stateFailed})
		return ok && v == 1
	})

	restarted := startPongServer(t, port)
	defer restarted.Close()
	waitFor(t, func() bool {
		body := render()
		v, ok := metricValue(t, body, "ko_conntest_state", map[string]string{"state": stateConnected})
		pings, okP := metricValue(t, body, "ko_conntest_pings_total", nil)
		return ok && v == 1 && okP && pings >= 2
	})

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("prober did not exit after context cancellation")
	}
}

func TestKubeClient(t *testing.T) {
	const podJSONFmt = `{"metadata":{"name":%[1]q,"labels":{"app.kubernetes.io/name":"ko"}},"spec":{"nodeName":%[2]q},"status":{"phase":%[3]q,"podIP":%[4]q}}`

	var gotSelector string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/namespaces/testns/pods/self":
			fmt.Fprintf(w, podJSONFmt, "self", "node-a", "Running", "10.0.0.1")
		case "/api/v1/namespaces/testns/pods":
			gotSelector = r.URL.Query().Get("labelSelector")
			if r.URL.Query().Get("watch") != "true" {
				fmt.Fprintf(w, `{"metadata":{"resourceVersion":"42"},"items":[%s,%s]}`,
					fmt.Sprintf(podJSONFmt, "p1", "node-a", "Pending", ""),
					fmt.Sprintf(podJSONFmt, "p2", "node-b", "Running", "10.0.0.2"))
				return
			}
			if r.URL.Query().Get("resourceVersion") != "42" {
				t.Errorf("unexpected watch resourceVersion: %s", r.URL.Query().Get("resourceVersion"))
			}
			flusher := w.(http.Flusher)
			fmt.Fprintf(w, `{"type":"ADDED","object":%s}`+"\n", fmt.Sprintf(podJSONFmt, "p3", "node-c", "Running", "10.0.0.3"))
			flusher.Flush()
			fmt.Fprintf(w, `{"type":"DELETED","object":%s}`+"\n", fmt.Sprintf(podJSONFmt, "p2", "node-b", "Running", "10.0.0.2"))
			flusher.Flush()
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	kube := newKubeClient(srv.URL, "token", "testns", srv.Client())

	self, err := kube.GetPod(context.Background(), "self")
	if err != nil {
		t.Fatal(err)
	}
	if self.Name != "self" || self.NodeName != "node-a" || self.Labels["app.kubernetes.io/name"] != "ko" {
		t.Fatalf("unexpected self pod: %+v", self)
	}

	pods, rv, err := kube.ListPods(context.Background(), "sel=1")
	if err != nil {
		t.Fatal(err)
	}
	if rv != "42" || len(pods) != 2 || pods[0].Name != "p1" || pods[1].Name != "p2" {
		t.Fatalf("unexpected pod list: %+v rv=%s", pods, rv)
	}
	if pods[1].IP != "10.0.0.2" || pods[1].Phase != "Running" {
		t.Fatalf("unexpected mapped pod: %+v", pods[1])
	}
	if gotSelector != "sel=1" {
		t.Fatalf("labelSelector not sent: %q", gotSelector)
	}

	events, err := kube.WatchPods(context.Background(), "sel=1", "42")
	if err != nil {
		t.Fatal(err)
	}
	var got []WatchEvent
	for ev := range events {
		got = append(got, ev)
	}
	if len(got) != 2 || got[0].Type != "ADDED" || got[0].Pod.Name != "p3" || got[1].Type != "DELETED" || got[1].Pod.Name != "p2" {
		t.Fatalf("unexpected watch events: %+v", got)
	}
}

func TestMetrics(t *testing.T) {
	m := newMetrics(identity{Pod: "self", Node: "node-a"}, prometheus.NewRegistry())

	unknown := Pod{Name: "unknown", NodeName: "node-x"}
	m.setState(unknown, stateConnected)
	m.addPing(unknown)
	if n := testutil.CollectAndCount(m.state); n != 0 {
		t.Fatalf("writes for unknown targets must not create series, got %d", n)
	}

	p := Pod{Name: "a", NodeName: "node-c"}
	m.addTarget(p)
	m.setState(p, stateConnected)
	m.setRTT(p, 0.5)
	m.addPing(p)
	m.addPing(p)
	m.addError(p)

	if err := testutil.CollectAndCompare(m.state, strings.NewReader(`
# HELP ko_conntest_state Mesh connection state per target pod.
# TYPE ko_conntest_state gauge
ko_conntest_state{source_node="node-a",source_pod="self",state="connecting",target_node="node-c",target_pod="a"} 0
ko_conntest_state{source_node="node-a",source_pod="self",state="connected",target_node="node-c",target_pod="a"} 1
ko_conntest_state{source_node="node-a",source_pod="self",state="failed",target_node="node-c",target_pod="a"} 0
`)); err != nil {
		t.Fatal(err)
	}
	if err := testutil.CollectAndCompare(m.rtt, strings.NewReader(`
# HELP ko_conntest_rtt_seconds Round-trip time of the last ping.
# TYPE ko_conntest_rtt_seconds gauge
ko_conntest_rtt_seconds{source_node="node-a",source_pod="self",target_node="node-c",target_pod="a"} 0.5
`)); err != nil {
		t.Fatal(err)
	}
	if err := testutil.CollectAndCompare(m.pings, strings.NewReader(`
# HELP ko_conntest_pings_total Successful pings per target pod.
# TYPE ko_conntest_pings_total counter
ko_conntest_pings_total{source_node="node-a",source_pod="self",target_node="node-c",target_pod="a"} 2
`)); err != nil {
		t.Fatal(err)
	}
	if err := testutil.CollectAndCompare(m.errors, strings.NewReader(`
# HELP ko_conntest_errors_total Connection or ping failures per target pod.
# TYPE ko_conntest_errors_total counter
ko_conntest_errors_total{source_node="node-a",source_pod="self",target_node="node-c",target_pod="a"} 1
`)); err != nil {
		t.Fatal(err)
	}

	m.removeTarget("a")
	for _, c := range []prometheus.Collector{m.state, m.rtt, m.pings, m.errors} {
		if n := testutil.CollectAndCount(c); n != 0 {
			t.Fatalf("removed target still has series, got %d", n)
		}
	}

	m.addTarget(p)
	if err := testutil.CollectAndCompare(m.state, strings.NewReader(`
# HELP ko_conntest_state Mesh connection state per target pod.
# TYPE ko_conntest_state gauge
ko_conntest_state{source_node="node-a",source_pod="self",state="connecting",target_node="node-c",target_pod="a"} 1
ko_conntest_state{source_node="node-a",source_pod="self",state="connected",target_node="node-c",target_pod="a"} 0
ko_conntest_state{source_node="node-a",source_pod="self",state="failed",target_node="node-c",target_pod="a"} 0
`)); err != nil {
		t.Fatal(err)
	}
	if n := testutil.CollectAndCount(m.pings); n != 0 {
		t.Fatalf("re-added target must not keep counter history, got %d", n)
	}
}

func TestConfigDurationUnmarshal(t *testing.T) {
	var cfg Config
	if err := yaml.Unmarshal([]byte("interval: 5s\ntimeout: 1500ms"), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Interval != Duration(5*time.Second) || cfg.Timeout != Duration(1500*time.Millisecond) {
		t.Fatalf("unexpected durations: %+v", cfg)
	}
	if err := yaml.Unmarshal([]byte("interval: abc"), &cfg); err == nil {
		t.Fatal("expected duration parse error")
	}
}

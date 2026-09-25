package conntest

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/castai/logging"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"
)

const (
	defaultSelector   = "app.kubernetes.io/name=ko"
	defaultListenPort = 9080
	defaultInterval   = 5 * time.Second
	defaultTimeout    = 2 * time.Second
	retryDelay        = 5 * time.Second
	lookupTimeout     = 10 * time.Second
	pingMsg           = "ping\n"
	pongMsg           = "pong\n"
)

type Duration time.Duration

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	v, err := time.ParseDuration(node.Value)
	if err != nil {
		return fmt.Errorf("parsing duration %q: %w", node.Value, err)
	}
	*d = Duration(v)
	return nil
}

type Config struct {
	Enabled    bool     `yaml:"enabled"`
	ListenPort int      `yaml:"listenPort"`
	Interval   Duration `yaml:"interval"`
	Timeout    Duration `yaml:"timeout"`
}

func (c Config) withDefaults() Config {
	if c.ListenPort == 0 {
		c.ListenPort = defaultListenPort
	}
	if c.Interval == 0 {
		c.Interval = Duration(defaultInterval)
	}
	if c.Timeout == 0 {
		c.Timeout = Duration(defaultTimeout)
	}
	return c
}

func (d Duration) std() time.Duration {
	return time.Duration(d)
}

type Option func(*Mesh)

func WithKubeAPI(api KubeAPI) Option {
	return func(m *Mesh) {
		m.kube = api
	}
}

func WithIdentity(pod, node string) Option {
	return func(m *Mesh) {
		m.podName, m.nodeName = pod, node
	}
}

func WithRegisterer(reg prometheus.Registerer) Option {
	return func(m *Mesh) {
		m.registerer = reg
	}
}

type Mesh struct {
	log        *logging.Logger
	cfg        Config
	kube       KubeAPI
	podName    string
	nodeName   string
	registerer prometheus.Registerer

	mu      sync.Mutex
	probers map[string]context.CancelFunc
	metrics *metrics

	listenAddr atomic.Value
}

func New(log *logging.Logger, cfg Config, opts ...Option) *Mesh {
	m := &Mesh{
		log:        log,
		cfg:        cfg.withDefaults(),
		probers:    map[string]context.CancelFunc{},
		registerer: prometheus.DefaultRegisterer,
	}
	for _, opt := range opts {
		opt(m)
	}
	m.metrics = newMetrics(identity{Pod: m.podName, Node: m.nodeName}, m.registerer)
	return m
}

func (m *Mesh) ListenAddr() string {
	if v, ok := m.listenAddr.Load().(string); ok {
		return v
	}
	return ""
}

func (m *Mesh) Run(ctx context.Context) error {
	if m.kube == nil {
		kube, err := newInClusterClient()
		if err != nil {
			return fmt.Errorf("conntest: %w", err)
		}
		m.kube = kube
	}
	m.resolveIdentity(ctx)
	m.metrics.setSelf(identity{Pod: m.podName, Node: m.nodeName})

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", m.cfg.ListenPort))
	if err != nil {
		return fmt.Errorf("conntest listen: %w", err)
	}
	defer listener.Close()
	m.listenAddr.Store(listener.Addr().String())

	errg, ctx := errgroup.WithContext(ctx)
	errg.Go(func() error {
		return m.serve(ctx, listener)
	})
	errg.Go(func() error {
		return m.discover(ctx)
	})
	return errg.Wait()
}

func (m *Mesh) serve(ctx context.Context, l net.Listener) error {
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
		case <-done:
		}
		l.Close()
	}()
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("conntest accept: %w", err)
		}
		go m.serveConn(ctx, conn)
	}
}

func (m *Mesh) serveConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
		case <-done:
		}
		conn.Close()
	}()
	reader := bufio.NewReader(conn)
	for {
		if _, err := reader.ReadString('\n'); err != nil {
			return
		}
		if _, err := conn.Write([]byte(pongMsg)); err != nil {
			return
		}
	}
}

func (m *Mesh) resolveIdentity(ctx context.Context) {
	if m.podName == "" {
		if name := os.Getenv("POD_NAME"); name != "" {
			m.podName = name
		} else if host, err := os.Hostname(); err == nil {
			m.podName = host
		}
	}
	if m.nodeName != "" {
		return
	}
	if name := os.Getenv("NODE_NAME"); name != "" {
		m.nodeName = name
		return
	}
	lookupCtx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	self, err := m.kube.GetPod(lookupCtx, m.podName)
	if err != nil {
		m.log.Warnf("conntest: looking up own pod %q: %v", m.podName, err)
		return
	}
	m.nodeName = self.NodeName
}

func (m *Mesh) podSelector(ctx context.Context) string {
	lookupCtx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	self, err := m.kube.GetPod(lookupCtx, m.podName)
	if err != nil {
		m.log.Warnf("conntest: deriving pod selector from own pod: %v", err)
		return defaultSelector
	}
	name := self.Labels["app.kubernetes.io/name"]
	if name == "" {
		return defaultSelector
	}
	selector := "app.kubernetes.io/name=" + name
	if instance := self.Labels["app.kubernetes.io/instance"]; instance != "" {
		selector += ",app.kubernetes.io/instance=" + instance
	}
	return selector
}

func (m *Mesh) discover(ctx context.Context) error {
	selector := m.podSelector(ctx)
	for ctx.Err() == nil {
		pods, resourceVersion, err := m.kube.ListPods(ctx, selector)
		if err != nil {
			m.log.Warnf("conntest: listing pods: %v", err)
			if !sleepCtx(ctx, retryDelay) {
				break
			}
			continue
		}
		m.reconcile(ctx, pods)

		events, err := m.kube.WatchPods(ctx, selector, resourceVersion)
		if err != nil {
			m.log.Warnf("conntest: watching pods: %v", err)
			if !sleepCtx(ctx, retryDelay) {
				break
			}
			continue
		}
		for ev := range events {
			m.applyPod(ctx, ev.Pod, ev.Type == "DELETED")
		}
	}
	return nil
}

func (m *Mesh) reconcile(ctx context.Context, pods []Pod) {
	seen := make(map[string]bool, len(pods))
	for _, p := range pods {
		seen[p.Name] = true
		m.applyPod(ctx, p, false)
	}
	m.mu.Lock()
	for name, cancel := range m.probers {
		if !seen[name] {
			cancel()
			delete(m.probers, name)
			m.metrics.removeTarget(name)
		}
	}
	m.mu.Unlock()
}

func (m *Mesh) applyPod(ctx context.Context, p Pod, deleted bool) {
	runnable := !deleted && p.Phase == "Running" && p.IP != "" && p.Name != m.podName
	m.mu.Lock()
	_, active := m.probers[p.Name]
	switch {
	case runnable && !active:
		proberCtx, cancel := context.WithCancel(ctx)
		m.probers[p.Name] = cancel
		m.metrics.addTarget(p)
		go m.runProber(proberCtx, p)
	case !runnable && active:
		m.probers[p.Name]()
		delete(m.probers, p.Name)
		m.metrics.removeTarget(p.Name)
	}
	m.mu.Unlock()
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

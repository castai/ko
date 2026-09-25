package conntest

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	stateConnecting = "connecting"
	stateConnected  = "connected"
	stateFailed     = "failed"

	labelSourcePod  = "source_pod"
	labelSourceNode = "source_node"
	labelTargetPod  = "target_pod"
	labelTargetNode = "target_node"
	labelState      = "state"
)

type identity struct {
	Pod  string
	Node string
}

type metrics struct {
	mu      sync.Mutex
	self    identity
	targets map[string]Pod

	state  *prometheus.GaugeVec
	rtt    *prometheus.GaugeVec
	pings  *prometheus.CounterVec
	errors *prometheus.CounterVec
}

func newMetrics(self identity, reg prometheus.Registerer) *metrics {
	labels := []string{labelSourcePod, labelSourceNode, labelTargetPod, labelTargetNode}
	m := &metrics{
		self:    self,
		targets: map[string]Pod{},
		state: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ko_conntest_state",
			Help: "Mesh connection state per target pod.",
		}, append(labels, labelState)),
		rtt: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "ko_conntest_rtt_seconds",
			Help: "Round-trip time of the last ping.",
		}, labels),
		pings: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ko_conntest_pings_total",
			Help: "Successful pings per target pod.",
		}, labels),
		errors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "ko_conntest_errors_total",
			Help: "Connection or ping failures per target pod.",
		}, labels),
	}
	reg.MustRegister(m.state, m.rtt, m.pings, m.errors)
	return m
}

func (m *metrics) setSelf(self identity) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.self = self
}

func (m *metrics) labelValues(p Pod) []string {
	return []string{m.self.Pod, m.self.Node, p.Name, p.NodeName}
}

func (m *metrics) addTarget(p Pod) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.targets[p.Name]; ok {
		return
	}
	m.targets[p.Name] = p
	m.setStateUnlocked(p, stateConnecting)
}

func (m *metrics) removeTarget(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.targets[name]; !ok {
		return
	}
	delete(m.targets, name)
	match := prometheus.Labels{labelTargetPod: name}
	m.state.DeletePartialMatch(match)
	m.rtt.DeletePartialMatch(match)
	m.pings.DeletePartialMatch(match)
	m.errors.DeletePartialMatch(match)
}

func (m *metrics) known(p Pod) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.targets[p.Name]
	return ok
}

func (m *metrics) setState(p Pod, state string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.targets[p.Name]; !ok {
		return
	}
	m.setStateUnlocked(p, state)
}

func (m *metrics) setStateUnlocked(p Pod, state string) {
	for _, s := range []string{stateConnecting, stateConnected, stateFailed} {
		value := 0.0
		if s == state {
			value = 1.0
		}
		m.state.WithLabelValues(append(m.labelValues(p), s)...).Set(value)
	}
}

func (m *metrics) setRTT(p Pod, seconds float64) {
	if !m.known(p) {
		return
	}
	m.rtt.WithLabelValues(m.labelValues(p)...).Set(seconds)
}

func (m *metrics) addPing(p Pod) {
	if !m.known(p) {
		return
	}
	m.pings.WithLabelValues(m.labelValues(p)...).Inc()
}

func (m *metrics) addError(p Pod) {
	if !m.known(p) {
		return
	}
	m.errors.WithLabelValues(m.labelValues(p)...).Inc()
}

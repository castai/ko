package tracer

import (
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	eventsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ko_ebpf_events_total",
		Help: "TCP connection events read from the eBPF ring buffer.",
	})
	decodeErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ko_ebpf_decode_error_total",
		Help: "eBPF events that failed to decode.",
	})
	filterEvents = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ko_filter_events_total",
		Help: "Connection events by CEL filter decision.",
	}, []string{"decision"})
	filterMatched = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ko_filter_matched_total",
		Help: "Connection events matched per CEL filter.",
	}, []string{"filter"})
	filterVerifyMismatches = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ko_filter_verify_mismatches_total",
		Help: "CEL filter decisions where the eBPF verdict disagreed with exact userspace evaluation; must stay zero.",
	})
	progRuntime = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ko_ebpf_prog_runtime_ns_total",
		Help: "Time spent executing BPF programs, in nanoseconds. Covers every program on the node (ko's own included), so the tracer's overhead can be compared with neighbors. Requires kernel-side stats accounting, which the agent enables while running (Linux 5.8+).",
	}, []string{"prog", "tag", "type"})
	progRuns = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "ko_ebpf_prog_runs_total",
		Help: "Number of BPF program executions, per program on the node.",
	}, []string{"prog", "tag", "type"})
	ringbufDroppedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "ko_ebpf_ringbuf_dropped_total",
		Help: "eBPF events dropped because the ring buffer was full.",
	})
)

func trackRingbufDrops(m *ebpf.Map, stop <-chan struct{}) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	var last uint64
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			var key uint32
			var vals []uint64
			if err := m.Lookup(&key, &vals); err != nil {
				return
			}
			var total uint64
			for _, v := range vals {
				total += v
			}
			if total > last {
				ringbufDroppedTotal.Add(float64(total - last))
				last = total
			}
		}
	}
}

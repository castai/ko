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

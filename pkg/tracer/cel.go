package tracer

import (
	"fmt"
	"net"
	"time"

	"github.com/cilium/ebpf"

	celfilter "github.com/castai/ko/pkg/filter"
)

type CelFilter struct {
	Name string `yaml:"name"`
	Expr string `yaml:"expr"`
}

func (t *Tracer) initFilters() error {
	if len(t.filter.Cel) == 0 {
		return nil
	}
	cfg := make([]celfilter.Config, 0, len(t.filter.Cel))
	for _, f := range t.filter.Cel {
		cfg = append(cfg, celfilter.Config{Name: f.Name, Expr: f.Expr})
	}
	set, err := celfilter.Compile(cfg)
	if err != nil {
		return fmt.Errorf("compile cel filters: %w", err)
	}
	t.filterSet = set
	return nil
}

func (t *Tracer) startFilters(objs *tracerObjects, stop <-chan struct{}) error {
	key := uint32(0)
	if t.filterSet != nil {
		prog := t.filterSet.BPFProg()
		if err := objs.KoFilterProg.Update(&key, &prog, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("program filter rules: %w", err)
		}
		t.verdictMap = objs.KoCgroupVerdict
		t.syncOnce()
		go t.syncVerdicts(stop)
	}
	enabled := uint64(1)
	if err := objs.KoFilterCfg.Update(&key, &enabled, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("enable cel filters: %w", err)
	}
	return nil
}

func (t *Tracer) syncVerdicts(stop <-chan struct{}) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			t.syncOnce()
		}
	}
}

func (t *Tracer) syncOnce() {
	if t.attrs == nil || t.verdictMap == nil {
		return
	}
	snapshot := t.attrs.AttrsSnapshot()
	for id, attrs := range snapshot {
		mask := t.filterSet.VerdictMask(attrs)
		if err := t.verdictMap.Update(&id, &mask, ebpf.UpdateAny); err != nil {
			t.log.Warnf("update cgroup verdict: %v", err)
			return
		}
	}
	var key uint64
	var val uint64
	it := t.verdictMap.Iterate()
	for it.Next(&key, &val) {
		if _, ok := snapshot[key]; !ok {
			t.verdictMap.Delete(&key)
		}
	}
}

func (t *Tracer) resolveFilter(raw tracerConnEventT) (uint16, bool) {
	attrs := celfilter.CgroupAttrs{}
	known := true
	if t.attrs != nil {
		a, ok := t.attrs.Attrs(raw.CgroupId)
		attrs, known = a, ok
	}
	ev := celfilter.Event{
		Type:        celfilter.EventType(raw.Type),
		Namespace:   attrs.Namespace,
		Container:   attrs.Container,
		Pod:         attrs.Pod,
		RTTUS:       raw.RttUs,
		LifeUS:      raw.LifeUs,
		Retransmits: raw.Retransmits,
		SegsOut:     raw.SegsOut,
		LocalIP:     decodeIP(raw.Family, raw.LocalIp),
		LocalPort:   raw.LocalPort,
		RemoteIP:    decodeIP(raw.Family, raw.RemoteIp),
		RemotePort:  raw.RemotePort,
	}
	idx, matched := t.filterSet.Evaluate(ev)
	if known && t.verdictMap != nil {
		mask := t.filterSet.VerdictMask(attrs)
		if err := t.verdictMap.Update(&raw.CgroupId, &mask, ebpf.UpdateAny); err != nil {
			t.log.Warnf("update cgroup verdict: %v", err)
		}
	}
	if !matched {
		return 0, false
	}
	return uint16(idx), true
}

func (t *Tracer) verifyBpfDecision(raw tracerConnEventT, bpfIdx uint16) {
	idx, matched := t.resolveFilter(raw)
	if !matched || uint16(idx) != bpfIdx {
		filterVerifyMismatches.Inc()
		t.log.Errorf("cel filter verify mismatch: bpf idx %d, userspace idx %d matched %v", bpfIdx, idx, matched)
	}
}

func decodeIP(family uint16, raw [16]uint8) net.IP {
	if family == afInet {
		return net.IP(append([]byte(nil), raw[:4]...))
	}
	return net.IP(append([]byte(nil), raw[:]...))
}

func trackFilterDrops(m *ebpf.Map, stop <-chan struct{}) {
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
				filterEvents.WithLabelValues("dropped_bpf").Add(float64(total - last))
				last = total
			}
		}
	}
}

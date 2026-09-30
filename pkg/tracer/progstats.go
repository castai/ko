package tracer

import (
	"errors"
	"io"
	"io/fs"
	"time"

	"github.com/cilium/ebpf"
)

// BPF_STATS_RUN_TIME from linux/bpf.h: the only stats selector the kernel
// offers, enabling per-program run time and run count accounting. Defined
// locally because x/sys gates the constant to Linux builds and this
// package must compile on darwin too.
const bpfStatsRunTime = 0

// enableProgStats arms kernel-side runtime accounting for every BPF
// program on the node while the returned handle is open. Requires Linux
// 5.8+. The accounting adds a small per-run cost to every program, which
// is why it is opt-in in the kernel.
func enableProgStats() (io.Closer, error) {
	return ebpf.EnableStats(bpfStatsRunTime)
}

// progSample is one program's kernel-side runtime accounting snapshot.
type progSample struct {
	Name     string
	Tag      string
	Type     string
	Runtime  time.Duration
	RunCount uint64
}

// snapshotProgStats walks every BPF program on the node and reads its
// kernel-side runtime accounting. Programs unloading mid-iteration are
// skipped. Values are only meaningful while bpf stats are enabled.
func snapshotProgStats() (map[ebpf.ProgramID]progSample, error) {
	samples := make(map[ebpf.ProgramID]progSample)
	var id ebpf.ProgramID
	for {
		next, err := ebpf.ProgramGetNextID(id)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return samples, nil
			}
			return nil, err
		}
		id = next
		prog, err := ebpf.NewProgramFromID(id)
		if err != nil {
			continue
		}
		info, infoErr := prog.Info()
		stats, statsErr := prog.Stats()
		prog.Close()
		if infoErr != nil || statsErr != nil {
			continue
		}
		samples[id] = progSample{
			Name:     info.Name,
			Tag:      info.Tag,
			Type:     info.Type.String(),
			Runtime:  stats.Runtime,
			RunCount: stats.RunCount,
		}
	}
}

// trackProgStats exports per-program runtime accounting as Prometheus
// counters. The kernel reports cumulative values, so each poll adds the
// delta since the previous one: agent restarts count from zero instead
// of importing the pre-agent total as a single spike, and replaced
// programs (new ids) restart their series.
func trackProgStats(stop <-chan struct{}) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	last := map[ebpf.ProgramID]progSample{}
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
		}
		cur, err := snapshotProgStats()
		if err != nil {
			return
		}
		for id, s := range cur {
			if prev, ok := last[id]; ok {
				if d := s.Runtime - prev.Runtime; d > 0 {
					progRuntime.WithLabelValues(s.Name, s.Tag, s.Type).Add(float64(d))
				}
				if d := s.RunCount - prev.RunCount; d > 0 {
					progRuns.WithLabelValues(s.Name, s.Tag, s.Type).Add(float64(d))
				}
			}
			last[id] = s
		}
		for id := range last {
			if _, ok := cur[id]; !ok {
				delete(last, id)
			}
		}
	}
}

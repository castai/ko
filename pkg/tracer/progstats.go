package tracer

import (
	"errors"
	"io"
	"io/fs"
	"time"

	"github.com/cilium/ebpf"
)

const bpfStatsRunTime = 0

func enableProgStats() (io.Closer, error) {
	return ebpf.EnableStats(bpfStatsRunTime)
}

type progSample struct {
	Name     string
	Tag      string
	Type     string
	Runtime  time.Duration
	RunCount uint64
}

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

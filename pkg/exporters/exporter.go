package exporters

import (
	"context"

	"github.com/castai/ko/pkg/kontext"
	"github.com/castai/ko/pkg/tracer"
)

// Event couples a connection event from the tracer with its resolved
// container context. Container is nil when the cgroup is unknown or the
// event did not come from a container.
type Event struct {
	tracer.ConnEvent
	Container *kontext.ContainerInfo
}

// Exporter consumes tracer events. Implementations keep an internal
// queue: Push only enqueues and never blocks, Run drains the queue and
// owns the actual delivery.
type Exporter interface {
	Run(ctx context.Context) error
	Push(event Event)
}

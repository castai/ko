package tracer

import (
	"context"
	"github.com/castai/logging"
)

func New(log *logging.Logger) *Tracer {
	return &Tracer{
		log: log,
	}
}

type Tracer struct {
	log *logging.Logger
}

func (t *Tracer) Run(ctx context.Context) error {
	t.log.Info("started tracer")
	defer t.log.Info("finished tracer")

	select {
	case <-ctx.Done():
		return ctx.Err()
	}
}

package app

import (
	"context"
	"github.com/castai/ko/pkg/tracer"
	"golang.org/x/sync/errgroup"
)

func New(tracer *tracer.Tracer) *App {
	return &App{
		tracer: tracer,
	}
}

type App struct {
	tracer *tracer.Tracer
}

func (a *App) Run(ctx context.Context) error {
	errg, ctx := errgroup.WithContext(ctx)
	errg.Go(func() error {
		return a.tracer.Run(ctx)
	})
	return errg.Wait()
}

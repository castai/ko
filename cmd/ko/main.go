package main

import (
	"context"
	"errors"
	"github.com/castai/ko/cmd/ko/app"
	"github.com/castai/ko/pkg/tracer"
	"github.com/castai/logging"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	log := logging.New()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := run(ctx, log); err != nil && !errors.Is(err, context.Canceled) {
		log.Error(err.Error())
		os.Exit(1)
	}
}

func run(ctx context.Context, log *logging.Logger) error {
	tr := tracer.New(log)
	instance := app.New(tr)
	return instance.Run(ctx)
}

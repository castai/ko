package nodeagent

import (
	"context"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/castai/ko/pkg/config"
	"github.com/castai/ko/pkg/exporters"
	"github.com/castai/ko/pkg/kontext"
	"github.com/castai/ko/pkg/tracer"
	"github.com/castai/logging"
)

func NewCommand(log *logging.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "node-agent",
		Short: "Run the node scoped agent",
		RunE: func(cmd *cobra.Command, args []string) error {
			path, _ := cmd.Flags().GetString("config")
			cfg, err := config.Load(path)
			if err != nil {
				return err
			}
			ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()
			return run(ctx, log, cfg)
		},
	}
	cmd.Flags().String("config", "", "path to the config file")
	return cmd
}

func run(ctx context.Context, log *logging.Logger, cfg config.Config) error {
	exps, err := exporters.Build(cfg)
	if err != nil {
		return err
	}

	kctx, err := kontext.New(log, kontext.DefaultSocket)
	if err != nil {
		log.Warnf("k8s context disabled: %v", err)
		kctx = nil
	}

	events := make(chan tracer.ConnEvent, 256)
	tr := tracer.New(log, tracer.WithEvents(events))
	instance := New(log, tr, kctx, events, exps...)
	return instance.Run(ctx)
}

func New(log *logging.Logger, tr *tracer.Tracer, kctx *kontext.Client, events <-chan tracer.ConnEvent, exps ...exporters.Exporter) *App {
	return &App{
		log:       log,
		tracer:    tr,
		kontext:   kctx,
		events:    events,
		exporters: exps,
	}
}

type App struct {
	log       *logging.Logger
	tracer    *tracer.Tracer
	kontext   *kontext.Client
	events    <-chan tracer.ConnEvent
	exporters []exporters.Exporter
}

func (a *App) Run(ctx context.Context) error {
	errg, ctx := errgroup.WithContext(ctx)

	if a.kontext != nil {
		errg.Go(func() error {
			return a.kontext.Run(ctx)
		})
	}

	errg.Go(func() error {
		return a.tracer.Run(ctx)
	})

	for _, exp := range a.exporters {
		errg.Go(func() error {
			return exp.Run(ctx)
		})
	}

	errg.Go(func() error {
		return a.consumeEvents(ctx)
	})

	return errg.Wait()
}

func (a *App) consumeEvents(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case event := <-a.events:
			a.push(ctx, event)
		}
	}
}

func (a *App) push(ctx context.Context, event tracer.ConnEvent) {
	ev := exporters.Event{ConnEvent: event}

	if event.CgroupID != 0 && a.kontext != nil {
		if info, err := a.kontext.GetContainerInfo(ctx, event.CgroupID); err == nil {
			ev.Container = info
		}
	}

	for _, exp := range a.exporters {
		exp.Push(ev)
	}
}

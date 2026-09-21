package main

import (
	"os"

	"github.com/spf13/cobra"

	clusteragent "github.com/castai/ko/cmd/ko/cluster-agent"
	nodeagent "github.com/castai/ko/cmd/ko/node-agent"
	"github.com/castai/logging"
)

// version is injected at build time via -ldflags.
var version = "dev"

func main() {
	log := logging.New()
	log.Infof("ko %s", version)

	root := &cobra.Command{
		Use:          "ko",
		Short:        "k8s observability agent",
		SilenceUsage: true,
	}
	root.AddCommand(nodeagent.NewCommand(log))
	root.AddCommand(clusteragent.NewCommand(log))

	if err := root.Execute(); err != nil {
		log.Error(err.Error())
		os.Exit(1)
	}
}

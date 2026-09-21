package clusteragent

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/castai/logging"
)

func NewCommand(log *logging.Logger) *cobra.Command {
	return &cobra.Command{
		Use:   "cluster-agent",
		Short: "Run the cluster scoped agent",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("cluster-agent is not implemented yet")
		},
	}
}

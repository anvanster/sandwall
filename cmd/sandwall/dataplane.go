//go:build linux

package main

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/anvanster/sandwall/internal/dataplane"
)

// newDataplaneCmd runs one sandbox's DNS proxy and relay. The daemon starts
// it; it is not meant to be run by hand.
func newDataplaneCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:    "dataplane --config <file>",
		Short:  "Run a sandbox's DNS proxy and relay (started by the daemon)",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireRoot(); err != nil {
				return err
			}
			cfg, err := dataplane.ReadConfig(configPath)
			if err != nil {
				return err
			}
			log := slog.New(slog.NewTextHandler(os.Stderr, nil)).With("sandbox", cfg.SandboxID)
			return dataplane.Run(cmd.Context(), cfg, log, dataplane.Hooks{})
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "data plane config written by the daemon")
	_ = cmd.MarkFlagRequired("config")
	return cmd
}

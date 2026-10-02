//go:build linux

package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/spf13/cobra"

	"github.com/anvanster/sandwall/internal/api"
	"github.com/anvanster/sandwall/internal/daemon"
	"github.com/anvanster/sandwall/internal/flowlog"
	"github.com/anvanster/sandwall/internal/policy"
	"github.com/anvanster/sandwall/internal/policy/psl"
)

func newPolicyCmd(g *globalFlags) *cobra.Command {
	cmd := &cobra.Command{Use: "policy", Short: "Manage sandbox policies"}
	cmd.AddCommand(&cobra.Command{
		Use:   "apply <id> <policy.yaml>",
		Short: "Hot-reload a sandbox's policy; established flows survive",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			pol, err := os.ReadFile(args[1])
			if err != nil {
				return err
			}
			err = api.NewClient(g.socket).Do(cmd.Context(), http.MethodPut, api.SandboxPath(args[0], "/policy"),
				api.PolicyRequest{Policy: string(pol)}, nil)
			if err != nil {
				return err
			}
			fmt.Printf("applied %s to %s\n", args[1], args[0])
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "lint <policy.yaml>",
		Short: "Validate a policy offline, including wildcards over shared hosting platforms",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pol, err := policy.Load(args[0])
			if err != nil {
				return err
			}
			for _, m := range pol.MultitenantWildcards() {
				if m.Acknowledged {
					fmt.Printf("acknowledged: %s\n", m)
				}
			}
			if err := pol.Lint(); err != nil {
				return fmt.Errorf("%w\n(Public Suffix List %s)", err, psl.Version())
			}
			fmt.Printf("%s: ok\n", args[0])
			return nil
		},
	})
	return cmd
}

func newLogsCmd(g *globalFlags) *cobra.Command {
	var follow, denyOnly bool
	cmd := &cobra.Command{
		Use:   "logs <id>",
		Short: "Print a sandbox's DNS, deny and flow log (JSONL)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return flowlog.Tail(flowlog.Path(g.logDir, args[0]), os.Stdout,
				flowlog.Filter{DenyOnly: denyOnly}, follow, cmd.Context().Done())
		},
	}
	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "keep printing new lines")
	cmd.Flags().BoolVar(&denyOnly, "deny-only", false, "only denials (deny events and refused DNS)")
	return cmd
}

func newNukeCmd(g *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "nuke",
		Short: "Remove ALL sandwall netns, veths, nft table and tc state, and restore sysctls. Idempotent.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireRoot(); err != nil {
				return err
			}
			// Let a running daemon drop its in-memory state and listeners first.
			err := api.NewClient(g.socket).Do(cmd.Context(), http.MethodPost, "/v1/nuke", nil, nil)
			if err != nil && !errors.Is(err, api.ErrDaemonUnavailable) {
				fmt.Fprintln(os.Stderr, "sandwall: daemon nuke failed, cleaning up directly:", err)
			}
			// Always sweep directly too, so nuke works with a dead daemon.
			if err := daemon.Cleanup(cmd.Context(), g.stateDir, g.chrootBase); err != nil {
				return err
			}
			fmt.Println("nuked")
			return nil
		},
	}
}

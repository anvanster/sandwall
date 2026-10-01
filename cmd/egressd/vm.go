//go:build linux

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/anvanster/egressd/internal/api"
	"github.com/anvanster/egressd/internal/daemon"
)

func newVMCmd(g *globalFlags) *cobra.Command {
	cmd := &cobra.Command{Use: "vm", Short: "Snapshot and clone Firecracker sandboxes"}
	cmd.AddCommand(newVMSnapshotCmd(g), newVMCloneCmd(g))
	return cmd
}

func newVMSnapshotCmd(g *globalFlags) *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "snapshot <id> --out dir/",
		Short: "Pause a VM sandbox, write a full snapshot plus its disks to dir, and resume it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			abs, err := filepath.Abs(out)
			if err != nil {
				return err
			}
			err = api.NewClient(g.socket).Do(cmd.Context(), http.MethodPost, api.SandboxPath(args[0], "/snapshot"),
				api.SnapshotRequest{OutDir: abs}, nil)
			if err != nil {
				return err
			}
			fmt.Printf("snapshot of %s written to %s\n", args[0], abs)
			return nil
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "output directory")
	_ = cmd.MarkFlagRequired("out")
	return cmd
}

func newVMCloneCmd(g *globalFlags) *cobra.Command {
	var (
		count      int
		policyPath string
		prefix     string
		stagger    time.Duration
	)
	cmd := &cobra.Command{
		Use:   "clone <snapshot-dir> --count N --policy p.yaml",
		Short: "Start N VM sandboxes from one snapshot, each in its own netns with its own policy and logs",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pol, err := os.ReadFile(policyPath)
			if err != nil {
				return err
			}
			dir, err := filepath.Abs(args[0])
			if err != nil {
				return err
			}
			var resp api.CloneResponse
			err = api.NewClient(g.socket).Do(cmd.Context(), http.MethodPost, "/v1/clones",
				api.CloneRequest{SnapshotDir: dir, Count: count, Prefix: prefix, Policy: string(pol), StaggerMs: stagger.Milliseconds()}, &resp)
			if err != nil {
				return err
			}
			var infos []daemon.Info
			if err := json.Unmarshal(resp.Created, &infos); err != nil {
				return err
			}
			for _, i := range infos {
				fmt.Printf("%s\t%s\n", i.ID, i.Netns)
			}
			if resp.Error != "" {
				return errors.New(resp.Error)
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&count, "count", 1, "number of clones")
	cmd.Flags().StringVar(&policyPath, "policy", "", "policy YAML file applied to every clone")
	cmd.Flags().StringVar(&prefix, "prefix", "clone", "clone IDs are <prefix>-1 ... <prefix>-N")
	cmd.Flags().DurationVar(&stagger, "stagger", 0, "pause between VM starts, to spread out memory faulting (needed on nested-virtualization hosts)")
	_ = cmd.MarkFlagRequired("policy")
	return cmd
}

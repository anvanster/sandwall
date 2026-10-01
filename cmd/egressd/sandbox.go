//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/anvanster/egressd/internal/api"
	"github.com/anvanster/egressd/internal/daemon"
)

// nobody/nogroup: exec-mode processes run unprivileged and capability-free.
const (
	nobodyUID = 65534
	nobodyGID = 65534
)

func newSandboxCmd(g *globalFlags) *cobra.Command {
	cmd := &cobra.Command{Use: "sandbox", Short: "Manage sandboxes"}
	cmd.AddCommand(newSandboxCreateCmd(g), newSandboxExecCmd(g), newSandboxListCmd(g), newSandboxDestroyCmd(g))
	return cmd
}

func newSandboxCreateCmd(g *globalFlags) *cobra.Command {
	var policyPath, mode, vmConfig string
	cmd := &cobra.Command{
		Use:   "create <id> --policy p.yaml",
		Short: "Create a sandbox with its own netns and egress policy",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if vmConfig != "" {
				return fmt.Errorf("--vm-config is not implemented yet (milestone M3)")
			}
			pol, err := os.ReadFile(policyPath)
			if err != nil {
				return err
			}
			var info daemon.Info
			err = api.NewClient(g.socket).Do(cmd.Context(), http.MethodPost, "/v1/sandboxes",
				api.CreateRequest{ID: args[0], Mode: mode, Policy: string(pol)}, &info)
			if err != nil {
				return err
			}
			fmt.Printf("created %s (netns %s, %s via %s)\n", info.ID, info.Netns, info.NsAddr, info.HostAddr)
			return nil
		},
	}
	cmd.Flags().StringVar(&policyPath, "policy", "", "policy YAML file")
	cmd.Flags().StringVar(&mode, "mode", daemon.ModeExec, "exec or vm")
	cmd.Flags().StringVar(&vmConfig, "vm-config", "", "Firecracker config (vm mode)")
	_ = cmd.MarkFlagRequired("policy")
	return cmd
}

func newSandboxExecCmd(g *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "exec <id> -- <cmd...>",
		Short: "Run a command in an exec-mode sandbox as nobody, without capabilities",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if cmd.ArgsLenAtDash() != 1 {
				return fmt.Errorf("usage: egressd sandbox exec <id> -- <cmd...>")
			}
			if err := requireRoot(); err != nil {
				return err
			}
			var info daemon.Info
			if err := api.NewClient(g.socket).Do(cmd.Context(), http.MethodGet, api.SandboxPath(args[0], ""), nil, &info); err != nil {
				return err
			}
			if info.Mode != daemon.ModeExec {
				return fmt.Errorf("sandbox %s is in %s mode; exec needs exec mode", info.ID, info.Mode)
			}
			return execInSandbox(info.Netns, args[1:])
		},
	}
}

// execInSandbox replaces this process with:
//
//	ip netns exec <ns> setpriv --reuid nobody --regid nogroup --clear-groups
//	   --inh-caps -all --bounding-set -all --no-new-privs -- cmd...
//
// `ip netns exec` enters the netns and bind-mounts /etc/netns/<ns>/resolv.conf;
// setpriv drops to nobody and removes every capability, so nothing in the
// sandbox can change its network configuration.
func execInSandbox(netnsName string, argv []string) error {
	ipPath, err := exec.LookPath("ip")
	if err != nil {
		return err
	}
	setpriv, err := exec.LookPath("setpriv")
	if err != nil {
		return fmt.Errorf("setpriv (util-linux) is required: %w", err)
	}
	full := append([]string{
		"ip", "netns", "exec", netnsName,
		setpriv,
		fmt.Sprintf("--reuid=%d", nobodyUID), fmt.Sprintf("--regid=%d", nobodyGID), "--clear-groups",
		"--inh-caps=-all", "--bounding-set=-all", "--no-new-privs",
		"--",
	}, argv...)
	env := append(os.Environ(), "HOME=/nonexistent", "USER=nobody", "LOGNAME=nobody")
	return syscall.Exec(ipPath, full, env)
}

func newSandboxListCmd(g *globalFlags) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List sandboxes",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var infos []daemon.Info
			if err := api.NewClient(g.socket).Do(cmd.Context(), http.MethodGet, "/v1/sandboxes", nil, &infos); err != nil {
				return err
			}
			if asJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(infos)
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tMODE\tNETNS\tADDR\tDOMAINS\tCREATED")
			for _, i := range infos {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", i.ID, i.Mode, i.Netns, i.NsAddr,
					strings.Join(i.Policy.Egress.AllowDomains, ","), i.Created.Format("2006-01-02 15:04:05"))
			}
			return tw.Flush()
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return cmd
}

func newSandboxDestroyCmd(g *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "destroy <id>",
		Short: "Destroy a sandbox (its log is kept)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := api.NewClient(g.socket).Do(cmd.Context(), http.MethodDelete, api.SandboxPath(args[0], ""), nil, nil); err != nil {
				return err
			}
			fmt.Printf("destroyed %s\n", args[0])
			return nil
		},
	}
}

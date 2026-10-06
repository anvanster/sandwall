//go:build linux

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/anvanster/sandwall/internal/api"
	"github.com/anvanster/sandwall/internal/daemon"
)

// nobody/nogroup: exec-mode processes run unprivileged and capability-free.
const (
	nobodyUID = 65534
	nobodyGID = 65534
)

func newSandboxCmd(g *globalFlags) *cobra.Command {
	cmd := &cobra.Command{Use: "sandbox", Short: "Manage sandboxes"}
	cmd.AddCommand(newSandboxCreateCmd(g), newSandboxExecCmd(g), newSandboxListCmd(g), newSandboxDestroyCmd(g),
		newSandboxQuarantineCmd(g), newSandboxReleaseCmd(g))
	return cmd
}

// createTimeout: a VM-mode create copies the kernel and disks and boots the
// VM, which can outlast the default request deadline on a slow disk.
func createTimeout(mode string) time.Duration {
	if mode == daemon.ModeVM {
		return 5 * time.Minute
	}
	return api.DefaultTimeout
}

func newSandboxCreateCmd(g *globalFlags) *cobra.Command {
	var policyPath, mode, vmConfig string
	cmd := &cobra.Command{
		Use:   "create <id> --policy p.yaml",
		Short: "Create a sandbox with its own netns and egress policy",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pol, err := os.ReadFile(policyPath)
			if err != nil {
				return err
			}
			req := api.CreateRequest{ID: args[0], Mode: mode, Policy: string(pol)}
			if vmConfig != "" {
				data, err := os.ReadFile(vmConfig)
				if err != nil {
					return err
				}
				req.VMConfig = string(data)
			}
			var info daemon.Info
			ctx, cancel := context.WithTimeout(cmd.Context(), createTimeout(mode))
			defer cancel()
			if err := api.NewClient(g.socket).Do(ctx, http.MethodPost, "/v1/sandboxes", req, &info); err != nil {
				return err
			}
			if info.VM != nil {
				fmt.Printf("created %s (netns %s, guest %s, console %s)\n", info.ID, info.Netns, info.VM.GuestAddr, info.VM.ConsoleLog)
			} else {
				fmt.Printf("created %s (netns %s, %s via %s)\n", info.ID, info.Netns, info.NsAddr, info.HostAddr)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&policyPath, "policy", "", "policy YAML file")
	cmd.Flags().StringVar(&mode, "mode", daemon.ModeExec, "exec or vm")
	cmd.Flags().StringVar(&vmConfig, "vm-config", "", "Firecracker config JSON without network-interfaces (vm mode)")
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
				return fmt.Errorf("usage: sandwall sandbox exec <id> -- <cmd...>")
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
			fmt.Fprintln(tw, "ID\tMODE\tNETNS\tSTATE\tDOMAINS\tCREATED")
			for _, i := range infos {
				state := "ready"
				if i.VM != nil && !i.VM.Running {
					state = "vm stopped"
				} else if i.VM != nil {
					state = "vm running"
				}
				if q := i.Quarantine; q != nil {
					state = "QUARANTINED"
					if q.Frozen {
						state += ",frozen"
					}
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", i.ID, i.Mode, i.Netns, state,
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

func newSandboxQuarantineCmd(g *globalFlags) *cobra.Command {
	var req api.QuarantineRequest
	cmd := &cobra.Command{
		Use:   "quarantine <id>",
		Short: "Cut a sandbox off the network at once, keeping it and its logs for forensics",
		Long: `Drop every packet from and to the sandbox, established connections included,
refuse and log all of its DNS queries, and keep its netns, VM and logs.
With --freeze its processes are stopped (exec mode) or its VM is paused.
The quarantine survives a daemon restart; lift it with "sandbox release".`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var info daemon.Info
			err := api.NewClient(g.socket).Do(cmd.Context(), http.MethodPost, api.SandboxPath(args[0], "/quarantine"), req, &info)
			if info.Quarantine != nil {
				frozen := ""
				if info.Quarantine.Frozen {
					frozen = ", frozen"
				}
				fmt.Printf("quarantined %s%s\n", args[0], frozen)
			}
			return err
		},
	}
	cmd.Flags().StringVar(&req.Reason, "reason", "", "why, recorded in the sandbox log")
	cmd.Flags().BoolVar(&req.Freeze, "freeze", false, "also stop the sandbox's processes, or pause its VM")
	return cmd
}

func newSandboxReleaseCmd(g *globalFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "release <id>",
		Short: "Lift a quarantine; the sandbox must resolve its allowlisted names again",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := api.NewClient(g.socket).Do(cmd.Context(), http.MethodDelete, api.SandboxPath(args[0], "/quarantine"), nil, nil); err != nil {
				return err
			}
			fmt.Printf("released %s\n", args[0])
			return nil
		},
	}
}

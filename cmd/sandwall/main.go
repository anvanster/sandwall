//go:build linux

// Command sandwall is the egress firewall daemon and its CLI.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/anvanster/sandwall/internal/api"
	"github.com/anvanster/sandwall/internal/daemon"
	"github.com/anvanster/sandwall/internal/fc"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

type globalFlags struct {
	socket     string
	stateDir   string
	logDir     string
	chrootBase string
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := newRootCmd().ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "sandwall:", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	g := &globalFlags{}
	root := &cobra.Command{
		Use:           "sandwall",
		Short:         "Egress firewall for AI agent sandboxes",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&g.socket, "socket", api.DefaultSocket, "daemon API socket")
	root.PersistentFlags().StringVar(&g.stateDir, "state-dir", daemon.DefaultStateDir, "daemon state directory")
	root.PersistentFlags().StringVar(&g.logDir, "log-dir", daemon.DefaultLogDir, "per-sandbox JSONL log directory")
	root.PersistentFlags().StringVar(&g.chrootBase, "chroot-base", fc.DefaultChrootBase, "jailer chroot base directory for VM mode")

	root.AddCommand(
		newDaemonCmd(g),
		newDataplaneCmd(),
		newSandboxCmd(g),
		newPolicyCmd(g),
		newVMCmd(g),
		newLogsCmd(g),
		newNukeCmd(g),
	)
	return root
}

func requireRoot() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root")
	}
	return nil
}

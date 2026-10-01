//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/anvanster/egressd/internal/api"
	"github.com/anvanster/egressd/internal/daemon"
	"github.com/anvanster/egressd/internal/flowlog"
	"github.com/anvanster/egressd/internal/metrics"
)

func newDaemonCmd(g *globalFlags) *cobra.Command {
	var (
		metricsAddr string
		upstream    string
		exempt      []string
	)
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Run the long-lived daemon (DNS proxies, log collectors, metrics, API)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := requireRoot(); err != nil {
				return err
			}
			prefixes := make([]netip.Prefix, 0, len(exempt))
			for _, e := range exempt {
				p, err := netip.ParsePrefix(e)
				if err != nil || !p.Addr().Is4() {
					return fmt.Errorf("--blocked-exempt %q: want an IPv4 CIDR", e)
				}
				prefixes = append(prefixes, p.Masked())
			}
			return runDaemon(cmd.Context(), g, metricsAddr, upstream, prefixes)
		},
	}
	cmd.Flags().StringVar(&metricsAddr, "metrics-addr", ":9464", "Prometheus listen address (empty to disable)")
	cmd.Flags().StringVar(&upstream, "upstream-dns", "", "default upstream resolver ip:port (default: first nameserver in /etc/resolv.conf)")
	cmd.Flags().StringSliceVar(&exempt, "blocked-exempt", nil, "CIDRs to carve out of the blocked ranges (testing only)")
	return cmd
}

func runDaemon(ctx context.Context, g *globalFlags, metricsAddr, upstream string, exempt []netip.Prefix) error {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if len(exempt) > 0 {
		log.Warn("blocked ranges have exemptions; do not use in production", "exempt", exempt)
	}
	m := metrics.New()
	mgr, err := daemon.New(ctx, daemon.Options{
		StateDir:        g.stateDir,
		LogDir:          g.logDir,
		BlockedExempt:   exempt,
		DefaultUpstream: upstream,
		Log:             log,
		Metrics:         m,
	})
	if err != nil {
		return err
	}
	defer mgr.Close()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errc := make(chan error, 3)

	deny := flowlog.NewDenyCollector(mgr.Sink(), mgr.SandboxForIndex,
		func(id, reason string) { m.Denied.WithLabelValues(id, reason).Inc() }, log)
	go func() { errc <- wrap("deny collector", deny.Run(ctx)) }()

	if metricsAddr != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", m.Handler())
		srv := &http.Server{Addr: metricsAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			<-ctx.Done()
			_ = srv.Close()
		}()
		go func() {
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- wrap("metrics", err)
			}
		}()
	}

	go func() { errc <- wrap("api", api.Serve(ctx, g.socket, api.NewHandler(mgr))) }()

	log.Info("egressd daemon started", "socket", g.socket, "metrics", metricsAddr, "sandboxes", len(mgr.List()))
	select {
	case <-ctx.Done():
		log.Info("shutting down; sandboxes stay in place and are restored on next start")
		return nil
	case err := <-errc:
		if err != nil {
			return err
		}
		return nil
	}
}

func wrap(what string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", what, err)
}

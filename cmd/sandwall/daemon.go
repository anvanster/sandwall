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
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/anvanster/sandwall/internal/alert"
	"github.com/anvanster/sandwall/internal/api"
	"github.com/anvanster/sandwall/internal/daemon"
	"github.com/anvanster/sandwall/internal/dnsproxy"
	"github.com/anvanster/sandwall/internal/fc"
	"github.com/anvanster/sandwall/internal/flowlog"
	"github.com/anvanster/sandwall/internal/metrics"
	"github.com/anvanster/sandwall/internal/nft"
	"github.com/anvanster/sandwall/internal/otelexport"
	"github.com/anvanster/sandwall/internal/relay"
)

func newDaemonCmd(g *globalFlags) *cobra.Command {
	var (
		metricsAddr string
		upstream    string
		exempt      []string
		paths       fc.Paths
		proxyURL    string
		proxyEnv    bool
		noProxy     string
		synthDNS    bool
		synthPool   string
		sniCheck    bool
		sniPorts    []int
		webhooks    []string
		secrets     []string
		otlpURL     string
		otlpHeaders []string
		otlpEvents  string
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
			paths.ChrootBase = g.chrootBase
			if paths.Firecracker != "" || paths.Jailer != "" {
				if err := paths.CheckUIDRange(); err != nil {
					return err
				}
			}
			for _, p := range []*string{&paths.Firecracker, &paths.Jailer} {
				if *p == "" {
					continue
				}
				abs, err := filepath.Abs(*p)
				if err != nil {
					return err
				}
				if _, err := os.Stat(abs); err != nil {
					return err
				}
				*p = abs
			}
			up, err := upstreamProxy(proxyURL, proxyEnv)
			if err != nil {
				return err
			}
			if !cmd.Flags().Changed("no-proxy") && proxyEnv {
				noProxy = envFirst("no_proxy", "NO_PROXY")
			}
			if noProxy != "" && up == nil {
				return errors.New("--no-proxy needs --upstream-proxy or --upstream-proxy-from-env")
			}
			np, notes, err := relay.ParseNoProxy(noProxy)
			if err != nil {
				return err
			}
			ports, err := sniCheckPorts(sniCheck, cmd.Flags().Changed("sni-check-ports"), sniPorts)
			if err != nil {
				return err
			}
			synth, err := syntheticPool(synthDNS, cmd.Flags().Changed("synthetic-dns-pool"), synthPool, up, np, prefixes)
			if err != nil {
				return err
			}
			eps, err := alert.ParseEndpoints(webhooks, secrets)
			if err != nil {
				return err
			}
			otlp, err := otlpConfig(otlpURL, otlpHeaders, otlpEvents)
			if err != nil {
				return err
			}
			return runDaemon(cmd.Context(), g, metricsAddr, upstream, prefixes, paths, up, np, notes, synth, sniCheck, ports, eps, otlp)
		},
	}
	cmd.Flags().StringVar(&metricsAddr, "metrics-addr", ":9464", "Prometheus listen address (empty to disable)")
	cmd.Flags().StringVar(&upstream, "upstream-dns", "", "default upstream resolver ip:port (default: first nameserver in /etc/resolv.conf)")
	cmd.Flags().StringSliceVar(&exempt, "blocked-exempt", nil, "CIDRs to carve out of the blocked ranges (testing only)")
	cmd.Flags().StringVar(&paths.Firecracker, "firecracker", "", "firecracker binary (enables vm mode)")
	cmd.Flags().StringVar(&paths.Jailer, "jailer", "", "jailer binary (enables vm mode)")
	cmd.Flags().IntVar(&paths.UIDBase, "vm-uid-base", fc.DefaultUIDBase, "VMMs run as uid/gid base+k; base+1..base+254 must be unused on the host")
	cmd.Flags().StringVar(&proxyURL, "upstream-proxy", "", "carry allowed sandbox TCP through this HTTP proxy, http://[user:pass@]host:port")
	cmd.Flags().BoolVar(&proxyEnv, "upstream-proxy-from-env", false, "take --upstream-proxy from https_proxy or http_proxy, and --no-proxy from no_proxy")
	cmd.Flags().IntSliceVar(&sniPorts, "sni-check-ports", nft.DefaultSNIPorts, "ports the SNI check covers: allowed TCP to them goes through the relay, UDP (QUIC) to DNS-learned addresses on them is rejected; list only ports where the client speaks first (TLS, HTTP)")
	cmd.Flags().BoolVar(&sniCheck, "sni-check", true, "check the TLS SNI or HTTP Host of allowed connections to ports 80 and 443 against the allowlist (--sni-check=false to forward them unchecked)")
	cmd.Flags().StringArrayVar(&webhooks, "webhook", nil, "name=URL of a webhook that policies can send alerts to (repeatable)")
	cmd.Flags().StringArrayVar(&secrets, "webhook-secret", nil, "name=file holding the HMAC-SHA256 key that signs that webhook's requests (repeatable)")
	cmd.Flags().StringVar(&otlpURL, "otlp-endpoint", "", "export events as OpenTelemetry logs to this OTLP/HTTP endpoint (base URL, /v1/logs is appended)")
	cmd.Flags().StringArrayVar(&otlpHeaders, "otlp-header", nil, "key=value header sent with OTLP requests, e.g. authorization (repeatable)")
	cmd.Flags().StringVar(&otlpEvents, "otlp-events", "all", "which events to export: all, or violations")
	cmd.Flags().StringVar(&noProxy, "no-proxy", "", "comma-separated names, IPv4 addresses and CIDRs that bypass the upstream proxy (no_proxy syntax)")
	cmd.Flags().BoolVar(&synthDNS, "synthetic-dns", false, "behind an upstream proxy whose network resolves internal names only: answer allowlisted names (except no_proxy ones) from --synthetic-dns-pool and let the proxy resolve them")
	cmd.Flags().StringVar(&synthPool, "synthetic-dns-pool", dnsproxy.DefaultSyntheticPool.String(), "IPv4 range for --synthetic-dns answers; must not be a real destination")
	return cmd
}

// sniCheckPorts validates --sni-check-ports and returns the ports sorted.
func sniCheckPorts(sniCheck, set bool, ports []int) ([]int, error) {
	if !sniCheck {
		if set {
			return nil, errors.New("--sni-check-ports needs the SNI check (drop --sni-check=false)")
		}
		return nil, nil
	}
	if len(ports) == 0 {
		return nil, errors.New("--sni-check-ports is empty; use --sni-check=false to turn the check off")
	}
	out := slices.Clone(ports)
	slices.Sort(out)
	for i, p := range out {
		switch {
		case p < 1 || p > 65535:
			return nil, fmt.Errorf("--sni-check-ports: %d is not a port", p)
		case p == 53 || p == 853:
			return nil, fmt.Errorf("--sni-check-ports: %d is DNS, which only the sandbox's DNS proxy may get", p)
		case i > 0 && out[i-1] == p:
			return nil, fmt.Errorf("--sni-check-ports: %d listed twice", p)
		}
	}
	return out, nil
}

// syntheticPool validates --synthetic-dns and its pool. The pool must not
// overlap a blocked range (the firewall would drop it), a no_proxy CIDR
// (that traffic would go direct, to nowhere) or a --blocked-exempt range.
func syntheticPool(enabled, poolSet bool, raw string, up *relay.Upstream, np relay.NoProxy, exempt []netip.Prefix) (netip.Prefix, error) {
	if !enabled {
		if poolSet {
			return netip.Prefix{}, errors.New("--synthetic-dns-pool needs --synthetic-dns")
		}
		return netip.Prefix{}, nil
	}
	if up == nil {
		return netip.Prefix{}, errors.New("--synthetic-dns needs --upstream-proxy or --upstream-proxy-from-env: only the proxy can resolve the names")
	}
	pool, err := netip.ParsePrefix(raw)
	if err != nil || !pool.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("--synthetic-dns-pool %q: want an IPv4 CIDR", raw)
	}
	pool = pool.Masked()
	if pool.Bits() > 24 {
		return netip.Prefix{}, fmt.Errorf("--synthetic-dns-pool %s: too small, use /24 or larger", pool)
	}
	for _, r := range append(append(append([]netip.Prefix(nil), nft.DefaultBlockedRanges...), np.CIDRs...), exempt...) {
		if pool.Overlaps(r) {
			return netip.Prefix{}, fmt.Errorf("--synthetic-dns-pool %s overlaps %s", pool, r)
		}
	}
	return pool, nil
}

// upstreamProxy resolves the proxy flags. With --upstream-proxy-from-env,
// https_proxy wins over http_proxy, lower case over upper case.
func upstreamProxy(raw string, fromEnv bool) (*relay.Upstream, error) {
	if fromEnv {
		if raw != "" {
			return nil, errors.New("use either --upstream-proxy or --upstream-proxy-from-env")
		}
		raw = envFirst("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY")
		if raw == "" {
			return nil, errors.New("--upstream-proxy-from-env: no https_proxy or http_proxy in the environment (sudo drops it unless preserved)")
		}
	}
	if raw == "" {
		return nil, nil
	}
	return relay.ParseUpstream(raw)
}

// otlpConfig validates the OTLP flags; nil means no export.
func otlpConfig(endpoint string, headers []string, events string) (*otelexport.Config, error) {
	if endpoint == "" {
		if len(headers) > 0 || events != "all" {
			return nil, errors.New("--otlp-header and --otlp-events need --otlp-endpoint")
		}
		return nil, nil
	}
	if _, err := otelexport.LogsURL(endpoint); err != nil {
		return nil, err
	}
	cfg := &otelexport.Config{Endpoint: endpoint, Headers: map[string]string{}}
	switch events {
	case "all":
	case "violations":
		cfg.ViolationsOnly = true
	default:
		return nil, fmt.Errorf("--otlp-events %q: want all or violations", events)
	}
	for _, h := range headers {
		k, v, ok := strings.Cut(h, "=")
		if !ok || strings.TrimSpace(k) == "" {
			return nil, fmt.Errorf("--otlp-header %q: want key=value", h)
		}
		cfg.Headers[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return cfg, nil
}

// envFirst returns the first non-empty environment variable of names.
func envFirst(names ...string) string {
	for _, n := range names {
		if v := os.Getenv(n); v != "" {
			return v
		}
	}
	return ""
}

func runDaemon(ctx context.Context, g *globalFlags, metricsAddr, upstream string, exempt []netip.Prefix, paths fc.Paths,
	proxy *relay.Upstream, noProxy relay.NoProxy, noProxyNotes []string, synthetic netip.Prefix, sniCheck bool, sniPorts []int, webhooks []alert.Endpoint, otlp *otelexport.Config) error {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if len(exempt) > 0 {
		log.Warn("blocked ranges have exemptions; do not use in production", "exempt", exempt)
	}
	if proxy != nil {
		log.Info("allowed sandbox TCP goes through the upstream proxy", "proxy", proxy.String(),
			"no_proxy_names", noProxy.Patterns, "no_proxy_cidrs", noProxy.CIDRs)
		for _, n := range noProxyNotes {
			log.Warn("no_proxy entry", "note", n)
		}
		if sniCheck && !slices.Equal(sniPorts, nft.DefaultSNIPorts) {
			log.Warn("--sni-check-ports has no effect behind an upstream proxy: all allowed TCP goes through the relay and other traffic is rejected")
		}
		if synthetic.IsValid() {
			log.Info("synthetic DNS: allowlisted names are answered from a pool and resolved by the proxy", "pool", synthetic)
		}
	} else if sniCheck {
		log.Info("SNI/Host check on", "ports", sniPorts)
	}
	m := metrics.New()
	mgr, err := daemon.New(ctx, daemon.Options{
		StateDir:        g.stateDir,
		LogDir:          g.logDir,
		BlockedExempt:   exempt,
		DefaultUpstream: upstream,
		UpstreamProxy:   proxy,
		NoProxy:         noProxy,
		SyntheticDNS:    synthetic,
		SNICheck:        sniCheck,
		SNIPorts:        sniPorts,
		Webhooks:        webhooks,
		OTLP:            otlp,
		FC:              paths,
		Log:             log,
		Metrics:         m,
	})
	if err != nil {
		return err
	}
	defer mgr.Close()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errc := make(chan error, 4)

	deny := flowlog.NewDenyCollector(mgr.Sink(), mgr.SandboxForIndex,
		func(id, reason string, logged bool) {
			m.Denied.WithLabelValues(id, reason).Inc()
			if logged {
				// A logged (de-duplicated) deny approximates one denied flow attempt.
				m.Flows.WithLabelValues(id, "deny").Inc()
			}
		}, log)
	go func() { errc <- wrap("deny collector", deny.Run(ctx)) }()

	flows := flowlog.NewFlowCollector(mgr.Sink(), mgr,
		func(id string, out, in uint64) {
			m.Flows.WithLabelValues(id, "allow").Inc()
			m.Bytes.WithLabelValues(id, "out").Add(float64(out))
			m.Bytes.WithLabelValues(id, "in").Add(float64(in))
		}, log)
	go func() { errc <- wrap("flow collector", flows.Run(ctx)) }()

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

	log.Info("sandwall daemon started", "socket", g.socket, "metrics", metricsAddr, "sandboxes", len(mgr.List()))
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

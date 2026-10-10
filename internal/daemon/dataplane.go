//go:build linux

package daemon

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"time"

	"github.com/anvanster/sandwall/internal/addressing"
	"github.com/anvanster/sandwall/internal/dataplane"
	"github.com/anvanster/sandwall/internal/flowlog"
	"github.com/anvanster/sandwall/internal/metrics"
	"github.com/anvanster/sandwall/internal/policy"
)

// Each sandbox's DNS proxy and relay run in a data plane process of their
// own (internal/dataplane), so relayed connections and sandbox DNS outlive a
// daemon restart or crash. The daemon starts or adopts it, reapplies policy
// and quarantine to it, restarts it if it dies, and tails the sandbox log
// for its events.

const (
	superviseInterval = 2 * time.Second
	controlTimeout    = 2 * time.Second
	// queryTimeout bounds the lookups on hot paths (flow attribution,
	// scrapes), so a stuck data plane cannot stall them.
	queryTimeout = 500 * time.Millisecond
)

func (mgr *Manager) dataplaneConfig(s *sandbox) dataplane.Config {
	cfg := dataplane.Config{
		Version:      dataplane.ProtocolVersion,
		SandboxID:    s.rec.ID,
		Index:        s.addr.Index,
		LogDir:       mgr.opts.LogDir,
		DNSStatePath: mgr.dnsStatePath(s.rec.ID),
		Socket:       s.dpFiles.Socket,
		PIDFile:      s.dpFiles.PID,
		DNSListen:    netip.AddrPortFrom(s.addr.HostAddr, 53),
		DNS:          mgr.proxySettings(s.policy),
		Quarantined:  s.rec.Quarantine != nil,
	}
	if mgr.relayed() {
		cfg.Relay = &dataplane.RelayConfig{
			Listen:    netip.AddrPortFrom(s.addr.HostAddr, addressing.RelayPort),
			Synthetic: mgr.syntheticPool(),
			Settings:  relaySettings(s.policy),
		}
		if mgr.opts.UpstreamProxy != nil {
			cfg.Relay.Upstream = mgr.opts.UpstreamProxy.URL().String()
			if mgr.opts.SNICheck {
				cfg.Relay.DirectListen = netip.AddrPortFrom(s.addr.HostAddr, addressing.RelayDirectPort)
			}
		}
	}
	return cfg
}

// dataplanePolicy is a hot reload for s with pol: settings plus the ruleset
// to re-render once the allow sets are refilled from the DNS cache.
func (mgr *Manager) dataplanePolicy(s *sandbox, pol *policy.Policy) dataplane.Policy {
	rules := mgr.sandboxRules(s.addr.Index, pol, nil, nil, false)
	rules.Quarantined = s.rec.Quarantine != nil
	return dataplane.Policy{DNS: mgr.proxySettings(pol), Relay: relaySettings(pol), Rules: rules}
}

// writeDataplaneConfig keeps the config file current, so a restarted data
// plane comes back with the sandbox's present settings and quarantine.
func (mgr *Manager) writeDataplaneConfig(s *sandbox) error {
	return dataplane.WriteConfig(s.dpFiles.Config, mgr.dataplaneConfig(s))
}

// startDataplane adopts the sandbox's running data plane when restoring and
// its structural config is unchanged, reapplying policy and quarantine;
// otherwise it (re)starts it. Adopting keeps its relayed connections.
func (mgr *Manager) startDataplane(ctx context.Context, s *sandbox, restoring bool) error {
	cfg := mgr.dataplaneConfig(s)
	if restoring {
		if _, ok := dataplane.Running(s.dpFiles); ok {
			cctx, cancel := context.WithTimeout(ctx, controlTimeout)
			st, err := s.dp.Status(cctx)
			cancel()
			if err == nil && st.Version == dataplane.ProtocolVersion && st.Hash == cfg.Hash() {
				if err := dataplane.WriteConfig(s.dpFiles.Config, cfg); err != nil {
					return err
				}
				if err := s.dp.SetQuarantined(ctx, cfg.Quarantined); err != nil {
					return err
				}
				if err := s.dp.ApplyPolicy(ctx, mgr.dataplanePolicy(s, s.policy)); err != nil {
					return err
				}
				mgr.log.Info("adopted data plane", "id", s.rec.ID, "pid", st.PID)
				return nil
			}
			mgr.log.Warn("restarting data plane: its configuration changed; its relayed connections end",
				"id", s.rec.ID, "status_err", err)
		}
	}
	if err := dataplane.Stop(s.dpFiles); err != nil {
		return err
	}
	if err := dataplane.WriteConfig(s.dpFiles.Config, cfg); err != nil {
		return err
	}
	pid, err := dataplane.Start(ctx, mgr.exe, s.dpFiles, mgr.dataplaneLog(s.rec.ID))
	if err != nil {
		return fmt.Errorf("data plane for %s: %w", s.rec.ID, err)
	}
	mgr.log.Info("started data plane", "id", s.rec.ID, "pid", pid)
	return nil
}

func (mgr *Manager) dataplaneLog(id string) string {
	return filepath.Join(mgr.opts.LogDir, id+".dataplane.log")
}

// stopDataplane ends a sandbox's data plane and its event follower.
func (mgr *Manager) stopDataplane(s *sandbox) error {
	s.stopFollow()
	return dataplane.Stop(s.dpFiles)
}

// followEvents feeds the data plane's events (dns, relay) from the sandbox
// log to the watchdog, alerts and OTel export; the daemon's own events
// reach them directly through its sink.
func (mgr *Manager) followEvents(id string) context.CancelFunc {
	ctx, cancel := context.WithCancel(mgr.bg)
	go flowlog.Follow(ctx, flowlog.Path(mgr.opts.LogDir, id), func(ev flowlog.Event) {
		if ev.SandboxID != id || (ev.Type != flowlog.TypeDNS && ev.Type != flowlog.TypeRelay) {
			return
		}
		if ev.Type == flowlog.TypeRelay && ev.Verdict == "deny" && ev.Reason != "" {
			// Relay refusals count with the firewall's denials.
			mgr.m.Denied.WithLabelValues(id, ev.Reason).Inc()
		}
		mgr.observe(ev)
	})
	return cancel
}

// supervise restarts data planes that died, until the daemon closes.
func (mgr *Manager) supervise() {
	t := time.NewTicker(superviseInterval)
	defer t.Stop()
	for {
		select {
		case <-mgr.bg.Done():
			return
		case <-t.C:
		}
		mgr.mu.Lock()
		all := make([]*sandbox, 0, len(mgr.byID))
		for _, s := range mgr.byID {
			all = append(all, s)
		}
		mgr.mu.Unlock()
		for _, s := range all {
			if _, ok := dataplane.Running(s.dpFiles); ok {
				continue
			}
			mgr.restartDataplane(s)
		}
	}
}

func (mgr *Manager) restartDataplane(s *sandbox) {
	mgr.opMu.Lock()
	defer mgr.opMu.Unlock()
	if cur, err := mgr.lookup(s.rec.ID); err != nil || cur != s {
		return // destroyed meanwhile
	}
	if _, ok := dataplane.Running(s.dpFiles); ok {
		return
	}
	mgr.log.Warn("data plane is not running; restarting it", "id", s.rec.ID)
	ctx, cancel := context.WithTimeout(mgr.bg, 30*time.Second)
	defer cancel()
	if err := mgr.startDataplane(ctx, s, false); err != nil {
		mgr.log.Error("restarting data plane", "id", s.rec.ID, "err", err)
	}
}

// dataplaneCounters reads every data plane's counters for a scrape.
func (mgr *Manager) dataplaneCounters() []metrics.DataplaneCounters {
	mgr.mu.Lock()
	all := make([]*sandbox, 0, len(mgr.byID))
	for _, s := range mgr.byID {
		all = append(all, s)
	}
	mgr.mu.Unlock()
	out := make([]metrics.DataplaneCounters, 0, len(all))
	for _, s := range all {
		ctx, cancel := context.WithTimeout(mgr.bg, queryTimeout)
		c, err := s.dp.Counters(ctx)
		cancel()
		if err != nil {
			continue
		}
		out = append(out, metrics.DataplaneCounters{Sandbox: s.rec.ID, DNS: c.DNS, Relay: c.Relay})
	}
	return out
}

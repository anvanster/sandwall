//go:build linux

package dataplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"sync"

	"github.com/anvanster/sandwall/internal/dnsproxy"
	"github.com/anvanster/sandwall/internal/flowlog"
	"github.com/anvanster/sandwall/internal/nft"
	"github.com/anvanster/sandwall/internal/relay"
)

// Hooks replace the kernel-facing parts, for tests.
type Hooks struct {
	Insert   dnsproxy.Inserter
	ApplyNFT func(ctx context.Context, script string) error
	OrigDst  func(*net.TCPConn) (netip.AddrPort, error)
}

type counters struct {
	mu    sync.Mutex
	dns   map[string]float64
	relay map[string]float64
}

func (c *counters) snapshot() Counters {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := Counters{DNS: map[string]float64{}, Relay: map[string]float64{}}
	for k, v := range c.dns {
		out.DNS[k] = v
	}
	for k, v := range c.relay {
		out.Relay[k] = v
	}
	return out
}

// Run serves a sandbox's DNS proxy, relay and control socket until ctx is
// cancelled, then stops them (closing relayed connections) and saves the
// DNS cache. The daemon cancels it only when it destroys the sandbox or has
// to restart the data plane.
func Run(ctx context.Context, cfg Config, log *slog.Logger, hooks Hooks) error {
	if hooks.Insert == nil {
		hooks.Insert = nft.InsertAllow
	}
	if hooks.ApplyNFT == nil {
		hooks.ApplyNFT = nft.Apply
	}
	sink, err := flowlog.NewSink(cfg.LogDir)
	if err != nil {
		return err
	}
	if err := sink.Open(cfg.SandboxID); err != nil {
		return err
	}
	defer sink.CloseAll()

	cnt := &counters{dns: map[string]float64{}, relay: map[string]float64{}}
	proxy := dnsproxy.New(dnsproxy.Config{
		SandboxID: cfg.SandboxID,
		Index:     cfg.Index,
		Listen:    cfg.DNSListen,
		Insert:    hooks.Insert,
		Sink:      sink,
		CountQuery: func(_, verdict string) {
			cnt.mu.Lock()
			cnt.dns[verdict]++
			cnt.mu.Unlock()
		},
		StatePath: cfg.DNSStatePath,
	}, cfg.DNS)
	if cfg.Quarantined {
		proxy.SetQuarantined(true)
	}
	if err := proxy.Start(); err != nil {
		return err
	}
	defer proxy.Stop()

	var relays []*relay.Relay
	if cfg.Relay != nil {
		var up *relay.Upstream
		if cfg.Relay.Upstream != "" {
			if up, err = relay.ParseUpstream(cfg.Relay.Upstream); err != nil {
				return err
			}
		}
		count := func(_, result, _ string) {
			cnt.mu.Lock()
			cnt.relay[result]++
			cnt.mu.Unlock()
		}
		start := func(listen netip.AddrPort, up *relay.Upstream, synthetic netip.Prefix) error {
			rl := relay.New(relay.Config{
				SandboxID: cfg.SandboxID, Listen: listen, Upstream: up, Domain: proxy.Domain,
				Synthetic: synthetic, Sink: sink, Count: count, Log: log, OrigDst: hooks.OrigDst,
			}, cfg.Relay.Settings)
			if cfg.Quarantined {
				rl.SetQuarantined(true)
			}
			if err := rl.Start(); err != nil {
				return err
			}
			relays = append(relays, rl)
			return nil
		}
		defer func() {
			for _, rl := range relays {
				rl.Stop()
			}
		}()
		if err := start(cfg.Relay.Listen, up, cfg.Relay.Synthetic); err != nil {
			return err
		}
		// no_proxy destinations are dialed directly; they never get synthetic
		// addresses, as no_proxy names are resolved for real.
		if cfg.Relay.DirectListen.IsValid() {
			if err := start(cfg.Relay.DirectListen, nil, netip.Prefix{}); err != nil {
				return err
			}
		}
	}

	srv := &server{cfg: cfg, proxy: proxy, relays: relays, counters: cnt, apply: hooks.ApplyNFT, log: log, quarantined: cfg.Quarantined}
	ln, err := listenControl(cfg.Socket)
	if err != nil {
		return err
	}
	defer os.Remove(cfg.Socket)
	httpSrv := &http.Server{Handler: srv.routes()}
	go func() { _ = httpSrv.Serve(ln) }()
	defer httpSrv.Close()

	if cfg.PIDFile != "" {
		if err := os.WriteFile(cfg.PIDFile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
			return err
		}
		defer os.Remove(cfg.PIDFile)
	}
	log.Info("data plane running", "sandbox", cfg.SandboxID, "dns", cfg.DNSListen, "relay", cfg.Relay != nil)
	<-ctx.Done()
	log.Info("data plane stopping", "sandbox", cfg.SandboxID)
	return nil
}

func listenControl(path string) (net.Listener, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

type server struct {
	cfg      Config
	proxy    *dnsproxy.Proxy
	relays   []*relay.Relay
	counters *counters
	apply    func(ctx context.Context, script string) error
	log      *slog.Logger

	mu          sync.Mutex // serializes policy and quarantine changes
	policy      *Policy    // the last applied policy, for rolling back
	quarantined bool
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, Status{Version: ProtocolVersion, PID: os.Getpid(), Hash: s.cfg.Hash()})
	})
	mux.HandleFunc("GET /v1/counters", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, s.counters.snapshot())
	})
	mux.HandleFunc("GET /v1/domain", func(w http.ResponseWriter, r *http.Request) {
		ip, err := netip.ParseAddr(r.URL.Query().Get("ip"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"domain": s.proxy.Domain(ip)})
	})
	mux.HandleFunc("PUT /v1/policy", func(w http.ResponseWriter, r *http.Request) {
		var p Policy
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.applyPolicy(r.Context(), p); err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("PUT /v1/quarantine", func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			Quarantined bool `json:"quarantined"`
		}
		if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.setQuarantined(q.Quarantined)
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

// applyPolicy swaps in new settings and re-renders the sandbox's ruleset with
// the allow sets refilled from the DNS cache, in one nft transaction while
// no DNS answer can insert. On failure the old DNS settings are put back;
// the nft transaction was atomic.
func (s *server) applyPolicy(ctx context.Context, p Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.proxy.Reload(p.DNS, func(live, direct []nft.AllowEntry) error {
		rules := p.Rules
		rules.Allowed, rules.Direct = live, direct
		script, err := nft.RenderSandbox(rules)
		if err != nil {
			return err
		}
		return s.apply(ctx, script)
	})
	if err != nil {
		old := s.cfg.DNS
		if s.policy != nil {
			old = s.policy.DNS
		}
		_ = s.proxy.Reload(old, func(_, _ []nft.AllowEntry) error { return nil })
		return fmt.Errorf("policy reload: %w", err)
	}
	for _, rl := range s.relays {
		rl.Reload(p.Relay)
	}
	s.policy = &p
	return nil
}

// setQuarantined acts only on a change: releasing also forgets the DNS
// cache, which must not happen when an adopting daemon merely restates the
// current state.
func (s *server) setQuarantined(q bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if q == s.quarantined {
		return
	}
	s.quarantined = q
	s.proxy.SetQuarantined(q)
	for _, rl := range s.relays {
		rl.SetQuarantined(q)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

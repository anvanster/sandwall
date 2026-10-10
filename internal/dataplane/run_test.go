//go:build linux

package dataplane

import (
	"context"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anvanster/sandwall/internal/dnsproxy"
	"github.com/anvanster/sandwall/internal/nft"
)

func TestControlAPI(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Version: ProtocolVersion, SandboxID: "t", Index: 4, LogDir: dir,
		DNSStatePath: filepath.Join(dir, "dns.json"),
		Socket:       filepath.Join(dir, "4.sock"), PIDFile: filepath.Join(dir, "4.pid"),
		DNSListen: netip.MustParseAddrPort("127.0.0.1:0"),
		DNS:       dnsproxy.Settings{AllowDomains: []string{"pypi.org"}, QPS: 10},
	}
	// A cached answer, as a previous run would have left it.
	if err := os.WriteFile(cfg.DNSStatePath, []byte(`{"version":1,"entries":[{"name":"pypi.org","addr":"151.101.0.223","expires":"`+
		time.Now().Add(time.Minute).Format(time.RFC3339Nano)+`"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var (
		mu      sync.Mutex
		scripts []string
	)
	hooks := Hooks{
		Insert: func(context.Context, int, []nft.AllowEntry, bool) error { return nil },
		ApplyNFT: func(_ context.Context, script string) error {
			mu.Lock()
			scripts = append(scripts, script)
			mu.Unlock()
			return nil
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, slog.Default(), hooks) }()

	c := NewClient(cfg.Socket)
	var st Status
	for i := 0; ; i++ {
		var err error
		if st, err = c.Status(context.Background()); err == nil {
			break
		}
		if i > 100 {
			t.Fatalf("control socket never came up: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if st.Hash != cfg.Hash() || st.PID != os.Getpid() || st.Version != ProtocolVersion {
		t.Errorf("status %+v", st)
	}
	if fi, err := os.Stat(cfg.Socket); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("socket mode %v, %v", fi.Mode(), err)
	}

	ctx2 := context.Background()
	if d, err := c.Domain(ctx2, netip.MustParseAddr("151.101.0.223")); err != nil || d != "pypi.org" {
		t.Errorf("domain from the persisted cache = %q, %v", d, err)
	}

	// Restating "not quarantined" (what an adopting daemon does) must not
	// forget the cache, as a real release would.
	if err := c.SetQuarantined(ctx2, false); err != nil {
		t.Fatal(err)
	}
	if d, _ := c.Domain(ctx2, netip.MustParseAddr("151.101.0.223")); d != "pypi.org" {
		t.Error("restating the current quarantine state cleared the DNS cache")
	}

	// A reload re-renders the ruleset with the cached address refilled.
	rules := nft.SandboxConfig{Index: 4, MaxConns: 64, NewConnsPerSec: 20}
	err := c.ApplyPolicy(ctx2, Policy{DNS: dnsproxy.Settings{AllowDomains: []string{"pypi.org", "github.com"}, QPS: 10}, Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := strings.Join(scripts, "\n")
	mu.Unlock()
	if !strings.Contains(got, "add element inet sandwall allow_4 { 151.101.0.223") {
		t.Errorf("reload did not refill allow_4 from the cache:\n%s", got)
	}
	// A failing reload is reported and leaves the old settings in place.
	if err := c.ApplyPolicy(ctx2, Policy{DNS: dnsproxy.Settings{QPS: 10}, Rules: nft.SandboxConfig{Index: 0}}); err == nil {
		t.Error("an invalid ruleset was accepted")
	}

	if _, err := c.Counters(ctx2); err != nil {
		t.Error(err)
	}
	if err := c.SetQuarantined(ctx2, true); err != nil {
		t.Fatal(err)
	}
	if err := c.SetQuarantined(ctx2, false); err != nil {
		t.Fatal(err)
	}
	if d, _ := c.Domain(ctx2, netip.MustParseAddr("151.101.0.223")); d != "" {
		t.Error("a real release kept the DNS cache")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}
	for _, p := range []string{cfg.Socket, cfg.PIDFile} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s left behind", p)
		}
	}
}

func TestHashIgnoresSettings(t *testing.T) {
	a := Config{Version: 1, SandboxID: "x", Index: 2, DNS: dnsproxy.Settings{QPS: 10}}
	b := a
	b.DNS.AllowDomains, b.Quarantined = []string{"pypi.org"}, true
	if a.Hash() != b.Hash() {
		t.Error("settings changed the structural hash")
	}
	c := a
	c.Relay = &RelayConfig{Upstream: "http://proxy:3128"}
	if a.Hash() == c.Hash() {
		t.Error("adding a relay did not change the hash")
	}
}

package nft

import (
	"flag"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite golden files")

func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -update to create)", err)
	}
	if string(want) != got {
		t.Errorf("%s mismatch (run go test -update to accept)\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

func TestRenderBase(t *testing.T) {
	golden(t, "base.nft", RenderBase(BaseConfig{
		BlockedRanges: DefaultBlockedRanges,
		BlockedExempt: []netip.Prefix{netip.MustParsePrefix("10.99.0.0/24")},
	}))
}

func TestRenderSandbox(t *testing.T) {
	got, err := RenderSandbox(SandboxConfig{
		Index:          7,
		AllowCIDRs:     []string{"203.0.113.0/24", "198.51.100.7/32"},
		MaxConns:       64,
		NewConnsPerSec: 20,
		Allowed: []AllowEntry{
			{Addr: netip.MustParseAddr("151.101.0.223"), Timeout: 300 * time.Second},
			{Addr: netip.MustParseAddr("140.82.112.3"), Timeout: 60 * time.Second},
			{Addr: netip.MustParseAddr("151.101.0.223"), Timeout: 120 * time.Second},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "sandbox.nft", got)
}

func TestRenderBaseProxy(t *testing.T) {
	golden(t, "base-proxy.nft", RenderBase(BaseConfig{BlockedRanges: DefaultBlockedRanges, Proxy: true}))
}

func TestRenderSandboxProxied(t *testing.T) {
	got, err := RenderSandbox(SandboxConfig{
		Index: 7, AllowCIDRs: []string{"203.0.113.0/24"}, MaxConns: 64, NewConnsPerSec: 20, Proxied: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "sandbox-proxy.nft", got)
}

func TestRenderSandboxRejectsBadInput(t *testing.T) {
	if _, err := RenderSandbox(SandboxConfig{Index: 0, MaxConns: 1, NewConnsPerSec: 1}); err == nil {
		t.Error("index 0 accepted")
	}
	if _, err := RenderSandbox(SandboxConfig{Index: 1, MaxConns: 0, NewConnsPerSec: 1}); err == nil {
		t.Error("zero max_conns accepted")
	}
	if _, err := RenderSandbox(SandboxConfig{Index: 1, MaxConns: 1, NewConnsPerSec: 1, AllowCIDRs: []string{"nope"}}); err == nil {
		t.Error("bad CIDR accepted")
	}
}

func TestRenderRemoveSandbox(t *testing.T) {
	got, err := RenderRemoveSandbox(7)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "remove.nft", got)
}

func TestRenderAllow(t *testing.T) {
	if RenderAllow(3, nil) != "" {
		t.Error("empty allow should render nothing")
	}
	golden(t, "allow.nft", RenderAllow(3, []AllowEntry{
		{Addr: netip.MustParseAddr("8.8.4.4"), Timeout: 90 * time.Second},
		{Addr: netip.MustParseAddr("1.1.1.1"), Timeout: 500 * time.Millisecond},
	}))
}

func TestLogPrefixRoundTrip(t *testing.T) {
	k, reason, ok := ParseLogPrefix(LogPrefix(42, ReasonDNSBypass))
	if !ok || k != 42 || reason != ReasonDNSBypass {
		t.Errorf("round trip = %d %q %v", k, reason, ok)
	}
	for _, bad := range []string{"", "foo:1:x ", "egressd:", "egressd:x:y ", "egressd:1: "} {
		if _, _, ok := ParseLogPrefix(bad); ok {
			t.Errorf("ParseLogPrefix(%q) accepted", bad)
		}
	}
}

func TestRenderVMNetns(t *testing.T) {
	got, err := RenderVMNetns(7)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "vm-netns.nft", got)
}

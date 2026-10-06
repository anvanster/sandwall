package dnsproxy

import (
	"net/netip"
	"testing"
	"time"

	"github.com/anvanster/sandwall/internal/nft"
	"github.com/miekg/dns"
)

func synthAnswer(t *testing.T, p *Proxy, name string) netip.Addr {
	t.Helper()
	resp, ev := p.handle(query(name, dns.TypeA), "udp")
	if resp.Rcode != dns.RcodeSuccess || ev.Reason != ReasonSynthetic || len(resp.Answer) != 1 {
		t.Fatalf("%s: rcode %d reason %q answers %v", name, resp.Rcode, ev.Reason, resp.Answer)
	}
	a := resp.Answer[0].(*dns.A)
	if a.Hdr.Ttl != uint32(SyntheticTTL/time.Second) {
		t.Errorf("%s: TTL %d", name, a.Hdr.Ttl)
	}
	addr, _ := netip.AddrFromSlice(a.A.To4())
	return addr
}

func TestSyntheticAnswersNeverQueryUpstream(t *testing.T) {
	up, n := fakeUpstream(t)
	pool := netip.MustParsePrefix("198.18.0.0/24")
	p, rec := newTestProxy(t, Settings{
		AllowDomains: []string{"pypi.org", "files.pythonhosted.org", "git.corp.example"},
		Direct:       []string{"git.corp.example"},
		QPS:          100, Upstream: up, Synthetic: pool,
	})

	a := synthAnswer(t, p, "pypi.org")
	b := synthAnswer(t, p, "files.pythonhosted.org")
	if !pool.Contains(a) || !pool.Contains(b) || a == b {
		t.Errorf("addresses %s, %s", a, b)
	}
	if a == pool.Addr() {
		t.Errorf("handed out the network address %s", a)
	}
	if again := synthAnswer(t, p, "PyPI.org."); again != a {
		t.Errorf("same name got %s, then %s", a, again)
	}
	if d := p.Domain(a); d != "pypi.org" {
		t.Errorf("Domain(%s) = %q", a, d)
	}
	if n.Load() != 0 {
		t.Errorf("upstream saw %d queries for synthetic names", n.Load())
	}
	for _, e := range rec.entries {
		if !pool.Contains(e.Addr) || e.Timeout != SyntheticTTL {
			t.Errorf("allow-set entry %+v", e)
		}
	}

	// Other types get an empty answer, still without asking upstream.
	if resp, ev := p.handle(query("pypi.org", dns.TypeTXT), "udp"); resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 || ev.Reason != ReasonSynthetic {
		t.Errorf("TXT: rcode %d answers %d reason %q", resp.Rcode, len(resp.Answer), ev.Reason)
	}
	// Names that are not allowlisted are still refused locally.
	if resp, _ := p.handle(query("evil.test", dns.TypeA), "udp"); resp.Rcode != dns.RcodeRefused {
		t.Errorf("evil.test: rcode %d", resp.Rcode)
	}
	if n.Load() != 0 {
		t.Errorf("upstream saw %d queries", n.Load())
	}

	// no_proxy names are resolved for real: they go out direct.
	resp, ev := p.handle(query("git.corp.example", dns.TypeA), "udp")
	if resp.Rcode != dns.RcodeSuccess || ev.Reason == ReasonSynthetic || n.Load() != 1 {
		t.Errorf("no_proxy name: rcode %d reason %q upstream queries %d", resp.Rcode, ev.Reason, n.Load())
	}
	if len(rec.direct) == 0 || pool.Contains(rec.direct[0].Addr) {
		t.Errorf("no_proxy name not inserted as direct: %+v", rec.direct)
	}
}

func TestSyntheticReloadKeepsMappings(t *testing.T) {
	pool := netip.MustParsePrefix("198.18.0.0/24")
	p, _ := newTestProxy(t, Settings{AllowDomains: []string{"pypi.org", "github.com"}, QPS: 100, Synthetic: pool})
	a := synthAnswer(t, p, "pypi.org")
	synthAnswer(t, p, "github.com")
	var live []nft.AllowEntry
	err := p.Reload(Settings{AllowDomains: []string{"pypi.org"}, QPS: 100, Synthetic: pool}, func(allowed, _ []nft.AllowEntry) error {
		live = allowed
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != 1 || live[0].Addr != a {
		t.Errorf("repopulated %+v, want only pypi.org's %s", live, a)
	}
	if again := synthAnswer(t, p, "pypi.org"); again != a {
		t.Errorf("mapping changed across reload: %s -> %s", a, again)
	}
}

func TestSyntheticPoolExhaustionAndReuse(t *testing.T) {
	pool := netip.MustParsePrefix("198.18.0.0/30") // two usable addresses
	p, _ := newTestProxy(t, Settings{AllowDomains: []string{"*.example.com"}, QPS: 100, Synthetic: pool})
	got := map[netip.Addr]bool{synthAnswer(t, p, "a.example.com"): true, synthAnswer(t, p, "b.example.com"): true}
	for a := range got {
		if a == netip.MustParseAddr("198.18.0.0") || a == netip.MustParseAddr("198.18.0.3") {
			t.Errorf("handed out the first or last address %s", a)
		}
	}
	if len(got) != 2 {
		t.Fatalf("two names share an address: %v", got)
	}
	resp, ev := p.handle(query("c.example.com", dns.TypeA), "udp")
	if resp.Rcode != dns.RcodeServerFailure || ev.Verdict != VerdictError {
		t.Errorf("exhausted pool: rcode %d verdict %q", resp.Rcode, ev.Verdict)
	}
	// Once the mappings expire, their addresses are handed out again.
	p.setMu.Lock()
	reused, err := p.allocate(pool, time.Now().Add(SyntheticTTL+time.Second))
	p.setMu.Unlock()
	if err != nil || !got[reused] {
		t.Errorf("after expiry allocate = %s, %v", reused, err)
	}
}

func TestSyntheticRefusedWhileQuarantined(t *testing.T) {
	p, rec := newTestProxy(t, Settings{AllowDomains: []string{"pypi.org"}, QPS: 100, Synthetic: DefaultSyntheticPool})
	p.SetQuarantined(true)
	if resp, _ := p.handle(query("pypi.org", dns.TypeA), "udp"); resp.Rcode != dns.RcodeRefused {
		t.Errorf("rcode %d", resp.Rcode)
	}
	if len(rec.entries) != 0 {
		t.Errorf("inserted %+v while quarantined", rec.entries)
	}
}

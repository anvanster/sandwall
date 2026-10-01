package dnsproxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/anvanster/egressd/internal/flowlog"
	"github.com/anvanster/egressd/internal/nft"
)

// fakeUpstream answers every A query with two records and a CNAME, plus an
// AAAA record that the proxy must strip, all with a long TTL.
func fakeUpstream(t *testing.T) (addr string, queries *atomic.Int32) {
	t.Helper()
	queries = new(atomic.Int32)
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		queries.Add(1)
		m := new(dns.Msg)
		m.SetReply(r)
		name := r.Question[0].Name
		cname, _ := dns.NewRR(name + " 3600 IN CNAME edge.cdn.test.")
		a1, _ := dns.NewRR("edge.cdn.test. 3600 IN A 192.0.2.10")
		a2, _ := dns.NewRR("edge.cdn.test. 30 IN A 192.0.2.11")
		aaaa, _ := dns.NewRR("edge.cdn.test. 3600 IN AAAA 2001:db8::1")
		m.Answer = []dns.RR{cname, a1, a2, aaaa}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String(), queries
}

type recorder struct {
	mu      sync.Mutex
	entries []nft.AllowEntry
	direct  []nft.AllowEntry
	fail    bool
}

func (r *recorder) insert(_ context.Context, k int, e []nft.AllowEntry, direct bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail {
		return errors.New("nft unavailable")
	}
	r.entries = append(r.entries, e...)
	if direct {
		r.direct = append(r.direct, e...)
	}
	return nil
}

func newTestProxy(t *testing.T, s Settings) (*Proxy, *recorder) {
	t.Helper()
	sink, err := flowlog.NewSink(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	p := New(Config{SandboxID: "t", Index: 1, Insert: rec.insert, Sink: sink}, s)
	return p, rec
}

func query(name string, qtype uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	return m
}

func TestAllowedQueryInsertsAndClamps(t *testing.T) {
	up, n := fakeUpstream(t)
	p, rec := newTestProxy(t, Settings{AllowDomains: []string{"pypi.org"}, QPS: 50, Upstream: up})

	resp, ev := p.handle(query("PyPI.org", dns.TypeA), "udp")
	if resp.Rcode != dns.RcodeSuccess || ev.Verdict != VerdictAllow {
		t.Fatalf("rcode %d verdict %q reason %q", resp.Rcode, ev.Verdict, ev.Reason)
	}
	if n.Load() != 1 {
		t.Errorf("upstream queries = %d", n.Load())
	}
	for _, rr := range resp.Answer {
		if rr.Header().Rrtype == dns.TypeAAAA {
			t.Error("AAAA record not stripped")
		}
		if rr.Header().Ttl > MaxTTL {
			t.Errorf("TTL %d not clamped", rr.Header().Ttl)
		}
	}
	want := map[string]time.Duration{"192.0.2.10": 300 * time.Second, "192.0.2.11": MinSetTimeout}
	if len(rec.entries) != 2 {
		t.Fatalf("inserted %v", rec.entries)
	}
	for _, e := range rec.entries {
		if want[e.Addr.String()] != e.Timeout {
			t.Errorf("entry %s timeout %s, want %s", e.Addr, e.Timeout, want[e.Addr.String()])
		}
	}
	if d := p.Domain(netip.MustParseAddr("192.0.2.10")); d != "pypi.org" {
		t.Errorf("domain = %q", d)
	}
}

func TestRefusedQueriesNeverReachUpstream(t *testing.T) {
	up, n := fakeUpstream(t)
	p, rec := newTestProxy(t, Settings{AllowDomains: []string{"pypi.org", "*.githubusercontent.com"}, QPS: 50, Upstream: up})

	for _, name := range []string{"example.com", "6578666974.attacker.test", "pypi.org.attacker.test", "githubusercontent.com"} {
		for _, qt := range []uint16{dns.TypeA, dns.TypeTXT, dns.TypeAAAA} {
			resp, ev := p.handle(query(name, qt), "udp")
			if resp.Rcode != dns.RcodeRefused || ev.Verdict != VerdictRefused {
				t.Errorf("%s/%s: rcode %d verdict %q", name, dns.TypeToString[qt], resp.Rcode, ev.Verdict)
			}
		}
	}
	chaos := query("version.bind", dns.TypeTXT)
	chaos.Question[0].Qclass = dns.ClassCHAOS
	if resp, _ := p.handle(chaos, "udp"); resp.Rcode != dns.RcodeRefused {
		t.Errorf("CHAOS rcode %d", resp.Rcode)
	}
	if n.Load() != 0 {
		t.Errorf("upstream saw %d queries for refused names", n.Load())
	}
	if len(rec.entries) != 0 {
		t.Errorf("inserted %v", rec.entries)
	}
}

func TestAAAAAndHTTPSSuppressedLocally(t *testing.T) {
	up, n := fakeUpstream(t)
	p, _ := newTestProxy(t, Settings{AllowDomains: []string{"pypi.org"}, QPS: 50, Upstream: up})
	for _, qt := range []uint16{dns.TypeAAAA, dns.TypeHTTPS} {
		resp, ev := p.handle(query("pypi.org", qt), "udp")
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 || ev.Verdict != VerdictAllow {
			t.Errorf("%s: rcode %d answers %d verdict %q", dns.TypeToString[qt], resp.Rcode, len(resp.Answer), ev.Verdict)
		}
	}
	if n.Load() != 0 {
		t.Errorf("upstream queries = %d", n.Load())
	}
}

func TestRateLimit(t *testing.T) {
	up, _ := fakeUpstream(t)
	p, _ := newTestProxy(t, Settings{AllowDomains: []string{"pypi.org"}, QPS: 3, Upstream: up})
	limited := 0
	for range 10 {
		resp, ev := p.handle(query("pypi.org", dns.TypeA), "udp")
		if resp.Rcode == dns.RcodeRefused {
			limited++
			if ev != nil && ev.Verdict != VerdictRateLimited {
				t.Errorf("verdict %q", ev.Verdict)
			}
		}
	}
	if limited < 6 {
		t.Errorf("only %d of 10 queries limited at 3 qps", limited)
	}
}

func TestInsertFailureIsServfail(t *testing.T) {
	up, _ := fakeUpstream(t)
	p, rec := newTestProxy(t, Settings{AllowDomains: []string{"pypi.org"}, QPS: 50, Upstream: up})
	rec.fail = true
	resp, ev := p.handle(query("pypi.org", dns.TypeA), "udp")
	if resp.Rcode != dns.RcodeServerFailure || ev.Verdict != VerdictError {
		t.Errorf("rcode %d verdict %q", resp.Rcode, ev.Verdict)
	}
	if p.Domain(netip.MustParseAddr("192.0.2.10")) != "" {
		t.Error("cache updated despite insert failure")
	}
}

func TestReloadRepopulatesOnlyStillAllowed(t *testing.T) {
	up, _ := fakeUpstream(t)
	p, _ := newTestProxy(t, Settings{AllowDomains: []string{"pypi.org", "github.com"}, QPS: 50, Upstream: up})
	if resp, _ := p.handle(query("pypi.org", dns.TypeA), "udp"); resp.Rcode != dns.RcodeSuccess {
		t.Fatal("setup query failed")
	}

	var got []nft.AllowEntry
	err := p.Reload(Settings{AllowDomains: []string{"github.com"}, QPS: 50, Upstream: up}, func(e, _ []nft.AllowEntry) error {
		got = e
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("pypi.org addresses survived its removal: %v", got)
	}

	err = p.Reload(Settings{AllowDomains: []string{"*.org"}, QPS: 50, Upstream: up}, func(e, _ []nft.AllowEntry) error {
		got = e
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("expected cached pypi.org addresses to be restored, got %v", got)
	}
	if resp, _ := p.handle(query("github.com", dns.TypeA), "udp"); resp.Rcode != dns.RcodeRefused {
		t.Error("reload did not swap the allowlist")
	}
}

func TestDirectNamesFeedTheDirectSet(t *testing.T) {
	up, _ := fakeUpstream(t)
	p, rec := newTestProxy(t, Settings{
		AllowDomains: []string{"pypi.org", "*.corp.example"}, QPS: 50, Upstream: up,
		Direct: []string{"*.corp.example"},
	})
	for _, name := range []string{"pypi.org", "git.corp.example"} {
		if resp, _ := p.handle(query(name, dns.TypeA), "udp"); resp.Rcode != dns.RcodeSuccess {
			t.Fatalf("%s: rcode %d", name, resp.Rcode)
		}
	}
	// The fake upstream answers every name with the same two addresses.
	if len(rec.entries) != 4 || len(rec.direct) != 2 {
		t.Fatalf("allow %v, direct %v", rec.entries, rec.direct)
	}

	var allowed, direct []nft.AllowEntry
	reload := func(s Settings) {
		t.Helper()
		if err := p.Reload(s, func(a, d []nft.AllowEntry) error { allowed, direct = a, d; return nil }); err != nil {
			t.Fatal(err)
		}
	}
	reload(Settings{AllowDomains: []string{"pypi.org", "*.corp.example"}, QPS: 50, Upstream: up, Direct: []string{"*.corp.example"}})
	if len(allowed) != 2 || len(direct) != 2 {
		t.Errorf("reload kept allow %v, direct %v", allowed, direct)
	}
	// A no_proxy name that is no longer allowlisted must not stay direct.
	reload(Settings{AllowDomains: []string{"pypi.org"}, QPS: 50, Upstream: up, Direct: []string{"*.corp.example"}})
	if len(allowed) != 2 || len(direct) != 0 {
		t.Errorf("after removing the name: allow %v, direct %v", allowed, direct)
	}
}

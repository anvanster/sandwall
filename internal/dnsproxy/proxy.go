// Package dnsproxy runs one DNS listener per sandbox. Allowlisted names are
// resolved upstream and their A records are inserted into the sandbox's
// nftables allow set before the answer is returned; in synthetic mode they
// are answered from an address pool instead (see synthetic.go). Every other
// name gets REFUSED locally and is never forwarded, so query names cannot be
// used as an exfiltration channel.
package dnsproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/time/rate"

	"github.com/anvanster/sandwall/internal/flowlog"
	"github.com/anvanster/sandwall/internal/nft"
)

// TTL handling: answers are clamped to MaxTTL; set entries live for
// max(clamped TTL, MinSetTimeout) so they outlast the client's cache.
const (
	MaxTTL        = 300
	MinSetTimeout = 60 * time.Second

	upstreamTimeout   = 3 * time.Second
	insertTimeout     = 5 * time.Second
	overLimitLogBurst = 5
)

// Verdicts recorded in DNS events and metrics.
const (
	VerdictAllow       = "allow"
	VerdictRefused     = "refused"
	VerdictRateLimited = "ratelimited"
	VerdictError       = "error"

	// ReasonQuarantined is logged for every query of a quarantined sandbox.
	ReasonQuarantined = "quarantined"
)

// Inserter adds DNS-learned addresses to allow_<k>, and with direct also to
// direct_<k> (names matching the upstream proxy's no_proxy list).
type Inserter func(ctx context.Context, k int, entries []nft.AllowEntry, direct bool) error

// Settings are the policy-derived knobs that hot reload can change.
type Settings struct {
	AllowDomains []string // normalized patterns
	QPS          int
	Upstream     string // host:port
	// Direct holds no_proxy name patterns (Allowlist syntax). Addresses of
	// allowlisted names that also match bypass the upstream proxy.
	Direct []string
	// Synthetic, when valid, answers allowlisted names that do not match
	// Direct with addresses from this pool instead of resolving them.
	Synthetic netip.Prefix
}

// Config identifies the sandbox a proxy serves.
type Config struct {
	SandboxID string
	Index     int
	Listen    netip.AddrPort
	Insert    Inserter
	Sink      *flowlog.Sink
	// CountQuery is notified once per query with its verdict. Optional.
	CountQuery func(sandboxID, verdict string)
	// StatePath, when set, keeps the DNS cache across daemon restarts (see
	// persist.go).
	StatePath string
}

// Proxy is the DNS proxy for one sandbox.
type Proxy struct {
	cfg Config

	mu          sync.RWMutex
	allow       *Allowlist
	direct      *Allowlist
	upstream    string
	synthetic   netip.Prefix
	limiter     *rate.Limiter
	overLimitLg *rate.Limiter
	quarantined bool

	// setMu serializes allow-set writes with policy reloads, which flush
	// and repopulate the set from the cache.
	setMu sync.Mutex
	cache *cache
	// synthNext is the next synthetic pool address to try; guarded by setMu.
	synthNext netip.Addr

	udp, tcp *dns.Server

	stopFlush chan struct{}
	flushDone chan struct{}
	stopOnce  sync.Once
}

// New creates a stopped proxy.
func New(cfg Config, s Settings) *Proxy {
	p := &Proxy{cfg: cfg, cache: newCache(), overLimitLg: rate.NewLimiter(1, overLimitLogBurst)}
	p.apply(s)
	return p
}

func (p *Proxy) apply(s Settings) {
	qps := max(s.QPS, 1)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.allow = NewAllowlist(s.AllowDomains)
	p.direct = NewAllowlist(s.Direct)
	p.upstream = s.Upstream
	p.synthetic = s.Synthetic
	p.limiter = rate.NewLimiter(rate.Limit(qps), qps)
}

// Start loads the persisted DNS cache and binds UDP and TCP listeners on
// the sandbox's host-side address.
func (p *Proxy) Start() error {
	if err := p.loadState(); err != nil {
		return fmt.Errorf("dns state %s: %w", p.cfg.StatePath, err)
	}
	addr := p.cfg.Listen.String()
	pc, err := net.ListenPacket("udp4", addr)
	if err != nil {
		return fmt.Errorf("dns listen udp %s: %w", addr, err)
	}
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		pc.Close()
		return fmt.Errorf("dns listen tcp %s: %w", addr, err)
	}
	p.udp = &dns.Server{PacketConn: pc, Handler: p}
	p.tcp = &dns.Server{Listener: ln, Handler: p}
	go func() { _ = p.udp.ActivateAndServe() }()
	go func() { _ = p.tcp.ActivateAndServe() }()
	if p.cfg.StatePath != "" {
		p.stopFlush, p.flushDone = make(chan struct{}), make(chan struct{})
		go p.flusher(p.stopFlush, p.flushDone)
	}
	return nil
}

// Stop closes both listeners and saves the DNS cache. It is idempotent.
func (p *Proxy) Stop() {
	p.stopOnce.Do(func() {
		for _, s := range []*dns.Server{p.udp, p.tcp} {
			if s != nil {
				_ = s.Shutdown()
			}
		}
		if p.stopFlush != nil {
			close(p.stopFlush)
			<-p.flushDone
			_ = p.saveState()
		}
	})
}

// Reload swaps in new settings and calls repopulate with every cached
// address still allowed by the new allowlist, and the subset that bypasses
// the upstream proxy. repopulate is expected to flush and refill the allow
// and direct sets; no insert can interleave with it.
func (p *Proxy) Reload(s Settings, repopulate func(allowed, direct []nft.AllowEntry) error) error {
	p.setMu.Lock()
	defer p.setMu.Unlock()
	p.apply(s)
	p.mu.RLock()
	allow, direct := p.allow, p.direct
	p.mu.RUnlock()
	now := time.Now()
	return repopulate(
		p.cache.live(allow.Allows, now),
		p.cache.live(func(n string) bool { return allow.Allows(n) && direct.Allows(n) }, now),
	)
}

// Domain returns the most recent allowlisted name that resolved to ip.
func (p *Proxy) Domain(ip netip.Addr) string { return p.cache.domain(ip) }

// SetQuarantined makes the proxy refuse every query without forwarding it
// (true), or answer by policy again (false). Releasing also forgets every
// learned address, so a released sandbox starts from empty allow sets.
func (p *Proxy) SetQuarantined(q bool) {
	p.setMu.Lock()
	defer p.setMu.Unlock()
	p.mu.Lock()
	p.quarantined = q
	p.mu.Unlock()
	if !q {
		p.cache.reset()
	}
}

// ServeDNS implements dns.Handler.
func (p *Proxy) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	resp, ev := p.handle(r, w.RemoteAddr().Network())
	if resp == nil {
		return
	}
	if _, isUDP := w.RemoteAddr().(*net.UDPAddr); isUDP {
		size := dns.MinMsgSize
		if opt := r.IsEdns0(); opt != nil {
			size = int(opt.UDPSize())
		}
		resp.Truncate(size)
	}
	_ = w.WriteMsg(resp)

	if ev != nil {
		p.cfg.Sink.Write(*ev)
		if p.cfg.CountQuery != nil {
			p.cfg.CountQuery(p.cfg.SandboxID, ev.Verdict)
		}
	}
}

func (p *Proxy) handle(r *dns.Msg, network string) (*dns.Msg, *flowlog.Event) {
	if r.Opcode != dns.OpcodeQuery || len(r.Question) != 1 {
		return reply(r, dns.RcodeFormatError), nil
	}
	q := r.Question[0]
	ev := &flowlog.Event{
		Type:      flowlog.TypeDNS,
		SandboxID: p.cfg.SandboxID,
		QName:     q.Name,
		QType:     dns.TypeToString[q.Qtype],
	}

	p.mu.RLock()
	allow, direct, upstream, synthetic, limiter, quarantined := p.allow, p.direct, p.upstream, p.synthetic, p.limiter, p.quarantined
	p.mu.RUnlock()

	if quarantined {
		// Logged like any refusal, but never rate-limited away: during an
		// incident every attempted name is evidence.
		ev.Verdict, ev.Reason = VerdictRefused, ReasonQuarantined
		return reply(r, dns.RcodeRefused), ev
	}

	if !limiter.Allow() {
		ev.Verdict = VerdictRateLimited
		if !p.overLimitLg.Allow() {
			// Still answered and counted, but not every over-limit query is logged.
			if p.cfg.CountQuery != nil {
				p.cfg.CountQuery(p.cfg.SandboxID, ev.Verdict)
			}
			return reply(r, dns.RcodeRefused), nil
		}
		return reply(r, dns.RcodeRefused), ev
	}

	if q.Qclass != dns.ClassINET || !allow.Allows(q.Name) {
		ev.Verdict = VerdictRefused
		ev.Reason = "not_allowlisted"
		return reply(r, dns.RcodeRefused), ev
	}

	switch q.Qtype {
	case dns.TypeAAAA:
		// IPv6 is disabled in sandboxes; answer "no addresses" without asking upstream.
		ev.Verdict, ev.Reason = VerdictAllow, "aaaa_suppressed"
		return reply(r, dns.RcodeSuccess), ev
	case dns.TypeHTTPS, dns.TypeSVCB:
		// Address hints in these records bypass the A-record allow set, and
		// ECH configs would defeat a future SNI check. Clients fall back to A.
		ev.Verdict, ev.Reason = VerdictAllow, "svcb_suppressed"
		return reply(r, dns.RcodeSuccess), ev
	}

	if synthetic.IsValid() && !direct.Allows(q.Name) {
		return p.synthesize(r, q, ev, synthetic)
	}

	resp, err := p.forward(r, upstream, network)
	if err != nil {
		ev.Verdict, ev.Reason = VerdictError, err.Error()
		return reply(r, dns.RcodeServerFailure), ev
	}
	entries := sanitize(resp)
	ev.Answers = answerStrings(resp)
	if err := p.insert(q.Name, entries, direct.Allows(q.Name)); err != nil {
		ev.Verdict, ev.Reason = VerdictError, "allow set insert failed: "+err.Error()
		return reply(r, dns.RcodeServerFailure), ev
	}
	ev.Verdict = VerdictAllow
	resp.Id = r.Id
	return resp, ev
}

func (p *Proxy) forward(r *dns.Msg, upstream, network string) (*dns.Msg, error) {
	if upstream == "" {
		return nil, errors.New("no upstream resolver configured")
	}
	q := r.Copy()
	q.Id = dns.Id()
	netw := "udp"
	if network == "tcp" {
		netw = "tcp"
	}
	c := &dns.Client{Net: netw, Timeout: upstreamTimeout}
	resp, _, err := c.Exchange(q, upstream)
	if err == nil && resp.Truncated && netw == "udp" {
		c.Net = "tcp"
		resp, _, err = c.Exchange(q, upstream)
	}
	if err != nil {
		return nil, fmt.Errorf("upstream %s: %w", upstream, err)
	}
	return resp, nil
}

func (p *Proxy) insert(qname string, entries []nft.AllowEntry, direct bool) error {
	p.setMu.Lock()
	defer p.setMu.Unlock()
	return p.insertLocked(qname, entries, direct)
}

// insertLocked adds entries to the allow (and direct) sets and the cache.
// The caller holds setMu.
func (p *Proxy) insertLocked(qname string, entries []nft.AllowEntry, direct bool) error {
	if len(entries) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), insertTimeout)
	defer cancel()
	if err := p.cfg.Insert(ctx, p.cfg.Index, entries, direct); err != nil {
		return err
	}
	p.cache.add(qname, entries, time.Now())
	return nil
}

// sanitize strips AAAA records, clamps TTLs and returns the A records as
// allow-set entries.
func sanitize(m *dns.Msg) []nft.AllowEntry {
	m.Answer = clamp(dropAAAA(m.Answer))
	m.Ns = clamp(dropAAAA(m.Ns))
	m.Extra = clamp(dropAAAA(m.Extra))
	var entries []nft.AllowEntry
	for _, rr := range m.Answer {
		a, ok := rr.(*dns.A)
		if !ok {
			continue
		}
		addr, ok := netip.AddrFromSlice(a.A.To4())
		if !ok {
			continue
		}
		timeout := max(time.Duration(a.Hdr.Ttl)*time.Second, MinSetTimeout)
		entries = append(entries, nft.AllowEntry{Addr: addr, Timeout: timeout})
	}
	return entries
}

func dropAAAA(rrs []dns.RR) []dns.RR {
	out := rrs[:0]
	for _, rr := range rrs {
		if rr.Header().Rrtype != dns.TypeAAAA {
			out = append(out, rr)
		}
	}
	return out
}

func clamp(rrs []dns.RR) []dns.RR {
	for _, rr := range rrs {
		h := rr.Header()
		if h.Rrtype != dns.TypeOPT && h.Ttl > MaxTTL {
			h.Ttl = MaxTTL
		}
	}
	return rrs
}

func answerStrings(m *dns.Msg) []string {
	var out []string
	for _, rr := range m.Answer {
		switch v := rr.(type) {
		case *dns.A:
			out = append(out, v.A.String())
		case *dns.CNAME:
			out = append(out, "CNAME "+v.Target)
		}
	}
	return out
}

func reply(r *dns.Msg, rcode int) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(r, rcode)
	m.RecursionAvailable = true
	return m
}

// cache remembers which allowlisted names resolved to which addresses, for
// flow-log domain attribution and for repopulating the set on reload.
type cache struct {
	dirty  atomic.Bool // changed since the last save
	mu     sync.Mutex
	byIP   map[netip.Addr]map[string]time.Time // name -> expiry
	recent map[netip.Addr]string
}

func newCache() *cache {
	return &cache{byIP: map[netip.Addr]map[string]time.Time{}, recent: map[netip.Addr]string{}}
}

func (c *cache) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.byIP = map[netip.Addr]map[string]time.Time{}
	c.recent = map[netip.Addr]string{}
	c.dirty.Store(true)
}

func normalizeName(qname string) string { return strings.ToLower(strings.TrimSuffix(qname, ".")) }

func (c *cache) add(qname string, entries []nft.AllowEntry, now time.Time) {
	name := normalizeName(qname)
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range entries {
		names := c.byIP[e.Addr]
		if names == nil {
			names = map[string]time.Time{}
			c.byIP[e.Addr] = names
		}
		if exp := now.Add(e.Timeout); exp.After(names[name]) {
			names[name] = exp
		}
		c.recent[e.Addr] = name
	}
	c.dirty.Store(true)
	c.gcLocked(now)
}

// gcLocked drops expired names. Domain attribution for an address is kept
// until all of its names have expired.
func (c *cache) gcLocked(now time.Time) {
	for ip, names := range c.byIP {
		for n, exp := range names {
			if !exp.After(now) {
				delete(names, n)
			}
		}
		if len(names) == 0 {
			delete(c.byIP, ip)
			delete(c.recent, ip)
		}
	}
}

// live returns every cached address with an unexpired name that match
// accepts, with the longest remaining lifetime among those names.
func (c *cache) live(match func(string) bool, now time.Time) []nft.AllowEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gcLocked(now)
	var out []nft.AllowEntry
	for ip, names := range c.byIP {
		var best time.Time
		for n, exp := range names {
			if match(n) && exp.After(best) {
				best = exp
			}
		}
		if remaining := best.Sub(now).Truncate(time.Second); remaining >= time.Second {
			out = append(out, nft.AllowEntry{Addr: ip, Timeout: remaining})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr.Less(out[j].Addr) })
	return out
}

func (c *cache) domain(ip netip.Addr) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.recent[ip]
}

package dnsproxy

import (
	"errors"
	"net/netip"
	"time"

	"github.com/miekg/dns"

	"github.com/anvanster/sandwall/internal/flowlog"
	"github.com/anvanster/sandwall/internal/nft"
)

// Synthetic DNS, for networks where only an upstream HTTP proxy reaches the
// internet and the site resolver answers internal names only. Allowlisted
// names (other than no_proxy ones) are answered with an address from a pool
// instead of being resolved: the sandbox connects to that address, the relay
// maps it back to the name and asks the proxy for the name, and the proxy
// does the real resolution. No query for these names leaves the host.

// SyntheticTTL is the TTL of synthetic answers and the lifetime of the
// name-to-address mapping and of its allow-set entry.
const SyntheticTTL = 300 * time.Second

// DefaultSyntheticPool is the RFC 2544 benchmarking range: never a real
// destination, and outside every blocked range.
var DefaultSyntheticPool = netip.MustParsePrefix("198.18.0.0/15")

// ReasonSynthetic marks a DNS answer from the synthetic pool.
const ReasonSynthetic = "synthetic"

var errPoolExhausted = errors.New("synthetic address pool exhausted")

// synthesize answers an allowlisted query from the pool. A records get the
// name's current pool address, or a newly allocated one; other types get an
// empty answer, as there is nothing real to return.
func (p *Proxy) synthesize(r *dns.Msg, q dns.Question, ev *flowlog.Event, pool netip.Prefix) (*dns.Msg, *flowlog.Event) {
	ev.Verdict, ev.Reason = VerdictAllow, ReasonSynthetic
	if q.Qtype != dns.TypeA {
		return reply(r, dns.RcodeSuccess), ev
	}
	addr, err := p.synthAddr(q.Name, pool)
	if err != nil {
		ev.Verdict, ev.Reason = VerdictError, err.Error()
		return reply(r, dns.RcodeServerFailure), ev
	}
	m := reply(r, dns.RcodeSuccess)
	m.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: uint32(SyntheticTTL / time.Second)},
		A:   addr.AsSlice(),
	}}
	ev.Answers = []string{addr.String()}
	return m, ev
}

// synthAddr returns the pool address for qname and (re)inserts it into the
// allow set for another SyntheticTTL. Allocation and insert run under setMu,
// so two queries never get the same address for different names, and a
// policy reload never interleaves.
func (p *Proxy) synthAddr(qname string, pool netip.Prefix) (netip.Addr, error) {
	p.setMu.Lock()
	defer p.setMu.Unlock()
	now := time.Now()
	addr, ok := p.cache.addrIn(qname, pool, now)
	if !ok {
		var err error
		if addr, err = p.allocate(pool, now); err != nil {
			return netip.Addr{}, err
		}
	}
	entries := []nft.AllowEntry{{Addr: addr, Timeout: SyntheticTTL}}
	if err := p.insertLocked(qname, entries, false); err != nil {
		return netip.Addr{}, err
	}
	return addr, nil
}

// allocate hands out the next pool address not mapped to any live name,
// round-robin, skipping the first and last address of the pool. Runs with
// setMu held.
func (p *Proxy) allocate(pool netip.Prefix, now time.Time) (netip.Addr, error) {
	first := pool.Masked().Addr().Next()
	size := 1<<(32-pool.Bits()) - 2
	if size <= 0 {
		return netip.Addr{}, errPoolExhausted
	}
	if !p.synthNext.IsValid() || !pool.Contains(p.synthNext) {
		p.synthNext = first
	}
	for range size {
		a := p.synthNext
		p.synthNext = a.Next()
		if !pool.Contains(p.synthNext.Next()) { // wrap before the last address
			p.synthNext = first
		}
		if !p.cache.inUse(a, now) {
			return a, nil
		}
	}
	return netip.Addr{}, errPoolExhausted
}

// addrIn returns the live address inside pool that name is mapped to.
func (c *cache) addrIn(qname string, pool netip.Prefix, now time.Time) (netip.Addr, bool) {
	name := normalizeName(qname)
	c.mu.Lock()
	defer c.mu.Unlock()
	for ip, names := range c.byIP {
		if exp, ok := names[name]; ok && pool.Contains(ip) && exp.After(now) {
			return ip, true
		}
	}
	return netip.Addr{}, false
}

// inUse reports whether any live name is mapped to ip.
func (c *cache) inUse(ip netip.Addr, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, exp := range c.byIP[ip] {
		if exp.After(now) {
			return true
		}
	}
	return false
}

// Package nft renders sandwall's nftables ruleset as text and applies it
// atomically with `nft -f`. sandwall only ever touches `table inet sandwall`.
//
// Layout:
//
//	table inet sandwall
//	  set blocked_ranges, blocked_exempt        (global, interval)
//	  set direct_cidrs                          (global, interval) no_proxy CIDRs
//	  set quarantined                           (global) host veths of quarantined sandboxes
//	  map pre_vmap, in_vmap, nat_vmap           (ifname -> jump sb_<k> / sbin_<k> / sbnat_<k>)
//	  chain prerouting  (hook)  host-bound traffic to input; iifname vmap @pre_vmap; unknown veth-h* drop
//	  chain relay_redirect (hook, nat) with the relay: iifname vmap @nat_vmap
//	  chain forward     (hook)  nothing reaches a sandbox but replies
//	  chain input       (hook)  iifname vmap @in_vmap;  unknown veth-h* drop
//	  chain postrouting (hook)  masquerade sandbox traffic leaving the host
//	  chain sb_<k>      per-sandbox egress policy
//	  chain sbin_<k>    per-sandbox access to host-local addresses (DNS proxy only)
//	  chain sbnat_<k>   allowed TCP to the relay: all of it with an upstream proxy (except
//	                    no_proxy destinations), ports 80 and 443 with the SNI check
//	  chain conn_reject shared reject for connection-limit overflows
//	  set allow_<k>     DNS-learned IPs, per-element timeout
//	  set allow_cidr_<k> static CIDRs from policy
//	  set direct_<k>    DNS-learned IPs of no_proxy names, per-element timeout
//
// Every render is idempotent: it can be re-applied on top of any prior state,
// including a partially created one.
package nft

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/anvanster/sandwall/internal/addressing"
)

// Table is the only nftables table sandwall owns.
const Table = "sandwall"

// LogGroup is the NFLOG group deny rules log to.
const LogGroup = 1

// LogPrefixPrefix starts every sandwall NFLOG prefix: "sandwall:<k>:<reason> ".
const LogPrefixPrefix = "sandwall:"

// Deny reasons carried in the NFLOG prefix.
const (
	ReasonDNSBypass    = "dns_bypass"
	ReasonBlockedRange = "blocked_range"
	ReasonRateLimit    = "rate_limit"
	ReasonConnLimit    = "conn_limit"
	ReasonNotAllowed   = "not_allowed"
	ReasonHostAccess   = "host_access"
	ReasonIPv6         = "ipv6"
	ReasonUnknownIface = "unknown_iface"
	// ReasonNoProxyRoute: allowed non-TCP traffic from a proxied sandbox,
	// which an HTTP proxy cannot carry.
	ReasonNoProxyRoute = "no_proxy_route"
	// ReasonQUICBlocked: with the SNI check, QUIC (UDP 443) to a
	// DNS-learned address, whose server name the relay cannot check.
	ReasonQUICBlocked = "quic_blocked"
	// ReasonQuarantined: anything from or to a quarantined sandbox, except
	// DNS to its own proxy (which refuses and logs every query).
	ReasonQuarantined = "quarantined"
)

// DefaultSNIPorts are the ports the SNI check covers unless configured:
// allowed TCP to them goes through the relay, and UDP (QUIC) to DNS-learned
// addresses on them is rejected.
var DefaultSNIPorts = []int{80, 443}

// PreroutingPriority runs sandbox policy after conntrack (-200) and before
// the proxy redirect (dstnat, -100).
const PreroutingPriority = -150

// DefaultBlockedRanges are never reachable from a sandbox,
// plus reserved 240/4 which also covers the limited broadcast address.
var DefaultBlockedRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// BaseConfig is the host-wide part of the ruleset.
type BaseConfig struct {
	BlockedRanges []netip.Prefix
	// BlockedExempt carves holes in BlockedRanges. Intended for test
	// endpoints only; the transfer supernet stays blocked regardless.
	BlockedExempt []netip.Prefix
	// Proxy redirects allowed sandbox TCP to the per-sandbox relay on
	// addressing.RelayPort instead of forwarding it.
	Proxy bool
	// SNICheck redirects allowed sandbox TCP to the SNI check ports (see
	// SandboxConfig.SNIPorts) to the relay, which checks the TLS SNI or HTTP
	// Host. Implied by Proxy.
	SNICheck bool
	// DirectCIDRs are no_proxy destinations: allowed traffic to them is
	// forwarded as without a proxy.
	DirectCIDRs []netip.Prefix
}

func (cfg SandboxConfig) sniPorts() []int {
	if len(cfg.SNIPorts) == 0 {
		return DefaultSNIPorts
	}
	return cfg.SNIPorts
}

// SandboxConfig is the per-sandbox part of the ruleset.
type SandboxConfig struct {
	Index          int
	AllowCIDRs     []string
	MaxConns       int
	NewConnsPerSec int
	// Allowed repopulates allow_<k> after the flush on (re)apply.
	Allowed []AllowEntry
	// PreserveAllowed keeps allow_<k> as is instead of flushing it. Used
	// when a restarted daemon re-adopts a running sandbox.
	PreserveAllowed bool
	// Proxied matches BaseConfig.Proxy: allowed TCP goes to the relay, and
	// other allowed traffic is rejected because the proxy cannot carry it,
	// except to no_proxy destinations (direct_<k>, direct_cidrs).
	Proxied bool
	// SNICheck matches BaseConfig.SNICheck: allowed TCP to SNIPorts goes to
	// the relay, and QUIC (UDP to those ports) to DNS-learned addresses is
	// rejected. Proxied sandboxes get the check for all TCP anyway.
	SNICheck bool
	// SNIPorts are the ports SNICheck covers; empty means DefaultSNIPorts.
	SNIPorts []int
	// Direct repopulates direct_<k> after the flush on (re)apply, like
	// Allowed; PreserveAllowed keeps it as is unless ResetDirect is set.
	Direct      []AllowEntry
	ResetDirect bool
	// Quarantined cuts the sandbox off: every packet from it is dropped,
	// established flows included, replies to it are dropped in forward,
	// its allow and direct sets are emptied, and only DNS to its own proxy
	// is admitted. Policy limits and allowlists are kept for the release.
	Quarantined bool
}

// AllowEntry is one DNS-learned address and how long it stays allowed.
type AllowEntry struct {
	Addr    netip.Addr
	Timeout time.Duration
}

// LogPrefix builds the NFLOG prefix for sandbox k and a reason.
func LogPrefix(k int, reason string) string {
	return fmt.Sprintf("%s%d:%s ", LogPrefixPrefix, k, reason)
}

// ParseLogPrefix is the inverse of LogPrefix.
func ParseLogPrefix(prefix string) (k int, reason string, ok bool) {
	rest, found := strings.CutPrefix(strings.TrimRight(prefix, " \x00"), LogPrefixPrefix)
	if !found {
		return 0, "", false
	}
	idx, reason, found := strings.Cut(rest, ":")
	if !found || reason == "" {
		return 0, "", false
	}
	if _, err := fmt.Sscanf(idx, "%d", &k); err != nil {
		return 0, "", false
	}
	return k, reason, true
}

func logDrop(k int, reason string) string {
	return fmt.Sprintf("counter log group %d prefix %q drop", LogGroup, LogPrefix(k, reason))
}

type builder struct{ strings.Builder }

func (b *builder) line(format string, args ...any) {
	fmt.Fprintf(&b.Builder, format, args...)
	b.WriteByte('\n')
}

// declareBase emits idempotent declarations of the table, global sets and
// maps, and fully (re)defines conn_reject: sandbox chains jump to it, and an
// empty conn_reject would let over-limit connections fall through.
func (b *builder) declareBase() {
	t := Table
	b.line("add table inet %s", t)
	b.line("add set inet %s blocked_ranges { type ipv4_addr; flags interval; auto-merge; }", t)
	b.line("add set inet %s blocked_exempt { type ipv4_addr; flags interval; auto-merge; }", t)
	b.line("add map inet %s pre_vmap { type ifname : verdict; }", t)
	b.line("add map inet %s in_vmap { type ifname : verdict; }", t)
	b.line("add map inet %s nat_vmap { type ifname : verdict; }", t)
	b.line("add set inet %s direct_cidrs { type ipv4_addr; flags interval; auto-merge; }", t)
	b.line("add set inet %s quarantined { type ifname; }", t)
	// TCP gets a reset: ICMP errors are rate-limited per destination by the
	// kernel (net.ipv4.icmp_ratelimit), which turns most rejects of a
	// connection burst into silent drops and client timeouts.
	b.line("add chain inet %s conn_reject", t)
	b.line("flush chain inet %s conn_reject", t)
	b.line("add rule inet %s conn_reject meta l4proto tcp reject with tcp reset", t)
	b.line("add rule inet %s conn_reject reject with icmpx admin-prohibited", t)
}

// RenderBase renders the host-wide ruleset. Re-applying it replaces the
// hook chains and global sets but leaves per-sandbox chains and sets alone.
func RenderBase(cfg BaseConfig) string {
	var b builder
	t := Table
	b.declareBase()
	b.line("flush set inet %s blocked_ranges", t)
	if len(cfg.BlockedRanges) > 0 {
		b.line("add element inet %s blocked_ranges { %s }", t, joinPrefixes(cfg.BlockedRanges))
	}
	b.line("flush set inet %s blocked_exempt", t)
	if len(cfg.BlockedExempt) > 0 {
		b.line("add element inet %s blocked_exempt { %s }", t, joinPrefixes(cfg.BlockedExempt))
	}
	b.line("flush set inet %s direct_cidrs", t)
	if cfg.Proxy && len(cfg.DirectCIDRs) > 0 {
		b.line("add element inet %s direct_cidrs { %s }", t, joinPrefixes(cfg.DirectCIDRs))
	}

	// Sandbox policy runs in prerouting, not forward: a proxy redirect
	// turns allowed traffic into input traffic, which forward never sees.
	// Traffic to the host itself is left to input and sbin_<k>, as before.
	b.line("add chain inet %s prerouting { type filter hook prerouting priority %d; policy accept; }", t, PreroutingPriority)
	b.line("flush chain inet %s prerouting", t)
	b.line("add rule inet %s prerouting iifname \"veth-h*\" fib daddr type { local, broadcast, multicast } accept", t)
	b.line("add rule inet %s prerouting iifname vmap @pre_vmap", t)
	b.line("add rule inet %s prerouting iifname \"veth-h*\" %s", t, logDrop(0, ReasonUnknownIface))

	// proxy_redirect was this chain's name before the relay also served the
	// SNI check without a proxy.
	b.line("add chain inet %s proxy_redirect { type nat hook prerouting priority dstnat; policy accept; }", t)
	b.line("flush chain inet %s proxy_redirect", t)
	b.line("delete chain inet %s proxy_redirect", t)
	b.line("add chain inet %s relay_redirect { type nat hook prerouting priority dstnat; policy accept; }", t)
	b.line("flush chain inet %s relay_redirect", t)
	if cfg.Proxy || cfg.SNICheck {
		// Only traffic sb_<k> accepted gets here; sbnat_<k> redirects it.
		b.line("add rule inet %s relay_redirect iifname vmap @nat_vmap", t)
	}

	b.line("add chain inet %s forward { type filter hook forward priority filter; policy accept; }", t)
	b.line("flush chain inet %s forward", t)
	// fwd_vmap dispatched policy from forward before it moved to prerouting.
	b.line("add map inet %s fwd_vmap { type ifname : verdict; }", t)
	b.line("delete map inet %s fwd_vmap", t)
	// Replies on flows a quarantined sandbox had open must not reach it.
	b.line("add rule inet %s forward oifname @quarantined counter drop", t)
	b.line("add rule inet %s forward oifname \"veth-h*\" ct state established,related accept", t)
	b.line("add rule inet %s forward oifname \"veth-h*\" counter drop", t)

	b.line("add chain inet %s input { type filter hook input priority filter; policy accept; }", t)
	b.line("flush chain inet %s input", t)
	// The host's own multicast/broadcast sent on veth-h<k> loops back as
	// input on that interface; it is not sandbox traffic.
	b.line("add rule inet %s input iifname \"veth-h*\" meta pkttype { broadcast, multicast } fib saddr type local accept", t)
	b.line("add rule inet %s input iifname vmap @in_vmap", t)
	b.line("add rule inet %s input iifname \"veth-h*\" %s", t, logDrop(0, ReasonUnknownIface))

	b.line("add chain inet %s postrouting { type nat hook postrouting priority srcnat; policy accept; }", t)
	b.line("flush chain inet %s postrouting", t)
	b.line("add rule inet %s postrouting ip saddr %s oifname != \"veth-h*\" masquerade", t, addressing.TransferSupernet)
	return b.String()
}

// RenderSandbox renders (or re-renders, for hot reload) one sandbox's chains
// and sets and hooks them into the dispatch maps.
func RenderSandbox(cfg SandboxConfig) (string, error) {
	sb, err := addressing.For(cfg.Index)
	if err != nil {
		return "", err
	}
	if cfg.MaxConns <= 0 || cfg.NewConnsPerSec <= 0 {
		return "", fmt.Errorf("sandbox %d: limits must be positive", cfg.Index)
	}
	cidrs := make([]netip.Prefix, 0, len(cfg.AllowCIDRs))
	for _, c := range cfg.AllowCIDRs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return "", fmt.Errorf("sandbox %d: allow_cidr %q: %w", cfg.Index, c, err)
		}
		cidrs = append(cidrs, p)
	}

	var b builder
	t, k := Table, cfg.Index
	b.declareBase()
	b.line("add chain inet %s sb_%d", t, k)
	b.line("flush chain inet %s sb_%d", t, k)
	b.line("add chain inet %s sbin_%d", t, k)
	b.line("flush chain inet %s sbin_%d", t, k)
	b.line("add chain inet %s sbnat_%d", t, k)
	b.line("flush chain inet %s sbnat_%d", t, k)
	b.line("add set inet %s allow_%d { type ipv4_addr; flags timeout; }", t, k)
	b.line("add set inet %s direct_%d { type ipv4_addr; flags timeout; }", t, k)
	if !cfg.PreserveAllowed || cfg.Quarantined {
		b.line("flush set inet %s allow_%d", t, k)
		if len(cfg.Allowed) > 0 && !cfg.Quarantined {
			b.line("add element inet %s allow_%d { %s }", t, k, joinAllow(cfg.Allowed))
		}
	}
	if !cfg.PreserveAllowed || cfg.ResetDirect || cfg.Quarantined {
		b.line("flush set inet %s direct_%d", t, k)
		if len(cfg.Direct) > 0 && !cfg.Quarantined {
			b.line("add element inet %s direct_%d { %s }", t, k, joinAllow(cfg.Direct))
		}
	}
	b.line("add set inet %s allow_cidr_%d { type ipv4_addr; flags interval; auto-merge; }", t, k)
	b.line("flush set inet %s allow_cidr_%d", t, k)
	if len(cidrs) > 0 {
		b.line("add element inet %s allow_cidr_%d { %s }", t, k, joinPrefixes(cidrs))
	}

	// The element is first ensured to exist so deleting it never fails.
	b.line("add element inet %s quarantined { %q }", t, sb.HostVeth)
	if cfg.Quarantined {
		in := fmt.Sprintf("add rule inet %s sbin_%d", t, k)
		b.line("add rule inet %s sb_%d %s", t, k, logDrop(k, ReasonQuarantined))
		b.line("%s ip daddr %s meta l4proto { tcp, udp } th dport 53 accept", in, sb.HostAddr)
		b.line("%s %s", in, logDrop(k, ReasonQuarantined))
		b.line("add element inet %s pre_vmap { %q : jump sb_%d }", t, sb.HostVeth, k)
		b.line("add element inet %s in_vmap { %q : jump sbin_%d }", t, sb.HostVeth, k)
		b.line("add element inet %s nat_vmap { %q : jump sbnat_%d }", t, sb.HostVeth, k)
		return b.String(), nil
	}
	b.line("delete element inet %s quarantined { %q }", t, sb.HostVeth)

	chain := fmt.Sprintf("add rule inet %s sb_%d", t, k)
	// 1. Return traffic for flows already admitted.
	b.line("%s ct state established,related accept", chain)
	// 2. DNS to the sandbox's own proxy. Host-bound traffic skips this chain
	//    and is admitted by sbin_<k>; kept so the chain reads as a complete policy.
	b.line("%s ip daddr %s meta l4proto { tcp, udp } th dport 53 accept", chain, sb.HostAddr)
	// 3. Any other DNS or DoT is a bypass attempt.
	b.line("%s meta l4proto { tcp, udp } th dport { 53, 853 } %s", chain, logDrop(k, ReasonDNSBypass))
	b.line("%s meta nfproto ipv6 %s", chain, logDrop(k, ReasonIPv6))
	// 4. Private, link-local, metadata and transfer ranges.
	b.line("%s ip daddr %s %s", chain, addressing.TransferSupernet, logDrop(k, ReasonBlockedRange))
	b.line("%s ip daddr @blocked_ranges ip daddr != @blocked_exempt %s", chain, logDrop(k, ReasonBlockedRange))
	// 5. New-connection rate. The limit lives in this chain, so it is per sandbox.
	b.line("%s ct state new limit rate over %d/second burst %d packets %s",
		chain, cfg.NewConnsPerSec, cfg.NewConnsPerSec, logDrop(k, ReasonRateLimit))
	// 6. Concurrent connections. Anonymous connlimit state is per rule, and
	//    this rule only sees sandbox k's packets, so the count is per sandbox.
	b.line("%s ct state new ct count over %d counter log group %d prefix %q jump conn_reject",
		chain, cfg.MaxConns, LogGroup, LogPrefix(k, ReasonConnLimit))
	// 7-8. Allowlist.
	if cfg.Proxied {
		// no_proxy destinations are forwarded as without a proxy (sbnat_<k>
		// does not redirect them), whatever the protocol.
		for _, direct := range []string{fmt.Sprintf("@direct_%d", k), "@direct_cidrs"} {
			for _, set := range []string{"allow", "allow_cidr"} {
				b.line("%s ip daddr %s ip daddr @%s_%d accept", chain, direct, set, k)
			}
		}
		// Other TCP goes on to the relay; an HTTP proxy cannot carry anything
		// else, so reject it at once (QUIC clients fall back to TCP).
		for _, set := range []string{"allow", "allow_cidr"} {
			b.line("%s ip daddr @%s_%d meta l4proto tcp accept", chain, set, k)
		}
		for _, set := range []string{"allow", "allow_cidr"} {
			b.line("%s ip daddr @%s_%d counter log group %d prefix %q jump conn_reject",
				chain, set, k, LogGroup, LogPrefix(k, ReasonNoProxyRoute))
		}
	} else {
		if cfg.SNICheck {
			// QUIC carries its server name encrypted, so the relay cannot
			// check it. allow_cidrs do not depend on the name.
			b.line("%s ip daddr @allow_%d ip daddr != @allow_cidr_%d udp dport { %s } counter log group %d prefix %q jump conn_reject",
				chain, k, k, joinInts(cfg.sniPorts()), LogGroup, LogPrefix(k, ReasonQUICBlocked))
		}
		b.line("%s ip daddr @allow_%d accept", chain, k)
		b.line("%s ip daddr @allow_cidr_%d accept", chain, k)
	}
	// 9. Default deny.
	b.line("%s %s", chain, logDrop(k, ReasonNotAllowed))

	in := fmt.Sprintf("add rule inet %s sbin_%d", t, k)
	b.line("%s ct state established,related accept", in)
	b.line("%s ip daddr %s meta l4proto { tcp, udp } th dport 53 accept", in, sb.HostAddr)
	if cfg.Proxied || cfg.SNICheck {
		// Only connections the relay redirect sent here; a sandbox
		// connecting to the relay port directly is host access.
		b.line("%s ip daddr %s tcp dport %d ct status dnat accept", in, sb.HostAddr, addressing.RelayPort)
	}
	b.line("%s %s", in, logDrop(k, ReasonHostAccess))

	// Runs only for traffic sb_<k> accepted. The redirect target is the
	// incoming interface's address, 10.200.k.1, where the relay listens.
	nat := fmt.Sprintf("add rule inet %s sbnat_%d", t, k)
	switch {
	case cfg.Proxied:
		b.line("%s ip daddr @direct_%d return", nat, k)
		b.line("%s ip daddr @direct_cidrs return", nat)
		b.line("%s meta l4proto tcp fib daddr type != local redirect to :%d", nat, addressing.RelayPort)
	case cfg.SNICheck:
		b.line("%s tcp dport { %s } fib daddr type != local redirect to :%d", nat, joinInts(cfg.sniPorts()), addressing.RelayPort)
	}

	b.line("add element inet %s pre_vmap { %q : jump sb_%d }", t, sb.HostVeth, k)
	b.line("add element inet %s in_vmap { %q : jump sbin_%d }", t, sb.HostVeth, k)
	b.line("add element inet %s nat_vmap { %q : jump sbnat_%d }", t, sb.HostVeth, k)
	return b.String(), nil
}

// RenderRemoveSandbox removes one sandbox's chains, sets and map entries.
// Each object is first ensured to exist, so the transaction succeeds no
// matter how much of the sandbox was created.
func RenderRemoveSandbox(k int) (string, error) {
	sb, err := addressing.For(k)
	if err != nil {
		return "", err
	}
	var b builder
	t := Table
	b.declareBase()
	b.line("add chain inet %s sb_%d", t, k)
	b.line("add chain inet %s sbin_%d", t, k)
	b.line("add chain inet %s sbnat_%d", t, k)
	b.line("add set inet %s allow_%d { type ipv4_addr; flags timeout; }", t, k)
	b.line("add set inet %s allow_cidr_%d { type ipv4_addr; flags interval; auto-merge; }", t, k)
	b.line("add set inet %s direct_%d { type ipv4_addr; flags timeout; }", t, k)
	b.line("add element inet %s pre_vmap { %q : jump sb_%d }", t, sb.HostVeth, k)
	b.line("add element inet %s in_vmap { %q : jump sbin_%d }", t, sb.HostVeth, k)
	b.line("add element inet %s nat_vmap { %q : jump sbnat_%d }", t, sb.HostVeth, k)
	b.line("delete element inet %s pre_vmap { %q }", t, sb.HostVeth)
	b.line("delete element inet %s in_vmap { %q }", t, sb.HostVeth)
	b.line("delete element inet %s nat_vmap { %q }", t, sb.HostVeth)
	b.line("add element inet %s quarantined { %q }", t, sb.HostVeth)
	b.line("delete element inet %s quarantined { %q }", t, sb.HostVeth)
	for _, c := range []string{"sb", "sbin", "sbnat"} {
		b.line("flush chain inet %s %s_%d", t, c, k)
		b.line("delete chain inet %s %s_%d", t, c, k)
	}
	b.line("delete set inet %s allow_%d", t, k)
	b.line("delete set inet %s allow_cidr_%d", t, k)
	b.line("delete set inet %s direct_%d", t, k)
	return b.String(), nil
}

// RenderAllow inserts or refreshes DNS-learned addresses in allow_<k>, and
// with direct also in direct_<k>. Re-adding an existing element does not
// extend its timeout, so each address is added (ensuring it exists),
// deleted, and added again with the new timeout, all in one atomic
// transaction.
func RenderAllow(k int, entries []AllowEntry, direct bool) string {
	if len(entries) == 0 {
		return ""
	}
	var b builder
	sets := []string{"allow"}
	if direct {
		sets = append(sets, "direct")
	}
	for _, name := range sets {
		set := fmt.Sprintf("inet %s %s_%d", Table, name, k)
		b.line("add element %s { %s }", set, joinAllow(entries))
		b.line("delete element %s { %s }", set, joinAddrs(entries))
		b.line("add element %s { %s }", set, joinAllow(entries))
	}
	return b.String()
}

// RenderDeleteTable removes everything sandwall ever created in nftables.
func RenderDeleteTable() string {
	return fmt.Sprintf("add table inet %s\ndelete table inet %s\n", Table, Table)
}

func joinInts(ns []int) string {
	s := make([]string, len(ns))
	for i, n := range ns {
		s[i] = fmt.Sprint(n)
	}
	return strings.Join(s, ", ")
}

func joinPrefixes(ps []netip.Prefix) string {
	s := make([]string, len(ps))
	for i, p := range ps {
		s[i] = p.Masked().String()
	}
	return strings.Join(s, ", ")
}

// sortedUnique orders entries by address and keeps the longest timeout for
// duplicates, so rendered output is deterministic and never self-conflicting.
func sortedUnique(entries []AllowEntry) []AllowEntry {
	best := make(map[netip.Addr]time.Duration, len(entries))
	for _, e := range entries {
		if e.Timeout > best[e.Addr] {
			best[e.Addr] = e.Timeout
		}
	}
	out := make([]AllowEntry, 0, len(best))
	for a, t := range best {
		out = append(out, AllowEntry{Addr: a, Timeout: t})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr.Less(out[j].Addr) })
	return out
}

func joinAllow(entries []AllowEntry) string {
	u := sortedUnique(entries)
	s := make([]string, len(u))
	for i, e := range u {
		s[i] = fmt.Sprintf("%s timeout %ds", e.Addr, int(max(e.Timeout, time.Second)/time.Second))
	}
	return strings.Join(s, ", ")
}

func joinAddrs(entries []AllowEntry) string {
	u := sortedUnique(entries)
	s := make([]string, len(u))
	for i, e := range u {
		s[i] = e.Addr.String()
	}
	return strings.Join(s, ", ")
}

// NetnsTable is the table sandwall owns inside a VM-mode sandbox netns.
const NetnsTable = "sandwall_vm"

// RenderVMNetns renders the ruleset inside a VM-mode sandbox's netns:
//   - guest DNS to 172.16.0.1 is DNATed to the sandbox's proxy;
//   - guest traffic leaving via veth-s<k> is masqueraded to 10.200.k.2, so the
//     host enforces policy exactly as for exec mode;
//   - only the guest address may be forwarded (no spoofing), and the guest
//     cannot reach the netns itself except for replies to connections the
//     netns opened (the control channel).
//
// DNS to any other server is forwarded unchanged, so the host still sees
// and logs it as a bypass attempt.
func RenderVMNetns(k int) (string, error) {
	sb, err := addressing.For(k)
	if err != nil {
		return "", err
	}
	var b builder
	t := NetnsTable
	tap := addressing.TapName
	b.line("add table ip %s", t)
	b.line("delete table ip %s", t)
	b.line("add table ip %s", t)
	b.line("add chain ip %s prerouting { type nat hook prerouting priority dstnat; policy accept; }", t)
	b.line("add rule ip %s prerouting iifname %q ip daddr %s meta l4proto { tcp, udp } th dport 53 dnat to %s:53",
		t, tap, addressing.TapAddr, sb.HostAddr)
	b.line("add chain ip %s postrouting { type nat hook postrouting priority srcnat; policy accept; }", t)
	b.line("add rule ip %s postrouting ip saddr %s oifname %q masquerade", t, addressing.GuestAddr, sb.NsVeth)
	b.line("add chain ip %s forward { type filter hook forward priority filter; policy drop; }", t)
	b.line("add rule ip %s forward iifname %q oifname %q ip saddr %s accept", t, tap, sb.NsVeth, addressing.GuestAddr)
	b.line("add rule ip %s forward iifname %q oifname %q ct state established,related accept", t, sb.NsVeth, tap)
	b.line("add chain ip %s input { type filter hook input priority filter; policy accept; }", t)
	b.line("add rule ip %s input iifname %q ct state established,related accept", t, tap)
	b.line("add rule ip %s input iifname %q drop", t, tap)
	return b.String(), nil
}

// Package nft renders egressd's nftables ruleset as text and applies it
// atomically with `nft -f`. egressd only ever touches `table inet egressd`.
//
// Layout:
//
//	table inet egressd
//	  set blocked_ranges, blocked_exempt        (global, interval)
//	  map fwd_vmap, in_vmap                     (ifname -> jump sb_<k> / sbin_<k>)
//	  chain forward     (hook)  iifname vmap @fwd_vmap; unknown veth-h* drop
//	  chain input       (hook)  iifname vmap @in_vmap;  unknown veth-h* drop
//	  chain postrouting (hook)  masquerade sandbox traffic leaving the host
//	  chain sb_<k>      per-sandbox egress policy (PRD §6 rules 1-9)
//	  chain sbin_<k>    per-sandbox access to host-local addresses (DNS proxy only)
//	  set allow_<k>     DNS-learned IPs, per-element timeout
//	  set allow_cidr_<k> static CIDRs from policy
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

	"github.com/anvanster/egressd/internal/addressing"
)

// Table is the only nftables table egressd owns.
const Table = "egressd"

// LogGroup is the NFLOG group deny rules log to.
const LogGroup = 1

// LogPrefixPrefix starts every egressd NFLOG prefix: "egressd:<k>:<reason> ".
const LogPrefixPrefix = "egressd:"

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
)

// DefaultBlockedRanges are never reachable from a sandbox (PRD §6 rule 4),
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

// declareBase emits idempotent declarations of the table, global sets and maps.
func (b *builder) declareBase() {
	b.line("add table inet %s", Table)
	b.line("add set inet %s blocked_ranges { type ipv4_addr; flags interval; auto-merge; }", Table)
	b.line("add set inet %s blocked_exempt { type ipv4_addr; flags interval; auto-merge; }", Table)
	b.line("add map inet %s fwd_vmap { type ifname : verdict; }", Table)
	b.line("add map inet %s in_vmap { type ifname : verdict; }", Table)
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

	b.line("add chain inet %s forward { type filter hook forward priority filter; policy accept; }", t)
	b.line("flush chain inet %s forward", t)
	b.line("add rule inet %s forward iifname vmap @fwd_vmap", t)
	b.line("add rule inet %s forward iifname \"veth-h*\" %s", t, logDrop(0, ReasonUnknownIface))
	b.line("add rule inet %s forward oifname \"veth-h*\" ct state established,related accept", t)
	b.line("add rule inet %s forward oifname \"veth-h*\" counter drop", t)

	b.line("add chain inet %s input { type filter hook input priority filter; policy accept; }", t)
	b.line("flush chain inet %s input", t)
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
	b.line("add set inet %s allow_%d { type ipv4_addr; flags timeout; }", t, k)
	if !cfg.PreserveAllowed {
		b.line("flush set inet %s allow_%d", t, k)
		if len(cfg.Allowed) > 0 {
			b.line("add element inet %s allow_%d { %s }", t, k, joinAllow(cfg.Allowed))
		}
	}
	b.line("add set inet %s allow_cidr_%d { type ipv4_addr; flags interval; auto-merge; }", t, k)
	b.line("flush set inet %s allow_cidr_%d", t, k)
	if len(cidrs) > 0 {
		b.line("add element inet %s allow_cidr_%d { %s }", t, k, joinPrefixes(cidrs))
	}

	chain := fmt.Sprintf("add rule inet %s sb_%d", t, k)
	// 1. Return traffic for flows already admitted.
	b.line("%s ct state established,related accept", chain)
	// 2. DNS to the sandbox's own proxy. The proxy address is host-local, so
	//    this traffic is actually admitted by sbin_<k>; kept for parity with PRD §6.
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
	b.line("%s ct state new ct count over %d counter log group %d prefix %q reject",
		chain, cfg.MaxConns, LogGroup, LogPrefix(k, ReasonConnLimit))
	// 7-8. Allowlist.
	b.line("%s ip daddr @allow_%d accept", chain, k)
	b.line("%s ip daddr @allow_cidr_%d accept", chain, k)
	// 9. Default deny.
	b.line("%s %s", chain, logDrop(k, ReasonNotAllowed))

	in := fmt.Sprintf("add rule inet %s sbin_%d", t, k)
	b.line("%s ct state established,related accept", in)
	b.line("%s ip daddr %s meta l4proto { tcp, udp } th dport 53 accept", in, sb.HostAddr)
	b.line("%s %s", in, logDrop(k, ReasonHostAccess))

	b.line("add element inet %s fwd_vmap { %q : jump sb_%d }", t, sb.HostVeth, k)
	b.line("add element inet %s in_vmap { %q : jump sbin_%d }", t, sb.HostVeth, k)
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
	b.line("add set inet %s allow_%d { type ipv4_addr; flags timeout; }", t, k)
	b.line("add set inet %s allow_cidr_%d { type ipv4_addr; flags interval; auto-merge; }", t, k)
	b.line("add element inet %s fwd_vmap { %q : jump sb_%d }", t, sb.HostVeth, k)
	b.line("add element inet %s in_vmap { %q : jump sbin_%d }", t, sb.HostVeth, k)
	b.line("delete element inet %s fwd_vmap { %q }", t, sb.HostVeth)
	b.line("delete element inet %s in_vmap { %q }", t, sb.HostVeth)
	for _, c := range []string{"sb", "sbin"} {
		b.line("flush chain inet %s %s_%d", t, c, k)
		b.line("delete chain inet %s %s_%d", t, c, k)
	}
	b.line("delete set inet %s allow_%d", t, k)
	b.line("delete set inet %s allow_cidr_%d", t, k)
	return b.String(), nil
}

// RenderAllow inserts or refreshes DNS-learned addresses in allow_<k>.
// Re-adding an existing element does not extend its timeout, so each
// address is added (ensuring it exists), deleted, and added again with the
// new timeout, all in one atomic transaction.
func RenderAllow(k int, entries []AllowEntry) string {
	if len(entries) == 0 {
		return ""
	}
	var b builder
	set := fmt.Sprintf("inet %s allow_%d", Table, k)
	b.line("add element %s { %s }", set, joinAllow(entries))
	b.line("delete element %s { %s }", set, joinAddrs(entries))
	b.line("add element %s { %s }", set, joinAllow(entries))
	return b.String()
}

// RenderDeleteTable removes everything egressd ever created in nftables.
func RenderDeleteTable() string {
	return fmt.Sprintf("add table inet %s\ndelete table inet %s\n", Table, Table)
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

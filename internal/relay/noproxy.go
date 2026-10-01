package relay

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// NoProxy is a parsed no_proxy list: destinations that bypass the upstream
// proxy and are forwarded as they would be without one. The sandbox policy
// still applies to them first.
type NoProxy struct {
	// Patterns are name patterns in dnsproxy.Allowlist syntax.
	Patterns []string
	CIDRs    []netip.Prefix
}

// Empty reports whether nothing bypasses the proxy.
func (n NoProxy) Empty() bool { return len(n.Patterns) == 0 && len(n.CIDRs) == 0 }

// ParseNoProxy parses a no_proxy value with the semantics of Go's
// net/http proxy support: entries are separated by commas (or spaces);
// "example.com" matches that name and its subdomains, ".example.com" (or
// "*.example.com") only its subdomains; IPv4 addresses and CIDRs match
// addresses. Ports are ignored, which only widens the entry. IPv6 entries
// and unparsable names are skipped and returned as notes for the caller to
// log. A lone "*" is an error: it would disable the proxy altogether.
func ParseNoProxy(s string) (NoProxy, []string, error) {
	var (
		out   NoProxy
		notes []string
		seen  = map[string]bool{}
	)
	addPattern := func(p string) {
		if !seen[p] {
			seen[p] = true
			out.Patterns = append(out.Patterns, p)
		}
	}
	for _, raw := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		e := strings.ToLower(strings.TrimSpace(raw))
		if e == "*" {
			return NoProxy{}, nil, errors.New("no_proxy=* would bypass the proxy for everything; run without an upstream proxy instead")
		}
		if p, err := netip.ParsePrefix(e); err == nil {
			if p.Addr().Is4() {
				out.CIDRs = append(out.CIDRs, p.Masked())
			} else {
				notes = append(notes, fmt.Sprintf("%q: IPv6 is not supported, skipped", raw))
			}
			continue
		}
		host, port := e, ""
		if h, p, err := net.SplitHostPort(e); err == nil {
			host, port = h, p
		}
		host = strings.Trim(host, "[]")
		portNote := func() {
			if port != "" {
				notes = append(notes, fmt.Sprintf("%q: port %s ignored, the entry applies to every port", raw, port))
			}
		}
		if a, err := netip.ParseAddr(host); err == nil {
			if a.Is4() {
				out.CIDRs = append(out.CIDRs, netip.PrefixFrom(a, 32))
				portNote()
			} else {
				notes = append(notes, fmt.Sprintf("%q: IPv6 is not supported, skipped", raw))
			}
			continue
		}
		subOnly := false
		if rest, ok := strings.CutPrefix(host, "*."); ok {
			host, subOnly = rest, true
		} else if rest, ok := strings.CutPrefix(host, "."); ok {
			host, subOnly = rest, true
		}
		host = strings.TrimSuffix(host, ".")
		if !validName(host) {
			notes = append(notes, fmt.Sprintf("%q: not a host name, skipped", raw))
			continue
		}
		if !subOnly {
			addPattern(host)
		}
		addPattern("*." + host)
		portNote()
	}
	return out, notes, nil
}

func validName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

// Package policy parses and validates per-sandbox egress policies.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Defaults applied when a limit is omitted from the policy file.
const (
	DefaultMaxConns        = 64
	DefaultNewConnsPerSec  = 20
	DefaultDNSQPS          = 50
	maxDomainLength        = 253
	defaultUpstreamDNSPort = "53"
)

// Policy is a validated egress policy for one sandbox.
type Policy struct {
	Egress      Egress `yaml:"egress" json:"egress"`
	Limits      Limits `yaml:"limits" json:"limits"`
	UpstreamDNS string `yaml:"upstream_dns,omitempty" json:"upstream_dns,omitempty"`
	// Quarantine configures automatic quarantine; nil means none.
	Quarantine *Quarantine `yaml:"quarantine,omitempty" json:"quarantine,omitempty"`
}

// Quarantine quarantines the sandbox automatically when any trigger fires.
type Quarantine struct {
	// Freeze also stops the sandbox's processes or pauses its VM.
	Freeze   bool      `yaml:"freeze,omitempty" json:"freeze,omitempty"`
	Triggers []Trigger `yaml:"triggers" json:"triggers"`
}

// Trigger fires when Count events with any of Reasons are logged within
// Window.
type Trigger struct {
	Reasons []string `yaml:"reasons" json:"reasons"`
	Count   int      `yaml:"count" json:"count"`
	Window  string   `yaml:"window" json:"window"` // Go duration, e.g. "60s"
}

// WindowDuration returns the parsed window.
func (t Trigger) WindowDuration() time.Duration {
	d, _ := time.ParseDuration(t.Window)
	return d
}

// TriggerReasons are the event reasons a trigger can count: deny reasons
// from the firewall, refusals by the relay, and DNS refusals.
var TriggerReasons = []string{
	// firewall (deny events)
	"dns_bypass", "blocked_range", "not_allowed", "host_access", "rate_limit",
	"conn_limit", "ipv6", "quic_blocked", "no_proxy_route",
	// relay (relay events with verdict deny)
	"sni_mismatch", "host_mismatch", "bad_client_hello", "proxy_refused",
	// DNS proxy: a name that is not allowlisted, and the query rate limit
	"dns_refused", "dns_ratelimited",
}

// Bounds on triggers, so a policy cannot make the daemon keep unbounded
// history.
const (
	MaxTriggerCount  = 10000
	MinTriggerWindow = time.Second
	MaxTriggerWindow = 24 * time.Hour
)

// Egress holds the allowlist.
type Egress struct {
	Default      string   `yaml:"default" json:"default"`
	AllowDomains []string `yaml:"allow_domains" json:"allow_domains"`
	AllowCIDRs   []string `yaml:"allow_cidrs" json:"allow_cidrs"`
}

// Limits holds rate and connection limits. Bandwidths are kept as the
// original strings for display; use the parsed accessors for values.
type Limits struct {
	MaxEgressBW    string `yaml:"max_egress_bw,omitempty" json:"max_egress_bw,omitempty"`
	MaxIngressBW   string `yaml:"max_ingress_bw,omitempty" json:"max_ingress_bw,omitempty"`
	MaxConns       int    `yaml:"max_conns,omitempty" json:"max_conns,omitempty"`
	NewConnsPerSec int    `yaml:"new_conns_per_sec,omitempty" json:"new_conns_per_sec,omitempty"`
	DNSQPS         int    `yaml:"dns_qps,omitempty" json:"dns_qps,omitempty"`
}

// Load reads and validates a policy file.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return p, nil
}

// Parse decodes YAML, rejects unknown fields, applies defaults and validates.
func Parse(data []byte) (*Policy, error) {
	var p Policy
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	if err := p.normalize(); err != nil {
		return nil, err
	}
	return &p, nil
}

func (p *Policy) normalize() error {
	var errs []error

	switch p.Egress.Default {
	case "", "deny":
		p.Egress.Default = "deny"
	default:
		errs = append(errs, fmt.Errorf("egress.default: only \"deny\" is supported, got %q", p.Egress.Default))
	}

	domains := make([]string, 0, len(p.Egress.AllowDomains))
	for _, d := range p.Egress.AllowDomains {
		n, err := NormalizePattern(d)
		if err != nil {
			errs = append(errs, fmt.Errorf("egress.allow_domains: %w", err))
			continue
		}
		domains = append(domains, n)
	}
	p.Egress.AllowDomains = domains

	cidrs := make([]string, 0, len(p.Egress.AllowCIDRs))
	for _, c := range p.Egress.AllowCIDRs {
		pfx, err := parseIPv4Prefix(c)
		if err != nil {
			errs = append(errs, fmt.Errorf("egress.allow_cidrs: %w", err))
			continue
		}
		cidrs = append(cidrs, pfx.String())
	}
	p.Egress.AllowCIDRs = cidrs

	for name, bw := range map[string]string{"max_egress_bw": p.Limits.MaxEgressBW, "max_ingress_bw": p.Limits.MaxIngressBW} {
		if bw == "" {
			continue
		}
		if _, err := ParseBandwidth(bw); err != nil {
			errs = append(errs, fmt.Errorf("limits.%s: %w", name, err))
		}
	}

	for name, v := range map[string]*int{
		"max_conns":         &p.Limits.MaxConns,
		"new_conns_per_sec": &p.Limits.NewConnsPerSec,
		"dns_qps":           &p.Limits.DNSQPS,
	} {
		if *v < 0 {
			errs = append(errs, fmt.Errorf("limits.%s: must be positive, got %d", name, *v))
		}
	}
	if p.Limits.MaxConns == 0 {
		p.Limits.MaxConns = DefaultMaxConns
	}
	if p.Limits.NewConnsPerSec == 0 {
		p.Limits.NewConnsPerSec = DefaultNewConnsPerSec
	}
	if p.Limits.DNSQPS == 0 {
		p.Limits.DNSQPS = DefaultDNSQPS
	}

	if p.UpstreamDNS != "" {
		up, err := normalizeUpstream(p.UpstreamDNS)
		if err != nil {
			errs = append(errs, fmt.Errorf("upstream_dns: %w", err))
		} else {
			p.UpstreamDNS = up
		}
	}

	if q := p.Quarantine; q != nil {
		if len(q.Triggers) == 0 {
			errs = append(errs, errors.New("quarantine: needs at least one trigger"))
		}
		for i := range q.Triggers {
			t := &q.Triggers[i]
			where := fmt.Sprintf("quarantine.triggers[%d]", i)
			if len(t.Reasons) == 0 {
				errs = append(errs, fmt.Errorf("%s.reasons: needs at least one reason", where))
			}
			var reasons []string
			for _, r := range t.Reasons {
				r = strings.ToLower(strings.TrimSpace(r))
				switch {
				case !slices.Contains(TriggerReasons, r):
					errs = append(errs, fmt.Errorf("%s.reasons: unknown reason %q (one of %s)", where, r, strings.Join(TriggerReasons, ", ")))
				case !slices.Contains(reasons, r):
					reasons = append(reasons, r)
				}
			}
			t.Reasons = reasons
			if t.Count < 1 || t.Count > MaxTriggerCount {
				errs = append(errs, fmt.Errorf("%s.count: must be between 1 and %d, got %d", where, MaxTriggerCount, t.Count))
			}
			d, err := time.ParseDuration(t.Window)
			switch {
			case err != nil:
				errs = append(errs, fmt.Errorf("%s.window: %q is not a duration such as \"60s\" or \"5m\"", where, t.Window))
			case d < MinTriggerWindow || d > MaxTriggerWindow:
				errs = append(errs, fmt.Errorf("%s.window: must be between %s and %s, got %s", where, MinTriggerWindow, MaxTriggerWindow, d))
			default:
				t.Window = d.String()
			}
		}
	}

	return errors.Join(errs...)
}

// EgressBitsPerSec returns the sandbox-to-world bandwidth cap, or 0 for none.
func (p *Policy) EgressBitsPerSec() uint64 {
	v, _ := ParseBandwidth(p.Limits.MaxEgressBW)
	return v
}

// IngressBitsPerSec returns the world-to-sandbox bandwidth cap, or 0 for none.
func (p *Policy) IngressBitsPerSec() uint64 {
	v, _ := ParseBandwidth(p.Limits.MaxIngressBW)
	return v
}

// NormalizePattern validates a domain allowlist entry and returns it in
// canonical form: lower case, no trailing dot. A leading "*." is the only
// wildcard form allowed and matches strict subdomains.
func NormalizePattern(s string) (string, error) {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	name := strings.TrimPrefix(d, "*.")
	if strings.Contains(name, "*") {
		return "", fmt.Errorf("%q: wildcard is only allowed as a leading \"*.\"", s)
	}
	if err := validateHostname(name); err != nil {
		return "", fmt.Errorf("%q: %w", s, err)
	}
	if name != d && !strings.Contains(name, ".") {
		return "", fmt.Errorf("%q: wildcard must cover at least a second-level domain", s)
	}
	return d, nil
}

func validateHostname(name string) error {
	if name == "" {
		return errors.New("empty domain")
	}
	if len(name) > maxDomainLength {
		return errors.New("domain too long")
	}
	if net.ParseIP(name) != nil {
		return errors.New("IP addresses belong in allow_cidrs")
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("invalid label %q", label)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("label %q starts or ends with a hyphen", label)
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return fmt.Errorf("label %q contains invalid character %q", label, c)
			}
		}
	}
	return nil
}

func parseIPv4Prefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	var pfx netip.Prefix
	if strings.Contains(s, "/") {
		var err error
		if pfx, err = netip.ParsePrefix(s); err != nil {
			return netip.Prefix{}, fmt.Errorf("%q: %w", s, err)
		}
	} else {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%q: %w", s, err)
		}
		pfx = netip.PrefixFrom(addr, addr.BitLen())
	}
	if !pfx.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("%q: only IPv4 is supported", s)
	}
	return pfx.Masked(), nil
}

func normalizeUpstream(s string) (string, error) {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		host, port = s, defaultUpstreamDNSPort
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.Is4() {
		return "", fmt.Errorf("%q: must be an IPv4 address with optional :port", s)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("%q: invalid port", s)
	}
	return net.JoinHostPort(host, port), nil
}

// ParseBandwidth parses tc-style rates (bit, kbit, mbit, gbit; decimal
// multipliers) into bits per second. An empty string means no limit.
func ParseBandwidth(s string) (uint64, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return 0, nil
	}
	units := []struct {
		suffix string
		mult   uint64
	}{{"gbit", 1e9}, {"mbit", 1e6}, {"kbit", 1e3}, {"bit", 1}}
	for _, u := range units {
		if num, ok := strings.CutSuffix(s, u.suffix); ok {
			v, err := strconv.ParseUint(strings.TrimSpace(num), 10, 64)
			if err != nil || v == 0 {
				return 0, fmt.Errorf("%q: expected a positive integer before %q", s, u.suffix)
			}
			return v * u.mult, nil
		}
	}
	return 0, fmt.Errorf("%q: unit must be one of bit, kbit, mbit, gbit", s)
}

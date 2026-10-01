// Package policy parses and validates per-sandbox egress policies.
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

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
}

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

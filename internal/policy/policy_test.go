package policy

import (
	"strings"
	"testing"
)

const prdExample = `
egress:
  default: deny
  allow_domains:
    - pypi.org
    - files.pythonhosted.org
    - GitHub.com.
    - "*.githubusercontent.com"
  allow_cidrs: [203.0.113.7, 198.51.100.0/24]
limits:
  max_egress_bw: 50mbit
  max_ingress_bw: 200mbit
  max_conns: 64
  new_conns_per_sec: 20
  dns_qps: 50
upstream_dns: 1.1.1.1
`

func TestParsePRDExample(t *testing.T) {
	p, err := Parse([]byte(prdExample))
	if err != nil {
		t.Fatal(err)
	}
	wantDomains := []string{"pypi.org", "files.pythonhosted.org", "github.com", "*.githubusercontent.com"}
	if strings.Join(p.Egress.AllowDomains, ",") != strings.Join(wantDomains, ",") {
		t.Errorf("domains = %v, want %v", p.Egress.AllowDomains, wantDomains)
	}
	if got := strings.Join(p.Egress.AllowCIDRs, ","); got != "203.0.113.7/32,198.51.100.0/24" {
		t.Errorf("cidrs = %s", got)
	}
	if p.EgressBitsPerSec() != 50_000_000 || p.IngressBitsPerSec() != 200_000_000 {
		t.Errorf("bandwidth = %d/%d", p.EgressBitsPerSec(), p.IngressBitsPerSec())
	}
	if p.UpstreamDNS != "1.1.1.1:53" {
		t.Errorf("upstream = %q", p.UpstreamDNS)
	}
}

func TestParseDefaults(t *testing.T) {
	p, err := Parse([]byte("egress:\n  allow_domains: [example.com]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Egress.Default != "deny" || p.Limits.MaxConns != DefaultMaxConns ||
		p.Limits.NewConnsPerSec != DefaultNewConnsPerSec || p.Limits.DNSQPS != DefaultDNSQPS {
		t.Errorf("defaults not applied: %+v", p)
	}
	if p.EgressBitsPerSec() != 0 {
		t.Errorf("expected unlimited egress")
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"unknown field":     "egress:\n  allow_domain: [x.com]\n",
		"default allow":     "egress:\n  default: allow\n",
		"mid wildcard":      "egress:\n  allow_domains: [\"foo.*.com\"]\n",
		"tld wildcard":      "egress:\n  allow_domains: [\"*.com\"]\n",
		"ip as domain":      "egress:\n  allow_domains: [1.2.3.4]\n",
		"bad label":         "egress:\n  allow_domains: [\"-x.com\"]\n",
		"ipv6 cidr":         "egress:\n  allow_cidrs: [\"2001:db8::/32\"]\n",
		"bad cidr":          "egress:\n  allow_cidrs: [\"10.0.0.0/33\"]\n",
		"bad bandwidth":     "limits:\n  max_egress_bw: 50mb\n",
		"zero bandwidth":    "limits:\n  max_egress_bw: 0mbit\n",
		"negative conns":    "limits:\n  max_conns: -1\n",
		"hostname upstream": "upstream_dns: dns.google\n",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(doc)); err == nil {
				t.Errorf("expected error for %q", doc)
			}
		})
	}
}

func TestParseBandwidth(t *testing.T) {
	cases := map[string]uint64{"": 0, "10mbit": 10_000_000, "1gbit": 1_000_000_000, "512kbit": 512_000, "800bit": 800, " 5 Mbit ": 5_000_000}
	for in, want := range cases {
		got, err := ParseBandwidth(in)
		if err != nil || got != want {
			t.Errorf("ParseBandwidth(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
}

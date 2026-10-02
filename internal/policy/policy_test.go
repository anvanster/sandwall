package policy

import (
	"strings"
	"testing"
	"time"
)

const fullExample = `
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

func TestParseFullExample(t *testing.T) {
	p, err := Parse([]byte(fullExample))
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

func TestQuarantineTriggers(t *testing.T) {
	p, err := Parse([]byte(`
egress: {allow_domains: [pypi.org]}
quarantine:
  freeze: true
  triggers:
    - {reasons: [DNS_Bypass, sni_mismatch, dns_bypass], count: 3, window: 60s}
    - {reasons: [dns_refused], count: 20, window: 5m}
`))
	if err != nil {
		t.Fatal(err)
	}
	q := p.Quarantine
	if q == nil || !q.Freeze || len(q.Triggers) != 2 {
		t.Fatalf("%+v", q)
	}
	if got := strings.Join(q.Triggers[0].Reasons, ","); got != "dns_bypass,sni_mismatch" {
		t.Errorf("reasons not normalized: %s", got)
	}
	if q.Triggers[0].Window != "1m0s" || q.Triggers[1].WindowDuration() != 5*time.Minute {
		t.Errorf("windows %q %v", q.Triggers[0].Window, q.Triggers[1].WindowDuration())
	}
	if p, err := Parse([]byte("egress: {allow_domains: [pypi.org]}\n")); err != nil || p.Quarantine != nil {
		t.Errorf("no quarantine block: %+v %v", p.Quarantine, err)
	}

	for name, bad := range map[string]string{
		"no triggers":    `quarantine: {freeze: true}`,
		"empty reasons":  `quarantine: {triggers: [{reasons: [], count: 1, window: 1s}]}`,
		"unknown reason": `quarantine: {triggers: [{reasons: [quarantined], count: 1, window: 1s}]}`,
		"zero count":     `quarantine: {triggers: [{reasons: [dns_bypass], count: 0, window: 1s}]}`,
		"huge count":     `quarantine: {triggers: [{reasons: [dns_bypass], count: 10001, window: 1s}]}`,
		"bad window":     `quarantine: {triggers: [{reasons: [dns_bypass], count: 1, window: soon}]}`,
		"short window":   `quarantine: {triggers: [{reasons: [dns_bypass], count: 1, window: 10ms}]}`,
		"long window":    `quarantine: {triggers: [{reasons: [dns_bypass], count: 1, window: 48h}]}`,
		"unknown field":  `quarantine: {triggers: [{reasons: [dns_bypass], count: 1, window: 1s, action: kill}]}`,
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestMultitenantWildcards(t *testing.T) {
	p, err := Parse([]byte(`
egress:
  allow_domains: ["*.vercel.app", "*.amazonaws.com", "*.co.uk", "*.github.io", "*.foo.vercel.app", "vercel.app", pypi.org, "*.files.pythonhosted.org"]
  allow_multitenant: ["*.GitHub.io"]
`))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]MultitenantWildcard{}
	for _, m := range p.MultitenantWildcards() {
		got[m.Pattern] = m
	}
	if len(got) != 4 {
		t.Fatalf("findings %v", got)
	}
	if m := got["*.amazonaws.com"]; !strings.HasSuffix(m.Suffix, ".amazonaws.com") || m.Acknowledged {
		t.Errorf("*.amazonaws.com: %+v", m)
	}
	if m := got["*.github.io"]; !m.Acknowledged {
		t.Errorf("acknowledgement not applied: %+v", m)
	}
	err = p.Lint()
	if err == nil {
		t.Fatal("unacknowledged wildcards passed Lint")
	}
	for _, want := range []string{`"*.vercel.app" matches every site hosted under the public suffix "vercel.app"`, `"*.co.uk"`, "allow_multitenant"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Lint error lacks %q:\n%v", want, err)
		}
	}
	if strings.Contains(err.Error(), "github.io") || strings.Contains(err.Error(), "foo.vercel.app") {
		t.Errorf("Lint reported an acknowledged or single-tenant pattern:\n%v", err)
	}

	if _, err := Parse([]byte("egress:\n  allow_domains: [pypi.org]\n  allow_multitenant: [\"*.vercel.app\"]\n")); err == nil {
		t.Error("acknowledgement of a pattern missing from allow_domains accepted")
	}
	clean, err := Parse([]byte("egress:\n  allow_domains: [pypi.org, \"*.files.pythonhosted.org\"]\n"))
	if err != nil || clean.Lint() != nil {
		t.Errorf("clean policy: %v %v", err, clean.Lint())
	}
}

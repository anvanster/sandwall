//go:build linux

package main

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/anvanster/sandwall/internal/relay"
)

func TestSyntheticPoolValidation(t *testing.T) {
	up, err := relay.ParseUpstream("http://proxy.example:3128")
	if err != nil {
		t.Fatal(err)
	}
	np := relay.NoProxy{CIDRs: []netip.Prefix{netip.MustParsePrefix("198.19.0.0/16")}}
	exempt := []netip.Prefix{netip.MustParsePrefix("198.18.5.0/24")}

	if p, err := syntheticPool(false, false, "198.18.0.0/15", nil, relay.NoProxy{}, nil); err != nil || p.IsValid() {
		t.Errorf("off: %v, %v", p, err)
	}
	if p, err := syntheticPool(true, false, "198.18.0.0/15", up, relay.NoProxy{}, nil); err != nil || p.String() != "198.18.0.0/15" {
		t.Errorf("default pool: %v, %v", p, err)
	}
	for name, tc := range map[string]struct {
		enabled, poolSet bool
		raw              string
		up               *relay.Upstream
		np               relay.NoProxy
		exempt           []netip.Prefix
		want             string
	}{
		"pool without the mode": {false, true, "198.18.0.0/15", up, relay.NoProxy{}, nil, "needs --synthetic-dns"},
		"no upstream proxy":     {true, false, "198.18.0.0/15", nil, relay.NoProxy{}, nil, "needs --upstream-proxy"},
		"not a CIDR":            {true, true, "198.18.0.1", up, relay.NoProxy{}, nil, "IPv4 CIDR"},
		"IPv6":                  {true, true, "fd00::/64", up, relay.NoProxy{}, nil, "IPv4 CIDR"},
		"too small":             {true, true, "198.18.0.0/28", up, relay.NoProxy{}, nil, "too small"},
		"blocked range":         {true, true, "10.64.0.0/16", up, relay.NoProxy{}, nil, "overlaps 10.0.0.0/8"},
		"no_proxy CIDR":         {true, false, "198.18.0.0/15", up, np, nil, "overlaps 198.19.0.0/16"},
		"blocked-exempt range":  {true, false, "198.18.0.0/15", up, relay.NoProxy{}, exempt, "overlaps 198.18.5.0/24"},
	} {
		_, err := syntheticPool(tc.enabled, tc.poolSet, tc.raw, tc.up, tc.np, tc.exempt)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err %v, want %q", name, err, tc.want)
		}
	}
}

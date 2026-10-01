//go:build linux

package flowlog

import (
	"fmt"
	"net/netip"

	"github.com/ti-mo/conntrack"
)

// KillFlows deletes every conntrack entry whose original source is src.
// The flow collector logs each one from its DESTROY event, with the bytes
// counted so far, and a flow cut this way cannot resume as established.
func KillFlows(src netip.Addr) (int, error) {
	c, err := conntrack.Dial(nil)
	if err != nil {
		return 0, fmt.Errorf("conntrack: %w", err)
	}
	defer c.Close()
	flows, err := c.Dump(nil)
	if err != nil {
		return 0, fmt.Errorf("conntrack dump: %w", err)
	}
	n := 0
	for _, f := range flows {
		if f.TupleOrig.IP.SourceAddress != src {
			continue
		}
		if err := c.Delete(f); err == nil {
			n++
		}
	}
	return n, nil
}

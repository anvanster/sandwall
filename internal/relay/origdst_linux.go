//go:build linux

package relay

import (
	"fmt"
	"net"
	"net/netip"

	"golang.org/x/sys/unix"
)

// originalDst returns the destination a REDIRECTed connection was sent to,
// from conntrack via SO_ORIGINAL_DST.
func originalDst(c *net.TCPConn) (netip.AddrPort, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	var (
		mreq *unix.IPv6Mreq
		serr error
	)
	// SO_ORIGINAL_DST fills a sockaddr_in; IPv6Mreq is the 20-byte struct
	// x/sys offers for it: family(2) port(2, big endian) addr(4) zero(8).
	if err := raw.Control(func(fd uintptr) {
		mreq, serr = unix.GetsockoptIPv6Mreq(int(fd), unix.SOL_IP, unix.SO_ORIGINAL_DST)
	}); err != nil {
		return netip.AddrPort{}, err
	}
	if serr != nil {
		return netip.AddrPort{}, fmt.Errorf("SO_ORIGINAL_DST: %w", serr)
	}
	b := mreq.Multiaddr
	port := uint16(b[2])<<8 | uint16(b[3])
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{b[4], b[5], b[6], b[7]}), port), nil
}

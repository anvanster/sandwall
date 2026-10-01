//go:build !linux

package relay

import (
	"errors"
	"net"
	"net/netip"
)

func originalDst(*net.TCPConn) (netip.AddrPort, error) {
	return netip.AddrPort{}, errors.New("SO_ORIGINAL_DST needs Linux")
}

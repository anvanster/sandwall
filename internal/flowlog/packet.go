package flowlog

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strconv"
)

// PacketInfo is the part of an IPv4 header a deny log needs.
type PacketInfo struct {
	Proto   string
	Src     netip.Addr
	Dst     netip.Addr
	DstPort uint16
}

// ParseIPv4 extracts protocol, addresses and destination port from a raw
// IPv4 packet as delivered by NFLOG.
func ParseIPv4(b []byte) (PacketInfo, error) {
	if len(b) < 20 || b[0]>>4 != 4 {
		return PacketInfo{}, errors.New("not an IPv4 packet")
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl {
		return PacketInfo{}, errors.New("truncated IPv4 header")
	}
	p := PacketInfo{
		Proto: ProtoName(b[9]),
		Src:   netip.AddrFrom4([4]byte(b[12:16])),
		Dst:   netip.AddrFrom4([4]byte(b[16:20])),
	}
	fragOffset := binary.BigEndian.Uint16(b[6:8]) & 0x1fff
	if (b[9] == 6 || b[9] == 17) && fragOffset == 0 && len(b) >= ihl+4 {
		p.DstPort = binary.BigEndian.Uint16(b[ihl+2 : ihl+4])
	}
	return p, nil
}

// ProtoName maps an IP protocol number to a short name.
func ProtoName(n uint8) string {
	switch n {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return strconv.Itoa(int(n))
	}
}

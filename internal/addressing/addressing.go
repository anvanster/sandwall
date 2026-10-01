// Package addressing derives every per-sandbox name and address from the
// sandbox index k, so all packages agree on one layout.
package addressing

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
)

// Index limits: k is the third octet of 10.200.k.0/30.
const (
	MinIndex = 1
	MaxIndex = 254
)

// TransferSupernet covers every sandbox transfer net.
var TransferSupernet = netip.MustParsePrefix("10.200.0.0/16")

// Guest-side constants for VM mode. They are identical in every sandbox,
// which is what makes snapshot clones work.
var (
	TapAddr   = netip.MustParseAddr("172.16.0.1")
	GuestAddr = netip.MustParseAddr("172.16.0.2")
)

// TapName is the tap device name inside every VM-mode netns.
const TapName = "tap0"

var (
	netnsPattern    = regexp.MustCompile(`^sb([0-9]+)$`)
	hostVethPattern = regexp.MustCompile(`^veth-h([0-9]+)$`)
	ifbPattern      = regexp.MustCompile(`^eg-ifb([0-9]+)$`)
)

// Sandbox holds the derived names and addresses for index k.
type Sandbox struct {
	Index    int
	Netns    string // sb<k>
	HostVeth string // veth-h<k>
	NsVeth   string // veth-s<k>
	IFB      string // eg-ifb<k>: carries sandbox->world traffic for shaping
	HostAddr netip.Addr
	NsAddr   netip.Addr
	Transfer netip.Prefix // 10.200.k.0/30
}

// For returns the layout for sandbox index k.
func For(k int) (Sandbox, error) {
	if k < MinIndex || k > MaxIndex {
		return Sandbox{}, fmt.Errorf("sandbox index %d out of range [%d,%d]", k, MinIndex, MaxIndex)
	}
	base := [4]byte{10, 200, byte(k), 0}
	return Sandbox{
		Index:    k,
		Netns:    "sb" + strconv.Itoa(k),
		HostVeth: "veth-h" + strconv.Itoa(k),
		NsVeth:   "veth-s" + strconv.Itoa(k),
		IFB:      "eg-ifb" + strconv.Itoa(k),
		HostAddr: netip.AddrFrom4([4]byte{10, 200, byte(k), 1}),
		NsAddr:   netip.AddrFrom4([4]byte{10, 200, byte(k), 2}),
		Transfer: netip.PrefixFrom(netip.AddrFrom4(base), 30),
	}, nil
}

// MustFor is For for indices already known to be valid.
func MustFor(k int) Sandbox {
	s, err := For(k)
	if err != nil {
		panic(err)
	}
	return s
}

// IndexFromNetns parses "sb<k>", returning false for foreign names.
func IndexFromNetns(name string) (int, bool) { return parseIndex(netnsPattern, name) }

// IndexFromHostVeth parses "veth-h<k>", returning false for foreign names.
func IndexFromHostVeth(name string) (int, bool) { return parseIndex(hostVethPattern, name) }

// IndexFromIFB parses "eg-ifb<k>", returning false for foreign names.
func IndexFromIFB(name string) (int, bool) { return parseIndex(ifbPattern, name) }

func parseIndex(re *regexp.Regexp, name string) (int, bool) {
	m := re.FindStringSubmatch(name)
	if m == nil {
		return 0, false
	}
	k, err := strconv.Atoi(m[1])
	if err != nil || k < MinIndex || k > MaxIndex || strconv.Itoa(k) != m[1] {
		return 0, false
	}
	return k, true
}

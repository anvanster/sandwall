//go:build linux

package nft

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// InsertAllow makes sure each address is in allow_<k> (and direct_<k> when
// direct) for at least its timeout, over netlink rather than an `nft -f`
// process: it runs on every allowed DNS answer, where a process per answer
// cost milliseconds.
//
// Each address is looked up first (GETSETELEM, microseconds):
//   - absent: it is added;
//   - present with at least its timeout left: nothing to do, the common case,
//     as resolver TTLs count down in step with the set's timeouts;
//   - present with less: it is refreshed by add, delete and add in one
//     batch. Adding an element that exists does not extend its timeout, and
//     a commit that deletes elements waits for an RCU grace period (about
//     6.5 ms in a nested VM, against 0.05 ms for a plain add), so refreshes
//     are kept to the cases that need one.
//
// Elements are written with refreshMargin on top of their timeout: the
// resolver's TTL and the set's timeout count down together, so without it a
// re-query within the TTL would always find slightly too little time left and
// refresh. Unlike RenderAllow, it never shortens an element's remaining
// time; removals go through a policy reload, which flushes and refills the
// sets.
func InsertAllow(ctx context.Context, k int, entries []AllowEntry, direct bool) error {
	return insertAllow(ctx, 0, k, entries, direct)
}

// insertAllow is InsertAllow in the network namespace netnsFD (0: the
// caller's), which lets tests use a throwaway namespace.
func insertAllow(ctx context.Context, netnsFD int, k int, entries []AllowEntry, direct bool) error {
	if len(entries) == 0 {
		return nil
	}
	u := sortedUnique(entries)
	padded := make([]AllowEntry, len(u))
	for i, e := range u {
		padded[i] = AllowEntry{Addr: e.Addr, Timeout: time.Duration(elemTimeoutSeconds(e.Timeout))*time.Second + refreshMargin}
	}
	sets := []string{fmt.Sprintf("allow_%d", k)}
	if direct {
		sets = append(sets, fmt.Sprintf("direct_%d", k))
	}
	conn, err := dialNFTables(ctx, netnsFD)
	if err != nil {
		return err
	}
	defer conn.Close()

	var cmds []netlink.Message
	add := func(typ uint16, set string, es []AllowEntry, timeout bool) error {
		m, err := setElemMsg(typ, set, es, timeout)
		cmds = append(cmds, m)
		return err
	}
	for _, set := range sets {
		var absent, short []AllowEntry
		for i, e := range u {
			left, found, err := elemRemaining(conn, set, e.Addr)
			if err != nil {
				return err
			}
			want := time.Duration(elemTimeoutSeconds(e.Timeout)) * time.Second
			switch {
			case !found:
				absent = append(absent, padded[i])
			case left < want:
				short = append(short, padded[i])
			}
		}
		if len(absent) > 0 {
			if err := add(nftMsgNewSetElem, set, absent, true); err != nil {
				return err
			}
		}
		if len(short) > 0 {
			for _, op := range []struct {
				typ     uint16
				timeout bool
			}{{nftMsgNewSetElem, true}, {nftMsgDelSetElem, false}, {nftMsgNewSetElem, true}} {
				if err := add(op.typ, set, short, op.timeout); err != nil {
					return err
				}
			}
		}
	}
	if len(cmds) == 0 {
		return nil
	}
	msgs := append([]netlink.Message{batchMsg(nfnlMsgBatchBegin)}, cmds...)
	return sendBatch(ctx, conn, append(msgs, batchMsg(nfnlMsgBatchEnd)))
}

// elemRemaining looks an address up in a set: whether it is there and how
// long until it expires (a very long time for an element without timeout).
// A missing set also reads as absent; the add that follows then fails.
func elemRemaining(conn *netlink.Conn, set string, addr netip.Addr) (time.Duration, bool, error) {
	m, err := setElemMsg(nftMsgGetSetElem, set, []AllowEntry{{Addr: addr}}, false)
	if err != nil {
		return 0, false, err
	}
	m.Header.Flags = netlink.Request
	replies, err := conn.Execute(m)
	if errors.Is(err, unix.ENOENT) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("nf_tables get %s in %s: %w", addr, set, err)
	}
	for _, r := range replies {
		if exp, ok := parseExpiration(r.Data); ok {
			return exp, true, nil
		}
	}
	return time.Duration(math.MaxInt64), true, nil
}

// parseExpiration reads NFTA_SET_ELEM_EXPIRATION (big-endian milliseconds)
// from a NEWSETELEM reply for one element.
func parseExpiration(data []byte) (time.Duration, bool) {
	if len(data) < 4 {
		return 0, false
	}
	var (
		exp   time.Duration
		found bool
	)
	ad, err := netlink.NewAttributeDecoder(data[4:])
	if err != nil {
		return 0, false
	}
	for ad.Next() {
		if ad.Type() != nftaSetElemListElements {
			continue
		}
		ad.Nested(func(list *netlink.AttributeDecoder) error {
			for list.Next() {
				list.Nested(func(el *netlink.AttributeDecoder) error {
					for el.Next() {
						if el.Type() == nftaSetElemExpiration && len(el.Bytes()) == 8 {
							exp, found = time.Duration(binary.BigEndian.Uint64(el.Bytes()))*time.Millisecond, true
						}
					}
					return nil
				})
			}
			return nil
		})
	}
	return exp, found && ad.Err() == nil
}

// nf_tables netlink constants (linux/netfilter/nfnetlink.h, nf_tables.h).
const (
	nfnlSubsysNFTables = 10
	nfnlMsgBatchBegin  = 0x10 // NLMSG_MIN_TYPE
	nfnlMsgBatchEnd    = 0x11
	nftMsgNewSetElem   = 12
	nftMsgGetSetElem   = 13
	nftMsgDelSetElem   = 14

	nftaSetElemListTable    = 1
	nftaSetElemListSet      = 2
	nftaSetElemListElements = 3
	nftaListElem            = 1
	nftaSetElemKey          = 1
	nftaSetElemTimeout      = 4
	nftaSetElemExpiration   = 5
	nftaDataValue           = 1

	batchTimeout = 5 * time.Second
	// refreshMargin is added to every element's timeout; see InsertAllow.
	refreshMargin = 10 * time.Second
)

// nfgenmsg: family, version (NFNETLINK_V0), and res_id in big endian.
func nfgen(family uint8, resID uint16) []byte {
	return []byte{family, 0, byte(resID >> 8), byte(resID)}
}

func batchMsg(typ uint16) netlink.Message {
	return netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(typ), Flags: netlink.Request},
		Data:   nfgen(unix.AF_UNSPEC, nfnlSubsysNFTables),
	}
}

// setElemMsg builds NEWSETELEM (create, not exclusive) or DELSETELEM for
// the IPv4 elements in table inet sandwall, set set.
func setElemMsg(typ uint16, set string, entries []AllowEntry, timeout bool) (netlink.Message, error) {
	ae := netlink.NewAttributeEncoder()
	ae.String(nftaSetElemListTable, Table)
	ae.String(nftaSetElemListSet, set)
	ae.Nested(nftaSetElemListElements, func(list *netlink.AttributeEncoder) error {
		for _, e := range entries {
			if !e.Addr.Is4() {
				return fmt.Errorf("set element %s is not IPv4", e.Addr)
			}
			list.Nested(nftaListElem, func(el *netlink.AttributeEncoder) error {
				key := e.Addr.As4()
				el.Nested(nftaSetElemKey, func(kv *netlink.AttributeEncoder) error {
					kv.Bytes(nftaDataValue, key[:])
					return nil
				})
				if timeout {
					el.Bytes(nftaSetElemTimeout, binary.BigEndian.AppendUint64(nil, uint64(elemTimeoutSeconds(e.Timeout))*1000))
				}
				return nil
			})
		}
		return nil
	})
	attrs, err := ae.Encode()
	if err != nil {
		return netlink.Message{}, err
	}
	flags := netlink.Request | netlink.Acknowledge
	if typ == nftMsgNewSetElem {
		flags |= netlink.Create
	}
	return netlink.Message{
		Header: netlink.Header{Type: netlink.HeaderType(nfnlSubsysNFTables<<8 | typ), Flags: flags},
		Data:   append(nfgen(unix.NFPROTO_INET, 0), attrs...),
	}, nil
}

// dialNFTables opens a netfilter netlink socket in netnsFD (0: the
// caller's namespace) with a deadline for the whole exchange.
func dialNFTables(ctx context.Context, netnsFD int) (*netlink.Conn, error) {
	conn, err := netlink.Dial(unix.NETLINK_NETFILTER, &netlink.Config{NetNS: netnsFD})
	if err != nil {
		return nil, fmt.Errorf("netlink: %w", err)
	}
	deadline := time.Now().Add(batchTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// sendBatch sends one batch and waits for the acknowledgement of every
// message that asked for one. A failing message aborts the whole batch;
// Receive returns its error.
func sendBatch(ctx context.Context, conn *netlink.Conn, msgs []netlink.Message) error {
	sent, err := conn.SendMessages(msgs)
	if err != nil {
		return fmt.Errorf("nf_tables batch: %w", err)
	}
	want := map[uint32]bool{}
	for _, m := range sent {
		if m.Header.Flags&netlink.Acknowledge != 0 {
			want[m.Header.Sequence] = true
		}
	}
	for len(want) > 0 {
		replies, err := conn.Receive()
		if err != nil {
			return fmt.Errorf("nf_tables batch: %w", err)
		}
		for _, r := range replies {
			if r.Header.Type == netlink.Error {
				delete(want, r.Header.Sequence)
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	return nil
}

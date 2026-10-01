//go:build linux

// Package shaper applies per-sandbox bandwidth limits with tc on the
// host-side veth:
//
//   - world -> sandbox: a tbf root qdisc on veth-h<k>, whose egress carries
//     packets towards the sandbox. Caps max_ingress_bw.
//   - sandbox -> world: packets arriving on veth-h<k> are redirected by an
//     ingress u32 match-all filter to eg-ifb<k>, whose tbf root qdisc
//     shapes them. Caps max_egress_bw.
//
// PRD §6 suggests an ingress policer for sandbox -> world. A policer drops
// instead of queueing, and on a sub-millisecond veth path TCP collapses to a
// fraction of the configured rate. Queueing on an IFB keeps TCP at the cap.
// The u32 filter is used because cls_matchall is not available everywhere.
package shaper

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/anvanster/egressd/internal/addressing"
)

const (
	tcTimeout = 10 * time.Second
	// tbf bucket: 10ms of traffic, at least 64 KiB so GSO packets fit.
	burstWindow = 10 * time.Millisecond
	minBurst    = 64 << 10
	tbfLatency  = "50ms"
)

// Limits are bandwidth caps in bits per second; 0 means unlimited.
type Limits struct {
	EgressBits  uint64 // sandbox -> world
	IngressBits uint64 // world -> sandbox
}

// Apply makes the sandbox's qdiscs match the limits. It is idempotent and
// removes limits that are no longer configured.
func Apply(ctx context.Context, sb addressing.Sandbox, l Limits) error {
	if l.IngressBits > 0 {
		if err := tbf(ctx, sb.HostVeth, l.IngressBits); err != nil {
			return err
		}
	} else if err := deleteQdisc(ctx, sb.HostVeth, "root"); err != nil {
		return err
	}

	if l.EgressBits == 0 {
		if err := deleteQdisc(ctx, sb.HostVeth, "ingress"); err != nil {
			return err
		}
		return deleteIFB(sb.IFB)
	}
	if err := ensureIFB(sb.IFB); err != nil {
		return err
	}
	if err := tbf(ctx, sb.IFB, l.EgressBits); err != nil {
		return err
	}
	if err := tc(ctx, "qdisc", "replace", "dev", sb.HostVeth, "handle", "ffff:", "ingress"); err != nil {
		return err
	}
	return tc(ctx, "filter", "replace", "dev", sb.HostVeth, "parent", "ffff:", "protocol", "all",
		"prio", "1", "handle", "800::1", "u32", "match", "u32", "0", "0",
		"action", "mirred", "egress", "redirect", "dev", sb.IFB)
}

func tbf(ctx context.Context, dev string, rateBits uint64) error {
	burst := max(uint64(float64(rateBits/8)*burstWindow.Seconds()), minBurst)
	return tc(ctx, "qdisc", "replace", "dev", dev, "root", "tbf",
		"rate", strconv.FormatUint(rateBits, 10)+"bit", "burst", strconv.FormatUint(burst, 10), "latency", tbfLatency)
}

func ensureIFB(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if !errors.As(err, &notFound) {
			return fmt.Errorf("look up %s: %w", name, err)
		}
		if err := netlink.LinkAdd(&netlink.Ifb{LinkAttrs: netlink.LinkAttrs{Name: name}}); err != nil {
			return fmt.Errorf("create %s: %w", name, err)
		}
		if link, err = netlink.LinkByName(name); err != nil {
			return err
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("up %s: %w", name, err)
	}
	return nil
}

func deleteIFB(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil // already gone
	}
	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("delete %s: %w", name, err)
	}
	return nil
}

// deleteQdisc removes a root or ingress qdisc, treating "nothing to delete"
// as success.
func deleteQdisc(ctx context.Context, dev, parent string) error {
	err := tc(ctx, "qdisc", "del", "dev", dev, parent)
	if err == nil {
		return nil
	}
	msg := err.Error()
	for _, benign := range []string{"No such file or directory", "Cannot delete qdisc with handle of zero", "Invalid handle", "Cannot find specified qdisc"} {
		if strings.Contains(msg, benign) {
			return nil
		}
	}
	return err
}

func tc(ctx context.Context, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, tcTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "tc", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("tc %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

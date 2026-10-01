//go:build linux

package flowlog

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"

	"github.com/anvanster/sandwall/internal/addressing"
)

const (
	ctReadBuffer = 8 << 20
	ctQueue      = 8192
	ctWorkers    = 2
	// Start times are kept for flows whose DESTROY event never arrives
	// (lost under ENOBUFS) only this long; TCP established times out at 5 days.
	ctStartTTL = 6 * 24 * time.Hour
	ctRetry    = time.Second

	// Conntrack TCP states (enum tcp_conntrack) at which a connection is
	// over even though its entry lingers (TIME_WAIT is 120s by default).
	tcpStateTimeWait = 7
	tcpStateClose    = 8
)

// FlowSource resolves conntrack tuples to sandboxes and domains.
type FlowSource interface {
	SandboxForIndex(k int) (string, bool)
	Domain(k int, ip netip.Addr) string
}

// FlowCounter is notified of every finished flow.
type FlowCounter func(sandboxID string, bytesOut, bytesIn uint64)

// FlowCollector turns conntrack DESTROY events for sandbox traffic into flow
// events. It needs net.netfilter.nf_conntrack_acct=1 for byte counters.
type FlowCollector struct {
	sink  *Sink
	src   FlowSource
	count FlowCounter
	log   *slog.Logger

	// query fetches counters for TCP flows that finished but whose
	// DESTROY event is still minutes away.
	query *conntrack.Conn

	mu      sync.Mutex
	starts  map[uint32]time.Time // conntrack ID -> first seen, for kernels without nf_conntrack_timestamp
	emitted map[uint32]time.Time // flows already logged at TIME_WAIT/CLOSE; their DESTROY is skipped
}

// NewFlowCollector wires a collector to its sink and lookups.
func NewFlowCollector(sink *Sink, src FlowSource, count FlowCounter, log *slog.Logger) *FlowCollector {
	return &FlowCollector{
		sink: sink, src: src, count: count, log: log,
		starts: map[uint32]time.Time{}, emitted: map[uint32]time.Time{},
	}
}

// Run listens for conntrack events until ctx is cancelled, reconnecting if
// the netlink socket fails (for example after a buffer overrun).
func (c *FlowCollector) Run(ctx context.Context) error {
	go c.gc(ctx)
	for {
		err := c.listen(ctx)
		if ctx.Err() != nil {
			return nil
		}
		c.log.Warn("conntrack listener failed; reconnecting", "err", err)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(ctRetry):
		}
	}
}

func (c *FlowCollector) listen(ctx context.Context) error {
	conn, err := conntrack.Dial(nil)
	if err != nil {
		return fmt.Errorf("conntrack dial: %w", err)
	}
	defer conn.Close()
	query, err := conntrack.Dial(nil)
	if err != nil {
		return fmt.Errorf("conntrack dial: %w", err)
	}
	defer query.Close()
	c.query = query
	if err := conn.SetReadBuffer(ctReadBuffer); err != nil {
		c.log.Warn("conntrack: could not enlarge read buffer", "err", err)
	}
	events := make(chan conntrack.Event, ctQueue)
	errs, err := conn.Listen(events, ctWorkers, netfilter.GroupsCT)
	if err != nil {
		return fmt.Errorf("conntrack listen: %w", err)
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errs:
			return err
		case ev := <-events:
			c.handle(ev, time.Now())
		}
	}
}

// sandboxOf maps an original-direction source address to a sandbox index.
// Only the sandbox's own netns address counts; anything else is not ours.
func sandboxOf(src netip.Addr) (int, bool) {
	if !addressing.TransferSupernet.Contains(src) {
		return 0, false
	}
	k := int(src.As4()[2])
	sb, err := addressing.For(k)
	if err != nil || src != sb.NsAddr {
		return 0, false
	}
	return k, true
}

func (c *FlowCollector) handle(ev conntrack.Event, now time.Time) {
	f := ev.Flow
	if f == nil {
		return
	}
	orig := f.TupleOrig
	k, ok := sandboxOf(orig.IP.SourceAddress)
	if !ok {
		return
	}
	dst := orig.IP.DestinationAddress
	if sb := addressing.MustFor(k); dst == sb.HostAddr {
		return // DNS to the sandbox's own proxy is logged by the proxy itself
	}

	switch ev.Type {
	case conntrack.EventNew:
		c.mu.Lock()
		c.starts[f.ID] = now
		c.mu.Unlock()

	case conntrack.EventUpdate:
		tcp := f.ProtoInfo.TCP
		if tcp == nil || (tcp.State != tcpStateTimeWait && tcp.State != tcpStateClose) {
			return
		}
		c.mu.Lock()
		_, done := c.emitted[f.ID]
		c.mu.Unlock()
		if done {
			return
		}
		// Update events carry no counters; ask for them.
		full, err := c.query.Get(*f)
		if err != nil {
			return // already gone: the DESTROY event will log it
		}
		c.mu.Lock()
		c.emitted[f.ID] = now
		c.mu.Unlock()
		c.emit(k, &full, now)

	case conntrack.EventDestroy:
		c.mu.Lock()
		_, done := c.emitted[f.ID]
		delete(c.emitted, f.ID)
		c.mu.Unlock()
		if !done {
			c.emit(k, f, now)
		}
	}
}

func (c *FlowCollector) emit(k int, f *conntrack.Flow, now time.Time) {
	orig := f.TupleOrig
	dst := orig.IP.DestinationAddress
	c.mu.Lock()
	start, seen := c.starts[f.ID]
	delete(c.starts, f.ID)
	c.mu.Unlock()
	if !f.Timestamp.Start.IsZero() {
		start, seen = f.Timestamp.Start, true
	}
	end := now
	if !f.Timestamp.Stop.IsZero() {
		end = f.Timestamp.Stop
	}

	id, ok := c.src.SandboxForIndex(k)
	if !ok {
		return
	}
	e := Event{
		TS:        end,
		Type:      TypeFlow,
		SandboxID: id,
		Verdict:   "allow",
		Proto:     ProtoName(orig.Proto.Protocol),
		DstIP:     dst.String(),
		DstPort:   orig.Proto.DestinationPort,
		DstDomain: c.src.Domain(k, dst),
		TSEnd:     &end,
		BytesOut:  f.CountersOrig.Bytes,
		BytesIn:   f.CountersReply.Bytes,
	}
	if seen {
		e.TSStart = &start
	}
	c.sink.Write(e)
	if c.count != nil {
		c.count(id, e.BytesOut, e.BytesIn)
	}
}

func (c *FlowCollector) gc(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			c.mu.Lock()
			for id, s := range c.starts {
				if now.Sub(s) > ctStartTTL {
					delete(c.starts, id)
				}
			}
			for id, s := range c.emitted {
				if now.Sub(s) > ctStartTTL {
					delete(c.emitted, id)
				}
			}
			c.mu.Unlock()
		}
	}
}

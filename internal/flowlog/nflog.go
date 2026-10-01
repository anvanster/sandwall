//go:build linux

package flowlog

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/florianl/go-nflog/v2"

	"github.com/anvanster/egressd/internal/nft"
)

// dedupeWindow suppresses repeated identical deny lines (for example TCP SYN
// retransmits) so a flood of dropped packets cannot flood the log. Metrics
// still count every packet.
const dedupeWindow = time.Second

// Resolver maps a sandbox index from a log prefix to its sandbox ID.
type Resolver func(k int) (sandboxID string, ok bool)

// DenyCounter is notified of every denied packet.
type DenyCounter func(sandboxID, reason string)

// DenyCollector turns NFLOG messages from egressd's deny rules into events.
type DenyCollector struct {
	sink    *Sink
	resolve Resolver
	count   DenyCounter
	log     *slog.Logger

	mu       sync.Mutex
	lastSeen map[denyKey]time.Time
}

type denyKey struct {
	k       int
	reason  string
	proto   string
	dst     string
	dstPort uint16
}

// NewDenyCollector wires a collector to its sink and lookup functions.
func NewDenyCollector(sink *Sink, resolve Resolver, count DenyCounter, log *slog.Logger) *DenyCollector {
	return &DenyCollector{sink: sink, resolve: resolve, count: count, log: log, lastSeen: map[denyKey]time.Time{}}
}

// Run subscribes to the NFLOG group until ctx is cancelled.
func (c *DenyCollector) Run(ctx context.Context) error {
	nf, err := nflog.Open(&nflog.Config{
		Group:    nft.LogGroup,
		Copymode: nflog.CopyPacket,
		// Headers are all we parse; cap the copy to keep messages small.
		Bufsize: 128,
	})
	if err != nil {
		return fmt.Errorf("nflog open: %w", err)
	}
	defer nf.Close()

	hook := func(a nflog.Attribute) int {
		c.handle(a)
		return 0
	}
	errFn := func(err error) int {
		if ctx.Err() != nil {
			return 1 // shutting down: the library unblocks reads with a deadline
		}
		c.log.Warn("nflog receive error", "err", err)
		return 0 // keep receiving; ENOBUFS under load is recoverable
	}
	if err := nf.RegisterWithErrorFunc(ctx, hook, errFn); err != nil {
		return fmt.Errorf("nflog register: %w", err)
	}
	go c.gc(ctx)
	<-ctx.Done()
	return nil
}

func (c *DenyCollector) handle(a nflog.Attribute) {
	if a.Prefix == nil {
		return
	}
	k, reason, ok := nft.ParseLogPrefix(*a.Prefix)
	if !ok {
		return
	}
	id, ok := c.resolve(k)
	if !ok {
		return
	}
	ev := Event{Type: TypeDeny, SandboxID: id, Verdict: "deny", Reason: reason}
	if a.Timestamp != nil {
		ev.TS = *a.Timestamp
	}
	if a.Payload != nil {
		if p, err := ParseIPv4(*a.Payload); err == nil {
			ev.Proto, ev.DstIP, ev.DstPort = p.Proto, p.Dst.String(), p.DstPort
		}
	}
	if c.count != nil {
		c.count(id, reason)
	}

	key := denyKey{k: k, reason: reason, proto: ev.Proto, dst: ev.DstIP, dstPort: ev.DstPort}
	now := time.Now()
	c.mu.Lock()
	last, seen := c.lastSeen[key]
	suppress := seen && now.Sub(last) < dedupeWindow
	if !suppress {
		c.lastSeen[key] = now
	}
	c.mu.Unlock()
	if !suppress {
		c.sink.Write(ev)
	}
}

func (c *DenyCollector) gc(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			c.mu.Lock()
			for k, v := range c.lastSeen {
				if now.Sub(v) > dedupeWindow {
					delete(c.lastSeen, k)
				}
			}
			c.mu.Unlock()
		}
	}
}

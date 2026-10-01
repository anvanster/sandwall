// Package watchdog quarantines sandboxes automatically. It watches every
// event the daemon logs and counts, per sandbox and trigger, the events
// whose reason the trigger lists. When a trigger's count is reached within
// its window, it fires once and the sandbox is quarantined.
//
// Events are counted as logged, so the deny log's de-duplication applies:
// a burst of identical dropped packets (same reason, protocol, destination
// and port) counts at most once per second. Counts measure attempts, not
// packets.
package watchdog

import (
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/anvanster/sandwall/internal/dnsproxy"
	"github.com/anvanster/sandwall/internal/flowlog"
	"github.com/anvanster/sandwall/internal/nft"
	"github.com/anvanster/sandwall/internal/policy"
)

// Trigger reasons that are not event reasons.
const (
	ReasonDNSRefused     = "dns_refused"     // a name that is not allowlisted
	ReasonDNSRateLimited = "dns_ratelimited" // over the policy's dns_qps
)

// Fire quarantines a sandbox. It is called on its own goroutine, once per
// arming.
type Fire func(sandboxID, reason string, freeze bool)

// Watchdog holds the trigger state of every sandbox.
type Watchdog struct {
	fire Fire
	now  func() time.Time

	mu    sync.Mutex
	boxes map[string]*box
}

type box struct {
	q     *policy.Quarantine
	armed bool
	hits  [][]time.Time // per trigger, oldest first, at most Count long
}

// New creates a watchdog that calls fire when a trigger fires.
func New(fire Fire) *Watchdog {
	return &Watchdog{fire: fire, now: time.Now, boxes: map[string]*box{}}
}

// Set (re)configures a sandbox and resets its counts. armed is false while
// the sandbox is quarantined. A nil q removes its triggers.
func (w *Watchdog) Set(sandboxID string, q *policy.Quarantine, armed bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if q == nil {
		delete(w.boxes, sandboxID)
		return
	}
	w.boxes[sandboxID] = &box{q: q, armed: armed, hits: make([][]time.Time, len(q.Triggers))}
}

// Remove forgets a sandbox.
func (w *Watchdog) Remove(sandboxID string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.boxes, sandboxID)
}

// Observe counts one logged event.
func (w *Watchdog) Observe(ev flowlog.Event) {
	reason := Reason(ev)
	if reason == "" {
		return
	}
	now := w.now()
	w.mu.Lock()
	b, ok := w.boxes[ev.SandboxID]
	if !ok || !b.armed {
		w.mu.Unlock()
		return
	}
	for i, t := range b.q.Triggers {
		if !slices.Contains(t.Reasons, reason) {
			continue
		}
		cutoff := now.Add(-t.WindowDuration())
		hits := b.hits[i]
		for len(hits) > 0 && !hits[0].After(cutoff) {
			hits = hits[1:]
		}
		hits = append(hits, now)
		if len(hits) > t.Count {
			hits = hits[len(hits)-t.Count:]
		}
		b.hits[i] = hits
		if len(hits) >= t.Count {
			b.armed = false
			msg := fmt.Sprintf("auto: %d x %s within %s (last: %s %s)",
				t.Count, strings.Join(t.Reasons, "|"), t.WindowDuration(), reason, detail(ev))
			freeze := b.q.Freeze
			w.mu.Unlock()
			go w.fire(ev.SandboxID, msg, freeze)
			return
		}
	}
	w.mu.Unlock()
}

// Reason maps a logged event to the trigger reason it counts as, or "".
func Reason(ev flowlog.Event) string {
	switch ev.Type {
	case flowlog.TypeDeny:
		if ev.Reason == nft.ReasonQuarantined || ev.Reason == nft.ReasonUnknownIface {
			return ""
		}
		return ev.Reason
	case flowlog.TypeRelay:
		if ev.Verdict != "deny" {
			return ""
		}
		return ev.Reason
	case flowlog.TypeDNS:
		switch {
		case ev.Verdict == dnsproxy.VerdictRefused && ev.Reason == "not_allowlisted":
			return ReasonDNSRefused
		case ev.Verdict == dnsproxy.VerdictRateLimited:
			return ReasonDNSRateLimited
		}
	}
	return ""
}

func detail(ev flowlog.Event) string {
	switch {
	case ev.QName != "":
		return ev.QName
	case ev.SNI != "":
		return ev.SNI
	case ev.HTTPHost != "":
		return ev.HTTPHost
	case ev.DstIP != "":
		return net.JoinHostPort(ev.DstIP, strconv.Itoa(int(ev.DstPort)))
	}
	return ""
}

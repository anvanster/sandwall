package watchdog

import (
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anvanster/sandwall/internal/flowlog"
	"github.com/anvanster/sandwall/internal/nft"
	"github.com/anvanster/sandwall/internal/policy"
	"github.com/anvanster/sandwall/internal/relay"
)

type fired struct {
	mu    sync.Mutex
	calls []string
	ch    chan struct{}
}

func (f *fired) fire(id, reason string, freeze bool) {
	f.mu.Lock()
	f.calls = append(f.calls, id+" "+reason)
	f.mu.Unlock()
	f.ch <- struct{}{}
}

func (f *fired) wait(t *testing.T) string {
	t.Helper()
	select {
	case <-f.ch:
	case <-time.After(time.Second):
		t.Fatal("trigger did not fire")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[len(f.calls)-1]
}

func (f *fired) none(t *testing.T) {
	t.Helper()
	select {
	case <-f.ch:
		t.Fatalf("trigger fired: %v", f.calls)
	case <-time.After(50 * time.Millisecond):
	}
}

func setup(t *testing.T) (*Watchdog, *fired, *time.Time) {
	f := &fired{ch: make(chan struct{}, 8)}
	w := New(f.fire)
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	w.now = func() time.Time { return now }
	return w, f, &now
}

func bypass(id, dst string) flowlog.Event {
	return flowlog.Event{Type: flowlog.TypeDeny, SandboxID: id, Verdict: "deny", Reason: nft.ReasonDNSBypass, DstIP: dst, DstPort: 53}
}

var q = &policy.Quarantine{Freeze: true, Triggers: []policy.Trigger{
	{Reasons: []string{"dns_bypass", "sni_mismatch"}, Count: 3, Window: "1m0s"},
	{Reasons: []string{"dns_refused"}, Count: 2, Window: "10s"},
}}

func TestFiresAtCountWithinWindowOnce(t *testing.T) {
	w, f, now := setup(t)
	w.Set("a", q, true)
	w.Set("b", q, true)
	w.Observe(bypass("a", "8.8.8.8"))
	*now = now.Add(30 * time.Second)
	w.Observe(flowlog.Event{Type: flowlog.TypeRelay, SandboxID: "a", Verdict: "deny", Reason: relay.ReasonSNIMismatch, SNI: "evil.test"})
	w.Observe(bypass("b", "8.8.8.8")) // another sandbox's events do not count
	f.none(t)
	*now = now.Add(29 * time.Second)
	w.Observe(bypass("a", "9.9.9.9"))
	got := f.wait(t)
	if !strings.HasPrefix(got, "a auto: 3 x dns_bypass|sni_mismatch within 1m0s (last: dns_bypass 9.9.9.9:53)") {
		t.Errorf("fired with %q", got)
	}
	w.Observe(bypass("a", "8.8.8.8"))
	f.none(t) // fires once per arming
}

func TestWindowExpires(t *testing.T) {
	w, f, now := setup(t)
	w.Set("a", q, true)
	refused := flowlog.Event{Type: flowlog.TypeDNS, SandboxID: "a", Verdict: "refused", Reason: "not_allowlisted", QName: "x.evil.test."}
	w.Observe(refused)
	*now = now.Add(11 * time.Second)
	w.Observe(refused)
	f.none(t)
	*now = now.Add(time.Second)
	w.Observe(refused)
	if got := f.wait(t); !strings.Contains(got, "dns_refused x.evil.test.") {
		t.Errorf("fired with %q", got)
	}
}

func TestDisarmedAndRearmed(t *testing.T) {
	w, f, _ := setup(t)
	w.Set("a", q, false) // quarantined
	for range 5 {
		w.Observe(bypass("a", "8.8.8.8"))
	}
	f.none(t)
	w.Set("a", q, true) // released: counts start from zero
	w.Observe(bypass("a", "8.8.8.8"))
	w.Observe(bypass("a", "8.8.8.8"))
	f.none(t)
	w.Observe(bypass("a", "8.8.8.8"))
	f.wait(t)
	w.Set("a", nil, true)
	for range 5 {
		w.Observe(bypass("a", "8.8.8.8"))
	}
	f.none(t)
}

func TestReason(t *testing.T) {
	for _, tc := range []struct {
		ev   flowlog.Event
		want string
	}{
		{bypass("a", "8.8.8.8"), "dns_bypass"},
		{flowlog.Event{Type: flowlog.TypeDeny, Reason: nft.ReasonQuarantined}, ""},
		{flowlog.Event{Type: flowlog.TypeRelay, Verdict: "allow"}, ""},
		{flowlog.Event{Type: flowlog.TypeRelay, Verdict: "deny", Reason: relay.ReasonHostMismatch}, "host_mismatch"},
		{flowlog.Event{Type: flowlog.TypeDNS, Verdict: "refused", Reason: "not_allowlisted"}, ReasonDNSRefused},
		{flowlog.Event{Type: flowlog.TypeDNS, Verdict: "refused", Reason: "quarantined"}, ""},
		{flowlog.Event{Type: flowlog.TypeDNS, Verdict: "ratelimited"}, ReasonDNSRateLimited},
		{flowlog.Event{Type: flowlog.TypeDNS, Verdict: "allow"}, ""},
		{flowlog.Event{Type: flowlog.TypeFlow}, ""},
	} {
		if got := Reason(tc.ev); got != tc.want {
			t.Errorf("Reason(%+v) = %q, want %q", tc.ev, got, tc.want)
		}
	}
}

// TestTriggerReasonsExist keeps the policy's vocabulary in step with the
// reasons the firewall, relay and watchdog actually produce.
func TestTriggerReasonsExist(t *testing.T) {
	produced := []string{
		nft.ReasonDNSBypass, nft.ReasonBlockedRange, nft.ReasonNotAllowed, nft.ReasonHostAccess,
		nft.ReasonRateLimit, nft.ReasonConnLimit, nft.ReasonIPv6, nft.ReasonQUICBlocked, nft.ReasonNoProxyRoute,
		relay.ReasonSNIMismatch, relay.ReasonHostMismatch, relay.ReasonBadClientHello, relay.ReasonProxyRefused,
		ReasonDNSRefused, ReasonDNSRateLimited,
	}
	for _, r := range policy.TriggerReasons {
		if !slices.Contains(produced, r) {
			t.Errorf("policy accepts %q, which nothing produces", r)
		}
	}
	for _, r := range produced {
		if !slices.Contains(policy.TriggerReasons, r) {
			t.Errorf("%q is produced but not accepted by policy triggers", r)
		}
	}
}

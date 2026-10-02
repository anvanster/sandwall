package alert

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/anvanster/sandwall/internal/flowlog"
	"github.com/anvanster/sandwall/internal/policy"
)

type receiver struct {
	srv    *httptest.Server
	mu     sync.Mutex
	got    []Payload
	sigs   []string
	fail   atomic.Int32 // answer 500 to this many requests first
	block  chan struct{}
	posted chan struct{}
}

func newReceiver(t *testing.T, secret []byte) *receiver {
	r := &receiver{posted: make(chan struct{}, 64)}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if r.block != nil {
			<-r.block
		}
		if r.fail.Add(-1) >= 0 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		body, _ := io.ReadAll(req.Body)
		if secret != nil {
			ts := req.Header.Get("X-Sandwall-Timestamp")
			if req.Header.Get("X-Sandwall-Signature") != "sha256="+Sign(secret, ts, body) {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
		var p Payload
		_ = json.Unmarshal(body, &p)
		r.mu.Lock()
		r.got = append(r.got, p)
		r.sigs = append(r.sigs, req.Header.Get("X-Sandwall-Signature"))
		r.mu.Unlock()
		r.posted <- struct{}{}
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *receiver) wait(t *testing.T, within time.Duration) Payload {
	t.Helper()
	select {
	case <-r.posted:
	case <-time.After(within):
		t.Fatal("no delivery")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.got[len(r.got)-1]
}

func (r *receiver) none(t *testing.T, within time.Duration) {
	t.Helper()
	select {
	case <-r.posted:
		t.Fatalf("unexpected delivery: %+v", r.got[len(r.got)-1])
	case <-time.After(within):
	}
}

type counts struct {
	mu sync.Mutex
	m  map[string]int
}

func (c *counts) count(name, result string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[name+"/"+result]++
}

func (c *counts) get(k string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m[k]
}

// waitFor polls until counter k reaches n: a delivery is counted after the
// receiver has answered.
func (c *counts) waitFor(t *testing.T, k string, n int, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for c.get(k) < n && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := c.get(k); got != n {
		t.Errorf("%s = %d, want %d", k, got, n)
	}
}

func (r *receiver) sig(i int) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sigs[i]
}

func dispatcher(t *testing.T, r *receiver, secret []byte) (*Dispatcher, *counts) {
	u, _ := url.Parse(r.srv.URL + "/hook")
	c := &counts{m: map[string]int{}}
	d := New(Config{Endpoints: []Endpoint{{Name: "ops", URL: u, Secret: secret}}, Count: c.count})
	t.Cleanup(d.Close)
	return d, c
}

func deny(id, reason string) flowlog.Event {
	return flowlog.Event{Type: flowlog.TypeDeny, SandboxID: id, Verdict: "deny", Reason: reason, DstIP: "8.8.8.8", DstPort: 53}
}

func TestBatchesSelectedReasonsAndSigns(t *testing.T) {
	secret := []byte("0123456789abcdef")
	r := newReceiver(t, secret)
	d, c := dispatcher(t, r, secret)
	d.Set("a", &policy.Alerts{Webhooks: []string{"ops"}, Reasons: []string{"dns_bypass"}})
	d.Set("b", &policy.Alerts{Webhooks: []string{"ops"}}) // every violation
	d.Observe(deny("a", "dns_bypass"))
	d.Observe(deny("a", "not_allowed"))                                               // not selected by a
	d.Observe(deny("b", "not_allowed"))                                               // selected by b
	d.Observe(deny("c", "dns_bypass"))                                                // no alerts for c
	d.Observe(flowlog.Event{Type: flowlog.TypeFlow, SandboxID: "b"})                  // not a violation
	d.Observe(flowlog.Event{Type: flowlog.TypeDNS, SandboxID: "b", Verdict: "allow"}) // not a violation
	p := r.wait(t, BatchInterval+2*time.Second)
	if p.Source != "sandwall" || len(p.Events) != 2 || p.Events[0].SandboxID != "a" || p.Events[1].SandboxID != "b" {
		t.Fatalf("payload %+v", p)
	}
	if s := r.sig(0); !strings.HasPrefix(s, "sha256=") {
		t.Errorf("signature %q", s)
	}
	c.waitFor(t, "ops/ok", 1, time.Second)
}

func TestQuarantineFlushesAtOnce(t *testing.T) {
	r := newReceiver(t, nil)
	d, _ := dispatcher(t, r, nil)
	d.Set("a", &policy.Alerts{Webhooks: []string{"ops"}, Reasons: []string{"quarantine", "dns_bypass"}})
	d.Observe(deny("a", "dns_bypass"))
	d.Observe(flowlog.Event{Type: flowlog.TypeQuarantine, SandboxID: "a", Verdict: "quarantined", Reason: "auto: ..."})
	p := r.wait(t, BatchInterval/2)
	if len(p.Events) != 2 || p.Events[1].Type != flowlog.TypeQuarantine {
		t.Fatalf("payload %+v", p)
	}
	if s := r.sig(0); s != "" {
		t.Errorf("signed without a secret: %q", s)
	}
}

func TestRetriesThenGivesUp(t *testing.T) {
	r := newReceiver(t, nil)
	r.fail.Store(2)
	d, c := dispatcher(t, r, nil)
	d.Set("a", &policy.Alerts{Webhooks: []string{"ops"}})
	d.Observe(flowlog.Event{Type: flowlog.TypeQuarantine, SandboxID: "a", Verdict: "quarantined"})
	r.wait(t, 5*time.Second) // third attempt succeeds
	c.waitFor(t, "ops/ok", 1, time.Second)
	r.fail.Store(10)
	d.Observe(flowlog.Event{Type: flowlog.TypeQuarantine, SandboxID: "a", Verdict: "released"})
	c.waitFor(t, "ops/error", 1, 6*time.Second)
}

func TestOverflowIsCountedAndReported(t *testing.T) {
	r := newReceiver(t, nil)
	r.block = make(chan struct{})
	d, c := dispatcher(t, r, nil)
	d.Set("a", &policy.Alerts{Webhooks: []string{"ops"}})
	// The first quarantine event is delivered and blocks the sender; the
	// rest fill the queue and overflow.
	d.Observe(flowlog.Event{Type: flowlog.TypeQuarantine, SandboxID: "a"})
	time.Sleep(100 * time.Millisecond)
	for range QueueSize + 50 {
		d.Observe(deny("a", "dns_bypass"))
	}
	if got := c.get("ops/dropped"); got < 50 {
		t.Fatalf("dropped %d, want at least 50", got)
	}
	close(r.block)
	r.wait(t, time.Second) // the blocked delivery
	var reported int
	deadline := time.After(10 * time.Second)
	for reported == 0 {
		select {
		case <-r.posted:
			r.mu.Lock()
			reported = r.got[len(r.got)-1].Dropped
			r.mu.Unlock()
		case <-deadline:
			t.Fatal("drop count never reported")
		}
	}
	if reported != c.get("ops/dropped") {
		t.Errorf("reported %d dropped, counted %d", reported, c.get("ops/dropped"))
	}
}

func TestCloseFlushes(t *testing.T) {
	r := newReceiver(t, nil)
	u, _ := url.Parse(r.srv.URL)
	d := New(Config{Endpoints: []Endpoint{{Name: "ops", URL: u}}})
	d.Set("a", &policy.Alerts{Webhooks: []string{"ops"}})
	d.Observe(deny("a", "dns_bypass"))
	d.Close()
	r.wait(t, time.Second)
}

func TestParseEndpoints(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	if err := os.WriteFile(key, []byte("  0123456789abcdefXYZ\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	short := filepath.Join(dir, "short")
	_ = os.WriteFile(short, []byte("tiny"), 0o600)
	eps, err := ParseEndpoints([]string{"Ops=https://hooks.example/x", "dev=http://127.0.0.1:9/h"}, []string{"ops=" + key})
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 2 || eps[0].Name != "ops" || string(eps[0].Secret) != "0123456789abcdefXYZ" || eps[1].Secret != nil {
		t.Errorf("%+v", eps)
	}
	for _, bad := range [][2][]string{
		{{"noequals"}, nil},
		{{"ops=ftp://x"}, nil},
		{{"ops=https://"}, nil},
		{{"a b=https://x"}, nil},
		{{"ops=https://x", "ops=https://y"}, nil},
		{{"ops=https://x"}, {"other=" + key}},
		{{"ops=https://x"}, {"ops=" + short}},
		{{"ops=https://x"}, {"ops=/nonexistent"}},
	} {
		if _, err := ParseEndpoints(bad[0], bad[1]); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
}

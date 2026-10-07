package dnsproxy

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/anvanster/sandwall/internal/flowlog"
)

func newPersistentProxy(t *testing.T, statePath string, s Settings) *Proxy {
	t.Helper()
	sink, err := flowlog.NewSink(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	return New(Config{SandboxID: "t", Index: 1, Insert: rec.insert, Sink: sink, StatePath: statePath}, s)
}

func TestSyntheticMappingsSurviveRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dns", "t.json")
	pool := netip.MustParsePrefix("198.18.0.0/24")
	s := Settings{AllowDomains: []string{"*.example.com"}, QPS: 100, Synthetic: pool}

	p1 := newPersistentProxy(t, path, s)
	a := synthAnswer(t, p1, "a.example.com")
	// A new mapping is on disk before the answer is returned, flush or not.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("new mapping not saved at once: %v", err)
	}
	b := synthAnswer(t, p1, "b.example.com")

	p2 := newPersistentProxy(t, path, s)
	if err := p2.loadState(); err != nil {
		t.Fatal(err)
	}
	if d := p2.Domain(a); d != "a.example.com" {
		t.Errorf("after restart Domain(%s) = %q", a, d)
	}
	if again := synthAnswer(t, p2, "a.example.com"); again != a {
		t.Errorf("a.example.com moved from %s to %s across the restart", a, again)
	}
	if c := synthAnswer(t, p2, "c.example.com"); c == a || c == b {
		t.Errorf("c.example.com got %s, an address restored for another name", c)
	}
}

func TestStateDropsExpiredAndSetsAsideUnreadable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "t.json")
	now := time.Now()
	st := stateFile{Version: stateVersion, Entries: []stateEntry{
		{Name: "live.example.com", Addr: netip.MustParseAddr("192.0.2.1"), Expires: now.Add(time.Minute)},
		{Name: "gone.example.com", Addr: netip.MustParseAddr("192.0.2.2"), Expires: now.Add(-time.Minute)},
	}}
	data, _ := json.Marshal(st)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	p := newPersistentProxy(t, path, Settings{AllowDomains: []string{"*.example.com"}, QPS: 100})
	if err := p.loadState(); err != nil {
		t.Fatal(err)
	}
	if p.Domain(netip.MustParseAddr("192.0.2.1")) != "live.example.com" || p.Domain(netip.MustParseAddr("192.0.2.2")) != "" {
		t.Errorf("loaded %+v", p.cache.snapshot(now))
	}

	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	p = newPersistentProxy(t, path, Settings{QPS: 100})
	if err := p.loadState(); err != nil {
		t.Fatal(err)
	}
	if len(p.cache.snapshot(now)) != 0 {
		t.Error("loaded entries from an unreadable file")
	}
	if _, err := os.Stat(path + ".unreadable"); err != nil {
		t.Errorf("unreadable file not set aside: %v", err)
	}
}

func TestStopSavesAndFlusherIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.json")
	p := newPersistentProxy(t, path, Settings{AllowDomains: []string{"*.example.com"}, QPS: 100})
	p.cache.load([]stateEntry{{Name: "x.example.com", Addr: netip.MustParseAddr("192.0.2.9"), Expires: time.Now().Add(time.Minute)}}, time.Now())
	p.stopFlush, p.flushDone = make(chan struct{}), make(chan struct{})
	go p.flusher(p.stopFlush, p.flushDone)
	p.Stop()
	p.Stop() // second call is a no-op
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var st stateFile
	if err := json.Unmarshal(data, &st); err != nil || len(st.Entries) != 1 || st.Entries[0].Name != "x.example.com" {
		t.Errorf("saved %s (%v)", data, err)
	}
}

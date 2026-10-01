//go:build linux

package flowlog

import (
	"encoding/json"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ti-mo/conntrack"
)

type fakeSource struct{}

func (fakeSource) SandboxForIndex(k int) (string, bool) {
	if k == 4 {
		return "box", true
	}
	return "", false
}

func (fakeSource) Domain(k int, ip netip.Addr) string {
	if ip == netip.MustParseAddr("151.101.0.223") {
		return "pypi.org"
	}
	return ""
}

func flow(id uint32, src, dst string, dport uint16) *conntrack.Flow {
	f := &conntrack.Flow{ID: id}
	f.TupleOrig.IP.SourceAddress = netip.MustParseAddr(src)
	f.TupleOrig.IP.DestinationAddress = netip.MustParseAddr(dst)
	f.TupleOrig.Proto.Protocol = 6
	f.TupleOrig.Proto.DestinationPort = dport
	return f
}

func TestSandboxOf(t *testing.T) {
	cases := map[string]int{"10.200.4.2": 4, "10.200.4.1": 0, "10.200.4.3": 0, "10.99.0.1": 0, "10.200.0.2": 0}
	for src, want := range cases {
		k, ok := sandboxOf(netip.MustParseAddr(src))
		if (want != 0) != ok || k != want {
			t.Errorf("sandboxOf(%s) = %d, %v", src, k, ok)
		}
	}
}

func TestFlowCollectorLogsDestroyWithStart(t *testing.T) {
	dir := t.TempDir()
	sink, err := NewSink(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Open("box"); err != nil {
		t.Fatal(err)
	}
	var counted uint64
	c := NewFlowCollector(sink, fakeSource{}, func(id string, out, in uint64) { counted += in }, slog.Default())

	t0 := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	f := flow(7, "10.200.4.2", "151.101.0.223", 443)
	c.handle(conntrack.Event{Type: conntrack.EventNew, Flow: f}, t0)

	done := flow(7, "10.200.4.2", "151.101.0.223", 443)
	done.CountersOrig.Bytes, done.CountersReply.Bytes = 1200, 10_485_760
	c.handle(conntrack.Event{Type: conntrack.EventDestroy, Flow: done}, t0.Add(3*time.Second))

	// Ignored: the sandbox's own DNS proxy, foreign sources, unknown sandboxes.
	c.handle(conntrack.Event{Type: conntrack.EventDestroy, Flow: flow(8, "10.200.4.2", "10.200.4.1", 53)}, t0)
	c.handle(conntrack.Event{Type: conntrack.EventDestroy, Flow: flow(9, "192.168.1.5", "1.1.1.1", 443)}, t0)
	c.handle(conntrack.Event{Type: conntrack.EventDestroy, Flow: flow(10, "10.200.5.2", "1.1.1.1", 443)}, t0)
	sink.CloseAll()

	data, err := os.ReadFile(Path(dir, "box"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 1 {
		t.Fatalf("want 1 flow line, got %d:\n%s", len(lines), data)
	}
	var e Event
	if err := json.Unmarshal([]byte(lines[0]), &e); err != nil {
		t.Fatal(err)
	}
	if e.Type != TypeFlow || e.DstDomain != "pypi.org" || e.DstPort != 443 || e.Proto != "tcp" ||
		e.BytesOut != 1200 || e.BytesIn != 10_485_760 || e.TSStart == nil || !e.TSStart.Equal(t0) ||
		e.TSEnd == nil || !e.TSEnd.Equal(t0.Add(3*time.Second)) {
		t.Errorf("unexpected flow event: %s", lines[0])
	}
	if counted != 10_485_760 {
		t.Errorf("counter saw %d bytes in", counted)
	}
	if len(c.starts) != 0 {
		t.Errorf("start times leaked: %v", c.starts)
	}
}

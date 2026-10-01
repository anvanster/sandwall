package flowlog

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestParseIPv4(t *testing.T) {
	// IPv4/TCP SYN 10.200.1.2 -> 169.254.169.254:80, IHL 5.
	pkt := []byte{
		0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0,
		10, 200, 1, 2,
		169, 254, 169, 254,
		0xc3, 0x50, 0x00, 0x50, // sport 50000, dport 80
	}
	p, err := ParseIPv4(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if p.Proto != "tcp" || p.Dst.String() != "169.254.169.254" || p.DstPort != 80 || p.Src.String() != "10.200.1.2" {
		t.Errorf("got %+v", p)
	}

	// Non-first fragment: no port.
	frag := append([]byte(nil), pkt...)
	frag[6], frag[7] = 0x00, 0x10
	if p, _ := ParseIPv4(frag); p.DstPort != 0 {
		t.Errorf("fragment port = %d", p.DstPort)
	}

	for _, bad := range [][]byte{nil, pkt[:10], {0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}} {
		if _, err := ParseIPv4(bad); err == nil {
			t.Errorf("accepted %x", bad)
		}
	}
}

func TestSinkAndTail(t *testing.T) {
	dir := t.TempDir()
	s, err := NewSink(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Open("a"); err != nil {
		t.Fatal(err)
	}
	s.Write(Event{Type: TypeDNS, SandboxID: "a", Verdict: "allow", QName: "pypi.org."})
	s.Write(Event{Type: TypeDNS, SandboxID: "a", Verdict: "refused", QName: "example.com."})
	s.Write(Event{Type: TypeDeny, SandboxID: "a", Verdict: "deny", Reason: "blocked_range"})
	s.Write(Event{Type: TypeDeny, SandboxID: "b", Verdict: "deny"}) // not open: dropped
	if err := s.Close("a"); err != nil {
		t.Fatal(err)
	}
	s.Write(Event{Type: TypeDeny, SandboxID: "a", Verdict: "deny"}) // closed: dropped

	if _, err := os.Stat(Path(dir, "b")); !os.IsNotExist(err) {
		t.Error("log created for sandbox that was never opened")
	}

	var all, deny bytes.Buffer
	if err := Tail(Path(dir, "a"), &all, Filter{}, false, nil); err != nil {
		t.Fatal(err)
	}
	if err := Tail(Path(dir, "a"), &deny, Filter{DenyOnly: true}, false, nil); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(all.String(), "\n"); n != 3 {
		t.Errorf("all: %d lines\n%s", n, all.String())
	}
	lines := strings.Split(strings.TrimSpace(deny.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("deny-only: %d lines\n%s", len(lines), deny.String())
	}
	var e Event
	if err := json.Unmarshal([]byte(lines[0]), &e); err != nil || e.QName != "example.com." || e.TS.IsZero() {
		t.Errorf("first deny line = %+v, %v", e, err)
	}
}

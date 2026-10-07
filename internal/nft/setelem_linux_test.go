//go:build linux

package nft

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// testNetns creates a throwaway network namespace (root only), so the test
// never touches the host's sandwall table.
func testNetns(t *testing.T) (name string, fd int) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("needs nft")
	}
	name = fmt.Sprintf("sandwall-test-%d", os.Getpid())
	if out, err := exec.Command("ip", "netns", "add", name).CombinedOutput(); err != nil {
		t.Fatalf("ip netns add: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", name).Run() })
	fd, err := unix.Open("/var/run/netns/"+name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(fd) })
	return name, fd
}

// setTimeouts lists a set's elements as address -> timeout in seconds.
func setTimeouts(t *testing.T, ns, set string) map[string]int {
	t.Helper()
	out, err := exec.Command("ip", "netns", "exec", ns, "nft", "-j", "list", "set", "inet", Table, set).Output()
	if err != nil {
		t.Fatalf("nft list set %s: %v", set, err)
	}
	var doc struct {
		Nftables []struct {
			Set *struct {
				Elem []struct {
					Elem struct {
						Val     string `json:"val"`
						Timeout int    `json:"timeout"`
					} `json:"elem"`
				} `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("%s: %v", out, err)
	}
	got := map[string]int{}
	for _, item := range doc.Nftables {
		if item.Set == nil {
			continue
		}
		for _, e := range item.Set.Elem {
			got[e.Elem.Val] = e.Elem.Timeout
		}
	}
	return got
}

func TestInsertAllowNetlink(t *testing.T) {
	ns, fd := testNetns(t)
	ctx := context.Background()
	sandbox, err := RenderSandbox(SandboxConfig{Index: 3, MaxConns: 64, NewConnsPerSec: 20})
	if err != nil {
		t.Fatal(err)
	}
	if err := ApplyInNetns(ctx, ns, RenderBase(BaseConfig{BlockedRanges: DefaultBlockedRanges})+sandbox); err != nil {
		t.Fatal(err)
	}
	a := netip.MustParseAddr

	err = insertAllow(ctx, fd, 3, []AllowEntry{
		{Addr: a("1.1.1.1"), Timeout: 90 * time.Second},
		{Addr: a("8.8.8.8"), Timeout: 500 * time.Millisecond},
		{Addr: a("1.1.1.1"), Timeout: 60 * time.Second}, // duplicate: the longest wins
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	// Written with refreshMargin (10s) on top.
	want := map[string]int{"1.1.1.1": 100, "8.8.8.8": 11}
	for _, set := range []string{"allow_3", "direct_3"} {
		if got := setTimeouts(t, ns, set); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%s = %v, want %v", set, got, want)
		}
	}

	// Re-inserting with a longer timeout refreshes the element; with a
	// shorter one it is left alone (never shortened).
	if err := insertAllow(ctx, fd, 3, []AllowEntry{{Addr: a("1.1.1.1"), Timeout: 300 * time.Second}}, false); err != nil {
		t.Fatal(err)
	}
	if got := setTimeouts(t, ns, "allow_3")["1.1.1.1"]; got != 310 {
		t.Errorf("raised timeout = %d, want 310", got)
	}
	if err := insertAllow(ctx, fd, 3, []AllowEntry{{Addr: a("1.1.1.1"), Timeout: 30 * time.Second}}, false); err != nil {
		t.Fatal(err)
	}
	if got := setTimeouts(t, ns, "allow_3")["1.1.1.1"]; got != 310 {
		t.Errorf("a shorter insert changed the timeout to %d, want it kept at 310", got)
	}
	if got := setTimeouts(t, ns, "direct_3")["1.1.1.1"]; got != 100 {
		t.Errorf("direct=false touched direct_3: timeout %d", got)
	}

	// An element the text path wrote with exactly the timeout has slightly
	// less left a moment later, so the netlink path refreshes it.
	entries := []AllowEntry{{Addr: a("9.9.9.9"), Timeout: 120 * time.Second}}
	if err := ApplyInNetns(ctx, ns, RenderAllow(3, entries, false)); err != nil {
		t.Fatal(err)
	}
	viaText := setTimeouts(t, ns, "allow_3")["9.9.9.9"]
	time.Sleep(10 * time.Millisecond)
	if err := insertAllow(ctx, fd, 3, entries, false); err != nil {
		t.Fatal(err)
	}
	if viaNetlink := setTimeouts(t, ns, "allow_3")["9.9.9.9"]; viaText != 120 || viaNetlink != 130 {
		t.Errorf("text path %d, then netlink path %d; want 120, then a refresh to 130", viaText, viaNetlink)
	}

	// A missing set fails the batch, which the DNS proxy turns into SERVFAIL.
	err = insertAllow(ctx, fd, 9, entries, false)
	if err == nil || !strings.Contains(err.Error(), "no such file") {
		t.Errorf("insert into a missing set: %v", err)
	}
}

// BenchmarkInsertAllow compares the refresh batch (add, delete, add) with a
// plain add, to see what the delete costs at commit.
func BenchmarkInsertAllow(b *testing.B) {
	t := &testing.T{}
	ns, fd := testNetns(t)
	if t.Skipped() || ns == "" {
		b.Skip("needs root and nft")
	}
	ctx := context.Background()
	sandbox, _ := RenderSandbox(SandboxConfig{Index: 3, MaxConns: 64, NewConnsPerSec: 20})
	if err := ApplyInNetns(ctx, ns, RenderBase(BaseConfig{})+sandbox); err != nil {
		b.Fatal(err)
	}
	defer exec.Command("ip", "netns", "del", ns).Run()
	e := []AllowEntry{{Addr: netip.MustParseAddr("192.0.2.1"), Timeout: time.Minute}}
	refresh := func(b *testing.B, ops []uint16) {
		for range b.N {
			conn, err := dialNFTables(ctx, fd)
			if err != nil {
				b.Fatal(err)
			}
			msgs := []netlink.Message{batchMsg(nfnlMsgBatchBegin)}
			for _, op := range ops {
				m, _ := setElemMsg(op, "allow_3", e, op == nftMsgNewSetElem)
				msgs = append(msgs, m)
			}
			if err := sendBatch(ctx, conn, append(msgs, batchMsg(nfnlMsgBatchEnd))); err != nil {
				b.Fatal(err)
			}
			conn.Close()
		}
	}
	b.Run("add-delete-add", func(b *testing.B) { refresh(b, []uint16{nftMsgNewSetElem, nftMsgDelSetElem, nftMsgNewSetElem}) })
	b.Run("add-only", func(b *testing.B) { refresh(b, []uint16{nftMsgNewSetElem}) })
	b.Run("InsertAllow-present", func(b *testing.B) {
		for range b.N {
			if err := insertAllow(ctx, fd, 3, e, false); err != nil {
				b.Fatal(err)
			}
		}
	})
}

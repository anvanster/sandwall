package relay

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anvanster/sandwall/internal/dnsproxy"
	"github.com/anvanster/sandwall/internal/flowlog"
)

// fakeProxy is an upstream HTTP proxy. CONNECT targets get `status`; on 200
// the tunnel reads what the client sends. Absolute-form requests are
// answered with 200 and the requested URL as body.
type fakeProxy struct {
	ln     net.Listener
	status int

	mu       sync.Mutex
	connects []string
	requests []*http.Request
	tunneled chan []byte
}

func newFakeProxy(t *testing.T, status int) *fakeProxy {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeProxy{ln: ln, status: status, tunneled: make(chan []byte, 8)}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handle(c)
		}
	}()
	return p
}

func (p *fakeProxy) handle(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		p.mu.Lock()
		p.requests = append(p.requests, req)
		p.mu.Unlock()
		if req.Method == http.MethodConnect {
			p.mu.Lock()
			p.connects = append(p.connects, req.RequestURI)
			p.mu.Unlock()
			if p.status != 200 {
				io.WriteString(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
				return
			}
			io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
			buf := make([]byte, 64<<10)
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, _ := io.ReadAtLeast(br, buf, 1)
			p.tunneled <- buf[:n]
			return
		}
		body := req.URL.String()
		io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"+body)
	}
}

func (p *fakeProxy) seen() (connects []string, requests []*http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.connects...), append([]*http.Request(nil), p.requests...)
}

type harness struct {
	relay *Relay
	proxy *fakeProxy
	log   string
}

func newHarness(t *testing.T, proxyStatus int, dst netip.AddrPort, s Settings, domain string) *harness {
	t.Helper()
	p := newFakeProxy(t, proxyStatus)
	up, err := ParseUpstream("http://user:secret@" + p.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	h := startRelay(t, up, dst, s, domain)
	h.proxy = p
	return h
}

// startRelay starts a relay whose connections all claim dst as their
// original destination. A nil up makes it dial dst directly.
func startRelay(t *testing.T, up *Upstream, dst netip.AddrPort, s Settings, domain string) *harness {
	t.Helper()
	dir := t.TempDir()
	sink, err := flowlog.NewSink(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Open("sb"); err != nil {
		t.Fatal(err)
	}
	r := New(Config{
		SandboxID: "sb",
		Listen:    netip.MustParseAddrPort("127.0.0.1:0"),
		Upstream:  up,
		Domain:    func(netip.Addr) string { return domain },
		Sink:      sink,
		OrigDst:   func(*net.TCPConn) (netip.AddrPort, error) { return dst, nil },
	}, s)
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Stop)
	return &harness{relay: r, log: filepath.Join(dir, "sb.jsonl")}
}

func (h *harness) dial(t *testing.T) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp4", h.relay.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// events polls the log until want events are there.
func (h *harness) events(t *testing.T, want int) []flowlog.Event {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		data, _ := os.ReadFile(h.log)
		var evs []flowlog.Event
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if line == "" {
				continue
			}
			var e flowlog.Event
			if err := json.Unmarshal([]byte(line), &e); err != nil {
				t.Fatal(err)
			}
			evs = append(evs, e)
		}
		if len(evs) >= want || time.Now().After(deadline) {
			if len(evs) != want {
				t.Fatalf("got %d events, want %d: %+v", len(evs), want, evs)
			}
			return evs
		}
		time.Sleep(20 * time.Millisecond)
	}
}

var pypi = netip.MustParseAddrPort("151.101.0.223:443")

func sendClientHello(c net.Conn, sni string) {
	go func() {
		_ = tls.Client(c, &tls.Config{ServerName: sni, InsecureSkipVerify: true}).Handshake()
	}()
}

// expectClosed waits for the relay to close the connection.
func expectClosed(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err := io.ReadAll(c)
	if err != nil && isTimeout(err) {
		t.Fatal("connection not closed by the relay")
	}
}

func TestTLSAllowedSNI(t *testing.T) {
	h := newHarness(t, 200, pypi, Settings{AllowDomains: []string{"pypi.org"}, MaxConns: 4}, "")
	sendClientHello(h.dial(t), "PyPI.org")
	select {
	case got := <-h.proxy.tunneled:
		if len(got) == 0 || got[0] != 0x16 {
			t.Fatalf("tunnel did not start with the replayed ClientHello: % x", got[:min(8, len(got))])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("nothing tunneled")
	}
	got, reqs := h.proxy.seen()
	if len(got) != 1 || got[0] != "pypi.org:443" {
		t.Fatalf("CONNECT targets %v, want [pypi.org:443]", got)
	}
	if a := reqs[0].Header.Get("Proxy-Authorization"); a != "Basic dXNlcjpzZWNyZXQ=" {
		t.Errorf("Proxy-Authorization %q", a)
	}
	ev := h.events(t, 1)[0]
	if ev.Type != flowlog.TypeRelay || ev.Verdict != "allow" || ev.SNI != "PyPI.org" || ev.Target != "pypi.org:443" ||
		ev.ProxyStatus != 200 || ev.DstIP != "151.101.0.223" || ev.SrcPort == 0 {
		t.Errorf("event %+v", ev)
	}
}

func TestTLSSNINotAllowlisted(t *testing.T) {
	h := newHarness(t, 200, pypi, Settings{AllowDomains: []string{"pypi.org"}, MaxConns: 4}, "pypi.org")
	c := h.dial(t)
	sendClientHello(c, "evil.test")
	expectClosed(t, c)
	ev := h.events(t, 1)[0]
	if ev.Verdict != "deny" || ev.Reason != ReasonSNIMismatch || ev.SNI != "evil.test" {
		t.Errorf("event %+v", ev)
	}
	if got, _ := h.proxy.seen(); len(got) != 0 {
		t.Errorf("proxy saw %v", got)
	}
}

func TestTLSUnknownSNIInsideAllowCIDRs(t *testing.T) {
	h := newHarness(t, 200, pypi, Settings{
		AllowDomains: []string{"pypi.org"}, AllowCIDRs: []netip.Prefix{netip.MustParsePrefix("151.101.0.0/16")}, MaxConns: 4,
	}, "")
	sendClientHello(h.dial(t), "other.test")
	select {
	case <-h.proxy.tunneled:
	case <-time.After(3 * time.Second):
		t.Fatal("nothing tunneled")
	}
	if got, _ := h.proxy.seen(); len(got) != 1 || got[0] != "151.101.0.223:443" {
		t.Fatalf("CONNECT targets %v", got)
	}
}

func TestHTTPPerRequestHostCheck(t *testing.T) {
	dst := netip.MustParseAddrPort("151.101.0.223:80")
	h := newHarness(t, 200, dst, Settings{AllowDomains: []string{"*.pythonhosted.org"}, MaxConns: 4}, "")
	c := h.dial(t)
	br := bufio.NewReader(c)
	io.WriteString(c, "GET /simple/ HTTP/1.1\r\nHost: files.pythonhosted.org\r\nProxy-Authorization: Basic c2FuZGJveA==\r\n\r\n")
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "http://files.pythonhosted.org/simple/" {
		t.Fatalf("first response %d %q", resp.StatusCode, body)
	}
	if _, reqs := h.proxy.seen(); reqs[0].Header.Get("Proxy-Authorization") != "Basic dXNlcjpzZWNyZXQ=" {
		t.Errorf("sandbox credentials reached the proxy: %q", reqs[0].Header.Get("Proxy-Authorization"))
	}

	io.WriteString(c, "GET / HTTP/1.1\r\nHost: evil.test\r\n\r\n")
	resp, err = http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("second response %d, want 403", resp.StatusCode)
	}
	evs := h.events(t, 2)
	if evs[0].Verdict != "allow" || evs[0].HTTPHost != "files.pythonhosted.org" || evs[0].Target != "files.pythonhosted.org" {
		t.Errorf("first event %+v", evs[0])
	}
	if evs[1].Verdict != "deny" || evs[1].Reason != ReasonHostMismatch || evs[1].HTTPHost != "evil.test" {
		t.Errorf("second event %+v", evs[1])
	}
	if _, reqs := h.proxy.seen(); len(reqs) != 1 {
		t.Errorf("proxy saw %d requests, want 1", len(reqs))
	}
}

// An IP-literal Host is let through because "only the address matters";
// the proxy must then be asked for that address, the one the firewall
// admitted, never for whatever address the Host header names.
func TestHTTPIPLiteralHostCannotRedirect(t *testing.T) {
	dst := netip.MustParseAddrPort("151.101.0.223:80")
	h := newHarness(t, 200, dst, Settings{AllowDomains: []string{"pypi.org"}, MaxConns: 4}, "")
	c := h.dial(t)
	io.WriteString(c, "GET /loot HTTP/1.1\r\nHost: 1.2.3.4\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "http://151.101.0.223/loot" {
		t.Errorf("proxy was asked for %q, want the admitted address http://151.101.0.223/loot", body)
	}
}

func TestServerFirstUsesDNSName(t *testing.T) {
	dst := netip.MustParseAddrPort("151.101.0.223:25")
	h := newHarness(t, 200, dst, Settings{AllowDomains: []string{"mail.example.org"}, MaxConns: 4}, "mail.example.org")
	c := h.dial(t)
	time.Sleep(peekTimeout + 200*time.Millisecond) // say nothing until the relay gives up waiting
	io.WriteString(c, "EHLO sandbox\r\n")
	select {
	case got := <-h.proxy.tunneled:
		if string(got) != "EHLO sandbox\r\n" {
			t.Fatalf("tunneled %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("nothing tunneled")
	}
	if got, _ := h.proxy.seen(); len(got) != 1 || got[0] != "mail.example.org:25" {
		t.Fatalf("CONNECT targets %v", got)
	}
}

func TestProxyRefusal(t *testing.T) {
	h := newHarness(t, 403, pypi, Settings{AllowDomains: []string{"pypi.org"}, MaxConns: 4}, "")
	c := h.dial(t)
	sendClientHello(c, "pypi.org")
	expectClosed(t, c)
	ev := h.events(t, 1)[0]
	if ev.Verdict != "deny" || ev.Reason != ReasonProxyRefused || ev.ProxyStatus != 403 || ev.Target != "pypi.org:443" {
		t.Errorf("event %+v", ev)
	}
}

func TestReloadAppliesToNewConnections(t *testing.T) {
	h := newHarness(t, 200, pypi, Settings{AllowDomains: []string{"pypi.org"}, MaxConns: 4}, "")
	h.relay.Reload(Settings{AllowDomains: []string{"example.org"}, MaxConns: 4})
	c := h.dial(t)
	sendClientHello(c, "pypi.org")
	expectClosed(t, c)
	if ev := h.events(t, 1)[0]; ev.Reason != ReasonSNIMismatch {
		t.Errorf("event %+v", ev)
	}
}

func TestDecide(t *testing.T) {
	r := New(Config{Domain: func(a netip.Addr) string {
		if a == netip.MustParseAddr("151.101.0.223") {
			return "pypi.org"
		}
		return "removed.example"
	}}, Settings{AllowDomains: []string{"pypi.org", "*.example.com"}, AllowCIDRs: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}})
	ip := netip.MustParseAddr
	for _, tc := range []struct {
		dst, name, want string
		denied          bool
	}{
		{"151.101.0.223", "pypi.org", "pypi.org", false},
		{"151.101.0.223", "PYPI.ORG.", "pypi.org", false},
		{"151.101.0.223", "a.example.com", "a.example.com", false},
		{"151.101.0.223", "example.com", "", true},
		{"151.101.0.223", "evil.test", "", true},
		{"203.0.113.9", "evil.test", "203.0.113.9", false},
		{"151.101.0.223", "", "pypi.org", false},
		{"198.51.100.1", "", "198.51.100.1", false}, // DNS name no longer allowlisted
		{"151.101.0.223", "10.0.0.1", "151.101.0.223", false},
	} {
		got, denied := r.decide(ip(tc.dst), tc.name)
		if got != tc.want || denied != tc.denied {
			t.Errorf("decide(%s, %q) = %q, %v; want %q, %v", tc.dst, tc.name, got, denied, tc.want, tc.denied)
		}
	}
}

func TestParseUpstream(t *testing.T) {
	for _, bad := range []string{"", "proxy:3128", "https://proxy:3128", "http://proxy", "http://proxy:3128/path", "socks5://proxy:1080"} {
		if _, err := ParseUpstream(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	u, err := ParseUpstream("http://u:p%40ss@proxy.example:3128/")
	if err != nil {
		t.Fatal(err)
	}
	if u.addr != "proxy.example:3128" || u.auth != "Basic dTpwQHNz" || u.String() != "http://proxy.example:3128" {
		t.Errorf("%+v", u)
	}
	if _, err := ParseUpstream("https://u:hunter2@proxy:3128"); err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("error leaks the password: %v", err)
	}
}

func TestReadClientHelloNotTLS(t *testing.T) {
	_, consumed, err := readClientHello(strings.NewReader("\x16garbage that is not a TLS record at all"))
	if !errors.Is(err, errNotHello) || len(consumed) == 0 {
		t.Errorf("err %v, consumed %d", err, len(consumed))
	}
}

func TestParseNoProxy(t *testing.T) {
	np, notes, err := ParseNoProxy("localhost, 127.0.0.1,.corp.example,*.lab.example,git.example.org:8443,10.0.0.0/8 ::1,[fd00::1]:80,bad_name!,198.51.100.7")
	if err != nil {
		t.Fatal(err)
	}
	wantPatterns := []string{"localhost", "*.localhost", "*.corp.example", "*.lab.example", "git.example.org", "*.git.example.org"}
	if strings.Join(np.Patterns, " ") != strings.Join(wantPatterns, " ") {
		t.Errorf("patterns %v, want %v", np.Patterns, wantPatterns)
	}
	var cidrs []string
	for _, p := range np.CIDRs {
		cidrs = append(cidrs, p.String())
	}
	if got := strings.Join(cidrs, " "); got != "127.0.0.1/32 10.0.0.0/8 198.51.100.7/32" {
		t.Errorf("cidrs %s", got)
	}
	if len(notes) != 4 { // port ignored, two IPv6, one bad name
		t.Errorf("notes %q", notes)
	}
	al := dnsproxy.NewAllowlist(np.Patterns)
	for name, want := range map[string]bool{
		"localhost": true, "corp.example": false, "a.corp.example": true,
		"git.example.org": true, "x.git.example.org": true, "example.org": false,
	} {
		if al.Allows(name) != want {
			t.Errorf("%s: matched %v, want %v", name, !want, want)
		}
	}
	if _, _, err := ParseNoProxy("a.example, *"); err == nil {
		t.Error("* accepted")
	}
	if np, _, err := ParseNoProxy(""); err != nil || !np.Empty() {
		t.Errorf("empty: %+v %v", np, err)
	}
}

// fakeOrigin is a destination server for the direct (SNI check) mode. It
// reports the first bytes of each connection, and answers anything that
// starts like an HTTP request with 200 and the request line as body.
type fakeOrigin struct {
	addr  netip.AddrPort
	first chan []byte
}

func newFakeOrigin(t *testing.T) *fakeOrigin {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	o := &fakeOrigin{addr: netip.MustParseAddrPort(ln.Addr().String()), first: make(chan []byte, 8)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				if b, _ := br.Peek(1); len(b) == 1 && b[0] != 0x16 {
					for {
						req, err := http.ReadRequest(br)
						if err != nil {
							return
						}
						line := req.Method + " " + req.RequestURI + " auth=" + req.Header.Get("Proxy-Authorization")
						o.first <- []byte(line)
						io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: "+strconv.Itoa(len(line))+"\r\n\r\n"+line)
					}
				}
				buf := make([]byte, 64<<10)
				n, _ := io.ReadAtLeast(br, buf, 1)
				o.first <- buf[:n]
			}()
		}
	}()
	return o
}

func TestDirectTLSAllowed(t *testing.T) {
	o := newFakeOrigin(t)
	h := startRelay(t, nil, o.addr, Settings{AllowDomains: []string{"pypi.org"}, MaxConns: 4}, "")
	sendClientHello(h.dial(t), "pypi.org")
	select {
	case got := <-o.first:
		if len(got) == 0 || got[0] != 0x16 {
			t.Fatalf("origin did not get the replayed ClientHello: % x", got[:min(8, len(got))])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("nothing reached the origin")
	}
	ev := h.events(t, 1)[0]
	if ev.Verdict != "allow" || ev.SNI != "pypi.org" || ev.Target != o.addr.String() || ev.ProxyStatus != 0 {
		t.Errorf("event %+v", ev)
	}
}

func TestDirectTLSSNIMismatch(t *testing.T) {
	o := newFakeOrigin(t)
	h := startRelay(t, nil, o.addr, Settings{AllowDomains: []string{"pypi.org"}, MaxConns: 4}, "pypi.org")
	c := h.dial(t)
	sendClientHello(c, "evil.test")
	expectClosed(t, c)
	if ev := h.events(t, 1)[0]; ev.Reason != ReasonSNIMismatch {
		t.Errorf("event %+v", ev)
	}
	select {
	case got := <-o.first:
		t.Fatalf("origin got %q", got)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestDirectHTTP(t *testing.T) {
	o := newFakeOrigin(t)
	h := startRelay(t, nil, o.addr, Settings{AllowDomains: []string{"files.pythonhosted.org"}, MaxConns: 4}, "")
	c := h.dial(t)
	br := bufio.NewReader(c)
	io.WriteString(c, "GET /simple/ HTTP/1.1\r\nHost: files.pythonhosted.org\r\nProxy-Authorization: Basic c2FuZGJveA==\r\n\r\n")
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "GET /simple/ auth=" {
		t.Fatalf("response %d %q (want origin form, no proxy credentials)", resp.StatusCode, body)
	}
	io.WriteString(c, "GET / HTTP/1.1\r\nHost: evil.test\r\n\r\n")
	if resp, err = http.ReadResponse(br, nil); err != nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("second request: %v %v", resp, err)
	}
	evs := h.events(t, 2)
	if evs[0].Verdict != "allow" || evs[0].Target != o.addr.String() || evs[1].Reason != ReasonHostMismatch {
		t.Errorf("events %+v", evs)
	}
}

func TestDirectDialError(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := netip.MustParseAddrPort(ln.Addr().String())
	ln.Close()
	h := startRelay(t, nil, closed, Settings{AllowDomains: []string{"pypi.org"}, MaxConns: 4}, "")
	c := h.dial(t)
	sendClientHello(c, "pypi.org")
	expectClosed(t, c)
	if ev := h.events(t, 1)[0]; ev.Verdict != "deny" || ev.Reason != ReasonDialError {
		t.Errorf("event %+v", ev)
	}
}

func TestQuarantineClosesAndRefuses(t *testing.T) {
	h := newHarness(t, 200, pypi, Settings{AllowDomains: []string{"pypi.org"}, MaxConns: 4}, "")
	c := h.dial(t)
	sendClientHello(c, "pypi.org")
	select {
	case <-h.proxy.tunneled:
	case <-time.After(3 * time.Second):
		t.Fatal("nothing tunneled")
	}
	// The fake proxy closes its side after the first read, so open a
	// connection that is still waiting in the peek to test the cut.
	idle := h.dial(t)
	time.Sleep(100 * time.Millisecond)
	h.relay.SetQuarantined(true)
	expectClosed(t, idle)
	late := h.dial(t)
	expectClosed(t, late)
	h.relay.SetQuarantined(false)
	sendClientHello(h.dial(t), "pypi.org")
	select {
	case <-h.proxy.tunneled:
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not accept connections after the release")
	}
}

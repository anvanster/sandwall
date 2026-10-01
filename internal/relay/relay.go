// Package relay carries a proxied sandbox's allowed TCP connections to an
// upstream HTTP proxy. The sandbox connects to the real destination; the
// host firewall applies the sandbox policy and then REDIRECTs the
// connection to this relay, one per sandbox on 10.200.k.1. The relay
// recovers the original destination, picks the name to ask the proxy for
// (TLS SNI, HTTP Host, or the DNS-learned name), checks it against the
// allowlist, and tunnels the connection through the proxy.
//
// The proxy only ever receives targets that are allowlisted names or
// addresses inside the policy's allow_cidrs (or addresses the firewall
// already admitted), so the sandbox cannot use it to reach anything else.
package relay

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/anvanster/egressd/internal/dnsproxy"
	"github.com/anvanster/egressd/internal/flowlog"
	"github.com/anvanster/egressd/internal/nft"
)

// Deny reasons the relay logs, in addition to nft.ReasonConnLimit.
const (
	ReasonSNIMismatch    = "sni_mismatch"
	ReasonHostMismatch   = "host_mismatch"
	ReasonBadClientHello = "bad_client_hello"
	ReasonProxyRefused   = "proxy_refused"
	ReasonProxyError     = "proxy_error"
)

// Results counted per relay decision.
const (
	ResultOK      = "ok"
	ResultDenied  = "denied"
	ResultRefused = "refused"
	ResultError   = "error"
)

const (
	// peekTimeout is how long the relay waits for the client to speak
	// first. Server-first protocols (SMTP, ...) get the DNS-learned name.
	peekTimeout  = time.Second
	helloTimeout = 10 * time.Second
)

// Settings are the policy-derived knobs that hot reload can change.
type Settings struct {
	AllowDomains []string // normalized patterns
	AllowCIDRs   []netip.Prefix
	MaxConns     int
}

// Config identifies the sandbox a relay serves.
type Config struct {
	SandboxID string
	Listen    netip.AddrPort
	Upstream  *Upstream
	// Domain returns the allowlisted name the sandbox last resolved to an
	// address, or "".
	Domain func(netip.Addr) string
	Sink   *flowlog.Sink
	// Count is notified once per decision. reason is set for denials.
	Count func(sandboxID, result, reason string)
	Log   *slog.Logger
	// OrigDst overrides SO_ORIGINAL_DST, for tests.
	OrigDst func(*net.TCPConn) (netip.AddrPort, error)
}

// Relay is the upstream-proxy relay for one sandbox.
type Relay struct {
	cfg Config

	mu       sync.RWMutex
	allow    *dnsproxy.Allowlist
	cidrs    []netip.Prefix
	maxConns int

	ln     net.Listener
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	connMu sync.Mutex
	conns  map[*net.TCPConn]struct{}
}

// New creates a stopped relay.
func New(cfg Config, s Settings) *Relay {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.OrigDst == nil {
		cfg.OrigDst = originalDst
	}
	if cfg.Domain == nil {
		cfg.Domain = func(netip.Addr) string { return "" }
	}
	r := &Relay{cfg: cfg, conns: map[*net.TCPConn]struct{}{}}
	r.Reload(s)
	return r
}

// Reload swaps in new settings. Open connections are kept, as forwarded
// flows are on a policy reload; later HTTP requests on a kept-alive
// connection are checked against the new allowlist.
func (r *Relay) Reload(s Settings) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.allow = dnsproxy.NewAllowlist(s.AllowDomains)
	r.cidrs = append([]netip.Prefix(nil), s.AllowCIDRs...)
	r.maxConns = max(s.MaxConns, 1)
}

// Start binds the listener on the sandbox's host-side address.
func (r *Relay) Start() error {
	ln, err := net.Listen("tcp4", r.cfg.Listen.String())
	if err != nil {
		return fmt.Errorf("relay listen %s: %w", r.cfg.Listen, err)
	}
	r.ln = ln
	r.ctx, r.cancel = context.WithCancel(context.Background())
	r.wg.Add(1)
	go r.acceptLoop()
	return nil
}

// Addr returns the bound listener address.
func (r *Relay) Addr() net.Addr { return r.ln.Addr() }

// Stop closes the listener and every relayed connection.
func (r *Relay) Stop() {
	if r.ln == nil {
		return
	}
	r.cancel()
	_ = r.ln.Close()
	r.connMu.Lock()
	for c := range r.conns {
		_ = c.Close()
	}
	r.connMu.Unlock()
	r.wg.Wait()
}

func (r *Relay) acceptLoop() {
	defer r.wg.Done()
	for {
		c, err := r.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			r.cfg.Log.Warn("relay accept", "sandbox", r.cfg.SandboxID, "err", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		tc := c.(*net.TCPConn)
		if !r.track(tc) {
			reset(tc)
			continue
		}
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			defer r.untrack(tc)
			r.serve(tc)
		}()
	}
}

// track registers a connection, refusing it above max_conns. The firewall
// already enforces max_conns on the sandbox leg; this is a second bound.
func (r *Relay) track(c *net.TCPConn) bool {
	r.mu.RLock()
	limit := r.maxConns
	r.mu.RUnlock()
	r.connMu.Lock()
	defer r.connMu.Unlock()
	if len(r.conns) >= limit {
		ev := r.baseEvent(c, netip.AddrPort{})
		r.deny(ev, nft.ReasonConnLimit)
		return false
	}
	r.conns[c] = struct{}{}
	return true
}

func (r *Relay) untrack(c *net.TCPConn) {
	r.connMu.Lock()
	delete(r.conns, c)
	r.connMu.Unlock()
	_ = c.Close()
}

func (r *Relay) serve(c *net.TCPConn) {
	dst, err := r.cfg.OrigDst(c)
	if err != nil {
		r.cfg.Log.Warn("relay: no original destination", "sandbox", r.cfg.SandboxID, "err", err)
		reset(c)
		return
	}
	ev := r.baseEvent(c, dst)
	br := bufio.NewReader(c)

	_ = c.SetReadDeadline(time.Now().Add(peekTimeout))
	first, err := br.Peek(1)
	_ = c.SetReadDeadline(time.Time{})
	switch {
	case isTimeout(err):
		// The client waits for the server to speak first.
		r.tunnel(c, br, nil, dst, "", ev)
	case err != nil:
		return // closed before sending anything
	case first[0] == 0x16: // TLS handshake record
		_ = c.SetReadDeadline(time.Now().Add(helloTimeout))
		sni, hello, herr := readClientHello(br)
		_ = c.SetReadDeadline(time.Time{})
		if herr != nil {
			r.deny(ev, ReasonBadClientHello)
			reset(c)
			return
		}
		ev.SNI = sni
		r.tunnel(c, br, hello, dst, sni, ev)
	case looksLikeHTTP(br):
		r.serveHTTP(c, br, dst, ev)
	default:
		r.tunnel(c, br, nil, dst, "", ev)
	}
}

// decide picks the proxy target host for a connection to dst. name is the
// TLS SNI or HTTP Host, or "" when the client sent neither.
//   - An allowlisted name is used as is: the proxy resolves it.
//   - A name that is not allowlisted is refused, unless dst is inside
//     allow_cidrs; then the address itself is the target, as the policy
//     allows that address whatever name the client presents.
//   - Without a name, the name the sandbox resolved to dst is used, else
//     the address (the firewall already admitted it).
func (r *Relay) decide(dst netip.Addr, name string) (host string, denied bool) {
	r.mu.RLock()
	allow, cidrs := r.allow, r.cidrs
	r.mu.RUnlock()
	inCIDRs := false
	for _, p := range cidrs {
		if p.Contains(dst) {
			inCIDRs = true
			break
		}
	}
	if name != "" {
		if _, err := netip.ParseAddr(name); err == nil {
			// An IP literal as Host or SNI: only the address matters.
			return dst.String(), false
		}
		if allow.Allows(name) {
			return strings.ToLower(strings.TrimSuffix(name, ".")), false
		}
		if inCIDRs {
			return dst.String(), false
		}
		return "", true
	}
	if d := r.cfg.Domain(dst); d != "" && allow.Allows(d) {
		return d, false
	}
	return dst.String(), false
}

// tunnel carries a connection through a CONNECT tunnel. prefix holds bytes
// already consumed from the client (the ClientHello).
func (r *Relay) tunnel(c *net.TCPConn, br *bufio.Reader, prefix []byte, dst netip.AddrPort, name string, ev flowlog.Event) {
	host, denied := r.decide(dst.Addr(), name)
	if denied {
		r.deny(ev, ReasonSNIMismatch)
		reset(c)
		return
	}
	ev.Target = net.JoinHostPort(host, strconv.Itoa(int(dst.Port())))
	start := time.Now()
	up, upBr, status, err := r.cfg.Upstream.Connect(r.ctx, ev.Target)
	ev.ConnectMS = time.Since(start).Milliseconds()
	ev.ProxyStatus = status
	if err != nil {
		r.proxyFailed(ev, status, err)
		reset(c)
		return
	}
	defer up.Close()
	defer context.AfterFunc(r.ctx, func() { up.Close() })()
	if len(prefix) > 0 {
		if _, err := up.Write(prefix); err != nil {
			reset(c)
			return
		}
	}
	r.allowed(ev)
	splice(c, br, up.(*net.TCPConn), upBr)
}

// serveHTTP forwards plain HTTP/1.x requests to the proxy in absolute form,
// checking the Host of every request. Proxies commonly allow CONNECT only
// to port 443, so plain HTTP is not tunnelled.
func (r *Relay) serveHTTP(c *net.TCPConn, br *bufio.Reader, dst netip.AddrPort, base flowlog.Event) {
	var (
		up   net.Conn
		upBr *bufio.Reader
	)
	defer func() {
		if up != nil {
			up.Close()
		}
	}()
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		ev := base
		ev.HTTPHost = req.Host
		if req.Method == http.MethodConnect {
			r.deny(ev, ReasonHostMismatch)
			writeStatus(c, http.StatusMethodNotAllowed)
			return
		}
		host, denied := r.decide(dst.Addr(), hostOnly(req.Host))
		if denied {
			r.deny(ev, ReasonHostMismatch)
			writeStatus(c, http.StatusForbidden)
			return
		}
		ev.Target = host
		if dst.Port() != 80 {
			ev.Target = net.JoinHostPort(host, strconv.Itoa(int(dst.Port())))
		}
		start := time.Now()
		if up == nil {
			if up, err = r.cfg.Upstream.Dial(r.ctx); err != nil {
				r.proxyFailed(ev, 0, err)
				writeStatus(c, http.StatusBadGateway)
				return
			}
			upBr = bufio.NewReader(up)
			defer context.AfterFunc(r.ctx, func() { up.Close() })()
		}
		req.URL.Scheme, req.URL.Host = "http", ev.Target
		req.Header.Del("Proxy-Authorization")
		req.Header.Del("Proxy-Connection")
		if a := r.cfg.Upstream.auth; a != "" {
			req.Header.Set("Proxy-Authorization", a)
		}
		if err := req.WriteProxy(up); err != nil {
			r.proxyFailed(ev, 0, err)
			return
		}
		resp, err := readFinalResponse(upBr, req, c)
		if err != nil {
			r.proxyFailed(ev, 0, err)
			writeStatus(c, http.StatusBadGateway)
			return
		}
		ev.ProxyStatus, ev.ConnectMS = resp.StatusCode, time.Since(start).Milliseconds()
		r.allowed(ev)
		if resp.StatusCode == http.StatusSwitchingProtocols {
			if err := resp.Write(c); err != nil {
				return
			}
			splice(c, br, up.(*net.TCPConn), upBr)
			return
		}
		werr := resp.Write(c)
		resp.Body.Close()
		if werr != nil || resp.Close || req.Close {
			return
		}
	}
}

// readFinalResponse reads the response to req, passing interim 1xx
// responses other than 101 straight to the client.
func readFinalResponse(br *bufio.Reader, req *http.Request, client io.Writer) (*http.Response, error) {
	for {
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode >= 200 || resp.StatusCode == http.StatusSwitchingProtocols {
			return resp, nil
		}
		if err := resp.Write(client); err != nil {
			return nil, err
		}
	}
}

func (r *Relay) baseEvent(c *net.TCPConn, dst netip.AddrPort) flowlog.Event {
	ev := flowlog.Event{Type: flowlog.TypeProxy, SandboxID: r.cfg.SandboxID, Proto: "tcp"}
	if src, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		ev.SrcPort = uint16(src.Port)
	}
	if dst.IsValid() {
		ev.DstIP, ev.DstPort = dst.Addr().String(), dst.Port()
		ev.DstDomain = r.cfg.Domain(dst.Addr())
	}
	return ev
}

func (r *Relay) allowed(ev flowlog.Event) {
	ev.Verdict = "allow"
	r.cfg.Sink.Write(ev)
	r.count(ResultOK, "")
}

func (r *Relay) deny(ev flowlog.Event, reason string) {
	ev.Verdict, ev.Reason = "deny", reason
	r.cfg.Sink.Write(ev)
	r.count(ResultDenied, reason)
}

func (r *Relay) proxyFailed(ev flowlog.Event, status int, err error) {
	reason, result := ReasonProxyError, ResultError
	if status != 0 {
		reason, result = ReasonProxyRefused, ResultRefused
	}
	ev.Verdict, ev.Reason = "deny", reason
	r.cfg.Sink.Write(ev)
	r.count(result, reason)
	r.cfg.Log.Debug("relay: upstream proxy failed", "sandbox", r.cfg.SandboxID, "target", ev.Target, "err", err)
}

func (r *Relay) count(result, reason string) {
	if r.cfg.Count != nil {
		r.cfg.Count(r.cfg.SandboxID, result, reason)
	}
}

// splice copies both ways until both sides are done, passing half-closes on.
func splice(c *net.TCPConn, cr io.Reader, up *net.TCPConn, upr io.Reader) {
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(up, cr)
		_ = up.CloseWrite()
		close(done)
	}()
	_, _ = io.Copy(c, upr)
	_ = c.CloseWrite()
	<-done
}

var httpMethods = []string{"GET ", "HEAD ", "POST ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "TRACE ", "CONNECT "}

// looksLikeHTTP checks the bytes already buffered, so it never waits.
func looksLikeHTTP(br *bufio.Reader) bool {
	b, _ := br.Peek(br.Buffered())
	for _, m := range httpMethods {
		if len(b) >= len(m) && string(b[:len(m)]) == m {
			return true
		}
	}
	return false
}

func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return strings.Trim(h, "[]")
	}
	return strings.Trim(hostport, "[]")
}

func writeStatus(w io.Writer, code int) {
	body := "egressd: " + http.StatusText(code) + "\n"
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(body), body)
}

// reset closes with RST, so the client sees a refused connection at once.
func reset(c *net.TCPConn) {
	_ = c.SetLinger(0)
	_ = c.Close()
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

package relay

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	dialTimeout    = 10 * time.Second
	connectTimeout = 15 * time.Second
)

// Upstream is the HTTP proxy that carries proxied sandboxes' traffic.
type Upstream struct {
	addr string // host:port
	auth string // Proxy-Authorization value, empty without credentials
}

// ParseUpstream parses http://[user:pass@]host:port. Only plain-HTTP
// proxies are supported; the port is required.
func ParseUpstream(raw string) (*Upstream, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("upstream proxy %q: %w", redact(raw), err)
	}
	if u.Scheme != "http" {
		return nil, fmt.Errorf("upstream proxy %q: only http:// proxies are supported", redact(raw))
	}
	if u.Hostname() == "" || u.Port() == "" {
		return nil, fmt.Errorf("upstream proxy %q: want http://host:port", redact(raw))
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("upstream proxy %q: unexpected path or query", redact(raw))
	}
	up := &Upstream{addr: net.JoinHostPort(u.Hostname(), u.Port())}
	if u.User != nil {
		pass, _ := u.User.Password()
		up.auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(u.User.Username()+":"+pass))
	}
	return up, nil
}

// String returns the proxy address without credentials.
func (u *Upstream) String() string { return "http://" + u.addr }

// Dial opens a connection to the proxy.
func (u *Upstream) Dial(ctx context.Context) (net.Conn, error) {
	d := net.Dialer{Timeout: dialTimeout}
	return d.DialContext(ctx, "tcp", u.addr)
}

// Connect opens a tunnel to target (host:port) with CONNECT. On a non-200
// answer it returns the proxy's status code and an error. The returned
// reader holds anything the proxy sent after its response headers.
func (u *Upstream) Connect(ctx context.Context, target string) (net.Conn, *bufio.Reader, int, error) {
	conn, err := u.Dial(ctx)
	if err != nil {
		return nil, nil, 0, err
	}
	_ = conn.SetDeadline(time.Now().Add(connectTimeout))
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if u.auth != "" {
		req += "Proxy-Authorization: " + u.auth + "\r\n"
	}
	if _, err := conn.Write([]byte(req + "\r\n")); err != nil {
		conn.Close()
		return nil, nil, 0, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		conn.Close()
		return nil, nil, 0, fmt.Errorf("CONNECT %s: %w", target, err)
	}
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, nil, resp.StatusCode, fmt.Errorf("CONNECT %s: proxy answered %s", target, resp.Status)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, br, resp.StatusCode, nil
}

// redact hides the password of a proxy URL for error messages.
func redact(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		if i := strings.LastIndex(raw, "@"); i >= 0 {
			return "<redacted>@" + raw[i+1:]
		}
		return raw
	}
	return u.Redacted()
}

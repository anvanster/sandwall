package dataplane

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Client talks to one data plane's control socket.
type Client struct {
	http *http.Client
}

// requestTimeout bounds every control request; a policy reload re-renders
// the sandbox's ruleset, which is the slowest.
const requestTimeout = 30 * time.Second

// NewClient returns a client for the control socket at path.
func NewClient(path string) *Client {
	return &Client{http: &http.Client{
		Timeout: requestTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", path)
			},
		},
	}}
}

// Status asks the data plane who it is.
func (c *Client) Status(ctx context.Context) (Status, error) {
	var s Status
	return s, c.do(ctx, http.MethodGet, "/v1/status", nil, &s)
}

// Counters returns the data plane's cumulative DNS and relay counters.
func (c *Client) Counters(ctx context.Context) (Counters, error) {
	var out Counters
	return out, c.do(ctx, http.MethodGet, "/v1/counters", nil, &out)
}

// Domain returns the allowlisted name the sandbox last resolved to ip.
func (c *Client) Domain(ctx context.Context, ip netip.Addr) (string, error) {
	var out struct {
		Domain string `json:"domain"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/domain?ip="+url.QueryEscape(ip.String()), nil, &out)
	return out.Domain, err
}

// ApplyPolicy hot-reloads the DNS and relay settings and the ruleset.
func (c *Client) ApplyPolicy(ctx context.Context, p Policy) error {
	return c.do(ctx, http.MethodPut, "/v1/policy", p, nil)
}

// SetQuarantined cuts the sandbox's DNS and relayed connections off, or
// restores them (releasing also forgets the DNS cache).
func (c *Client) SetQuarantined(ctx context.Context, q bool) error {
	return c.do(ctx, http.MethodPut, "/v1/quarantine", map[string]bool{"quarantined": q}, nil)
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://dataplane"+path, body)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("data plane: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("data plane: %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

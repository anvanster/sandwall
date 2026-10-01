// Package api is the JSON-over-HTTP transport between the sandwall CLI and
// daemon on a unix socket. It holds no logic of its own.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// DefaultSocket is where the daemon listens.
const DefaultSocket = "/run/sandwall.sock"

// CreateRequest is the body of POST /v1/sandboxes.
type CreateRequest struct {
	ID     string `json:"id"`
	Mode   string `json:"mode,omitempty"`
	Policy string `json:"policy"`
	// VMConfig is a Firecracker config JSON, for mode "vm".
	VMConfig string `json:"vm_config,omitempty"`
}

// SnapshotRequest is the body of POST /v1/sandboxes/{id}/snapshot.
type SnapshotRequest struct {
	OutDir string `json:"out_dir"`
}

// CloneRequest is the body of POST /v1/clones.
type CloneRequest struct {
	SnapshotDir string `json:"snapshot_dir"`
	Count       int    `json:"count"`
	Prefix      string `json:"prefix,omitempty"`
	Policy      string `json:"policy"`
	// StaggerMs is the pause between VM starts.
	StaggerMs int64 `json:"stagger_ms,omitempty"`
}

// CloneResponse lists the clones created (daemon.Info objects). Error is
// set when only some of the requested clones could be created.
type CloneResponse struct {
	Created json.RawMessage `json:"created"`
	Error   string          `json:"error,omitempty"`
}

// PolicyRequest is the body of PUT /v1/sandboxes/{id}/policy.
type PolicyRequest struct {
	Policy string `json:"policy"`
}

// QuarantineRequest is the body of POST /v1/sandboxes/{id}/quarantine.
type QuarantineRequest struct {
	Reason string `json:"reason,omitempty"`
	Freeze bool   `json:"freeze,omitempty"`
}

// ErrorResponse is returned with every non-2xx status.
type ErrorResponse struct {
	Error string `json:"error"`
}

// ErrDaemonUnavailable means nothing is listening on the socket.
var ErrDaemonUnavailable = errors.New("sandwall daemon is not running")

// Client talks to the daemon.
type Client struct {
	http *http.Client
}

// NewClient returns a client for the daemon socket.
func NewClient(socket string) *Client {
	return &Client{http: &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socket)
			},
		},
	}}
}

// Do sends a request and decodes a JSON response into out (if non-nil).
func (c *Client) Do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://sandwall"+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		var opErr *net.OpError
		if errors.As(err, &opErr) && opErr.Op == "dial" {
			return fmt.Errorf("%w (%v)", ErrDaemonUnavailable, opErr.Err)
		}
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var e ErrorResponse
		if json.NewDecoder(resp.Body).Decode(&e) == nil && e.Error != "" {
			return errors.New(e.Error)
		}
		return fmt.Errorf("daemon returned %s", resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// SandboxPath builds /v1/sandboxes/{id}[/suffix] with the ID escaped.
func SandboxPath(id string, suffix string) string {
	return "/v1/sandboxes/" + url.PathEscape(id) + suffix
}

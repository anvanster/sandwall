package relay

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"time"
)

// errGotHello stops the TLS handshake once the ClientHello is parsed.
var errGotHello = errors.New("client hello read")

// errNotHello means the bytes started like TLS but held no parsable
// ClientHello.
var errNotHello = errors.New("no parsable TLS ClientHello")

// readClientHello reads a TLS ClientHello from r and returns its server
// name and every byte consumed, to be replayed upstream. crypto/tls does the
// parsing, so a ClientHello split across records or segments is handled
// the same way a TLS server would handle it.
func readClientHello(r io.Reader) (sni string, consumed []byte, err error) {
	rc := &recordingConn{r: r}
	var got bool
	srv := tls.Server(rc, &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			sni, got = h.ServerName, true
			return nil, errGotHello
		},
	})
	_ = srv.Handshake()
	if !got {
		return "", rc.buf.Bytes(), errNotHello
	}
	return sni, rc.buf.Bytes(), nil
}

// recordingConn feeds the TLS server from r, records what it reads and
// discards what it writes (the alert sent when the handshake is aborted).
type recordingConn struct {
	r   io.Reader
	buf bytes.Buffer
}

func (c *recordingConn) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.buf.Write(p[:n])
	return n, err
}

func (c *recordingConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *recordingConn) Close() error                     { return nil }
func (c *recordingConn) LocalAddr() net.Addr              { return nil }
func (c *recordingConn) RemoteAddr() net.Addr             { return nil }
func (c *recordingConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingConn) SetWriteDeadline(time.Time) error { return nil }

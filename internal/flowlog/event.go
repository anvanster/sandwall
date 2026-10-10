// Package flowlog writes per-sandbox JSONL event logs and runs the collectors
// that feed them: NFLOG for denied packets, conntrack for finished flows.
package flowlog

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Event types.
const (
	TypeDNS  = "dns"
	TypeDeny = "deny"
	TypeFlow = "flow"
	// TypeRelay records one decision of the relay (SNI/Host check and
	// upstream proxy): a connection or HTTP request carried on (verdict
	// allow) or refused by the relay, the proxy or the destination
	// (verdict deny, with a reason).
	TypeRelay = "relay"
	// TypeQuarantine records a sandbox being quarantined (verdict
	// "quarantined") or released ("released"); reason is the operator's.
	TypeQuarantine = "quarantine"
)

// Event is one JSONL log line. Fields irrelevant to a type are omitted.
type Event struct {
	TS        time.Time `json:"ts"`
	Type      string    `json:"type"`
	SandboxID string    `json:"sandbox_id"`
	Verdict   string    `json:"verdict"`
	Reason    string    `json:"reason,omitempty"`

	// DNS
	QName   string   `json:"qname,omitempty"`
	QType   string   `json:"qtype,omitempty"`
	Answers []string `json:"answers,omitempty"`

	// Deny and flow
	Proto     string `json:"proto,omitempty"`
	DstIP     string `json:"dst_ip,omitempty"`
	DstPort   uint16 `json:"dst_port,omitempty"`
	DstDomain string `json:"dst_domain,omitempty"`

	// Flow
	TSStart  *time.Time `json:"ts_start,omitempty"`
	TSEnd    *time.Time `json:"ts_end,omitempty"`
	BytesOut uint64     `json:"bytes_out,omitempty"`
	BytesIn  uint64     `json:"bytes_in,omitempty"`

	// Relay
	SrcPort     uint16 `json:"src_port,omitempty"`
	Target      string `json:"target,omitempty"` // CONNECT target, absolute-form request host, or dialed address
	SNI         string `json:"sni,omitempty"`
	HTTPHost    string `json:"http_host,omitempty"`
	ProxyStatus int    `json:"proxy_status,omitempty"`
	ConnectMS   int64  `json:"connect_ms,omitempty"`
}

// IsDenial reports whether an event records something the policy blocked.
func (e *Event) IsDenial() bool {
	return e.Type == TypeDeny || e.Type == TypeQuarantine ||
		((e.Type == TypeDNS || e.Type == TypeRelay) && e.Verdict != "allow")
}

// Path returns the log file for a sandbox.
func Path(dir, sandboxID string) string {
	return filepath.Join(dir, sandboxID+".jsonl")
}

// Sink fans events out to one append-only file per sandbox.
type Sink struct {
	dir      string
	mu       sync.Mutex
	files    map[string]*os.File
	observer func(Event)
}

// SetObserver registers fn to see every event written to an open sandbox
// log, after it is written. fn must not block.
func (s *Sink) SetObserver(fn func(Event)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.observer = fn
}

// NewSink creates the log directory if needed.
func NewSink(dir string) (*Sink, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	return &Sink{dir: dir, files: map[string]*os.File{}}, nil
}

// Open starts accepting events for a sandbox. Reopening is a no-op.
func (s *Sink) Open(sandboxID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.files[sandboxID]; ok {
		return nil
	}
	f, err := os.OpenFile(Path(s.dir, sandboxID), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	s.files[sandboxID] = f
	return nil
}

// Close stops accepting events for a sandbox. The file is kept for audit.
func (s *Sink) Close(sandboxID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.files[sandboxID]
	if !ok {
		return nil
	}
	delete(s.files, sandboxID)
	return f.Close()
}

// Write appends one event. Events for sandboxes that are not open are dropped.
func (s *Sink) Write(e Event) {
	if e.TS.IsZero() {
		e.TS = time.Now()
	}
	line, err := json.Marshal(e)
	if err != nil {
		return
	}
	line = append(line, '\n')
	s.mu.Lock()
	f, ok := s.files[e.SandboxID]
	if ok {
		// One write per line on an O_APPEND file keeps lines intact.
		_, _ = f.Write(line)
	}
	obs := s.observer
	s.mu.Unlock()
	if ok && obs != nil {
		obs(e)
	}
}

// CloseAll closes every open file.
func (s *Sink) CloseAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, f := range s.files {
		_ = f.Close()
		delete(s.files, id)
	}
}

// Filter selects events to print.
type Filter struct {
	DenyOnly bool
}

func (f Filter) match(line []byte) bool {
	if !f.DenyOnly {
		return true
	}
	var e Event
	if err := json.Unmarshal(line, &e); err != nil {
		return false
	}
	return e.IsDenial()
}

// Tail copies matching lines from a sandbox log to w. With follow it keeps
// polling for new lines until stop is closed, and handles truncation.
func Tail(path string, w io.Writer, f Filter, follow bool, stop <-chan struct{}) error {
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("no log for this sandbox at %s", path)
		}
		return err
	}
	defer file.Close()

	r := bufio.NewReader(file)
	var partial strings.Builder
	var offset int64
	for {
		chunk, err := r.ReadString('\n')
		offset += int64(len(chunk))
		partial.WriteString(chunk)
		if err == nil {
			line := partial.String()
			partial.Reset()
			if f.match([]byte(line)) {
				if _, werr := io.WriteString(w, line); werr != nil {
					return werr
				}
			}
			continue
		}
		if !errors.Is(err, io.EOF) {
			return err
		}
		if !follow {
			return nil
		}
		select {
		case <-stop:
			return nil
		case <-time.After(200 * time.Millisecond):
		}
		if st, err := file.Stat(); err == nil && st.Size() < offset {
			if _, err := file.Seek(0, io.SeekStart); err != nil {
				return err
			}
			r.Reset(file)
			partial.Reset()
			offset = 0
		}
	}
}

// followPoll is how often Follow checks for new lines.
const followPoll = 200 * time.Millisecond

// Follow calls fn for every complete JSONL line appended to path after the
// call, until ctx is done. Lines already there are skipped, so a restarted
// reader never replays them; a file created later is read from its start,
// and a truncated one from its new start. Lines that do not parse are
// skipped.
func Follow(ctx context.Context, path string, fn func(Event)) {
	var (
		f       *os.File
		r       *bufio.Reader
		offset  int64
		partial []byte
	)
	defer func() {
		if f != nil {
			f.Close()
		}
	}()
	open := func(fromEnd bool) {
		var err error
		if f, err = os.Open(path); err != nil {
			f = nil
			return
		}
		offset = 0
		if fromEnd {
			if offset, err = f.Seek(0, io.SeekEnd); err != nil {
				f.Close()
				f = nil
				return
			}
		}
		r, partial = bufio.NewReader(f), nil
	}
	open(true)
	for {
		if f == nil {
			open(false) // created after Follow started: all of it is new
		}
		if f != nil {
			for {
				chunk, err := r.ReadBytes('\n')
				offset += int64(len(chunk))
				partial = append(partial, chunk...)
				if err != nil {
					break
				}
				var e Event
				if json.Unmarshal(partial, &e) == nil {
					fn(e)
				}
				partial = partial[:0]
			}
			if st, err := f.Stat(); err == nil && st.Size() < offset {
				f.Close()
				f = nil
				open(false)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(followPoll):
		}
	}
}

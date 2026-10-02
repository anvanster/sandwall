// Package alert delivers sandbox policy violations to webhooks.
//
// Endpoints (name, URL, signing secret) are configured on the daemon; a
// sandbox's policy selects endpoints by name and, optionally, the reasons
// it reports. Delivery never blocks the data path: events are queued per
// endpoint in a bounded queue (overflow is counted and reported in the
// next payload), batched for up to BatchInterval or BatchSize events, and
// POSTed as JSON. A quarantine event flushes its batch at once.
//
// With a secret, each request carries
//
//	X-Sandwall-Timestamp: <unix seconds>
//	X-Sandwall-Signature: sha256=<hex HMAC-SHA256(secret, "<timestamp>.<body>")>
//
// so receivers can authenticate it and reject replays.
package alert

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/anvanster/sandwall/internal/flowlog"
	"github.com/anvanster/sandwall/internal/policy"
	"github.com/anvanster/sandwall/internal/watchdog"
)

// Delivery tuning.
const (
	BatchInterval   = 2 * time.Second
	BatchSize       = 100
	QueueSize       = 1000
	attempts        = 3
	requestTimeout  = 5 * time.Second
	closeFlushLimit = 10 * time.Second
)

// Results counted per delivery attempt sequence or dropped event.
const (
	ResultOK      = "ok"
	ResultError   = "error"
	ResultDropped = "dropped"
)

// Endpoint is one named webhook.
type Endpoint struct {
	Name   string
	URL    *url.URL
	Secret []byte // empty: requests are not signed
}

// Payload is the JSON body of a delivery.
type Payload struct {
	Source string          `json:"source"` // "sandwall"
	SentAt time.Time       `json:"sent_at"`
	Events []flowlog.Event `json:"events"`
	// Dropped counts events lost to a full queue since the last delivery.
	Dropped int `json:"dropped,omitempty"`
}

// Config wires the dispatcher.
type Config struct {
	Endpoints []Endpoint
	// Proxy chooses a proxy per request, as http.Transport.Proxy; nil
	// connects directly.
	Proxy func(*http.Request) (*url.URL, error)
	// Count is notified per delivery (ok, error) and per dropped event.
	Count func(webhook, result string)
	Log   *slog.Logger
}

// Dispatcher routes logged events to webhooks.
type Dispatcher struct {
	cfg    Config
	client *http.Client
	queues map[string]*queue

	mu    sync.RWMutex
	boxes map[string]*policy.Alerts

	wg sync.WaitGroup
}

type queue struct {
	ep      Endpoint
	ch      chan flowlog.Event
	mu      sync.Mutex
	dropped int
	stop    chan struct{}
}

// New starts one delivery goroutine per endpoint.
func New(cfg Config) *Dispatcher {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	d := &Dispatcher{
		cfg:    cfg,
		client: &http.Client{Timeout: requestTimeout, Transport: &http.Transport{Proxy: cfg.Proxy}},
		queues: map[string]*queue{},
		boxes:  map[string]*policy.Alerts{},
	}
	for _, ep := range cfg.Endpoints {
		q := &queue{ep: ep, ch: make(chan flowlog.Event, QueueSize), stop: make(chan struct{})}
		d.queues[ep.Name] = q
		d.wg.Add(1)
		go d.run(q)
	}
	return d
}

// Has reports whether a webhook name is configured.
func (d *Dispatcher) Has(name string) bool {
	_, ok := d.queues[name]
	return ok
}

// Set selects a sandbox's alerts; nil turns them off.
func (d *Dispatcher) Set(sandboxID string, a *policy.Alerts) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if a == nil {
		delete(d.boxes, sandboxID)
		return
	}
	d.boxes[sandboxID] = a
}

// Remove forgets a sandbox.
func (d *Dispatcher) Remove(sandboxID string) { d.Set(sandboxID, nil) }

// Observe queues an event for the webhooks its sandbox selected, if it is
// a violation the sandbox reports. It never blocks.
func (d *Dispatcher) Observe(ev flowlog.Event) {
	reason := Reason(ev)
	if reason == "" {
		return
	}
	d.mu.RLock()
	a := d.boxes[ev.SandboxID]
	d.mu.RUnlock()
	if a == nil || (len(a.Reasons) > 0 && !slices.Contains(a.Reasons, reason)) {
		return
	}
	for _, name := range a.Webhooks {
		q, ok := d.queues[name]
		if !ok {
			continue
		}
		select {
		case q.ch <- ev:
		default:
			q.mu.Lock()
			q.dropped++
			q.mu.Unlock()
			d.count(name, ResultDropped)
		}
	}
}

// Reason maps an event to the alert reason it is reported under, or "".
func Reason(ev flowlog.Event) string {
	if ev.Type == flowlog.TypeQuarantine {
		return policy.AlertQuarantine
	}
	return watchdog.Reason(ev)
}

// Close delivers what is queued, within a bounded time, and stops.
func (d *Dispatcher) Close() {
	for _, q := range d.queues {
		close(q.stop)
	}
	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(closeFlushLimit):
		d.cfg.Log.Warn("webhook deliveries still pending at shutdown")
	}
}

func (d *Dispatcher) run(q *queue) {
	defer d.wg.Done()
	var batch []flowlog.Event
	timer := time.NewTimer(BatchInterval)
	timer.Stop()
	flush := func() {
		q.mu.Lock()
		dropped := q.dropped
		q.dropped = 0
		q.mu.Unlock()
		if len(batch) > 0 || dropped > 0 {
			d.deliver(q.ep, Payload{Source: "sandwall", SentAt: time.Now().UTC(), Events: batch, Dropped: dropped})
		}
		batch = nil
		timer.Stop()
	}
	for {
		select {
		case ev := <-q.ch:
			if len(batch) == 0 {
				timer.Reset(BatchInterval)
			}
			batch = append(batch, ev)
			if len(batch) >= BatchSize || ev.Type == flowlog.TypeQuarantine {
				flush()
			}
		case <-timer.C:
			flush()
		case <-q.stop:
			for {
				select {
				case ev := <-q.ch:
					batch = append(batch, ev)
				default:
					flush()
					return
				}
			}
		}
	}
}

func (d *Dispatcher) deliver(ep Endpoint, p Payload) {
	body, err := json.Marshal(p)
	if err != nil {
		return
	}
	var lastErr error
	for i := range attempts {
		if i > 0 {
			time.Sleep(time.Duration(i) * time.Second)
		}
		if lastErr = d.post(ep, body); lastErr == nil {
			d.count(ep.Name, ResultOK)
			return
		}
	}
	d.count(ep.Name, ResultError)
	d.cfg.Log.Warn("webhook delivery failed", "webhook", ep.Name, "events", len(p.Events), "err", lastErr)
}

func (d *Dispatcher) post(ep Endpoint, body []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.URL.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "sandwall")
	if len(ep.Secret) > 0 {
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		req.Header.Set("X-Sandwall-Timestamp", ts)
		req.Header.Set("X-Sandwall-Signature", "sha256="+Sign(ep.Secret, ts, body))
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s answered %s", ep.Name, resp.Status)
	}
	return nil
}

// Sign returns the hex HMAC-SHA256 of "<timestamp>.<body>".
func Sign(secret []byte, timestamp string, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(timestamp + "."))
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

func (d *Dispatcher) count(name, result string) {
	if d.cfg.Count != nil {
		d.cfg.Count(name, result)
	}
}

package otelexport

import (
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	collogs "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/protobuf/proto"

	"github.com/anvanster/sandwall/internal/flowlog"
)

type collector struct {
	srv     *httptest.Server
	mu      sync.Mutex
	records []*logspb.LogRecord
	paths   []string
	auth    []string
	service string
}

func newCollector(t *testing.T) *collector {
	c := &collector{}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			zr, err := gzip.NewReader(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			body = zr
		}
		data, _ := io.ReadAll(body)
		var req collogs.ExportLogsServiceRequest
		if err := proto.Unmarshal(data, &req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		c.mu.Lock()
		c.paths = append(c.paths, r.URL.Path)
		c.auth = append(c.auth, r.Header.Get("Authorization"))
		for _, rl := range req.ResourceLogs {
			for _, a := range rl.Resource.GetAttributes() {
				if a.Key == "service.name" {
					c.service = a.Value.GetStringValue()
				}
			}
			for _, sl := range rl.ScopeLogs {
				c.records = append(c.records, sl.LogRecords...)
			}
		}
		c.mu.Unlock()
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func attrs(r *logspb.LogRecord) map[string]string {
	m := map[string]string{}
	for _, a := range r.Attributes {
		if s := a.Value.GetStringValue(); s != "" {
			m[a.Key] = s
		} else if i := a.Value.GetIntValue(); i != 0 {
			m[a.Key] = strconv.FormatInt(i, 10)
		}
	}
	return m
}

func export(t *testing.T, c *collector, violationsOnly bool, evs ...flowlog.Event) {
	t.Helper()
	e, err := New(context.Background(), Config{
		Endpoint: c.srv.URL, Headers: map[string]string{"Authorization": "Bearer t0ken"}, ViolationsOnly: violationsOnly,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range evs {
		e.Observe(ev)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}

var ts = time.Date(2026, 10, 2, 9, 15, 2, 0, time.UTC)

func TestExportsRecordsWithAttributes(t *testing.T) {
	c := newCollector(t)
	export(t, c, false,
		flowlog.Event{TS: ts, Type: flowlog.TypeDeny, SandboxID: "agent", Verdict: "deny", Reason: "dns_bypass", Proto: "udp", DstIP: "8.8.8.8", DstPort: 53},
		flowlog.Event{TS: ts, Type: flowlog.TypeDNS, SandboxID: "agent", Verdict: "allow", QName: "pypi.org.", QType: "A", Answers: []string{"151.101.0.223"}},
		flowlog.Event{TS: ts, Type: flowlog.TypeRelay, SandboxID: "agent", Verdict: "deny", Reason: "sni_mismatch", SNI: "evil.test", DstIP: "151.101.0.223", DstPort: 443},
		flowlog.Event{TS: ts, Type: flowlog.TypeQuarantine, SandboxID: "agent", Verdict: "quarantined", Reason: "auto: 3 x dns_bypass"},
	)
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.records) != 4 {
		t.Fatalf("got %d records", len(c.records))
	}
	if c.paths[0] != "/v1/logs" || c.auth[0] != "Bearer t0ken" || c.service != "sandwall" {
		t.Errorf("path %q auth %q service %q", c.paths[0], c.auth[0], c.service)
	}
	deny := c.records[0]
	a := attrs(deny)
	if deny.EventName != "sandwall.deny" || deny.SeverityText != "WARN" || deny.TimeUnixNano != uint64(ts.UnixNano()) ||
		a["sandwall.sandbox.id"] != "agent" || a["sandwall.reason"] != "dns_bypass" ||
		a["destination.address"] != "8.8.8.8" || a["destination.port"] != "53" || a["network.transport"] != "udp" {
		t.Errorf("deny record: %v %v %v", deny.EventName, deny.SeverityText, a)
	}
	if got := deny.Body.GetStringValue(); got != "deny deny dns_bypass udp 8.8.8.8:53" {
		t.Errorf("body %q", got)
	}
	if a := attrs(c.records[1]); a["dns.question.name"] != "pypi.org." || c.records[1].SeverityText != "INFO" {
		t.Errorf("dns record %v", a)
	}
	if a := attrs(c.records[2]); a["tls.client.server_name"] != "evil.test" {
		t.Errorf("relay record %v", a)
	}
	if c.records[3].SeverityText != "ERROR" || c.records[3].EventName != "sandwall.quarantine" {
		t.Errorf("quarantine record %v %v", c.records[3].SeverityText, c.records[3].EventName)
	}
}

func TestViolationsOnly(t *testing.T) {
	c := newCollector(t)
	export(t, c, true,
		flowlog.Event{TS: ts, Type: flowlog.TypeFlow, SandboxID: "agent", Verdict: "allow", DstIP: "151.101.0.223"},
		flowlog.Event{TS: ts, Type: flowlog.TypeDNS, SandboxID: "agent", Verdict: "allow", QName: "pypi.org."},
		flowlog.Event{TS: ts, Type: flowlog.TypeDNS, SandboxID: "agent", Verdict: "refused", Reason: "not_allowlisted", QName: "x.evil.test."},
		flowlog.Event{TS: ts, Type: flowlog.TypeQuarantine, SandboxID: "agent", Verdict: "released"},
	)
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.records) != 2 || c.records[0].EventName != "sandwall.dns" || c.records[1].EventName != "sandwall.quarantine" {
		t.Errorf("exported %d records", len(c.records))
	}
}

func TestLogsURL(t *testing.T) {
	for in, want := range map[string]string{
		"http://collector:4318":               "http://collector:4318/v1/logs",
		"https://collector:4318/":             "https://collector:4318/v1/logs",
		"https://otlp.example/ingest/v1/logs": "https://otlp.example/ingest/v1/logs",
	} {
		u, err := LogsURL(in)
		if err != nil || u.String() != want {
			t.Errorf("LogsURL(%q) = %v, %v; want %s", in, u, err, want)
		}
	}
	for _, bad := range []string{"", "collector:4318", "grpc://collector:4317"} {
		if _, err := LogsURL(bad); err == nil {
			t.Errorf("LogsURL(%q) accepted", bad)
		}
	}
}

// Package otelexport exports the daemon's events as OpenTelemetry log
// records over OTLP/HTTP (protobuf, gzip).
//
// Every event written to a sandbox log can be exported, or only violations
// (the events a quarantine trigger or alert can count, plus quarantines).
// Records carry the event's fields as attributes, using OpenTelemetry
// semantic-convention names where one exists and sandwall.* otherwise, and
// the event type as the record's event name ("sandwall.deny", ...).
//
// Export never blocks the data path: the SDK's batch processor drops
// records when its queue is full and logs how many.
package otelexport

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"

	"github.com/anvanster/sandwall/internal/alert"
	"github.com/anvanster/sandwall/internal/flowlog"
)

// Scope is the instrumentation scope name of exported records.
const Scope = "github.com/anvanster/sandwall"

// Config configures the exporter.
type Config struct {
	// Endpoint is the OTLP/HTTP base URL ("https://collector:4318"), to
	// which /v1/logs is appended, or a full logs URL with a path.
	Endpoint string
	// Headers are sent with every request (e.g. authorization). The
	// OTEL_EXPORTER_OTLP_HEADERS variables are honoured too.
	Headers map[string]string
	// ViolationsOnly exports only violations and quarantines.
	ViolationsOnly bool
	// Proxy chooses a proxy per request; nil connects directly.
	Proxy func(*http.Request) (*url.URL, error)
	Log   *slog.Logger
}

// Exporter turns events into log records.
type Exporter struct {
	provider       *sdklog.LoggerProvider
	logger         otellog.Logger
	violationsOnly bool
}

// New starts an exporter. It does not contact the collector until the
// first batch is exported.
func New(ctx context.Context, cfg Config) (*Exporter, error) {
	u, err := LogsURL(cfg.Endpoint)
	if err != nil {
		return nil, err
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	log := cfg.Log
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(err error) {
		log.Warn("otlp export", "err", err)
	}))
	opts := []otlploghttp.Option{
		otlploghttp.WithEndpointURL(u.String()),
		otlploghttp.WithCompression(otlploghttp.GzipCompression),
	}
	if len(cfg.Headers) > 0 {
		opts = append(opts, otlploghttp.WithHeaders(cfg.Headers))
	}
	if cfg.Proxy != nil {
		opts = append(opts, otlploghttp.WithProxy(otlploghttp.HTTPTransportProxyFunc(cfg.Proxy)))
	}
	exp, err := otlploghttp.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("otlp exporter: %w", err)
	}
	host, _ := os.Hostname()
	res := resource.NewSchemaless(
		attribute.String("service.name", "sandwall"),
		attribute.String("host.name", host),
	)
	provider := sdklog.NewLoggerProvider(
		sdklog.WithResource(res),
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exp)),
	)
	return &Exporter{provider: provider, logger: provider.Logger(Scope), violationsOnly: cfg.ViolationsOnly}, nil
}

// LogsURL turns an OTLP endpoint into the logs URL: a base URL gets
// /v1/logs appended, as with OTEL_EXPORTER_OTLP_ENDPOINT.
func LogsURL(endpoint string) (*url.URL, error) {
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("otlp endpoint %q: want an http:// or https:// URL", endpoint)
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/v1/logs"
	}
	return u, nil
}

// Observe exports one event. It never blocks.
func (e *Exporter) Observe(ev flowlog.Event) {
	if e.violationsOnly && alert.Reason(ev) == "" {
		return
	}
	var r otellog.Record
	Fill(&r, ev, time.Now())
	e.logger.Emit(context.Background(), r)
}

// Shutdown exports what is queued, within ctx.
func (e *Exporter) Shutdown(ctx context.Context) error { return e.provider.Shutdown(ctx) }

// Fill maps an event onto a log record.
func Fill(r *otellog.Record, ev flowlog.Event, now time.Time) {
	r.SetTimestamp(ev.TS)
	r.SetObservedTimestamp(now)
	r.SetEventName("sandwall." + ev.Type)
	sev, text := severity(ev)
	r.SetSeverity(sev)
	r.SetSeverityText(text)
	r.SetBody(attribute.StringValue(summary(ev)))

	attrs := []attribute.KeyValue{
		attribute.String("sandwall.sandbox.id", ev.SandboxID),
		attribute.String("sandwall.event.type", ev.Type),
	}
	str := func(k, v string) {
		if v != "" {
			attrs = append(attrs, attribute.String(k, v))
		}
	}
	num := func(k string, v int64) {
		if v != 0 {
			attrs = append(attrs, attribute.Int64(k, v))
		}
	}
	str("sandwall.verdict", ev.Verdict)
	str("sandwall.reason", ev.Reason)
	str("network.transport", ev.Proto)
	str("destination.address", ev.DstIP)
	num("destination.port", int64(ev.DstPort))
	str("sandwall.destination.domain", ev.DstDomain)
	str("dns.question.name", ev.QName)
	str("sandwall.dns.question.type", ev.QType)
	if len(ev.Answers) > 0 {
		attrs = append(attrs, attribute.StringSlice("dns.answers", ev.Answers))
	}
	if ev.TSStart != nil {
		attrs = append(attrs, attribute.String("sandwall.flow.start", ev.TSStart.UTC().Format(time.RFC3339Nano)))
	}
	if ev.TSEnd != nil {
		attrs = append(attrs, attribute.String("sandwall.flow.end", ev.TSEnd.UTC().Format(time.RFC3339Nano)))
	}
	num("sandwall.bytes_out", int64(ev.BytesOut))
	num("sandwall.bytes_in", int64(ev.BytesIn))
	num("source.port", int64(ev.SrcPort))
	str("sandwall.relay.target", ev.Target)
	str("tls.client.server_name", ev.SNI)
	str("sandwall.http.host", ev.HTTPHost)
	num("sandwall.proxy.status", int64(ev.ProxyStatus))
	num("sandwall.relay.connect_ms", ev.ConnectMS)
	r.AddAttributes(attrs...)
}

func severity(ev flowlog.Event) (otellog.Severity, string) {
	switch {
	case ev.Type == flowlog.TypeQuarantine && ev.Verdict == "quarantined":
		return otellog.SeverityError1, "ERROR"
	case ev.IsDenial() || ev.Verdict == "error":
		return otellog.SeverityWarn1, "WARN"
	}
	return otellog.SeverityInfo1, "INFO"
}

// summary is a one-line human-readable body.
func summary(ev flowlog.Event) string {
	parts := []string{ev.Type, ev.Verdict}
	if ev.Reason != "" {
		parts = append(parts, ev.Reason)
	}
	switch {
	case ev.QName != "":
		parts = append(parts, ev.QType, ev.QName)
	case ev.DstIP != "":
		dst := fmt.Sprintf("%s %s:%d", ev.Proto, ev.DstIP, ev.DstPort)
		if ev.DstDomain != "" {
			dst += " (" + ev.DstDomain + ")"
		}
		parts = append(parts, dst)
	}
	if ev.SNI != "" {
		parts = append(parts, "sni="+ev.SNI)
	}
	if ev.HTTPHost != "" {
		parts = append(parts, "host="+ev.HTTPHost)
	}
	return strings.Join(parts, " ")
}

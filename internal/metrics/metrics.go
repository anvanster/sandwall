// Package metrics exposes sandwall's Prometheus metrics. Every series carries
// a "sandbox" label holding the sandbox ID.
package metrics

import (
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds the sandwall collectors on a private registry.
type Metrics struct {
	reg    *prometheus.Registry
	Flows  *prometheus.CounterVec
	Bytes  *prometheus.CounterVec
	Denied *prometheus.CounterVec
	// sandwall_dns_queries_total and sandwall_relay_connections_total are
	// counted by each sandbox's data plane process and read at scrape time
	// through SetDataplaneSource.
	dataplane *dataplaneCollector
	// Quarantined is 1 while a sandbox is quarantined.
	Quarantined *prometheus.GaugeVec
	// AutoQuarantines counts quarantines started by a policy trigger.
	AutoQuarantines *prometheus.CounterVec
	// WebhookDeliveries counts webhook deliveries (ok, error) and events
	// dropped from a full queue, per webhook. It has no sandbox label.
	WebhookDeliveries *prometheus.CounterVec
}

// New registers all collectors.
func New() *Metrics {
	m := &Metrics{
		reg: prometheus.NewRegistry(),
		Flows: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sandwall_flows_total", Help: "Finished flows by verdict.",
		}, []string{"sandbox", "verdict"}),
		Bytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sandwall_bytes_total", Help: "Bytes by direction (out = sandbox to world).",
		}, []string{"sandbox", "direction"}),
		Denied: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sandwall_denied_total", Help: "Packets dropped or rejected by reason.",
		}, []string{"sandbox", "reason"}),
		Quarantined: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "sandwall_quarantined", Help: "1 while the sandbox is quarantined.",
		}, []string{"sandbox"}),
		AutoQuarantines: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sandwall_auto_quarantines_total", Help: "Quarantines started by a policy trigger.",
		}, []string{"sandbox"}),
		WebhookDeliveries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sandwall_webhook_deliveries_total", Help: "Webhook deliveries by result (ok, error), and events dropped from a full queue (dropped).",
		}, []string{"webhook", "result"}),
	}
	m.dataplane = &dataplaneCollector{
		dns: prometheus.NewDesc("sandwall_dns_queries_total", "DNS queries by verdict.", []string{"sandbox", "verdict"}, nil),
		relay: prometheus.NewDesc("sandwall_relay_connections_total",
			"Connections and HTTP requests through the relay (SNI/Host check, upstream proxy) by result.", []string{"sandbox", "result"}, nil),
	}
	m.reg.MustRegister(m.Flows, m.Bytes, m.Denied, m.dataplane, m.Quarantined, m.AutoQuarantines, m.WebhookDeliveries,
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return m
}

// Forget drops every series for a destroyed sandbox so label cardinality
// does not grow with sandbox churn.
func (m *Metrics) Forget(sandboxID string) {
	l := prometheus.Labels{"sandbox": sandboxID}
	for _, v := range []*prometheus.CounterVec{m.Flows, m.Bytes, m.Denied, m.AutoQuarantines} {
		v.DeletePartialMatch(l)
	}
	m.Quarantined.DeletePartialMatch(l)
}

// Handler serves the registry in the Prometheus exposition format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{Registry: m.reg})
}

// DataplaneCounters are one sandbox's data plane counters.
type DataplaneCounters struct {
	Sandbox string
	DNS     map[string]float64 // by verdict
	Relay   map[string]float64 // by result
}

// SetDataplaneSource sets the function read at every scrape for the
// counters kept by the sandboxes' data plane processes. A data plane that
// restarts starts its counters from zero, which Prometheus treats as a
// counter reset.
func (m *Metrics) SetDataplaneSource(fn func() []DataplaneCounters) {
	m.dataplane.mu.Lock()
	m.dataplane.source = fn
	m.dataplane.mu.Unlock()
}

type dataplaneCollector struct {
	dns, relay *prometheus.Desc
	mu         sync.Mutex
	source     func() []DataplaneCounters
}

func (c *dataplaneCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.dns
	ch <- c.relay
}

func (c *dataplaneCollector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	source := c.source
	c.mu.Unlock()
	if source == nil {
		return
	}
	for _, sc := range source() {
		for verdict, v := range sc.DNS {
			ch <- prometheus.MustNewConstMetric(c.dns, prometheus.CounterValue, v, sc.Sandbox, verdict)
		}
		for result, v := range sc.Relay {
			ch <- prometheus.MustNewConstMetric(c.relay, prometheus.CounterValue, v, sc.Sandbox, result)
		}
	}
}

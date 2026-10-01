// Package metrics exposes sandwall's Prometheus metrics. Every series carries
// a "sandbox" label holding the sandbox ID.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds the sandwall collectors on a private registry.
type Metrics struct {
	reg        *prometheus.Registry
	Flows      *prometheus.CounterVec
	Bytes      *prometheus.CounterVec
	DNSQueries *prometheus.CounterVec
	Denied     *prometheus.CounterVec
	// RelayConnections counts relay decisions: ok, denied, refused (by
	// the upstream proxy) or error.
	RelayConnections *prometheus.CounterVec
	// Quarantined is 1 while a sandbox is quarantined.
	Quarantined *prometheus.GaugeVec
	// AutoQuarantines counts quarantines started by a policy trigger.
	AutoQuarantines *prometheus.CounterVec
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
		DNSQueries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sandwall_dns_queries_total", Help: "DNS queries by verdict.",
		}, []string{"sandbox", "verdict"}),
		Denied: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sandwall_denied_total", Help: "Packets dropped or rejected by reason.",
		}, []string{"sandbox", "reason"}),
		RelayConnections: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sandwall_relay_connections_total", Help: "Connections and HTTP requests through the relay (SNI/Host check, upstream proxy) by result.",
		}, []string{"sandbox", "result"}),
		Quarantined: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "sandwall_quarantined", Help: "1 while the sandbox is quarantined.",
		}, []string{"sandbox"}),
		AutoQuarantines: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "sandwall_auto_quarantines_total", Help: "Quarantines started by a policy trigger.",
		}, []string{"sandbox"}),
	}
	m.reg.MustRegister(m.Flows, m.Bytes, m.DNSQueries, m.Denied, m.RelayConnections, m.Quarantined, m.AutoQuarantines,
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return m
}

// Forget drops every series for a destroyed sandbox so label cardinality
// does not grow with sandbox churn.
func (m *Metrics) Forget(sandboxID string) {
	l := prometheus.Labels{"sandbox": sandboxID}
	for _, v := range []*prometheus.CounterVec{m.Flows, m.Bytes, m.DNSQueries, m.Denied, m.RelayConnections, m.AutoQuarantines} {
		v.DeletePartialMatch(l)
	}
	m.Quarantined.DeletePartialMatch(l)
}

// Handler serves the registry in the Prometheus exposition format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{Registry: m.reg})
}

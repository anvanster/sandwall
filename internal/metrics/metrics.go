// Package metrics exposes egressd's Prometheus metrics. Every series carries
// a "sandbox" label holding the sandbox ID.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds the egressd collectors on a private registry.
type Metrics struct {
	reg        *prometheus.Registry
	Flows      *prometheus.CounterVec
	Bytes      *prometheus.CounterVec
	DNSQueries *prometheus.CounterVec
	Denied     *prometheus.CounterVec
	// ProxyConnects counts relay decisions: ok, denied, refused (by the
	// upstream proxy) or error.
	ProxyConnects *prometheus.CounterVec
}

// New registers all collectors.
func New() *Metrics {
	m := &Metrics{
		reg: prometheus.NewRegistry(),
		Flows: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "egressd_flows_total", Help: "Finished flows by verdict.",
		}, []string{"sandbox", "verdict"}),
		Bytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "egressd_bytes_total", Help: "Bytes by direction (out = sandbox to world).",
		}, []string{"sandbox", "direction"}),
		DNSQueries: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "egressd_dns_queries_total", Help: "DNS queries by verdict.",
		}, []string{"sandbox", "verdict"}),
		Denied: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "egressd_denied_total", Help: "Packets dropped or rejected by reason.",
		}, []string{"sandbox", "reason"}),
		ProxyConnects: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "egressd_proxy_connects_total", Help: "Connections and HTTP requests through the upstream proxy by result.",
		}, []string{"sandbox", "result"}),
	}
	m.reg.MustRegister(m.Flows, m.Bytes, m.DNSQueries, m.Denied, m.ProxyConnects,
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	return m
}

// Forget drops every series for a destroyed sandbox so label cardinality
// does not grow with sandbox churn.
func (m *Metrics) Forget(sandboxID string) {
	l := prometheus.Labels{"sandbox": sandboxID}
	for _, v := range []*prometheus.CounterVec{m.Flows, m.Bytes, m.DNSQueries, m.Denied, m.ProxyConnects} {
		v.DeletePartialMatch(l)
	}
}

// Handler serves the registry in the Prometheus exposition format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{Registry: m.reg})
}

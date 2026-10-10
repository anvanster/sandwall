// Package dataplane runs a sandbox's DNS proxy and relay in their own
// process, apart from the daemon. Connections the relay carries and the DNS
// the sandbox depends on then outlive a daemon restart or crash: a restarted
// daemon adopts the running data plane, as it adopts running Firecracker VMs.
//
// The daemon writes a Config file and starts `sandwall dataplane --config
// <file>` detached. It talks to the data plane over a root-only unix socket
// (Client): policy reloads, quarantine, the DNS name behind an address (for
// flow logs) and counters (for metrics). The data plane appends its own
// events (dns, relay) to the sandbox's JSONL log; the daemon tails them for
// alerts, auto-quarantine and OTel export.
package dataplane

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/anvanster/sandwall/internal/dnsproxy"
	"github.com/anvanster/sandwall/internal/nft"
	"github.com/anvanster/sandwall/internal/relay"
)

// ProtocolVersion changes whenever Config or the control API change
// incompatibly; a restarted daemon then restarts the data plane instead of
// adopting it.
const ProtocolVersion = 1

// Config is everything a sandbox's data plane needs.
type Config struct {
	Version   int    `json:"version"`
	SandboxID string `json:"sandbox_id"`
	Index     int    `json:"index"`
	// LogDir holds the sandbox's JSONL log (shared with the daemon, both
	// appending) and the data plane's own diagnostics.
	LogDir       string `json:"log_dir"`
	DNSStatePath string `json:"dns_state_path"`
	Socket       string `json:"socket"`
	PIDFile      string `json:"pid_file"`

	DNSListen netip.AddrPort    `json:"dns_listen"`
	DNS       dnsproxy.Settings `json:"dns"`
	// Relay is nil when the sandbox has no relay (no SNI check, no proxy).
	Relay *RelayConfig `json:"relay,omitempty"`

	Quarantined bool `json:"quarantined"`
}

// RelayConfig configures the relay.
type RelayConfig struct {
	Listen netip.AddrPort `json:"listen"`
	// Upstream is the upstream proxy URL, credentials included, or "".
	Upstream  string         `json:"upstream,omitempty"`
	Synthetic netip.Prefix   `json:"synthetic,omitempty"`
	Settings  relay.Settings `json:"settings"`
	// DirectListen, behind an upstream proxy with the SNI check, is a
	// second relay that dials no_proxy destinations directly; the firewall
	// redirects their check-port connections there. Zero means none.
	DirectListen netip.AddrPort `json:"direct_listen,omitempty"`
}

// Policy is a hot reload: new DNS and relay settings, and the sandbox's
// ruleset to re-render once the allow sets are refilled from the DNS cache.
type Policy struct {
	DNS   dnsproxy.Settings `json:"dns"`
	Relay relay.Settings    `json:"relay"`
	Rules nft.SandboxConfig `json:"rules"`
}

// Status answers GET /v1/status.
type Status struct {
	Version int    `json:"version"`
	PID     int    `json:"pid"`
	Hash    string `json:"hash"`
}

// Counters answers GET /v1/counters: cumulative since the data plane
// started.
type Counters struct {
	DNS   map[string]float64 `json:"dns"`   // by verdict
	Relay map[string]float64 `json:"relay"` // by result
}

// Hash identifies the parts of a Config that cannot change while the data
// plane runs: listeners, files, the relay's upstream and synthetic pool.
// Settings and quarantine are reapplied to an adopted data plane instead.
func (c Config) Hash() string {
	type structural struct {
		Version              int
		SandboxID            string
		Index                int
		LogDir, DNSStatePath string
		Socket, PIDFile      string
		DNSListen            netip.AddrPort
		Synthetic            netip.Prefix
		Relay                bool
		RelayListen          netip.AddrPort
		DirectListen         netip.AddrPort
		Upstream             string
	}
	s := structural{
		Version: c.Version, SandboxID: c.SandboxID, Index: c.Index, LogDir: c.LogDir,
		DNSStatePath: c.DNSStatePath, Socket: c.Socket, PIDFile: c.PIDFile,
		DNSListen: c.DNSListen, Synthetic: c.DNS.Synthetic,
	}
	if c.Relay != nil {
		s.Relay, s.RelayListen, s.DirectListen, s.Upstream = true, c.Relay.Listen, c.Relay.DirectListen, c.Relay.Upstream
	}
	data, _ := json.Marshal(s)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// WriteConfig stores c at path, readable by root only: it can hold upstream
// proxy credentials.
func WriteConfig(path string, c Config) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ReadConfig loads a Config written by WriteConfig.
func ReadConfig(path string) (Config, error) {
	var c Config
	data, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return c, fmt.Errorf("%s: %w", path, err)
	}
	if c.Version != ProtocolVersion {
		return c, fmt.Errorf("%s: protocol version %d, this binary speaks %d", path, c.Version, ProtocolVersion)
	}
	return c, nil
}

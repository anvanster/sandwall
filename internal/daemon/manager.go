//go:build linux

// Package daemon owns sandbox lifecycle. It is the only place that knows how
// netns, nft, dnsproxy, flowlog and metrics fit together; internal/api is
// just a transport in front of it.
package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/anvanster/egressd/internal/addressing"
	"github.com/anvanster/egressd/internal/dnsproxy"
	"github.com/anvanster/egressd/internal/flowlog"
	"github.com/anvanster/egressd/internal/metrics"
	"github.com/anvanster/egressd/internal/netns"
	"github.com/anvanster/egressd/internal/nft"
	"github.com/anvanster/egressd/internal/policy"
	"github.com/anvanster/egressd/internal/shaper"
)

// Sandbox modes.
const (
	ModeExec = "exec"
	ModeVM   = "vm"
)

// Default filesystem locations.
const (
	DefaultStateDir = "/var/lib/egressd"
	DefaultLogDir   = "/var/log/egressd"
)

var idPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$`)

// ErrNotFound is returned for unknown sandbox IDs.
var ErrNotFound = errors.New("sandbox not found")

// ErrExists is returned when creating a sandbox ID that is already in use.
var ErrExists = errors.New("sandbox already exists")

// Options configure a Manager.
type Options struct {
	StateDir string
	LogDir   string
	// BlockedExempt carves test endpoints out of the blocked ranges.
	BlockedExempt []netip.Prefix
	// DefaultUpstream is used when a policy has no upstream_dns.
	DefaultUpstream string
	Log             *slog.Logger
	Metrics         *metrics.Metrics
}

// Record is the persisted description of a sandbox.
type Record struct {
	ID      string    `json:"id"`
	Index   int       `json:"index"`
	Mode    string    `json:"mode"`
	Policy  string    `json:"policy"` // original YAML
	Created time.Time `json:"created"`
}

// Info is the API view of a sandbox.
type Info struct {
	ID       string         `json:"id"`
	Index    int            `json:"index"`
	Mode     string         `json:"mode"`
	Netns    string         `json:"netns"`
	HostVeth string         `json:"host_veth"`
	HostAddr string         `json:"host_addr"`
	NsAddr   string         `json:"ns_addr"`
	Created  time.Time      `json:"created"`
	Policy   *policy.Policy `json:"policy"`
	LogPath  string         `json:"log_path"`
}

type sandbox struct {
	rec    Record
	addr   addressing.Sandbox
	policy *policy.Policy
	proxy  *dnsproxy.Proxy
}

// Manager creates, reloads and destroys sandboxes.
type Manager struct {
	opts Options
	log  *slog.Logger
	sink *flowlog.Sink
	m    *metrics.Metrics

	mu      sync.Mutex
	byID    map[string]*sandbox
	byIndex map[int]*sandbox
}

// New prepares the host (sysctls, base ruleset) and restores sandboxes
// persisted by a previous daemon run.
func New(ctx context.Context, opts Options) (*Manager, error) {
	if opts.StateDir == "" {
		opts.StateDir = DefaultStateDir
	}
	if opts.LogDir == "" {
		opts.LogDir = DefaultLogDir
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Metrics == nil {
		opts.Metrics = metrics.New()
	}
	if opts.DefaultUpstream == "" {
		up, err := SystemResolver()
		if err != nil {
			return nil, err
		}
		opts.DefaultUpstream = up
	}
	sink, err := flowlog.NewSink(opts.LogDir)
	if err != nil {
		return nil, err
	}
	mgr := &Manager{
		opts: opts, log: opts.Log, sink: sink, m: opts.Metrics,
		byID: map[string]*sandbox{}, byIndex: map[int]*sandbox{},
	}
	if err := mgr.ensureHost(ctx); err != nil {
		return nil, err
	}
	if err := mgr.restore(ctx); err != nil {
		return nil, err
	}
	return mgr, nil
}

// SystemResolver returns the first nameserver from /etc/resolv.conf.
func SystemResolver() (string, error) {
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return "", fmt.Errorf("read system resolver: %w", err)
	}
	for _, s := range cfg.Servers {
		if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
			return netip.AddrPortFrom(a, 53).String(), nil
		}
	}
	return "", errors.New("no IPv4 nameserver in /etc/resolv.conf; set upstream_dns in the policy or --upstream-dns")
}

func (mgr *Manager) recordsDir() string { return filepath.Join(mgr.opts.StateDir, "sandboxes") }
func (mgr *Manager) sysctlFile() string { return filepath.Join(mgr.opts.StateDir, "sysctl-orig.json") }
func (mgr *Manager) recordPath(id string) string {
	return filepath.Join(mgr.recordsDir(), id+".json")
}

// ensureHost applies host sysctls and the base ruleset. Idempotent, so it
// also recovers from a nuke run while the daemon was up.
func (mgr *Manager) ensureHost(ctx context.Context) error {
	if err := netns.EnableHostSysctls(mgr.sysctlFile()); err != nil {
		return fmt.Errorf("host sysctls: %w", err)
	}
	base := nft.RenderBase(nft.BaseConfig{BlockedRanges: nft.DefaultBlockedRanges, BlockedExempt: mgr.opts.BlockedExempt})
	if err := nft.Apply(ctx, base); err != nil {
		return fmt.Errorf("base ruleset: %w", err)
	}
	return nil
}

func (mgr *Manager) restore(ctx context.Context) error {
	entries, err := os.ReadDir(mgr.recordsDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(mgr.recordsDir(), e.Name()))
		if err != nil {
			return err
		}
		var rec Record
		if err := json.Unmarshal(data, &rec); err != nil {
			mgr.log.Error("skipping corrupt sandbox record", "file", e.Name(), "err", err)
			continue
		}
		pol, err := policy.Parse([]byte(rec.Policy))
		if err != nil {
			mgr.log.Error("skipping sandbox with invalid stored policy", "id", rec.ID, "err", err)
			continue
		}
		mgr.mu.Lock()
		err = mgr.setupLocked(ctx, rec, pol, true)
		mgr.mu.Unlock()
		if err != nil {
			mgr.log.Error("failed to restore sandbox", "id", rec.ID, "err", err)
			continue
		}
		mgr.log.Info("restored sandbox", "id", rec.ID, "index", rec.Index)
	}
	return nil
}

// Create builds a new sandbox.
func (mgr *Manager) Create(ctx context.Context, id, mode, policyYAML string) (Info, error) {
	if !idPattern.MatchString(id) {
		return Info{}, fmt.Errorf("invalid sandbox id %q: use 1-63 of [a-zA-Z0-9_.-], starting alphanumeric", id)
	}
	switch mode {
	case "", ModeExec:
		mode = ModeExec
	case ModeVM:
		return Info{}, errors.New("vm mode is not implemented yet (milestone M3)")
	default:
		return Info{}, fmt.Errorf("unknown mode %q", mode)
	}
	pol, err := policy.Parse([]byte(policyYAML))
	if err != nil {
		return Info{}, err
	}

	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	if _, ok := mgr.byID[id]; ok {
		return Info{}, fmt.Errorf("%w: %s", ErrExists, id)
	}
	k, err := mgr.allocIndexLocked()
	if err != nil {
		return Info{}, err
	}
	if err := mgr.ensureHost(ctx); err != nil {
		return Info{}, err
	}
	rec := Record{ID: id, Index: k, Mode: mode, Policy: policyYAML, Created: time.Now().UTC()}
	if err := mgr.setupLocked(ctx, rec, pol, false); err != nil {
		if cerr := mgr.teardown(ctx, addressing.MustFor(k)); cerr != nil {
			mgr.log.Error("rollback after failed create", "id", id, "err", cerr)
		}
		return Info{}, err
	}
	if err := mgr.persist(rec); err != nil {
		mgr.destroyLocked(ctx, mgr.byID[id])
		return Info{}, err
	}
	mgr.log.Info("created sandbox", "id", id, "index", k, "mode", mode)
	return mgr.infoLocked(mgr.byID[id]), nil
}

// allocIndexLocked picks the lowest free index that also has no leftovers
// on the host from a previous run.
func (mgr *Manager) allocIndexLocked() (int, error) {
	stale := map[int]bool{}
	if left, err := netns.Leftovers(); err == nil {
		for _, k := range left {
			stale[k] = true
		}
	}
	for k := addressing.MinIndex; k <= addressing.MaxIndex; k++ {
		if _, used := mgr.byIndex[k]; !used && !stale[k] {
			return k, nil
		}
	}
	return 0, errors.New("no free sandbox index")
}

// setupLocked brings every piece of a sandbox to the desired state. It is
// idempotent; restoring passes preserveAllowed to keep DNS-learned set
// entries made before the daemon restarted.
func (mgr *Manager) setupLocked(ctx context.Context, rec Record, pol *policy.Policy, preserveAllowed bool) error {
	sb, err := addressing.For(rec.Index)
	if err != nil {
		return err
	}
	if err := netns.Create(sb); err != nil {
		return err
	}
	if err := shaper.Apply(ctx, sb, shapeLimits(pol)); err != nil {
		return err
	}
	if rec.Mode == ModeExec {
		if err := netns.WriteResolvConf(sb); err != nil {
			return err
		}
	}
	script, err := nft.RenderSandbox(sandboxRules(sb.Index, pol, nil, preserveAllowed))
	if err != nil {
		return err
	}
	if err := nft.Apply(ctx, script); err != nil {
		return err
	}
	if err := mgr.sink.Open(rec.ID); err != nil {
		return err
	}
	proxy := dnsproxy.New(dnsproxy.Config{
		SandboxID:  rec.ID,
		Index:      sb.Index,
		Listen:     netip.AddrPortFrom(sb.HostAddr, 53),
		Insert:     insertAllowed,
		Sink:       mgr.sink,
		CountQuery: func(id, verdict string) { mgr.m.DNSQueries.WithLabelValues(id, verdict).Inc() },
	}, mgr.proxySettings(pol))
	if err := proxy.Start(); err != nil {
		_ = mgr.sink.Close(rec.ID)
		return err
	}
	s := &sandbox{rec: rec, addr: sb, policy: pol, proxy: proxy}
	mgr.byID[rec.ID] = s
	mgr.byIndex[sb.Index] = s
	return nil
}

func sandboxRules(k int, pol *policy.Policy, allowed []nft.AllowEntry, preserve bool) nft.SandboxConfig {
	return nft.SandboxConfig{
		Index:           k,
		AllowCIDRs:      pol.Egress.AllowCIDRs,
		MaxConns:        pol.Limits.MaxConns,
		NewConnsPerSec:  pol.Limits.NewConnsPerSec,
		Allowed:         allowed,
		PreserveAllowed: preserve,
	}
}

func shapeLimits(pol *policy.Policy) shaper.Limits {
	return shaper.Limits{EgressBits: pol.EgressBitsPerSec(), IngressBits: pol.IngressBitsPerSec()}
}

func (mgr *Manager) proxySettings(pol *policy.Policy) dnsproxy.Settings {
	up := pol.UpstreamDNS
	if up == "" {
		up = mgr.opts.DefaultUpstream
	}
	return dnsproxy.Settings{AllowDomains: pol.Egress.AllowDomains, QPS: pol.Limits.DNSQPS, Upstream: up}
}

func insertAllowed(ctx context.Context, k int, entries []nft.AllowEntry) error {
	return nft.Apply(ctx, nft.RenderAllow(k, entries))
}

// ApplyPolicy hot-reloads a sandbox's policy: the chain is re-rendered and
// the allow sets flushed and repopulated in one transaction, so established
// flows survive.
func (mgr *Manager) ApplyPolicy(ctx context.Context, id, policyYAML string) (Info, error) {
	pol, err := policy.Parse([]byte(policyYAML))
	if err != nil {
		return Info{}, err
	}
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	s, ok := mgr.byID[id]
	if !ok {
		return Info{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if err := mgr.ensureHost(ctx); err != nil {
		return Info{}, err
	}
	err = s.proxy.Reload(mgr.proxySettings(pol), func(live []nft.AllowEntry) error {
		script, err := nft.RenderSandbox(sandboxRules(s.addr.Index, pol, live, false))
		if err != nil {
			return err
		}
		return nft.Apply(ctx, script)
	})
	if err != nil {
		// Put the proxy back on the old policy; the nft transaction was atomic.
		_ = s.proxy.Reload(mgr.proxySettings(s.policy), func([]nft.AllowEntry) error { return nil })
		return Info{}, err
	}
	if err := shaper.Apply(ctx, s.addr, shapeLimits(pol)); err != nil {
		return Info{}, fmt.Errorf("policy applied to firewall and DNS but not to tc: %w", err)
	}
	rec := s.rec
	rec.Policy = policyYAML
	if err := mgr.persist(rec); err != nil {
		return Info{}, err
	}
	s.rec, s.policy = rec, pol
	mgr.log.Info("applied policy", "id", id)
	return mgr.infoLocked(s), nil
}

// Destroy removes a sandbox and everything it created. Its log is kept.
func (mgr *Manager) Destroy(ctx context.Context, id string) error {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	s, ok := mgr.byID[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return mgr.destroyLocked(ctx, s)
}

func (mgr *Manager) destroyLocked(ctx context.Context, s *sandbox) error {
	s.proxy.Stop()
	err := mgr.teardown(ctx, s.addr)
	_ = mgr.sink.Close(s.rec.ID)
	mgr.m.Forget(s.rec.ID)
	delete(mgr.byID, s.rec.ID)
	delete(mgr.byIndex, s.addr.Index)
	if rerr := os.Remove(mgr.recordPath(s.rec.ID)); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
		err = errors.Join(err, rerr)
	}
	if err == nil {
		mgr.log.Info("destroyed sandbox", "id", s.rec.ID)
	}
	return err
}

func (mgr *Manager) teardown(ctx context.Context, sb addressing.Sandbox) error {
	var errs []error
	if script, err := nft.RenderRemoveSandbox(sb.Index); err != nil {
		errs = append(errs, err)
	} else if err := nft.Apply(ctx, script); err != nil {
		errs = append(errs, err)
	}
	if err := netns.Destroy(sb); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Nuke stops every sandbox the daemon knows about and removes all egressd
// state from the host, including leftovers it does not know about.
func (mgr *Manager) Nuke(ctx context.Context) error {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	for _, s := range mgr.byID {
		s.proxy.Stop()
		_ = mgr.sink.Close(s.rec.ID)
		mgr.m.Forget(s.rec.ID)
	}
	mgr.byID = map[string]*sandbox{}
	mgr.byIndex = map[int]*sandbox{}
	return Cleanup(ctx, mgr.opts.StateDir)
}

// Cleanup removes all egressd netns, veths, /etc/netns entries, the nft
// table and persisted records, then restores host sysctls. It needs no
// running daemon and is idempotent.
func Cleanup(ctx context.Context, stateDir string) error {
	if stateDir == "" {
		stateDir = DefaultStateDir
	}
	var errs []error
	left, err := netns.Leftovers()
	if err != nil {
		errs = append(errs, err)
	}
	for _, k := range left {
		if err := netns.Destroy(addressing.MustFor(k)); err != nil {
			errs = append(errs, err)
		}
	}
	if err := nft.Apply(ctx, nft.RenderDeleteTable()); err != nil {
		errs = append(errs, err)
	}
	if err := os.RemoveAll(filepath.Join(stateDir, "sandboxes")); err != nil {
		errs = append(errs, err)
	}
	if err := netns.RestoreHostSysctls(filepath.Join(stateDir, "sysctl-orig.json")); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Get returns one sandbox.
func (mgr *Manager) Get(id string) (Info, error) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	s, ok := mgr.byID[id]
	if !ok {
		return Info{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return mgr.infoLocked(s), nil
}

// List returns all sandboxes ordered by index.
func (mgr *Manager) List() []Info {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	out := make([]Info, 0, len(mgr.byID))
	for _, s := range mgr.byID {
		out = append(out, mgr.infoLocked(s))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out
}

// SandboxForIndex resolves a log-prefix index to a sandbox ID.
func (mgr *Manager) SandboxForIndex(k int) (string, bool) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	s, ok := mgr.byIndex[k]
	if !ok {
		return "", false
	}
	return s.rec.ID, true
}

// Domain returns the allowlisted name that most recently resolved to ip in
// sandbox k, for flow-log attribution.
func (mgr *Manager) Domain(k int, ip netip.Addr) string {
	mgr.mu.Lock()
	s, ok := mgr.byIndex[k]
	mgr.mu.Unlock()
	if !ok {
		return ""
	}
	return s.proxy.Domain(ip)
}

// Sink exposes the event sink for collectors.
func (mgr *Manager) Sink() *flowlog.Sink { return mgr.sink }

// Close stops DNS listeners and closes logs. Sandboxes keep existing and
// are restored by the next daemon start; without the proxy their DNS fails
// closed.
func (mgr *Manager) Close() {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	for _, s := range mgr.byID {
		s.proxy.Stop()
	}
	mgr.sink.CloseAll()
}

func (mgr *Manager) infoLocked(s *sandbox) Info {
	return Info{
		ID: s.rec.ID, Index: s.addr.Index, Mode: s.rec.Mode, Netns: s.addr.Netns,
		HostVeth: s.addr.HostVeth, HostAddr: s.addr.HostAddr.String(), NsAddr: s.addr.NsAddr.String(),
		Created: s.rec.Created, Policy: s.policy, LogPath: flowlog.Path(mgr.opts.LogDir, s.rec.ID),
	}
}

func (mgr *Manager) persist(rec Record) error {
	if err := os.MkdirAll(mgr.recordsDir(), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	tmp := mgr.recordPath(rec.ID) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, mgr.recordPath(rec.ID))
}

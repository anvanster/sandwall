//go:build linux

// Package daemon owns sandbox lifecycle. It is the only place that knows how
// netns, nft, shaper, dnsproxy, fc, flowlog and metrics fit together;
// internal/api is just a transport in front of it.
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
	"github.com/anvanster/egressd/internal/fc"
	"github.com/anvanster/egressd/internal/flowlog"
	"github.com/anvanster/egressd/internal/metrics"
	"github.com/anvanster/egressd/internal/netns"
	"github.com/anvanster/egressd/internal/nft"
	"github.com/anvanster/egressd/internal/policy"
	"github.com/anvanster/egressd/internal/relay"
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

// MaxClones bounds one clone request.
const MaxClones = 200

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
	// UpstreamProxy, when set, carries every sandbox's allowed TCP through
	// this HTTP proxy instead of forwarding it to the uplink.
	UpstreamProxy *relay.Upstream
	// NoProxy lists destinations that bypass UpstreamProxy.
	NoProxy relay.NoProxy
	// FC locates firecracker and jailer for VM mode. VM mode is unavailable
	// when either binary is unset.
	FC      fc.Paths
	Log     *slog.Logger
	Metrics *metrics.Metrics
}

// Record is the persisted description of a sandbox.
type Record struct {
	ID      string    `json:"id"`
	Index   int       `json:"index"`
	Mode    string    `json:"mode"`
	Policy  string    `json:"policy"` // original YAML
	Created time.Time `json:"created"`
	// VM mode: exactly one of VMConfig (boot) or Snapshot (clone) is set.
	VMConfig string `json:"vm_config,omitempty"`
	Snapshot string `json:"snapshot,omitempty"`
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
	VM       *VMInfo        `json:"vm,omitempty"`
}

// VMInfo describes a VM-mode sandbox's microVM.
type VMInfo struct {
	Running    bool   `json:"running"`
	GuestAddr  string `json:"guest_addr"`
	JailRoot   string `json:"jail_root"`
	ConsoleLog string `json:"console_log"`
	ClonedFrom string `json:"cloned_from,omitempty"`
}

type sandbox struct {
	rec    Record
	addr   addressing.Sandbox
	policy *policy.Policy
	proxy  *dnsproxy.Proxy
	relay  *relay.Relay // nil without an upstream proxy
}

// stop closes the sandbox's DNS proxy and relay listeners.
func (s *sandbox) stop() {
	s.proxy.Stop()
	if s.relay != nil {
		s.relay.Stop()
	}
}

// Manager creates, reloads and destroys sandboxes.
type Manager struct {
	opts Options
	log  *slog.Logger
	sink *flowlog.Sink
	m    *metrics.Metrics

	// opMu serializes lifecycle operations, which may take seconds (VM
	// boot, image copies). mu only guards the maps, so log collectors'
	// lookups never wait behind a lifecycle operation.
	opMu sync.Mutex
	mu   sync.Mutex
	// resetDirect makes restore drop DNS-learned direct_<k> entries,
	// because no_proxy changed since they were learned.
	resetDirect bool
	byID        map[string]*sandbox
	byIndex     map[int]*sandbox
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
	if opts.FC.ChrootBase == "" {
		opts.FC.ChrootBase = fc.DefaultChrootBase
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
	changed, err := mgr.recordNoProxy()
	if err != nil {
		return nil, err
	}
	mgr.resetDirect = changed
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

// recordNoProxy stores the effective no_proxy list and reports whether it
// differs from the one the previous daemon run stored.
func (mgr *Manager) recordNoProxy() (bool, error) {
	var cur relay.NoProxy
	if mgr.opts.UpstreamProxy != nil {
		cur = mgr.opts.NoProxy
	}
	data, err := json.Marshal(cur)
	if err != nil {
		return false, err
	}
	path := filepath.Join(mgr.opts.StateDir, "no-proxy.json")
	prev, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if string(prev) == string(data) {
		return false, nil
	}
	if err := os.MkdirAll(mgr.opts.StateDir, 0o700); err != nil {
		return false, err
	}
	return true, os.WriteFile(path, data, 0o600)
}
func (mgr *Manager) recordPath(id string) string {
	return filepath.Join(mgr.recordsDir(), id+".json")
}

func (mgr *Manager) vm(sb addressing.Sandbox, id string) fc.VM {
	return fc.VM{Paths: mgr.opts.FC, Sandbox: sb, ConsoleLog: filepath.Join(mgr.opts.LogDir, id+".console.log")}
}

func (mgr *Manager) vmAvailable() error {
	if mgr.opts.FC.Firecracker == "" || mgr.opts.FC.Jailer == "" {
		return errors.New("vm mode needs the daemon started with --firecracker and --jailer")
	}
	return nil
}

// ensureHost applies host sysctls and the base ruleset. Idempotent, so it
// also recovers from a nuke run while the daemon was up.
func (mgr *Manager) ensureHost(ctx context.Context) error {
	if err := netns.EnableHostSysctls(mgr.sysctlFile()); err != nil {
		return fmt.Errorf("host sysctls: %w", err)
	}
	base := nft.RenderBase(nft.BaseConfig{
		BlockedRanges: nft.DefaultBlockedRanges,
		BlockedExempt: mgr.opts.BlockedExempt,
		Proxy:         mgr.opts.UpstreamProxy != nil,
		DirectCIDRs:   mgr.opts.NoProxy.CIDRs,
	})
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
	mgr.opMu.Lock()
	defer mgr.opMu.Unlock()
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
		if err := mgr.setup(ctx, rec, pol, true); err != nil {
			mgr.log.Error("failed to restore sandbox", "id", rec.ID, "err", err)
			continue
		}
		mgr.log.Info("restored sandbox", "id", rec.ID, "index", rec.Index, "mode", rec.Mode)
	}
	return nil
}

// Create builds a new sandbox. vmConfig is the Firecracker config JSON for
// vm mode and must be empty for exec mode.
func (mgr *Manager) Create(ctx context.Context, id, mode, policyYAML, vmConfig string) (Info, error) {
	switch mode {
	case "", ModeExec:
		mode = ModeExec
		if vmConfig != "" {
			return Info{}, errors.New("a vm config only applies to --mode vm")
		}
	case ModeVM:
		if err := mgr.vmAvailable(); err != nil {
			return Info{}, err
		}
		if vmConfig == "" {
			return Info{}, errors.New("vm mode needs --vm-config")
		}
		if _, err := fc.ParseVMConfig([]byte(vmConfig)); err != nil {
			return Info{}, err
		}
	default:
		return Info{}, fmt.Errorf("unknown mode %q", mode)
	}
	mgr.opMu.Lock()
	defer mgr.opMu.Unlock()
	return mgr.create(ctx, Record{ID: id, Mode: mode, Policy: policyYAML, VMConfig: vmConfig})
}

// MaxStagger bounds the pause between clone starts.
const MaxStagger = time.Minute

// Clone starts count VM sandboxes from a snapshot directory, named
// <prefix>-1 ... <prefix>-<count>, all with the given policy, waiting
// stagger between VM starts. It stops at the first failure and returns the
// clones created so far.
func (mgr *Manager) Clone(ctx context.Context, snapshotDir string, count int, prefix, policyYAML string, stagger time.Duration) ([]Info, error) {
	if err := mgr.vmAvailable(); err != nil {
		return nil, err
	}
	if count < 1 || count > MaxClones {
		return nil, fmt.Errorf("count must be between 1 and %d", MaxClones)
	}
	if stagger < 0 || stagger > MaxStagger {
		return nil, fmt.Errorf("stagger must be between 0 and %s", MaxStagger)
	}
	dir, err := filepath.Abs(snapshotDir)
	if err != nil {
		return nil, err
	}
	if _, err := fc.ReadSnapshotMeta(dir); err != nil {
		return nil, err
	}
	if prefix == "" {
		prefix = "clone"
	}
	mgr.opMu.Lock()
	defer mgr.opMu.Unlock()
	var out []Info
	for i := 1; i <= count; i++ {
		if i > 1 && stagger > 0 {
			select {
			case <-ctx.Done():
				return out, ctx.Err()
			case <-time.After(stagger):
			}
		}
		info, err := mgr.create(ctx, Record{
			ID: fmt.Sprintf("%s-%d", prefix, i), Mode: ModeVM, Policy: policyYAML, Snapshot: dir,
		})
		if err != nil {
			return out, fmt.Errorf("clone %d of %d: %w", i, count, err)
		}
		out = append(out, info)
	}
	return out, nil
}

// create runs with opMu held.
func (mgr *Manager) create(ctx context.Context, rec Record) (Info, error) {
	if !idPattern.MatchString(rec.ID) {
		return Info{}, fmt.Errorf("invalid sandbox id %q: use 1-63 of [a-zA-Z0-9_.-], starting alphanumeric", rec.ID)
	}
	pol, err := policy.Parse([]byte(rec.Policy))
	if err != nil {
		return Info{}, err
	}
	mgr.mu.Lock()
	_, exists := mgr.byID[rec.ID]
	mgr.mu.Unlock()
	if exists {
		return Info{}, fmt.Errorf("%w: %s", ErrExists, rec.ID)
	}
	k, err := mgr.allocIndex()
	if err != nil {
		return Info{}, err
	}
	if err := mgr.ensureHost(ctx); err != nil {
		return Info{}, err
	}
	rec.Index = k
	rec.Created = time.Now().UTC()
	if err := mgr.setup(ctx, rec, pol, false); err != nil {
		mgr.unregister(rec.ID, k)
		_ = mgr.sink.Close(rec.ID)
		if cerr := mgr.teardown(ctx, rec.ID, addressing.MustFor(k)); cerr != nil {
			mgr.log.Error("rollback after failed create", "id", rec.ID, "err", cerr)
		}
		return Info{}, err
	}
	if err := mgr.persist(rec); err != nil {
		_ = mgr.destroy(ctx, rec.ID)
		return Info{}, err
	}
	mgr.log.Info("created sandbox", "id", rec.ID, "index", k, "mode", rec.Mode)
	return mgr.Get(rec.ID)
}

// allocIndex picks the lowest free index that also has no leftovers on the
// host from a previous run. Runs with opMu held.
func (mgr *Manager) allocIndex() (int, error) {
	stale := map[int]bool{}
	if left, err := netns.Leftovers(); err == nil {
		for _, k := range left {
			stale[k] = true
		}
	}
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	for k := addressing.MinIndex; k <= addressing.MaxIndex; k++ {
		if _, used := mgr.byIndex[k]; !used && !stale[k] {
			return k, nil
		}
	}
	return 0, errors.New("no free sandbox index")
}

// setup brings every piece of a sandbox to the desired state and registers
// it. It is idempotent; restoring keeps DNS-learned allow-set entries (and
// direct-set entries, unless no_proxy changed) and
// adopts a VM that is still running. Runs with opMu held.
func (mgr *Manager) setup(ctx context.Context, rec Record, pol *policy.Policy, restoring bool) error {
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
	vm := mgr.vm(sb, rec.ID)
	switch rec.Mode {
	case ModeExec:
		if err := netns.WriteResolvConf(sb); err != nil {
			return err
		}
	case ModeVM:
		if err := netns.SetupVM(sb, vm.UID()); err != nil {
			return err
		}
		script, err := nft.RenderVMNetns(sb.Index)
		if err != nil {
			return err
		}
		if err := nft.ApplyInNetns(ctx, sb.Netns, script); err != nil {
			return err
		}
	}
	rules := mgr.sandboxRules(sb.Index, pol, nil, nil, restoring)
	rules.ResetDirect = restoring && mgr.resetDirect
	script, err := nft.RenderSandbox(rules)
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
	var rl *relay.Relay
	if mgr.opts.UpstreamProxy != nil {
		rl = relay.New(relay.Config{
			SandboxID: rec.ID,
			Listen:    netip.AddrPortFrom(sb.HostAddr, addressing.RelayPort),
			Upstream:  mgr.opts.UpstreamProxy,
			Domain:    proxy.Domain,
			Sink:      mgr.sink,
			Count:     mgr.countRelay,
			Log:       mgr.log,
		}, relaySettings(pol))
		if err := rl.Start(); err != nil {
			proxy.Stop()
			_ = mgr.sink.Close(rec.ID)
			return err
		}
	}
	s := &sandbox{rec: rec, addr: sb, policy: pol, proxy: proxy, relay: rl}
	mgr.mu.Lock()
	mgr.byID[rec.ID] = s
	mgr.byIndex[sb.Index] = s
	mgr.mu.Unlock()

	// The VM starts last: its DNS and policy are in place before it boots.
	if rec.Mode == ModeVM && !(restoring && vm.Alive()) {
		if err := mgr.startVM(ctx, vm, rec, pol); err != nil {
			return err
		}
	}
	return nil
}

func (mgr *Manager) startVM(ctx context.Context, vm fc.VM, rec Record, pol *policy.Policy) error {
	if err := mgr.vmAvailable(); err != nil {
		return err
	}
	if rec.Snapshot != "" {
		return vm.Restore(ctx, rec.Snapshot, vmLimits(pol))
	}
	cfg, err := fc.ParseVMConfig([]byte(rec.VMConfig))
	if err != nil {
		return err
	}
	return vm.Boot(ctx, cfg, vmLimits(pol))
}

func (mgr *Manager) sandboxRules(k int, pol *policy.Policy, allowed, direct []nft.AllowEntry, preserve bool) nft.SandboxConfig {
	return nft.SandboxConfig{
		Proxied:         mgr.opts.UpstreamProxy != nil,
		Direct:          direct,
		Index:           k,
		AllowCIDRs:      pol.Egress.AllowCIDRs,
		MaxConns:        pol.Limits.MaxConns,
		NewConnsPerSec:  pol.Limits.NewConnsPerSec,
		Allowed:         allowed,
		PreserveAllowed: preserve,
	}
}

func relaySettings(pol *policy.Policy) relay.Settings {
	cidrs := make([]netip.Prefix, 0, len(pol.Egress.AllowCIDRs))
	for _, c := range pol.Egress.AllowCIDRs {
		if p, err := netip.ParsePrefix(c); err == nil {
			cidrs = append(cidrs, p.Masked())
		}
	}
	return relay.Settings{AllowDomains: pol.Egress.AllowDomains, AllowCIDRs: cidrs, MaxConns: pol.Limits.MaxConns}
}

func (mgr *Manager) countRelay(id, result, reason string) {
	mgr.m.ProxyConnects.WithLabelValues(id, result).Inc()
	if reason != "" {
		mgr.m.Denied.WithLabelValues(id, reason).Inc()
	}
}

func shapeLimits(pol *policy.Policy) shaper.Limits {
	return shaper.Limits{EgressBits: pol.EgressBitsPerSec(), IngressBits: pol.IngressBitsPerSec()}
}

func vmLimits(pol *policy.Policy) fc.RateLimits {
	return fc.RateLimits{TxBits: pol.EgressBitsPerSec(), RxBits: pol.IngressBitsPerSec()}
}

func (mgr *Manager) proxySettings(pol *policy.Policy) dnsproxy.Settings {
	up := pol.UpstreamDNS
	if up == "" {
		up = mgr.opts.DefaultUpstream
	}
	s := dnsproxy.Settings{AllowDomains: pol.Egress.AllowDomains, QPS: pol.Limits.DNSQPS, Upstream: up}
	if mgr.opts.UpstreamProxy != nil {
		s.Direct = mgr.opts.NoProxy.Patterns
	}
	return s
}

func insertAllowed(ctx context.Context, k int, entries []nft.AllowEntry, direct bool) error {
	return nft.Apply(ctx, nft.RenderAllow(k, entries, direct))
}

// ApplyPolicy hot-reloads a sandbox's policy: the chain is re-rendered and
// the allow sets flushed and repopulated in one transaction, so established
// flows survive. tc and Firecracker limits follow.
func (mgr *Manager) ApplyPolicy(ctx context.Context, id, policyYAML string) (Info, error) {
	pol, err := policy.Parse([]byte(policyYAML))
	if err != nil {
		return Info{}, err
	}
	mgr.opMu.Lock()
	defer mgr.opMu.Unlock()
	s, err := mgr.lookup(id)
	if err != nil {
		return Info{}, err
	}
	if err := mgr.ensureHost(ctx); err != nil {
		return Info{}, err
	}
	err = s.proxy.Reload(mgr.proxySettings(pol), func(live, direct []nft.AllowEntry) error {
		script, err := nft.RenderSandbox(mgr.sandboxRules(s.addr.Index, pol, live, direct, false))
		if err != nil {
			return err
		}
		return nft.Apply(ctx, script)
	})
	if err != nil {
		// Put the proxy back on the old policy; the nft transaction was atomic.
		_ = s.proxy.Reload(mgr.proxySettings(s.policy), func(_, _ []nft.AllowEntry) error { return nil })
		return Info{}, err
	}
	if s.relay != nil {
		s.relay.Reload(relaySettings(pol))
	}
	if err := shaper.Apply(ctx, s.addr, shapeLimits(pol)); err != nil {
		return Info{}, fmt.Errorf("policy applied to firewall and DNS but not to tc: %w", err)
	}
	if s.rec.Mode == ModeVM {
		if vm := mgr.vm(s.addr, id); vm.Alive() {
			if err := vm.SetRateLimits(ctx, vmLimits(pol)); err != nil {
				return Info{}, fmt.Errorf("policy applied to firewall, DNS and tc but not to the VM: %w", err)
			}
		}
	}
	rec := s.rec
	rec.Policy = policyYAML
	if err := mgr.persist(rec); err != nil {
		return Info{}, err
	}
	mgr.mu.Lock()
	s.rec, s.policy = rec, pol
	mgr.mu.Unlock()
	mgr.log.Info("applied policy", "id", id)
	return mgr.Get(id)
}

// Snapshot writes a VM sandbox's snapshot to outDir, for `vm clone`.
func (mgr *Manager) Snapshot(ctx context.Context, id, outDir string) error {
	if err := mgr.vmAvailable(); err != nil {
		return err
	}
	if !filepath.IsAbs(outDir) {
		return errors.New("snapshot output directory must be an absolute path")
	}
	mgr.opMu.Lock()
	defer mgr.opMu.Unlock()
	s, err := mgr.lookup(id)
	if err != nil {
		return err
	}
	if s.rec.Mode != ModeVM {
		return fmt.Errorf("sandbox %s is in %s mode; only vm sandboxes can be snapshotted", id, s.rec.Mode)
	}
	vm := mgr.vm(s.addr, id)
	if !vm.Alive() {
		return fmt.Errorf("sandbox %s: VM is not running", id)
	}
	if err := vm.Snapshot(ctx, id, outDir); err != nil {
		return err
	}
	mgr.log.Info("snapshotted sandbox", "id", id, "dir", outDir)
	return nil
}

// Destroy removes a sandbox and everything it created. Its logs are kept.
func (mgr *Manager) Destroy(ctx context.Context, id string) error {
	mgr.opMu.Lock()
	defer mgr.opMu.Unlock()
	return mgr.destroy(ctx, id)
}

func (mgr *Manager) destroy(ctx context.Context, id string) error {
	s, err := mgr.lookup(id)
	if err != nil {
		return err
	}
	s.stop()
	mgr.unregister(id, s.addr.Index)
	err = mgr.teardown(ctx, id, s.addr)
	_ = mgr.sink.Close(id)
	mgr.m.Forget(id)
	if rerr := os.Remove(mgr.recordPath(id)); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
		err = errors.Join(err, rerr)
	}
	if err == nil {
		mgr.log.Info("destroyed sandbox", "id", id)
	}
	return err
}

func (mgr *Manager) teardown(ctx context.Context, id string, sb addressing.Sandbox) error {
	var errs []error
	if err := mgr.vm(sb, id).Stop(); err != nil {
		errs = append(errs, err)
	}
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
	mgr.opMu.Lock()
	defer mgr.opMu.Unlock()
	mgr.mu.Lock()
	all := mgr.byID
	mgr.byID = map[string]*sandbox{}
	mgr.byIndex = map[int]*sandbox{}
	mgr.mu.Unlock()
	for id, s := range all {
		s.stop()
		_ = mgr.sink.Close(id)
		mgr.m.Forget(id)
	}
	return Cleanup(ctx, mgr.opts.StateDir, mgr.opts.FC.ChrootBase)
}

// Cleanup removes all egressd VMs and jails, netns, veths, IFBs,
// /etc/netns entries, the nft table and persisted records, then restores
// host sysctls. It needs no running daemon and is idempotent.
func Cleanup(ctx context.Context, stateDir, chrootBase string) error {
	if stateDir == "" {
		stateDir = DefaultStateDir
	}
	var errs []error
	if err := fc.CleanupJails(chrootBase); err != nil {
		errs = append(errs, err)
	}
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

func (mgr *Manager) lookup(id string) (*sandbox, error) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	s, ok := mgr.byID[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return s, nil
}

func (mgr *Manager) unregister(id string, k int) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	if s, ok := mgr.byID[id]; ok {
		s.stop()
	}
	delete(mgr.byID, id)
	delete(mgr.byIndex, k)
}

// Get returns one sandbox.
func (mgr *Manager) Get(id string) (Info, error) {
	s, err := mgr.lookup(id)
	if err != nil {
		return Info{}, err
	}
	return mgr.info(s), nil
}

// List returns all sandboxes ordered by index.
func (mgr *Manager) List() []Info {
	mgr.mu.Lock()
	all := make([]*sandbox, 0, len(mgr.byID))
	for _, s := range mgr.byID {
		all = append(all, s)
	}
	mgr.mu.Unlock()
	out := make([]Info, 0, len(all))
	for _, s := range all {
		out = append(out, mgr.info(s))
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

// Close stops DNS and relay listeners and closes logs. Sandboxes, including running
// VMs, keep existing and are restored by the next daemon start; without
// the proxy their DNS fails closed.
func (mgr *Manager) Close() {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	for _, s := range mgr.byID {
		s.stop()
	}
	mgr.sink.CloseAll()
}

func (mgr *Manager) info(s *sandbox) Info {
	mgr.mu.Lock()
	rec, pol := s.rec, s.policy
	mgr.mu.Unlock()
	info := Info{
		ID: rec.ID, Index: s.addr.Index, Mode: rec.Mode, Netns: s.addr.Netns,
		HostVeth: s.addr.HostVeth, HostAddr: s.addr.HostAddr.String(), NsAddr: s.addr.NsAddr.String(),
		Created: rec.Created, Policy: pol, LogPath: flowlog.Path(mgr.opts.LogDir, rec.ID),
	}
	if rec.Mode == ModeVM {
		vm := mgr.vm(s.addr, rec.ID)
		info.VM = &VMInfo{
			Running: vm.Alive(), GuestAddr: addressing.GuestAddr.String(),
			JailRoot: vm.Root(), ConsoleLog: vm.ConsoleLog, ClonedFrom: rec.Snapshot,
		}
	}
	return info
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

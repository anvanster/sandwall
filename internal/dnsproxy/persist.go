package dnsproxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"time"
)

// The DNS cache (which allowlisted name resolved to which address, until
// when) is kept in Config.StatePath across daemon restarts. A restarted
// daemon keeps the sandbox's allow sets, and without the cache it would lose
// what they mean: synthetic DNS addresses would map to no name, flow logs
// would lose dst_domain, and a policy reload would refill the sets from
// nothing.
//
// Changes are flushed every flushInterval, off the DNS answer path, and when
// the proxy stops. A newly allocated synthetic address is written at once:
// were that mapping lost in a crash, the address could later be handed to
// another name while a client still connects to it for the first.

const (
	flushInterval = 2 * time.Second
	stateVersion  = 1
)

type stateFile struct {
	Version int          `json:"version"`
	Entries []stateEntry `json:"entries"`
}

type stateEntry struct {
	Name    string     `json:"name"`
	Addr    netip.Addr `json:"addr"`
	Expires time.Time  `json:"expires"`
}

// loadState fills the cache from StatePath, dropping expired entries. A
// missing file is an empty cache; an unreadable one is moved aside (kept for
// inspection) and the proxy starts empty, as it would have before.
func (p *Proxy) loadState() error {
	if p.cfg.StatePath == "" {
		return nil
	}
	data, err := os.ReadFile(p.cfg.StatePath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var st stateFile
	if err := json.Unmarshal(data, &st); err != nil || st.Version != stateVersion {
		return os.Rename(p.cfg.StatePath, p.cfg.StatePath+".unreadable")
	}
	p.cache.load(st.Entries, time.Now())
	return nil
}

// saveState writes the cache to StatePath atomically. The caller need not
// hold any lock.
func (p *Proxy) saveState() error {
	if p.cfg.StatePath == "" {
		return nil
	}
	entries := p.cache.snapshot(time.Now())
	data, err := json.Marshal(stateFile{Version: stateVersion, Entries: entries})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p.cfg.StatePath), 0o700); err != nil {
		return err
	}
	tmp := p.cfg.StatePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, p.cfg.StatePath); err != nil {
		return fmt.Errorf("dns state: %w", err)
	}
	return nil
}

// flusher saves the cache whenever it changed, until stop is closed.
func (p *Proxy) flusher(stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	t := time.NewTicker(flushInterval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if p.cache.takeDirty() {
				if err := p.saveState(); err != nil {
					p.cache.markDirty() // retry next tick
				}
			}
		}
	}
}

// snapshot lists every live (name, address) pair.
func (c *cache) snapshot(now time.Time) []stateEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []stateEntry
	for ip, names := range c.byIP {
		for n, exp := range names {
			if exp.After(now) {
				out = append(out, stateEntry{Name: n, Addr: ip, Expires: exp})
			}
		}
	}
	return out
}

// load adds persisted entries that have not expired. The most recently
// expiring name of an address becomes its domain.
func (c *cache) load(entries []stateEntry, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range entries {
		if !e.Addr.IsValid() || e.Name == "" || !e.Expires.After(now) {
			continue
		}
		names := c.byIP[e.Addr]
		if names == nil {
			names = map[string]time.Time{}
			c.byIP[e.Addr] = names
		}
		if e.Expires.After(names[e.Name]) {
			names[e.Name] = e.Expires
		}
		if cur, ok := c.recent[e.Addr]; !ok || e.Expires.After(names[cur]) {
			c.recent[e.Addr] = e.Name
		}
	}
}

func (c *cache) markDirty() { c.dirty.Store(true) }

func (c *cache) takeDirty() bool { return c.dirty.Swap(false) }

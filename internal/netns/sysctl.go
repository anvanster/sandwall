//go:build linux

package netns

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// HostSysctls are the host-wide settings sandwall needs. Their original
// values are recorded before the first change and restored by nuke.
var HostSysctls = map[string]string{
	"net/ipv4/ip_forward":                  "1",
	"net/netfilter/nf_conntrack_acct":      "1",
	"net/netfilter/nf_conntrack_events":    "1",
	"net/netfilter/nf_conntrack_timestamp": "1",
}

// optionalSysctls may be missing on some kernels (for example without
// CONFIG_NF_CONNTRACK_TIMESTAMP); they are skipped rather than failing.
var optionalSysctls = map[string]bool{
	"net/netfilter/nf_conntrack_timestamp": true,
}

func sysctlExists(key string) bool {
	_, err := os.Stat(filepath.Join("/proc/sys", key))
	return err == nil
}

// EnableHostSysctls records original values to stateFile (only if no record
// exists yet, so a daemon restart never overwrites the true originals) and
// then applies HostSysctls.
func EnableHostSysctls(stateFile string) error {
	if _, err := os.Stat(stateFile); errors.Is(err, fs.ErrNotExist) {
		orig := make(map[string]string, len(HostSysctls))
		for k := range HostSysctls {
			if optionalSysctls[k] && !sysctlExists(k) {
				continue
			}
			v, err := readSysctl(k)
			if err != nil {
				return fmt.Errorf("read sysctl %s: %w", k, err)
			}
			orig[k] = v
		}
		data, err := json.MarshalIndent(orig, "", "  ")
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(stateFile), 0o755); err != nil {
			return err
		}
		if err := writeFileAtomic(stateFile, data, 0o644); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	for k, v := range HostSysctls {
		if optionalSysctls[k] && !sysctlExists(k) {
			continue
		}
		if err := writeSysctl(k, v); err != nil {
			return err
		}
	}
	return nil
}

// RestoreHostSysctls writes back the recorded originals and removes the
// record. Without a record it does nothing.
func RestoreHostSysctls(stateFile string) error {
	data, err := os.ReadFile(stateFile)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var orig map[string]string
	if err := json.Unmarshal(data, &orig); err != nil {
		return fmt.Errorf("%s: %w", stateFile, err)
	}
	var errs []error
	for k, v := range orig {
		if _, managed := HostSysctls[k]; !managed {
			continue
		}
		if err := writeSysctl(k, v); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return os.Remove(stateFile)
}

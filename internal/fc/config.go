// Package fc runs Firecracker microVMs for VM-mode sandboxes: it prepares a
// jailer chroot, launches `jailer --netns`, talks to the Firecracker API and
// takes and restores snapshots.
//
// Every jail uses the same names (vmlinux, drive-<id>, tap0, the guest MAC
// and IP), so a snapshot taken in one sandbox restores unchanged in any other.
package fc

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/anvanster/egressd/internal/addressing"
)

// Fixed guest network identity, identical in every sandbox.
const (
	GuestMAC   = "06:00:AC:10:00:02"
	GuestIface = "eth0"
	// GuestIPArg configures the guest network from the kernel command line.
	GuestIPArg = "ip=172.16.0.2::172.16.0.1:255.255.255.252::eth0:off"
)

// Jail-relative file names.
const (
	KernelFile = "vmlinux"
	ConfigFile = "fc.json"
	SocketPath = "/run/firecracker.socket"
)

var driveIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_]{1,32}$`)

// VMConfig is a Firecracker --config-file. egressd owns networking, so a
// config must not contain network-interfaces; everything it does not know
// about is passed through untouched.
type VMConfig struct {
	BootSource BootSource `json:"boot-source"`
	Drives     []Drive    `json:"drives"`
	// Other passes through every remaining top-level key.
	Other map[string]json.RawMessage `json:"-"`
}

// BootSource is the boot-source section.
type BootSource struct {
	KernelImagePath string `json:"kernel_image_path"`
	BootArgs        string `json:"boot_args,omitempty"`
	InitrdPath      string `json:"initrd_path,omitempty"`
}

// Drive is one entry of the drives section. Unknown fields pass through.
type Drive struct {
	DriveID      string                     `json:"drive_id"`
	PathOnHost   string                     `json:"path_on_host"`
	IsRootDevice bool                       `json:"is_root_device"`
	IsReadOnly   bool                       `json:"is_read_only"`
	Other        map[string]json.RawMessage `json:"-"`
}

// ParseVMConfig validates a user-supplied Firecracker config.
func ParseVMConfig(data []byte) (*VMConfig, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("vm config: %w", err)
	}
	cfg := &VMConfig{Other: map[string]json.RawMessage{}}
	for k, v := range raw {
		switch k {
		case "boot-source":
			if err := json.Unmarshal(v, &cfg.BootSource); err != nil {
				return nil, fmt.Errorf("vm config boot-source: %w", err)
			}
		case "drives":
			var drives []map[string]json.RawMessage
			if err := json.Unmarshal(v, &drives); err != nil {
				return nil, fmt.Errorf("vm config drives: %w", err)
			}
			for _, d := range drives {
				drive, err := parseDrive(d)
				if err != nil {
					return nil, err
				}
				cfg.Drives = append(cfg.Drives, drive)
			}
		case "network-interfaces":
			return nil, errors.New("vm config: network-interfaces is managed by egressd; remove it")
		default:
			cfg.Other[k] = v
		}
	}
	if cfg.BootSource.KernelImagePath == "" {
		return nil, errors.New("vm config: boot-source.kernel_image_path is required")
	}
	if cfg.BootSource.InitrdPath != "" {
		return nil, errors.New("vm config: initrd is not supported")
	}
	roots := 0
	for _, d := range cfg.Drives {
		if d.IsRootDevice {
			roots++
		}
	}
	if roots != 1 {
		return nil, fmt.Errorf("vm config: need exactly one root drive, found %d", roots)
	}
	return cfg, nil
}

func parseDrive(raw map[string]json.RawMessage) (Drive, error) {
	d := Drive{Other: map[string]json.RawMessage{}}
	for k, v := range raw {
		var err error
		switch k {
		case "drive_id":
			err = json.Unmarshal(v, &d.DriveID)
		case "path_on_host":
			err = json.Unmarshal(v, &d.PathOnHost)
		case "is_root_device":
			err = json.Unmarshal(v, &d.IsRootDevice)
		case "is_read_only":
			err = json.Unmarshal(v, &d.IsReadOnly)
		default:
			d.Other[k] = v
		}
		if err != nil {
			return d, fmt.Errorf("vm config drive field %s: %w", k, err)
		}
	}
	if !driveIDPattern.MatchString(d.DriveID) {
		return d, fmt.Errorf("vm config: drive_id %q must match %s", d.DriveID, driveIDPattern)
	}
	if d.PathOnHost == "" {
		return d, fmt.Errorf("vm config: drive %s has no path_on_host", d.DriveID)
	}
	return d, nil
}

// DriveFile is the jail-relative file name for a drive.
func DriveFile(driveID string) string { return "drive-" + driveID }

// BootArgs returns the kernel command line with egressd's network settings:
// any user ip= is replaced, and IPv6 is disabled.
func BootArgs(user string) string {
	var keep []string
	for _, f := range strings.Fields(user) {
		if strings.HasPrefix(f, "ip=") || strings.HasPrefix(f, "ipv6.disable=") {
			continue
		}
		keep = append(keep, f)
	}
	return strings.Join(append(keep, "ipv6.disable=1", GuestIPArg), " ")
}

// RateLimits are Firecracker token-bucket caps in bits per second, 0 = none.
type RateLimits struct {
	TxBits uint64 // guest -> world
	RxBits uint64 // world -> guest
}

// refillMs is the token-bucket refill period; size is one period's bytes.
// A 100ms bucket starved TCP to half the configured rate in testing; a 1s
// bucket reaches it, and the host tbf still does the fine-grained shaping.
const refillMs = 1000

type tokenBucket struct {
	Size       uint64 `json:"size"`
	RefillTime uint64 `json:"refill_time"`
}

type rateLimiter struct {
	Bandwidth tokenBucket `json:"bandwidth"`
}

// limiter returns a Firecracker rate limiter. A zero bucket disables it,
// which is how a PATCH removes a previous limit.
func limiter(bits uint64) *rateLimiter {
	if bits == 0 {
		return &rateLimiter{}
	}
	return &rateLimiter{Bandwidth: tokenBucket{Size: max(bits/8*refillMs/1000, 1), RefillTime: refillMs}}
}

type netIface struct {
	IfaceID       string       `json:"iface_id"`
	GuestMAC      string       `json:"guest_mac,omitempty"`
	HostDevName   string       `json:"host_dev_name,omitempty"`
	RxRateLimiter *rateLimiter `json:"rx_rate_limiter,omitempty"`
	TxRateLimiter *rateLimiter `json:"tx_rate_limiter,omitempty"`
}

// JailConfig renders the config file written into the jail: jail-relative
// paths, egressd's boot args and the fixed tap0/MAC network interface.
func JailConfig(cfg *VMConfig, limits RateLimits) ([]byte, error) {
	out := make(map[string]any, len(cfg.Other)+4)
	for k, v := range cfg.Other {
		out[k] = v
	}
	out["boot-source"] = BootSource{KernelImagePath: KernelFile, BootArgs: BootArgs(cfg.BootSource.BootArgs)}
	drives := make([]map[string]any, 0, len(cfg.Drives))
	for _, d := range cfg.Drives {
		m := make(map[string]any, len(d.Other)+4)
		for k, v := range d.Other {
			m[k] = v
		}
		m["drive_id"] = d.DriveID
		m["path_on_host"] = DriveFile(d.DriveID)
		m["is_root_device"] = d.IsRootDevice
		m["is_read_only"] = d.IsReadOnly
		drives = append(drives, m)
	}
	out["drives"] = drives
	iface := netIface{IfaceID: GuestIface, GuestMAC: GuestMAC, HostDevName: addressing.TapName}
	if limits.TxBits > 0 {
		iface.TxRateLimiter = limiter(limits.TxBits)
	}
	if limits.RxBits > 0 {
		iface.RxRateLimiter = limiter(limits.RxBits)
	}
	out["network-interfaces"] = []netIface{iface}
	return json.MarshalIndent(out, "", "  ")
}

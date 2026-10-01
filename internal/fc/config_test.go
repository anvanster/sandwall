package fc

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const userConfig = `{
  "boot-source": {"kernel_image_path": "/assets/vmlinux", "boot_args": "console=ttyS0 ip=10.0.0.5::10.0.0.1:255.255.255.0::eth0:off ipv6.disable=0 panic=1"},
  "drives": [
    {"drive_id": "rootfs", "path_on_host": "/assets/rootfs.ext4", "is_root_device": true, "is_read_only": false, "cache_type": "Writeback"},
    {"drive_id": "data", "path_on_host": "/assets/data.img", "is_root_device": false, "is_read_only": true}
  ],
  "machine-config": {"vcpu_count": 2, "mem_size_mib": 512},
  "logger": {"level": "Info"}
}`

func TestJailConfig(t *testing.T) {
	cfg, err := ParseVMConfig([]byte(userConfig))
	if err != nil {
		t.Fatal(err)
	}
	out, err := JailConfig(cfg, RateLimits{TxBits: 10_000_000})
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		BootSource BootSource        `json:"boot-source"`
		Drives     []map[string]any  `json:"drives"`
		Machine    map[string]int    `json:"machine-config"`
		Logger     map[string]string `json:"logger"`
		Net        []netIface        `json:"network-interfaces"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if got.BootSource.KernelImagePath != KernelFile {
		t.Errorf("kernel path %q not jail-relative", got.BootSource.KernelImagePath)
	}
	args := got.BootSource.BootArgs
	if strings.Contains(args, "10.0.0.5") || strings.Contains(args, "ipv6.disable=0") ||
		!strings.Contains(args, GuestIPArg) || !strings.Contains(args, "ipv6.disable=1") || !strings.HasPrefix(args, "console=ttyS0 panic=1") {
		t.Errorf("boot args = %q", args)
	}
	if len(got.Drives) != 2 || got.Drives[0]["path_on_host"] != "drive-rootfs" ||
		got.Drives[0]["cache_type"] != "Writeback" || got.Drives[1]["is_read_only"] != true {
		t.Errorf("drives = %v", got.Drives)
	}
	if got.Machine["vcpu_count"] != 2 || got.Logger["level"] != "Info" {
		t.Errorf("pass-through keys lost: %s", out)
	}
	if len(got.Net) != 1 || got.Net[0].HostDevName != "tap0" || got.Net[0].GuestMAC != GuestMAC {
		t.Fatalf("network-interfaces = %+v", got.Net)
	}
	if tx := got.Net[0].TxRateLimiter; tx == nil || tx.Bandwidth.Size != 1_250_000 || tx.Bandwidth.RefillTime != refillMs {
		t.Errorf("tx limiter = %+v", tx)
	}
	if got.Net[0].RxRateLimiter != nil {
		t.Errorf("rx limiter set without a limit")
	}
}

func TestParseVMConfigRejects(t *testing.T) {
	cases := map[string]string{
		"network owned by egressd": `{"boot-source":{"kernel_image_path":"k"},"drives":[{"drive_id":"r","path_on_host":"r","is_root_device":true}],"network-interfaces":[]}`,
		"no kernel":                `{"drives":[{"drive_id":"r","path_on_host":"r","is_root_device":true}]}`,
		"no root drive":            `{"boot-source":{"kernel_image_path":"k"},"drives":[{"drive_id":"r","path_on_host":"r"}]}`,
		"two root drives":          `{"boot-source":{"kernel_image_path":"k"},"drives":[{"drive_id":"a","path_on_host":"a","is_root_device":true},{"drive_id":"b","path_on_host":"b","is_root_device":true}]}`,
		"path in drive id":         `{"boot-source":{"kernel_image_path":"k"},"drives":[{"drive_id":"../x","path_on_host":"r","is_root_device":true}]}`,
		"initrd":                   `{"boot-source":{"kernel_image_path":"k","initrd_path":"i"},"drives":[{"drive_id":"r","path_on_host":"r","is_root_device":true}]}`,
		"not json":                 `{`,
	}
	for name, doc := range cases {
		if _, err := ParseVMConfig([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLimiterZeroDisables(t *testing.T) {
	if l := limiter(0); l.Bandwidth.Size != 0 || l.Bandwidth.RefillTime != 0 {
		t.Errorf("zero limit = %+v", l)
	}
}

func TestCheckIDRange(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	passwd := write("passwd", "root:x:0:0::/root:/bin/sh\njason:x:1000:1000::/home/jason:/bin/bash\n")
	subuid := write("subuid", "jason:100000:65536\n")
	files := map[string]string{passwd: "passwd", subuid: "sub", filepath.Join(dir, "missing"): "sub"}
	if err := checkIDRange(DefaultUIDBase, files); err != nil {
		t.Errorf("default base: %v", err)
	}
	if err := checkIDRange(100000, files); err == nil || !strings.Contains(err.Error(), "jason:100000:65536") {
		t.Errorf("subuid overlap not reported: %v", err)
	}
	if err := checkIDRange(999, files); err == nil {
		t.Error("ids overlapping user 1000 accepted")
	}
	if err := checkIDRange(maxID-10, files); err == nil {
		t.Error("ids above 2^31-1 accepted")
	}
}

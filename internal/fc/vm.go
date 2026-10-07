//go:build linux

package fc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/anvanster/sandwall/internal/addressing"
)

const (
	apiReadyTimeout = 10 * time.Second
	apiCallTimeout  = 60 * time.Second
	snapshotDir     = "snapshot"
	snapshotState   = "vmstate"
	snapshotMem     = "mem"
	snapshotMeta    = "meta.json"
)

var jailPattern = regexp.MustCompile(`^sandwall-sb([0-9]+)$`)

// VM is one sandbox's microVM.
type VM struct {
	Paths   Paths
	Sandbox addressing.Sandbox
	// ConsoleLog receives the VMM's stdout/stderr, including the guest serial console.
	ConsoleLog string
}

// JailID is the jailer --id for sandbox k.
func JailID(k int) string { return fmt.Sprintf("sandwall-sb%d", k) }

// UID is the uid and gid the VMM runs as.
func (v VM) UID() int { return v.Paths.uidBase() + v.Sandbox.Index }

func (v VM) jailDir() string {
	return filepath.Join(v.Paths.ChrootBase, filepath.Base(v.Paths.Firecracker), JailID(v.Sandbox.Index))
}

// Root is the jail's chroot directory.
func (v VM) Root() string { return filepath.Join(v.jailDir(), "root") }

func (v VM) socket() string { return filepath.Join(v.Root(), SocketPath) }

// Boot prepares a fresh jail from cfg and starts the VM.
func (v VM) Boot(ctx context.Context, cfg *VMConfig, limits RateLimits) error {
	if err := v.resetJail(); err != nil {
		return err
	}
	if err := copyFile(cfg.BootSource.KernelImagePath, filepath.Join(v.Root(), KernelFile)); err != nil {
		return fmt.Errorf("kernel: %w", err)
	}
	for _, d := range cfg.Drives {
		if err := copyFile(d.PathOnHost, filepath.Join(v.Root(), DriveFile(d.DriveID))); err != nil {
			return fmt.Errorf("drive %s: %w", d.DriveID, err)
		}
	}
	jc, err := JailConfig(cfg, limits)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(v.Root(), ConfigFile), jc, 0o600); err != nil {
		return err
	}
	if err := v.chownJail(); err != nil {
		return err
	}
	return v.start(ctx, "--config-file", ConfigFile)
}

// SnapshotMeta describes a snapshot directory written by Snapshot.
type SnapshotMeta struct {
	Created    time.Time `json:"created"`
	SourceID   string    `json:"source_sandbox"`
	DriveFiles []string  `json:"drive_files"`
}

// Snapshot pauses the VM, writes a full snapshot plus copies of its drives
// to outDir, and resumes it. Memory and disks are captured while paused, so
// they are consistent with each other.
func (v VM) Snapshot(ctx context.Context, sourceID, outDir string, keepPaused bool) (err error) {
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return err
	}
	inJail := filepath.Join(v.Root(), snapshotDir)
	if err := os.MkdirAll(inJail, 0o700); err != nil {
		return err
	}
	if err := os.Chown(inJail, v.UID(), v.UID()); err != nil {
		return err
	}
	defer os.RemoveAll(inJail)

	if err := v.api(ctx, http.MethodPatch, "/vm", map[string]string{"state": "Paused"}); err != nil {
		return fmt.Errorf("pause: %w", err)
	}
	defer func() {
		if keepPaused {
			return
		}
		if rerr := v.api(ctx, http.MethodPatch, "/vm", map[string]string{"state": "Resumed"}); rerr != nil {
			err = errors.Join(err, fmt.Errorf("resume: %w", rerr))
		}
	}()
	err = v.api(ctx, http.MethodPut, "/snapshot/create", map[string]string{
		"snapshot_type": "Full",
		"snapshot_path": snapshotDir + "/" + snapshotState,
		"mem_file_path": snapshotDir + "/" + snapshotMem,
	})
	if err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	meta := SnapshotMeta{Created: time.Now().UTC(), SourceID: sourceID}
	for _, name := range []string{snapshotState, snapshotMem} {
		if err := moveFile(filepath.Join(inJail, name), filepath.Join(outDir, name)); err != nil {
			return err
		}
	}
	// Clones hard-link the memory file and run as different uids; the VMM
	// only maps it privately, so world-readable and read-only is enough.
	if err := os.Chmod(filepath.Join(outDir, snapshotMem), 0o444); err != nil {
		return err
	}
	drives, err := filepath.Glob(filepath.Join(v.Root(), DriveFile("*")))
	if err != nil {
		return err
	}
	for _, d := range drives {
		name := filepath.Base(d)
		if err := copyFile(d, filepath.Join(outDir, name)); err != nil {
			return err
		}
		meta.DriveFiles = append(meta.DriveFiles, name)
	}
	sort.Strings(meta.DriveFiles)
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(outDir, snapshotMeta), data, 0o600)
}

// ReadSnapshotMeta validates a snapshot directory.
func ReadSnapshotMeta(dir string) (SnapshotMeta, error) {
	var meta SnapshotMeta
	data, err := os.ReadFile(filepath.Join(dir, snapshotMeta))
	if err != nil {
		return meta, fmt.Errorf("not an sandwall snapshot directory: %w", err)
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return meta, fmt.Errorf("%s: %w", snapshotMeta, err)
	}
	for _, f := range append([]string{snapshotState, snapshotMem}, meta.DriveFiles...) {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			return meta, fmt.Errorf("snapshot incomplete: %w", err)
		}
	}
	return meta, nil
}

// Restore starts the VM from a snapshot directory. The guest memory file is
// hard-linked when possible and mapped privately, so clones share its pages;
// drives are copied because the guest writes to them. Rate limits from the
// clone's own policy replace the ones captured in the snapshot.
func (v VM) Restore(ctx context.Context, dir string, limits RateLimits) error {
	meta, err := ReadSnapshotMeta(dir)
	if err != nil {
		return err
	}
	if err := v.resetJail(); err != nil {
		return err
	}
	if err := copyFile(filepath.Join(dir, snapshotState), filepath.Join(v.Root(), snapshotState)); err != nil {
		return err
	}
	if err := linkOrCopy(filepath.Join(dir, snapshotMem), filepath.Join(v.Root(), snapshotMem)); err != nil {
		return err
	}
	for _, f := range meta.DriveFiles {
		if err := copyFile(filepath.Join(dir, f), filepath.Join(v.Root(), f)); err != nil {
			return err
		}
	}
	if err := v.chownJail(); err != nil {
		return err
	}
	if err := v.start(ctx); err != nil {
		return err
	}
	err = v.api(ctx, http.MethodPut, "/snapshot/load", map[string]any{
		"snapshot_path": snapshotState,
		"mem_backend":   map[string]string{"backend_type": "File", "backend_path": snapshotMem},
		"resume_vm":     false,
	})
	if err != nil {
		return fmt.Errorf("snapshot load: %w", err)
	}
	if err := v.SetRateLimits(ctx, limits); err != nil {
		return err
	}
	if err := v.api(ctx, http.MethodPatch, "/vm", map[string]string{"state": "Resumed"}); err != nil {
		return fmt.Errorf("resume: %w", err)
	}
	return nil
}

// SetRateLimits updates the guest NIC's token buckets on a running VM.
func (v VM) SetRateLimits(ctx context.Context, l RateLimits) error {
	iface := netIface{IfaceID: GuestIface, RxRateLimiter: limiter(l.RxBits), TxRateLimiter: limiter(l.TxBits)}
	if err := v.api(ctx, http.MethodPatch, "/network-interfaces/"+GuestIface, iface); err != nil {
		return fmt.Errorf("rate limits: %w", err)
	}
	return nil
}

// Alive reports whether the VMM process for this jail is running.
func (v VM) Alive() bool {
	pid, err := v.pid()
	if err != nil {
		return false
	}
	return syscall.Kill(pid, 0) == nil
}

// Stop kills the VMM and removes the jail. It is idempotent.
// Pause stops the guest's vCPUs; its memory and devices are kept.
func (v VM) Pause(ctx context.Context) error {
	return v.api(ctx, http.MethodPatch, "/vm", map[string]string{"state": "Paused"})
}

// Resume restarts a paused guest.
func (v VM) Resume(ctx context.Context) error {
	return v.api(ctx, http.MethodPatch, "/vm", map[string]string{"state": "Resumed"})
}

func (v VM) Stop() error {
	if pid, err := v.pid(); err == nil {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		waitGone(pid, 5*time.Second)
	}
	return removeJail(v.jailDir())
}

// CleanupJails removes every sandwall jail directory under chrootBase (all
// exec-file names), killing VMMs still recorded in them.
func CleanupJails(chrootBase string) error {
	if chrootBase == "" {
		chrootBase = DefaultChrootBase
	}
	execDirs, err := os.ReadDir(chrootBase)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	for _, ed := range execDirs {
		jails, err := os.ReadDir(filepath.Join(chrootBase, ed.Name()))
		if err != nil {
			continue
		}
		for _, j := range jails {
			if !jailPattern.MatchString(j.Name()) {
				continue
			}
			dir := filepath.Join(chrootBase, ed.Name(), j.Name())
			if pid, err := readPid(filepath.Join(dir, "root")); err == nil {
				_ = syscall.Kill(pid, syscall.SIGKILL)
				waitGone(pid, 5*time.Second)
			}
			if err := removeJail(dir); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// start launches the jailer, which enters the sandbox netns, chroots, drops
// to the sandbox uid and execs Firecracker. The VMM gets its own session so
// it outlives a daemon restart.
func (v VM) start(ctx context.Context, fcArgs ...string) error {
	if v.Alive() {
		return errors.New("VM is already running")
	}
	logf, err := os.OpenFile(v.ConsoleLog, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	defer logf.Close()
	uid := strconv.Itoa(v.UID())
	args := append([]string{
		"--id", JailID(v.Sandbox.Index),
		"--exec-file", v.Paths.Firecracker,
		"--uid", uid, "--gid", uid,
		"--chroot-base-dir", v.Paths.ChrootBase,
		"--netns", filepath.Join("/var/run/netns", v.Sandbox.Netns),
		"--",
		"--api-sock", SocketPath,
	}, fcArgs...)
	cmd := exec.Command(v.Paths.Jailer, args...)
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("jailer: %w", err)
	}
	exited := make(chan struct{})
	go func() { // reap; the VM's lifetime is tracked via firecracker.pid
		_ = cmd.Wait()
		close(exited)
	}()

	deadline := time.After(apiReadyTimeout)
	for {
		if err := v.api(ctx, http.MethodGet, "/", nil); err == nil {
			return nil
		}
		select {
		case <-exited:
			return fmt.Errorf("firecracker exited during start; see %s", v.ConsoleLog)
		case <-deadline:
			return fmt.Errorf("firecracker API did not come up; see %s", v.ConsoleLog)
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// resetJail removes any previous jail and creates an empty chroot.
func (v VM) resetJail() error {
	if err := removeJail(v.jailDir()); err != nil {
		return err
	}
	return os.MkdirAll(v.Root(), 0o700)
}

// chownJail hands the jail to the sandbox uid. Hard-linked files (the shared
// snapshot memory) are left alone: their inode belongs to every clone.
func (v VM) chownJail() error {
	return filepath.Walk(v.Root(), func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && fi.Mode().IsRegular() && st.Nlink > 1 {
			return nil
		}
		return os.Lchown(p, v.UID(), v.UID())
	})
}

func (v VM) pid() (int, error) { return readPid(v.Root()) }

func readPid(root string) (int, error) {
	data, err := os.ReadFile(filepath.Join(root, "firecracker.pid"))
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(data)))
}

// api calls the Firecracker API over the jail's unix socket.
func (v VM) api(ctx context.Context, method, path string, body any) error {
	ctx, cancel := context.WithTimeout(ctx, apiCallTimeout)
	defer cancel()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://firecracker"+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	sock := v.socket()
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
	}}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}

// removeJail deletes a jail directory, including the device nodes and
// cgroup/proc mounts the jailer may have left.
func removeJail(dir string) error {
	root := filepath.Join(dir, "root")
	for _, m := range []string{"proc", "sys/fs/cgroup", "sys"} {
		_ = syscall.Unmount(filepath.Join(root, m), syscall.MNT_DETACH)
	}
	if err := os.RemoveAll(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func waitGone(pid int, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if syscall.Kill(pid, 0) != nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// copyFile copies a (typically sparse) image with cp, which keeps holes and
// uses reflinks where the filesystem supports them.
func copyFile(src, dst string) error {
	out, err := exec.Command("cp", "--sparse=always", "--reflink=auto", src, dst).CombinedOutput()
	if err != nil {
		return fmt.Errorf("cp %s %s: %w: %s", src, dst, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func linkOrCopy(src, dst string) error {
	if err := os.Link(src, dst); err == nil {
		return nil
	}
	return copyFile(src, dst)
}

func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	if err := copyFile(src, dst); err != nil {
		return err
	}
	return os.Remove(src)
}

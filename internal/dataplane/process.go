//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	// Dir is the data planes' directory inside the daemon's state dir.
	Dir = "dataplane"

	startTimeout = 10 * time.Second
	stopTimeout  = 5 * time.Second
)

// Files are where a sandbox's data plane keeps its config, control socket
// and pid. They are named by sandbox index, not ID: a unix socket path is
// limited to about 108 bytes and IDs can be 63.
type Files struct {
	Config, Socket, PID string
}

// FilesFor returns the files of sandbox index k under stateDir.
func FilesFor(stateDir string, k int) Files {
	base := filepath.Join(stateDir, Dir, strconv.Itoa(k))
	return Files{Config: base + ".json", Socket: base + ".sock", PID: base + ".pid"}
}

// Running returns the pid of the data plane started with f.Config, if it is
// alive. The command line is checked, so a reused pid is never mistaken
// for it.
func Running(f Files) (int, bool) {
	data, err := os.ReadFile(f.PID)
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, isDataplane(pid, f.Config)
}

func isDataplane(pid int, configPath string) bool {
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	args := bytes.Split(bytes.TrimRight(cmdline, "\x00"), []byte{0})
	return len(args) >= 4 && string(args[1]) == "dataplane" && string(args[len(args)-1]) == configPath
}

// Start launches `exe dataplane --config f.Config` in its own session, so it
// outlives the daemon, with its diagnostics appended to logPath, and waits
// until its control socket answers.
func Start(ctx context.Context, exe string, f Files, logPath string) (int, error) {
	logf, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return 0, err
	}
	defer logf.Close()
	cmd := exec.Command(exe, "dataplane", "--config", f.Config)
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("start data plane: %w", err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }() // reap; liveness is tracked through the pid file

	c := NewClient(f.Socket)
	deadline := time.After(startTimeout)
	for {
		sctx, cancel := context.WithTimeout(ctx, time.Second)
		st, err := c.Status(sctx)
		cancel()
		if err == nil && st.PID == cmd.Process.Pid {
			return st.PID, nil
		}
		select {
		case err := <-exited:
			return 0, fmt.Errorf("data plane exited during start (%v); see %s", err, logPath)
		case <-deadline:
			_ = cmd.Process.Kill()
			return 0, fmt.Errorf("data plane did not come up; see %s", logPath)
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			return 0, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// Stop asks the data plane to stop (SIGTERM: it closes its listeners and
// relayed connections and saves the DNS cache), kills it if it has not
// exited within stopTimeout, and removes its files. It is idempotent.
func Stop(f Files) error {
	if pid, ok := Running(f); ok {
		_ = syscall.Kill(pid, syscall.SIGTERM)
		if !waitGone(pid, stopTimeout) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			waitGone(pid, stopTimeout)
		}
	}
	var errs []error
	for _, p := range []string{f.Config, f.Socket, f.PID} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// KillAll kills every data plane under stateDir and removes its directory,
// for nuke. It needs no daemon.
func KillAll(stateDir string) error {
	dir := filepath.Join(stateDir, Dir)
	pids, _ := filepath.Glob(filepath.Join(dir, "*.pid"))
	for _, p := range pids {
		f := Files{PID: p, Config: strings.TrimSuffix(p, ".pid") + ".json"}
		if pid, ok := Running(f); ok {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			waitGone(pid, stopTimeout)
		}
	}
	return os.RemoveAll(dir)
}

func waitGone(pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if syscall.Kill(pid, 0) != nil {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

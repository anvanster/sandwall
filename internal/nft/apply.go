package nft

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const applyTimeout = 10 * time.Second

// Apply runs a rendered script through `nft -f -` as one atomic transaction.
// An empty script is a no-op.
func Apply(ctx context.Context, script string) error {
	if strings.TrimSpace(script) == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, applyTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft -f: %w: %s\n--- script ---\n%s", err, strings.TrimSpace(stderr.String()), script)
	}
	return nil
}

// ApplyInNetns runs a rendered script through `nft -f -` inside a named netns.
func ApplyInNetns(ctx context.Context, netnsName, script string) error {
	ctx, cancel := context.WithTimeout(ctx, applyTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", netnsName, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft -f in %s: %w: %s\n--- script ---\n%s", netnsName, err, strings.TrimSpace(stderr.String()), script)
	}
	return nil
}

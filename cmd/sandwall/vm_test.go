//go:build linux

package main

import (
	"testing"
	"time"

	"github.com/anvanster/sandwall/internal/api"
)

func TestCloneTimeoutCoversStagger(t *testing.T) {
	// The case that failed: 20 clones 3s apart outlasted a fixed 60s.
	got := cloneTimeout(20, 3*time.Second)
	if min := 19*3*time.Second + api.DefaultTimeout; got < min {
		t.Errorf("cloneTimeout(20, 3s) = %s, want at least %s", got, min)
	}
	if cloneTimeout(1, 0) <= api.DefaultTimeout {
		t.Error("a single clone gets no more than the default")
	}
}

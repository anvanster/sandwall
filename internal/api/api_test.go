package api

import (
	"context"
	"testing"
	"time"
)

func TestWithDefaultDeadline(t *testing.T) {
	ctx, cancel := WithDefaultDeadline(context.Background())
	defer cancel()
	dl, ok := ctx.Deadline()
	if !ok {
		t.Fatal("no deadline applied")
	}
	if left := time.Until(dl); left <= DefaultTimeout-time.Second || left > DefaultTimeout {
		t.Errorf("default deadline %s away, want about %s", left, DefaultTimeout)
	}

	// A caller's own deadline, longer than the default, is kept.
	long, cancelLong := context.WithTimeout(context.Background(), time.Hour)
	defer cancelLong()
	got, cancel2 := WithDefaultDeadline(long)
	defer cancel2()
	if dl, _ := got.Deadline(); time.Until(dl) < 59*time.Minute {
		t.Errorf("caller deadline shortened to %s", time.Until(dl))
	}
}

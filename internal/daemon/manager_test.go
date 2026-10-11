//go:build linux

package daemon

import "testing"

func TestValidID(t *testing.T) {
	for _, id := range []string{"agent", "c-1", "a.b_c", "A0", "x123456789012345678901234567890123456789012345678901234567890ab"} {
		if err := ValidID(id); err != nil {
			t.Errorf("ValidID(%q) = %v", id, err)
		}
	}
	for _, id := range []string{"", ".", "..", ".hidden", "-x", "a/b", "../etc", "a\\b", "a b", "x1234567890123456789012345678901234567890123456789012345678901ab"} {
		if ValidID(id) == nil {
			t.Errorf("ValidID(%q) accepted", id)
		}
	}
}

package psl

import (
	"slices"
	"testing"
)

func TestIsSuffix(t *testing.T) {
	for name, want := range map[string]bool{
		"com": true, "co.uk": true, "vercel.app": true, "github.io": true, "s3.amazonaws.com": true,
		"herokuapp.com": true, "githubusercontent.com": true,
		"example.com": false, "pypi.org": false, "amazonaws.com": false, "foo.vercel.app": false,
		// wildcard and exception rules: "*.ck" and "!www.ck"
		"anything.ck": true, "www.ck": false,
	} {
		if got := IsSuffix(name); got != want {
			t.Errorf("IsSuffix(%q) = %v, want %v", name, got, want)
		}
	}
	if Version() == "" {
		t.Error("embedded list has no version line")
	}
}

func TestSuffixesUnder(t *testing.T) {
	under := SuffixesUnder("amazonaws.com")
	if !slices.Contains(under, "s3.amazonaws.com") {
		t.Errorf("s3.amazonaws.com not under amazonaws.com: %d rules", len(under))
	}
	for _, name := range []string{"pypi.org", "pythonhosted.org", "attacker.test", "vercel.app"} {
		if got := SuffixesUnder(name); len(got) != 0 {
			t.Errorf("SuffixesUnder(%q) = %v", name, got)
		}
	}
}

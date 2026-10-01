package dnsproxy

import "testing"

func TestAllowlist(t *testing.T) {
	a := NewAllowlist([]string{"pypi.org", "github.com", "*.githubusercontent.com"})
	cases := map[string]bool{
		"pypi.org.":                            true,
		"PyPI.org":                             true,
		"files.pypi.org.":                      false,
		"github.com.":                          true,
		"api.github.com.":                      false,
		"raw.githubusercontent.com.":           true,
		"a.b.githubusercontent.com.":           true,
		"githubusercontent.com.":               false,
		"evilgithubusercontent.com.":           false,
		"githubusercontent.com.attacker.test.": false,
		"pypi.org.attacker.test.":              false,
		".":                                    false,
		"":                                     false,
	}
	for name, want := range cases {
		if got := a.Allows(name); got != want {
			t.Errorf("Allows(%q) = %v, want %v", name, got, want)
		}
	}
}

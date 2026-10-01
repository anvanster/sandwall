package dnsproxy

import "strings"

// Allowlist matches query names against normalized policy patterns.
// "example.com" matches only that name; "*.example.com" matches any strict
// subdomain of example.com but not example.com itself.
type Allowlist struct {
	exact    map[string]struct{}
	suffixes []string // each with a leading dot, e.g. ".example.com"
}

// NewAllowlist builds a matcher from patterns already normalized by
// policy.NormalizePattern.
func NewAllowlist(patterns []string) *Allowlist {
	a := &Allowlist{exact: make(map[string]struct{}, len(patterns))}
	for _, p := range patterns {
		if rest, ok := strings.CutPrefix(p, "*"); ok {
			a.suffixes = append(a.suffixes, rest)
		} else {
			a.exact[p] = struct{}{}
		}
	}
	return a
}

// Allows reports whether a query name is allowlisted. The name may be in
// DNS wire form with a trailing dot and any letter case.
func (a *Allowlist) Allows(qname string) bool {
	name := strings.ToLower(strings.TrimSuffix(qname, "."))
	if name == "" {
		return false
	}
	if _, ok := a.exact[name]; ok {
		return true
	}
	for _, s := range a.suffixes {
		if len(name) > len(s) && strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

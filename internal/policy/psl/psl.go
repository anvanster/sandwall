// Package psl answers questions about public suffixes from an embedded copy
// of the Public Suffix List (https://publicsuffix.org, MPL-2.0; refresh it
// with `make psl-update`).
//
// A public suffix is a name under which unrelated parties can register or
// host their own names: ICANN suffixes such as "com" or "co.uk", and the
// list's private section of hosting platforms such as "vercel.app",
// "github.io" or "s3.amazonaws.com".
package psl

import (
	_ "embed"
	"sort"
	"strings"
	"sync"
)

//go:embed public_suffix_list.dat
var data string

type list struct {
	version    string
	rules      map[string]bool // "vercel.app"
	wildcards  map[string]bool // "*.compute.amazonaws.com" stored as "compute.amazonaws.com"
	exceptions map[string]bool // "!www.ck" stored as "www.ck"
	all        []string        // every rule as written, without "!" rules, sorted
}

var load = sync.OnceValue(func() *list {
	l := &list{rules: map[string]bool{}, wildcards: map[string]bool{}, exceptions: map[string]bool{}}
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "// VERSION: "); ok {
			l.version = v
		}
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		rule := strings.ToLower(strings.Fields(line)[0])
		switch {
		case strings.HasPrefix(rule, "!"):
			l.exceptions[rule[1:]] = true
			continue
		case strings.HasPrefix(rule, "*."):
			l.wildcards[rule[2:]] = true
		default:
			l.rules[rule] = true
		}
		l.all = append(l.all, rule)
	}
	sort.Strings(l.all)
	return l
})

// Version is the embedded list's version line.
func Version() string { return load().version }

// IsSuffix reports whether name (lower case, no trailing dot) is a public
// suffix.
func IsSuffix(name string) bool {
	l := load()
	if l.exceptions[name] {
		return false
	}
	if l.rules[name] {
		return true
	}
	_, parent, ok := strings.Cut(name, ".")
	return ok && l.wildcards[parent]
}

// SuffixesUnder returns the public suffix rules strictly below name, as
// written in the list (e.g. "s3.amazonaws.com" or "*.compute.amazonaws.com"
// for "amazonaws.com").
func SuffixesUnder(name string) []string {
	var out []string
	for _, r := range load().all {
		if strings.HasSuffix(r, "."+name) {
			out = append(out, r)
		}
	}
	return out
}

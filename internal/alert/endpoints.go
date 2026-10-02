package alert

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/anvanster/sandwall/internal/policy"
)

// ParseEndpoints builds endpoints from daemon flags: webhooks are
// "name=url", secrets "name=/path/to/file" (the file's contents, with
// surrounding whitespace trimmed, are the HMAC key).
func ParseEndpoints(webhooks, secrets []string) ([]Endpoint, error) {
	var eps []Endpoint
	index := map[string]int{}
	for _, w := range webhooks {
		name, raw, ok := strings.Cut(w, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		if !ok || !policy.ValidWebhookName(name) {
			return nil, fmt.Errorf("--webhook %q: want name=url, name of letters, digits, - and _", w)
		}
		if _, dup := index[name]; dup {
			return nil, fmt.Errorf("--webhook %q: duplicate name", name)
		}
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return nil, fmt.Errorf("--webhook %s: want an http:// or https:// URL", name)
		}
		index[name] = len(eps)
		eps = append(eps, Endpoint{Name: name, URL: u})
	}
	for _, s := range secrets {
		name, path, ok := strings.Cut(s, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		i, known := index[name]
		if !ok || !known {
			return nil, fmt.Errorf("--webhook-secret %q: want name=file for a name given with --webhook", s)
		}
		data, err := os.ReadFile(strings.TrimSpace(path))
		if err != nil {
			return nil, fmt.Errorf("--webhook-secret %s: %w", name, err)
		}
		secret := []byte(strings.TrimSpace(string(data)))
		if len(secret) < 16 {
			return nil, fmt.Errorf("--webhook-secret %s: the secret must be at least 16 bytes", name)
		}
		eps[i].Secret = secret
	}
	return eps, nil
}

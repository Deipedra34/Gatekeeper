package admin

import (
	"fmt"
	"net/url"
	"strings"

	"gopkg.in/yaml.v3"

	"gatekeeper/internal/config"
	"gatekeeper/internal/middleware"
)

// redacted replaces a secret value in /admin/v1/config.
const redacted = "[REDACTED]"

// redactedConfig renders cfg for /admin/v1/config, using the same keys
// as the YAML file, with every secret removed:
//
//   - auth.api_keys, and rate_limit.clients keys when they're API keys,
//     become their fingerprints ("key:<12 hex>"), as in /metrics;
//   - auth.jwt.secret, storage.redis.password, and each admin token's
//     sha256 become "[REDACTED]";
//   - credentials embedded in backend or collector URLs are dropped.
//
// Then, as a safety net, any other string anywhere in the tree that
// contains one of those secrets is replaced too. File paths (TLS keys,
// CA bundles) are shown, their contents never are. cfg isn't modified:
// the work is done on a generic copy.
func redactedConfig(cfg *config.Config) (map[string]any, error) {
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var tree map[string]any
	if err := yaml.Unmarshal(raw, &tree); err != nil {
		return nil, err
	}

	secrets := []string{cfg.Storage.Redis.Password, cfg.Auth.JWT.Secret}
	secrets = append(secrets, cfg.Auth.APIKeys...)
	for _, t := range cfg.Admin.Tokens {
		secrets = append(secrets, t.SHA256)
	}

	setPath(tree, redacted, "storage", "redis", "password")
	setPath(tree, redacted, "auth", "jwt", "secret")
	if keys, ok := getPath(tree, "auth", "api_keys").([]any); ok {
		for i, k := range keys {
			keys[i] = middleware.APIKeyFingerprint(fmt.Sprint(k))
		}
	}
	if cfg.RateLimit.Scope == "api_key" {
		if clients, ok := getPath(tree, "rate_limit", "clients").(map[string]any); ok {
			fingerprinted := map[string]any{}
			for k, v := range clients {
				fingerprinted[middleware.APIKeyFingerprint(k)] = v
			}
			setPath(tree, fingerprinted, "rate_limit", "clients")
			for k := range clients {
				secrets = append(secrets, k)
			}
		}
	}
	if tokens, ok := getPath(tree, "admin", "tokens").([]any); ok {
		for _, t := range tokens {
			if m, ok := t.(map[string]any); ok && m["sha256"] != nil && m["sha256"] != "" {
				m["sha256"] = redacted
			}
		}
	}
	if routes, ok := tree["routes"].([]any); ok {
		for _, rt := range routes {
			m, ok := rt.(map[string]any)
			if !ok {
				continue
			}
			stripURLCredentials(m, "target")
			if backends, ok := m["backends"].([]any); ok {
				for _, b := range backends {
					if bm, ok := b.(map[string]any); ok {
						stripURLCredentials(bm, "target")
					}
				}
			}
			secrets = append(secrets, redactTransformValues(m)...)
		}
	}
	if tr, ok := tree["tracing"].(map[string]any); ok {
		stripURLCredentials(tr, "endpoint")
	}

	return scrub(tree, scrubbable(secrets)).(map[string]any), nil
}

// sensitiveNameParts mark a header or query parameter whose configured
// value is treated as a credential in /admin/v1/config — e.g. a
// set_headers Authorization the gateway sends to a backend.
var sensitiveNameParts = []string{"auth", "cookie", "token", "secret", "key", "password", "passwd", "credential", "signature", "session"}

func sensitiveName(name string) bool {
	lower := strings.ToLower(name)
	for _, p := range sensitiveNameParts {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// redactTransformValues redacts the values of sensitive-looking headers
// and query parameters a route's transform sets, returning the values
// it removed so the safety-net pass catches any copy elsewhere.
func redactTransformValues(route map[string]any) []string {
	var removed []string
	for _, p := range [][]string{
		{"transform", "request", "add_headers"}, {"transform", "request", "set_headers"},
		{"transform", "request", "add_query_params"},
		{"transform", "response", "add_headers"}, {"transform", "response", "set_headers"},
	} {
		values, ok := getPath(route, p...).(map[string]any)
		if !ok {
			continue
		}
		for name, v := range values {
			if s, ok := v.(string); ok && s != "" && sensitiveName(name) {
				removed = append(removed, s)
				values[name] = redacted
			}
		}
	}
	return removed
}

// minScrubLen is the shortest secret the safety-net pass looks for;
// shorter ones would blank out unrelated values. They're still redacted
// at their known locations above.
const minScrubLen = 6

func scrubbable(ss []string) []string {
	out := ss[:0:0]
	for _, s := range ss {
		if len(s) >= minScrubLen {
			out = append(out, s)
		}
	}
	return out
}

// scrub walks v and replaces any string or map key containing a secret.
func scrub(v any, secrets []string) any {
	contains := func(s string) bool {
		for _, secret := range secrets {
			if strings.Contains(s, secret) {
				return true
			}
		}
		return false
	}
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		n := 0
		for k, val := range t {
			if contains(k) {
				n++
				k = fmt.Sprintf("%s-%d", redacted, n)
			}
			out[k] = scrub(val, secrets)
		}
		return out
	case []any:
		for i := range t {
			t[i] = scrub(t[i], secrets)
		}
		return t
	case string:
		if contains(t) {
			return redacted
		}
		return t
	default:
		return v
	}
}

func getPath(tree map[string]any, path ...string) any {
	var cur any = tree
	for _, p := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[p]
	}
	return cur
}

// setPath replaces the value at path if it's present and non-empty.
func setPath(tree map[string]any, value any, path ...string) {
	parent, ok := getPath(tree, path[:len(path)-1]...).(map[string]any)
	if !ok {
		return
	}
	last := path[len(path)-1]
	if cur, ok := parent[last]; ok && cur != nil && cur != "" {
		parent[last] = value
	}
}

// stripURLCredentials drops the user:password part of the URL at m[key].
func stripURLCredentials(m map[string]any, key string) {
	s, ok := m[key].(string)
	if !ok || s == "" {
		return
	}
	u, err := url.Parse(s)
	if err != nil {
		m[key] = redacted // unparseable; don't risk echoing it
		return
	}
	if u.User != nil {
		u.User = nil
		m[key] = u.String()
	}
}

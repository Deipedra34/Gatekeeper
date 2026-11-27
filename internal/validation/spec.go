// Package validation checks requests against a route's OpenAPI 3.x spec
// before the gateway forwards them: the operation the method and path
// resolve to, its path, query, and header parameters, and its JSON
// request body, all with github.com/getkin/kin-openapi.
//
// Specs are loaded and checked once, when the router is built (startup
// and every reload), and compiled into a router that resolves a request
// to its operation; per request there's only the lookup and the checks.
package validation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
)

// maxSpecBytes bounds the spec file read at load time.
const maxSpecBytes = 32 << 20

// Spec is a loaded, checked OpenAPI document. It's immutable once
// loaded, so routers and requests share it freely.
type Spec struct {
	// Path is the spec file, as the config names it.
	Path string
	// Digest is the SHA-256 of the file's contents, hex encoded.
	Digest string
	// OpenAPI, Title, and Version are the document's openapi version and
	// its info.title and info.version.
	OpenAPI, Title, Version string
	// Operations is how many operations (path and method pairs) it has.
	Operations int
	// LoadedAt is when the file was loaded.
	LoadedAt time.Time
	// IgnoredParameters counts the parameters left unchecked because
	// they carry credentials (see ParseSpec).
	IgnoredParameters int

	doc    *openapi3.T
	router routers.Router

	// secretHeaders are the canonical names of the headers that carry
	// credentials, which validation never sees.
	secretHeaders []string
	// refs are the other files the spec's $refs pulled in, with the
	// digest of each, so a reload can tell whether any of them changed.
	refs map[string]string
}

// builtinSecretHeaders always carry credentials, whatever the config.
var builtinSecretHeaders = []string{"Authorization", "Proxy-Authorization", "Cookie"}

// LoadSpecReusing is LoadSpec, except that it returns prev itself when
// prev was loaded from the same path, with the same secretHeaders, and
// neither the file nor any file its $refs pulled in has changed since:
// a reload then costs reading the files, not compiling the spec again.
// reused reports which happened.
func LoadSpecReusing(path string, prev *Spec, secretHeaders ...string) (spec *Spec, reused bool, err error) {
	data, err := readSpecFile(path)
	if err != nil {
		return nil, false, err
	}
	if prev != nil && prev.unchanged(path, data, canonicalSecrets(secretHeaders)) {
		return prev, true, nil
	}
	spec, err = ParseSpec(path, data, secretHeaders...)
	return spec, false, err
}

// unchanged reports whether s is what loading data, the contents of
// path, with secrets would produce.
func (s *Spec) unchanged(path string, data []byte, secrets []string) bool {
	if s.Path != path || s.Digest != digest(data) || !slices.Equal(s.secretHeaders, secrets) {
		return false
	}
	for file, sum := range s.refs {
		ref, err := os.ReadFile(file)
		if err != nil || digest(ref) != sum {
			return false
		}
	}
	return true
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// LoadSpec reads, parses, and checks the OpenAPI spec at path.
// secretHeaders are headers carrying credentials besides Authorization,
// Proxy-Authorization, and Cookie (the API key header); see ParseSpec.
func LoadSpec(path string, secretHeaders ...string) (*Spec, error) {
	data, err := readSpecFile(path)
	if err != nil {
		return nil, err
	}
	return ParseSpec(path, data, secretHeaders...)
}

func readSpecFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, specFileError(path, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("OpenAPI spec %s is a directory, not a file", path)
	}
	if info.Size() > maxSpecBytes {
		return nil, fmt.Errorf("OpenAPI spec %s is larger than %d bytes", path, maxSpecBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, specFileError(path, err)
	}
	return data, nil
}

// specFileError describes a failure to read the spec file, naming the
// path once.
func specFileError(path string, err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("OpenAPI spec %s does not exist", path)
	}
	var pe *fs.PathError
	if errors.As(err, &pe) {
		err = pe.Err
	}
	return fmt.Errorf("OpenAPI spec %s could not be read: %w", path, err)
}

// ParseSpec parses and checks data, the contents of the OpenAPI spec at
// path (YAML or JSON). Relative $refs to other local files resolve
// against path's directory; references to anything else — http(s) URLs
// included — are refused, so loading a spec never reaches the network.
//
// Credentials are left to the gateway's own auth, which has already run
// by the time a request is validated: the spec's security requirements
// are dropped, and so are its cookie parameters and its header
// parameters for Authorization, Proxy-Authorization, Cookie, and
// secretHeaders. Those headers are also removed from the copy of each
// request that is validated, so their values never reach the validator,
// its errors, or the logs.
func ParseSpec(path string, data []byte, secretHeaders ...string) (*Spec, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("OpenAPI spec %s: %w", path, err)
	}
	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	refs := map[string]string{}
	// Local files only, each recorded with its digest.
	loader.ReadFromURIFunc = func(l *openapi3.Loader, location *url.URL) ([]byte, error) {
		data, err := openapi3.ReadFromFile(l, location)
		if err == nil {
			refs[filepath.FromSlash(location.Path)] = digest(data)
		}
		return data, err
	}
	doc, err := loader.LoadFromDataWithPath(data, &url.URL{Path: filepath.ToSlash(abs)})
	if err != nil {
		return nil, fmt.Errorf("OpenAPI spec %s could not be parsed: %w", path, err)
	}
	if !strings.HasPrefix(doc.OpenAPI, "3.") {
		return nil, fmt.Errorf("OpenAPI spec %s: openapi version %q is not supported; use OpenAPI 3.x", path, doc.OpenAPI)
	}
	if err := doc.Validate(context.Background()); err != nil {
		return nil, fmt.Errorf("OpenAPI spec %s is invalid: %w", path, err)
	}

	// Only the path of a server URL matters here: the gateway, not the
	// spec, decides which host and scheme a request arrived on.
	pathOnlyServers(doc)
	secrets := canonicalSecrets(secretHeaders)
	ignored := dropCredentials(doc, secrets)
	router, err := gorillamux.NewRouter(doc)
	if err != nil {
		return nil, fmt.Errorf("OpenAPI spec %s: compiling its paths: %w", path, err)
	}

	s := &Spec{
		Path:     path,
		Digest:   digest(data),
		OpenAPI:  doc.OpenAPI,
		LoadedAt: time.Now(),
		doc:      doc,
		router:   router,

		IgnoredParameters: ignored,
		secretHeaders:     secrets,
		refs:              refs,
	}
	if doc.Info != nil {
		s.Title, s.Version = doc.Info.Title, doc.Info.Version
	}
	if doc.Paths != nil {
		for _, item := range doc.Paths.Map() {
			s.Operations += len(item.Operations())
		}
	}
	return s, nil
}

// pathOnlyServers reduces every server URL in doc, top-level and per
// path, to its path ("https://api.example.com/v1" becomes "/v1"), so
// operations match on the request path alone. Server variables in the
// path are kept.
func pathOnlyServers(doc *openapi3.T) {
	doc.Servers = pathOnly(doc.Servers)
	if doc.Paths == nil {
		return
	}
	for _, item := range doc.Paths.Map() {
		item.Servers = pathOnly(item.Servers)
	}
}

func pathOnly(servers openapi3.Servers) openapi3.Servers {
	if len(servers) == 0 {
		return servers
	}
	out := make(openapi3.Servers, 0, len(servers))
	seen := map[string]bool{}
	for _, srv := range servers {
		if srv == nil {
			continue
		}
		u := srv.URL
		if _, rest, ok := strings.Cut(u, "://"); ok {
			u = "/"
			if i := strings.IndexByte(rest, '/'); i >= 0 {
				u = rest[i:]
			}
		}
		if u == "" {
			u = "/"
		}
		if seen[u] {
			continue
		}
		seen[u] = true
		cp := *srv
		cp.URL = u
		out = append(out, &cp)
	}
	return out
}

// findRoute resolves req to an operation of the spec. A HEAD request
// resolves to the path's GET operation when it has no HEAD of its own.
func (s *Spec) findRoute(req *http.Request) (*routers.Route, map[string]string, error) {
	route, params, err := s.router.FindRoute(req)
	if errors.Is(err, routers.ErrMethodNotAllowed) && req.Method == http.MethodHead {
		get := *req
		get.Method = http.MethodGet
		return s.router.FindRoute(&get)
	}
	return route, params, err
}

// canonicalSecrets returns the built-in credential headers plus extra,
// canonicalised and without duplicates.
func canonicalSecrets(extra []string) []string {
	out := make([]string, 0, len(builtinSecretHeaders)+len(extra))
	for _, name := range append(append([]string(nil), builtinSecretHeaders...), extra...) {
		if name == "" {
			continue
		}
		canon := http.CanonicalHeaderKey(name)
		if !slices.Contains(out, canon) {
			out = append(out, canon)
		}
	}
	return out
}

// dropCredentials removes from doc what validation must not look at:
// security requirements, cookie parameters, and header parameters named
// in secrets. It returns how many parameters it removed.
func dropCredentials(doc *openapi3.T, secrets []string) int {
	doc.Security = nil
	if doc.Paths == nil {
		return 0
	}
	removed := 0
	keep := func(params openapi3.Parameters) openapi3.Parameters {
		out := params[:0:0]
		for _, ref := range params {
			if p := ref.Value; p != nil {
				if p.In == openapi3.ParameterInCookie ||
					(p.In == openapi3.ParameterInHeader && slices.Contains(secrets, http.CanonicalHeaderKey(p.Name))) {
					removed++
					continue
				}
			}
			out = append(out, ref)
		}
		return out
	}
	for _, item := range doc.Paths.Map() {
		item.Parameters = keep(item.Parameters)
		for _, op := range item.Operations() {
			op.Security = nil
			op.Parameters = keep(op.Parameters)
		}
	}
	return removed
}

// withoutSecrets returns h minus the spec's credential headers. Values
// are shared with h, not copied.
func (s *Spec) withoutSecrets(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for name, values := range h {
		if !slices.Contains(s.secretHeaders, http.CanonicalHeaderKey(name)) {
			out[name] = values
		}
	}
	return out
}

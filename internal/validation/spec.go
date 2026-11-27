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

	doc    *openapi3.T
	router routers.Router
}

// LoadSpec reads, parses, and checks the OpenAPI spec at path.
func LoadSpec(path string) (*Spec, error) {
	data, err := readSpecFile(path)
	if err != nil {
		return nil, err
	}
	return ParseSpec(path, data)
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
func ParseSpec(path string, data []byte) (*Spec, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("OpenAPI spec %s: %w", path, err)
	}
	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	loader.ReadFromURIFunc = openapi3.ReadFromFile // local files only
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
	router, err := gorillamux.NewRouter(doc)
	if err != nil {
		return nil, fmt.Errorf("OpenAPI spec %s: compiling its paths: %w", path, err)
	}

	sum := sha256.Sum256(data)
	s := &Spec{
		Path:     path,
		Digest:   hex.EncodeToString(sum[:]),
		OpenAPI:  doc.OpenAPI,
		LoadedAt: time.Now(),
		doc:      doc,
		router:   router,
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

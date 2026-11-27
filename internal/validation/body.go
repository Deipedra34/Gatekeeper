package validation

import (
	"bytes"
	"io"
	"mime"
	"net/http"
	"slices"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
)

// requestBody is route's operation's request body, or nil if it
// declares none.
func requestBody(route *routers.Route) *openapi3.RequestBody {
	if op := route.Operation; op != nil && op.RequestBody != nil {
		return op.RequestBody.Value
	}
	return nil
}

// hasBody reports whether req carries a body (or may: a chunked one of
// unknown length).
func hasBody(req *http.Request) bool {
	return req.Body != nil && req.Body != http.NoBody && req.ContentLength != 0
}

// prepareBody decides whether req's body is checked against rb and, if
// it is, reads it: in (kin-openapi's copy of req) gets a reader of its
// own over the bytes, and req gets the same bytes back, unchanged, for
// the backend. It returns a non-nil result when the body fails before
// it's checked against the schema.
//
// A body is checked when it's JSON and its Content-Type is one the
// operation declares; a body without a Content-Type is checked as the
// operation's JSON media type, when it has one. Any other body goes to
// the backend unread. A missing body is left to kin-openapi, which
// reports it if the operation requires one.
func (v *Validator) prepareBody(req, in *http.Request, rb *openapi3.RequestBody, opts *openapi3filter.Options) *Result {
	if !hasBody(req) {
		opts.ExcludeRequestBody = false
		return nil
	}
	ct := req.Header.Get("Content-Type")
	mediaType, declared := declaredMediaType(rb, ct)
	if !declared || !isJSON(mediaType) {
		return nil
	}

	data, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(data))
	if err != nil {
		return &Result{Outcome: Invalid, Reason: ReasonBody,
			Violations: []Violation{{In: "body", Message: "could not be read"}}}
	}

	in.Body = io.NopCloser(bytes.NewReader(data))
	in.ContentLength = int64(len(data))
	if ct == "" {
		in.Header.Set("Content-Type", mediaType)
	}
	opts.ExcludeRequestBody = false
	return nil
}

// declaredMediaType returns the media type of a body sent with
// Content-Type ct, and whether rb declares it. With no ct, it's rb's
// JSON media type, if it has one.
func declaredMediaType(rb *openapi3.RequestBody, ct string) (string, bool) {
	if ct == "" {
		keys := make([]string, 0, len(rb.Content))
		for k := range rb.Content {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			if mt, _, err := mime.ParseMediaType(k); err == nil && isJSON(mt) {
				return mt, true
			}
		}
		return "", false
	}
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return "", false
	}
	return mt, rb.Content.Get(ct) != nil
}

// isJSON reports whether mediaType is JSON: application/json, or any
// type with the +json suffix.
func isJSON(mediaType string) bool {
	return mediaType == "application/json" || strings.HasSuffix(mediaType, "+json")
}

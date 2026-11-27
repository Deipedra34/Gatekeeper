package validation

import (
	"bytes"
	"io"
	"mime"
	"net/http"
	"slices"
	"strconv"
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

	data, complete, err := v.readBody(req)
	if err != nil {
		return &Result{Outcome: Invalid, Reason: ReasonBody,
			Violations: []Violation{{In: "body", Message: "could not be read"}}}
	}
	if !complete {
		return v.tooLarge()
	}

	in.Body = io.NopCloser(bytes.NewReader(data))
	in.ContentLength = int64(len(data))
	if ct == "" {
		in.Header.Set("Content-Type", mediaType)
	}
	opts.ExcludeRequestBody = false
	return nil
}

// readBody reads req's body for validation, up to max_body_bytes, and
// puts it back on req for the backend: req.Body then yields exactly the
// bytes the client sent, all of them, whether or not they were all read
// here. complete is false when the body is larger than the limit; data
// is then only its beginning, and the rest is still unread.
//
// A body whose Content-Length is already over the limit isn't read at
// all.
func (v *Validator) readBody(req *http.Request) (data []byte, complete bool, err error) {
	limit := v.cfg.MaxBodyBytes
	if req.ContentLength > limit {
		return nil, false, nil
	}
	orig := req.Body
	data, err = io.ReadAll(io.LimitReader(orig, limit+1))
	if err != nil || int64(len(data)) > limit {
		// Whatever was read goes back in front of whatever wasn't.
		req.Body = &restoredBody{Reader: io.MultiReader(bytes.NewReader(data), orig), closer: orig}
		return data, false, err
	}
	// All of it: the original body is spent, so it's closed now and the
	// backend reads the buffered copy.
	_ = orig.Close()
	req.Body = io.NopCloser(bytes.NewReader(data))
	return data, true, nil
}

// restoredBody is a request body put back after validation read its
// beginning: those bytes, then the rest of the original body.
type restoredBody struct {
	io.Reader
	closer io.Closer
}

func (b *restoredBody) Close() error { return b.closer.Close() }

// tooLarge is the result for a body over max_body_bytes.
func (v *Validator) tooLarge() *Result {
	return &Result{
		Outcome: Invalid,
		Reason:  ReasonBodyTooLarge,
		Violations: []Violation{{In: "body",
			Message: "is larger than the " + strconv.FormatInt(v.cfg.MaxBodyBytes, 10) + " bytes this route validates"}},
	}
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

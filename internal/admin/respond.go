package admin

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
)

// Error codes in the "error.code" field of every non-2xx response.
const (
	codeUnauthorized    = "unauthorized"
	codeForbidden       = "forbidden"
	codeTooManyFailures = "too_many_auth_failures"
	codeNotFound        = "not_found"
	codeMethod          = "method_not_allowed"
	codeBadRequest      = "bad_request"
	codeBodyTooLarge    = "body_too_large"
	codeInvalidConfig   = "invalid_config"
	codeConflict        = "conflict"
	codeInternal        = "internal_error"
)

// errorBody is the one error shape every admin endpoint returns:
//
//	{"error": {"code": "invalid_config", "message": "..."}}
type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false) // responses are JSON, never embedded in HTML
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	if rec, ok := w.(*statusRecorder); ok {
		rec.errCode = code
	}
	writeJSON(w, status, errorBody{Error: errorDetail{Code: code, Message: message}})
}

// decodeBody decodes an optional JSON request body into v. An empty body
// leaves v untouched. Unknown fields are rejected, so a typo'd field
// fails loudly instead of being ignored.
func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.ContentLength == 0 && r.Body == http.NoBody {
		return true
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var tooLarge *http.MaxBytesError
		switch {
		case errors.As(err, &tooLarge):
			writeError(w, http.StatusRequestEntityTooLarge, codeBodyTooLarge,
				"request body exceeds "+strconv.FormatInt(tooLarge.Limit, 10)+" bytes")
		case errors.Is(err, io.EOF):
			return true // an empty body sent without Content-Length
		default:
			writeError(w, http.StatusBadRequest, codeBadRequest, "request body must be a JSON object: "+err.Error())
		}
		return false
	}
	return true
}

// dryRun reports whether the request asks for a dry run
// (?dry_run=true): report what would happen, change nothing.
func dryRun(r *http.Request) bool {
	v, _ := strconv.ParseBool(r.URL.Query().Get("dry_run"))
	return v
}

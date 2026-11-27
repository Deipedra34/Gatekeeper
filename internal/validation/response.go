package validation

import (
	"encoding/json"
	"net/http"
)

// ErrorCode is the "error.code" of every response rejecting a request
// that failed validation; "error.reason" says how it failed.
const ErrorCode = "request_validation_failed"

// Status is the status enforce mode answers r with: rejectStatus (400
// or 422, per reject_status), except 413 for a body over the size limit
// and 500 when the validator itself failed.
func (r Result) Status(rejectStatus int) int {
	switch r.Reason {
	case ReasonBodyTooLarge:
		return http.StatusRequestEntityTooLarge
	case ReasonInternal:
		return http.StatusInternalServerError
	}
	return rejectStatus
}

// errorBody is the JSON rejecting an invalid request, in the same
// envelope as the admin API's errors:
//
//	{"error": {"code": "request_validation_failed", "message": "...",
//	  "reason": "body", "request_id": "...",
//	  "violations": [{"in": "body", "field": "/items/0/quantity", "message": "must be at least 1"}]}}
type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code       string      `json:"code"`
	Message    string      `json:"message"`
	Reason     string      `json:"reason"`
	RequestID  string      `json:"request_id,omitempty"`
	Violations []Violation `json:"violations"`
	// Truncated is set when there were more violations than are listed.
	Truncated bool `json:"violations_truncated,omitempty"`
}

// reasonMessages are the error messages, by reason.
var reasonMessages = map[string]string{
	ReasonUnknownOperation: "the API specification has no operation for this request",
	ReasonContentType:      "the request body's Content-Type is not accepted",
	ReasonBodyTooLarge:     "the request body is too large to validate",
	ReasonParameter:        "the request does not match the API specification",
	ReasonBody:             "the request does not match the API specification",
	ReasonTimeout:          "the request could not be validated in time",
	ReasonInternal:         "the request could not be validated",
}

// WriteError answers an invalid request with status and r as JSON.
// requestID, when the gateway assigned one, is included so the client
// can quote it. The body lists which fields failed and why, never the
// values sent.
func WriteError(w http.ResponseWriter, status int, r Result, requestID string) {
	violations := r.Violations
	if violations == nil {
		violations = []Violation{}
	}
	msg, ok := reasonMessages[r.Reason]
	if !ok {
		msg = "the request does not match the API specification"
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorBody{Error: errorDetail{
		Code:       ErrorCode,
		Message:    msg,
		Reason:     r.Reason,
		RequestID:  requestID,
		Violations: violations,
		Truncated:  r.Truncated,
	}})
}

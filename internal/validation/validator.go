package validation

import (
	"context"
	"errors"
	"net/http"

	"github.com/getkin/kin-openapi/routers"

	"gatekeeper/internal/config"
)

// Outcome is what checking a request found.
type Outcome uint8

const (
	// Passed: the request matches its operation in the spec.
	Passed Outcome = iota
	// Invalid: it doesn't; Result.Reason and Result.Violations say why.
	Invalid
	// Unmatched: it matches no operation in the spec, and the route
	// doesn't reject unknown operations, so it goes on unchecked.
	Unmatched
)

func (o Outcome) String() string {
	switch o {
	case Passed:
		return "passed"
	case Invalid:
		return "invalid"
	case Unmatched:
		return "unmatched"
	}
	return "unknown"
}

// Reasons a request is invalid: the bounded "reason" label of the
// validation metrics and the "reason" of an error response. A request
// failing several ways gets the first that applies, in this order.
const (
	// ReasonUnknownOperation: no operation matches the method and path.
	ReasonUnknownOperation = "unknown_operation"
)

// Violation is one way a request fails its spec. It names the part of
// the request at fault, never its value.
type Violation struct {
	// In is where the fault is: "path", "query", "header", "body", or
	// "request" for the request as a whole.
	In string `json:"in"`
	// Field names the parameter, or the JSON pointer of the body value
	// ("/items/0/quantity"); empty for the body or request as a whole.
	Field string `json:"field,omitempty"`
	// Message says what's wrong, in terms of the spec.
	Message string `json:"message"`
}

// Result is the outcome of checking one request.
type Result struct {
	Outcome Outcome
	// Reason is why the request is Invalid (one of the Reason
	// constants); "" otherwise.
	Reason string
	// Violations lists what's wrong with an Invalid request.
	Violations []Violation
	// Operation names the operation the request resolved to — its
	// operationId, or its method and path template — and is "" when it
	// resolved to none.
	Operation string
}

// Validator checks requests against one spec with one route's
// settings. It's safe for concurrent use.
type Validator struct {
	spec *Spec
	cfg  config.RouteValidation
}

// New returns a Validator checking requests against spec with cfg's
// settings (defaults filled in for any left unset).
func New(spec *Spec, cfg config.RouteValidation) *Validator {
	return &Validator{spec: spec, cfg: cfg.WithDefaults()}
}

// Spec returns the spec requests are checked against.
func (v *Validator) Spec() *Spec { return v.spec }

// Config returns the validator's settings, defaults included.
func (v *Validator) Config() config.RouteValidation { return v.cfg }

// Check checks req, which must carry the path the backend will receive
// (after the route's strip_prefix and rewrite).
func (v *Validator) Check(ctx context.Context, req *http.Request) Result {
	route, _, err := v.spec.findRoute(req)
	if err != nil {
		return v.unknownOperation(err)
	}
	return Result{Outcome: Passed, Operation: operationName(route)}
}

// unknownOperation is the result for a request that resolved to no
// operation, err saying why.
func (v *Validator) unknownOperation(err error) Result {
	if !v.cfg.RejectUnknownOperations {
		return Result{Outcome: Unmatched}
	}
	msg := "no operation in the API specification matches this path"
	if errors.Is(err, routers.ErrMethodNotAllowed) {
		msg = "the API specification has no operation for this method on this path"
	}
	return Result{
		Outcome:    Invalid,
		Reason:     ReasonUnknownOperation,
		Violations: []Violation{{In: "request", Message: msg}},
	}
}

// operationName names route's operation for logs and the admin API: its
// operationId, or its method and path template (never the request's own
// path, which may carry identifiers).
func operationName(route *routers.Route) string {
	if op := route.Operation; op != nil && op.OperationID != "" {
		return op.OperationID
	}
	return route.Method + " " + route.Path
}

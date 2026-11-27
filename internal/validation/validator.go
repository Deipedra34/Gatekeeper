package validation

import (
	"context"
	"errors"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
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
	// ReasonParameter: a path, query, or header parameter is missing or
	// doesn't match its schema.
	ReasonParameter = "parameter"
	// ReasonBody: the body is missing, malformed, or doesn't match its
	// schema.
	ReasonBody = "body"
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

	// options are the kin-openapi settings every check starts from.
	options openapi3filter.Options
}

// New returns a Validator checking requests against spec with cfg's
// settings (defaults filled in for any left unset).
func New(spec *Spec, cfg config.RouteValidation) *Validator {
	v := &Validator{spec: spec, cfg: cfg.WithDefaults()}
	v.options = openapi3filter.Options{
		// Every fault, not just the first, so a client can fix them all
		// at once.
		MultiError: true,
		// Authentication is the gateway's job, done before validation.
		AuthenticationFunc: openapi3filter.NoopAuthenticationFunc,
		// The backend gets the request as the client sent it: nothing
		// the spec defaults is added to it.
		SkipSettingDefaults:     true,
		ExcludeRequestBody:      true,
		SchemaValidationOptions: schemaOptions(spec),
	}
	return v
}

// schemaOptions are the schema checks used with spec: the common string
// formats kin-openapi leaves undefined by default, and — on OpenAPI 3.0,
// where it's supported — schema errors without the offending value.
func schemaOptions(spec *Spec) []openapi3.SchemaValidationOption {
	opts := []openapi3.SchemaValidationOption{openapi3.WithStringFormatValidators(stringFormats)}
	if !spec.doc.IsOpenAPI31OrLater() {
		opts = append(opts, openapi3.DisableSchemaErrorDetails())
	}
	return opts
}

// stringFormats validate the string formats kin-openapi doesn't check
// by default (it does date, date-time, and byte itself).
var stringFormats = map[string]openapi3.StringFormatValidator{
	"email": openapi3.NewRegexpFormatValidator(openapi3.FormatOfStringForEmail),
	"uuid":  openapi3.NewRegexpFormatValidator(openapi3.FormatOfStringForUUIDOfRFC9562),
	"ipv4":  openapi3.NewIPValidator(true),
	"ipv6":  openapi3.NewIPValidator(false),
}

// Spec returns the spec requests are checked against.
func (v *Validator) Spec() *Spec { return v.spec }

// Config returns the validator's settings, defaults included.
func (v *Validator) Config() config.RouteValidation { return v.cfg }

// Check checks req, which must carry the path the backend will receive
// (after the route's strip_prefix and rewrite).
func (v *Validator) Check(ctx context.Context, req *http.Request) Result {
	route, params, err := v.spec.findRoute(req)
	if err != nil {
		return v.unknownOperation(err)
	}
	res := Result{Outcome: Passed, Operation: operationName(route)}

	// kin-openapi gets a shallow copy of its own, with no body and no
	// credentials: it never touches the request that goes on to the
	// backend, and never sees a secret.
	in := req.WithContext(ctx)
	in.Body = http.NoBody
	in.Header = v.spec.withoutSecrets(req.Header)
	opts := v.options
	if rb := requestBody(route); rb != nil {
		if fail := v.prepareBody(req, in, rb, &opts); fail != nil {
			fail.Operation = res.Operation
			return *fail
		}
	}
	err = openapi3filter.ValidateRequest(ctx, &openapi3filter.RequestValidationInput{
		Request:    in,
		PathParams: params,
		Route:      route,
		Options:    &opts,
	})
	if err != nil {
		res.Outcome = Invalid
		res.Reason, res.Violations = collect(err)
	}
	return res
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

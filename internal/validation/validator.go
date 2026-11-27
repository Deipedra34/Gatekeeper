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

// What became of a validated request: the "result" label of
// gatekeeper_validation_requests_total and the validation.result span
// attribute.
const (
	ResultPassed     = "passed"
	ResultRejected   = "rejected"    // invalid, in enforce mode
	ResultReportOnly = "report_only" // invalid, forwarded anyway
	ResultUnmatched  = "unmatched"   // no operation matched; forwarded unchecked
)

// Label names what becomes of the request r is for, on a route in
// report_only mode or not.
func (r Result) Label(reportOnly bool) string {
	switch {
	case r.Outcome == Passed:
		return ResultPassed
	case r.Outcome == Unmatched:
		return ResultUnmatched
	case reportOnly:
		return ResultReportOnly
	}
	return ResultRejected
}

// Reasons a request is invalid: the bounded "reason" label of the
// validation metrics and the "reason" of an error response. A request
// failing several ways gets the first that applies, in this order.
const (
	// ReasonUnknownOperation: no operation matches the method and path.
	ReasonUnknownOperation = "unknown_operation"
	// ReasonContentType: the body's Content-Type is missing or isn't one
	// the operation declares (with validate_content_type on).
	ReasonContentType = "content_type"
	// ReasonBodyTooLarge: the body is larger than max_body_bytes.
	ReasonBodyTooLarge = "body_too_large"
	// ReasonParameter: a path, query, or header parameter is missing or
	// doesn't match its schema.
	ReasonParameter = "parameter"
	// ReasonBody: the body is missing, malformed, or doesn't match its
	// schema.
	ReasonBody = "body"
	// ReasonTimeout: checking the request took longer than the timeout.
	ReasonTimeout = "timeout"
	// ReasonInternal: the validator itself failed (kin-openapi panicked).
	ReasonInternal = "internal"
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
	// Violations lists what's wrong with an Invalid request, at most 20
	// of them; Truncated is set when there were more.
	Violations []Violation
	Truncated  bool
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

	// kin-openapi gets a copy of its own, with no body and no
	// credentials: it never touches the request that goes on to the
	// backend, and never sees a secret. Its URL is its own too, since a
	// check that times out goes on running after Check returns.
	in := req.WithContext(ctx)
	u := *req.URL
	in.URL = &u
	in.Body = http.NoBody
	in.Header = v.spec.withoutSecrets(req.Header)
	opts := v.options
	if rb := requestBody(route); rb != nil {
		if fail := v.prepareBody(req, in, rb, &opts); fail != nil {
			fail.Operation = res.Operation
			return *fail
		}
	}
	err = v.run(ctx, &openapi3filter.RequestValidationInput{
		Request:    in,
		PathParams: params,
		Route:      route,
		Options:    &opts,
	})
	switch {
	case err == nil:
	case errors.Is(err, errTimeout):
		res.Outcome, res.Reason = Invalid, ReasonTimeout
		res.Violations = []Violation{{In: "request", Message: "could not be validated within the time limit"}}
	case errors.Is(err, errPanic):
		res.Outcome, res.Reason = Invalid, ReasonInternal
		res.Violations = []Violation{{In: "request", Message: "could not be validated"}}
	default:
		res.Outcome = Invalid
		res.Reason, res.Violations, res.Truncated = collect(err)
	}
	return res
}

// validateRequest is kin-openapi's check, a variable so tests can make
// it slow or panic.
var validateRequest = openapi3filter.ValidateRequest

var (
	errTimeout = errors.New("validation: timed out")
	errPanic   = errors.New("validation: validator panicked")
)

// run checks input against the spec on a goroutine of its own, giving up
// once the timeout is up (or ctx is done). The body was read and bounded
// before this, so what the timeout bounds is the checking itself; a
// check that is given up on finishes in the background, on its own copy
// of the request, and its result is dropped. A panic in kin-openapi is
// recovered and reported as errPanic.
func (v *Validator) run(ctx context.Context, input *openapi3filter.RequestValidationInput) error {
	ctx, cancel := context.WithTimeout(ctx, v.cfg.Timeout.Duration)
	defer cancel()
	done := make(chan error, 1) // buffered: an abandoned check never blocks
	go func() {
		defer func() {
			if recover() != nil {
				done <- errPanic
			}
		}()
		done <- validateRequest(ctx, input)
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return errTimeout
	}
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

package proxy

import (
	"fmt"
	"net/http"

	"gatekeeper/internal/config"
	"gatekeeper/internal/middleware"
	"gatekeeper/internal/validation"
)

// Where validation runs: in the router, once the request's route is
// known — after access control, auth, and rate limiting, which see the
// request first, and before anything that costs more or has effects: the
// traffic split's variant choice, fault injection, the cache, retries,
// circuit breakers, and the backend. A rejected request reaches none of
// those. Running after the rate limiter means validation's cost — the
// costliest per-request step before the backend — is bounded per client
// by the rate limit, and an invalid request still counts against it.

// buildValidator compiles rt's validation section, if it has one that's
// enabled: its spec is loaded (once per file for the whole router) and
// checked now, so a missing or broken spec fails startup or the reload.
func (r *Router) buildValidator(rt config.Route, label string, specs map[string]*validation.Spec) (*validation.Validator, error) {
	vc := rt.Validation
	if vc == nil || !vc.Enabled {
		return nil, nil
	}
	spec, ok := specs[vc.OpenAPIFile]
	if !ok {
		var err error
		if spec, err = validation.LoadSpec(vc.OpenAPIFile, r.apiKeyHeader); err != nil {
			return nil, fmt.Errorf("proxy: route %s: validation: %w", label, err)
		}
		specs[vc.OpenAPIFile] = spec
	}
	return validation.New(spec, *vc), nil
}

// validate checks req against rt's spec. It returns the request to carry
// on with — its body put back for the backend — and true, or false when
// req was invalid and has been answered. In report_only mode an invalid
// request carries on too, exactly as the client sent it.
func (r *Router) validate(rt *route, w http.ResponseWriter, req *http.Request) (*http.Request, bool) {
	// A copy, so the body validation puts back is this request's alone.
	req = req.WithContext(req.Context())
	cfg := rt.validator.Config()
	res := rt.validator.Check(req.Context(), req)
	if res.Outcome != validation.Invalid || cfg.ReportOnly() {
		return req, true
	}
	rid, _ := middleware.RequestIDFrom(req.Context())
	validation.WriteError(w, res.Status(cfg.RejectStatus), res, rid)
	return req, false
}

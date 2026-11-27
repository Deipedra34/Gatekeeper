package gateway

import (
	"errors"
	"fmt"

	"gatekeeper/internal/config"
	"gatekeeper/internal/proxy"
	"gatekeeper/internal/validation"
)

// Validation returns the routes validated against an OpenAPI spec, with
// their specs and counts.
func (g *Gateway) Validation() []proxy.RouteValidator {
	return g.router.Load().Validators()
}

// logValidation logs the spec each validated route checks requests
// against — at startup and on every reload, so the log shows which
// version of a spec is in force.
func (g *Gateway) logValidation(validators []proxy.RouteValidator) {
	for _, rv := range validators {
		spec, cfg := rv.Validator.Spec(), rv.Validator.Config()
		verb := "rejecting"
		if cfg.ReportOnly() {
			verb = "reporting (report_only)"
		}
		g.logger.Printf("validation: route %s: %s requests that don't match %s (%q %s, OpenAPI %s, %d operations, sha256 %.12s)",
			rv.Route, verb, spec.Path, spec.Title, spec.Version, spec.OpenAPI, spec.Operations, spec.Digest)
		if spec.IgnoredParameters > 0 {
			g.logger.Printf("validation: route %s: %d credential parameter(s) in %s are left to auth and not validated", rv.Route, spec.IgnoredParameters, spec.Path)
		}
	}
}

// checkSpecs loads and checks the OpenAPI spec of every route of cfg
// that validates, as a reload would, without using them.
func checkSpecs(cfg *config.Config) error {
	var errs []error
	for _, rt := range cfg.Routes {
		if v := rt.Validation; v != nil && v.Enabled {
			if _, err := validation.LoadSpec(v.OpenAPIFile, cfg.Auth.Header); err != nil {
				errs = append(errs, fmt.Errorf("route %s: validation: %w", rt.Label(), err))
			}
		}
	}
	return errors.Join(errs...)
}

package admin

import (
	"net/http"
	"time"

	"gatekeeper/internal/validation"
)

// validationRouteView is a validated route as GET /admin/v1/validation
// shows it.
type validationRouteView struct {
	Route    string                   `json:"route"`
	RouteID  string                   `json:"route_id"`
	Mode     string                   `json:"mode"`
	Spec     validationSpecView       `json:"spec"`
	Settings validationSettingsView   `json:"settings"`
	Counters validation.StatsSnapshot `json:"counters"`
}

type validationSpecView struct {
	File       string    `json:"file"`
	Title      string    `json:"title"`
	Version    string    `json:"version"`
	OpenAPI    string    `json:"openapi"`
	Operations int       `json:"operations"`
	SHA256     string    `json:"sha256"`
	LoadedAt   time.Time `json:"loaded_at"`
	// IgnoredCredentialParameters counts the spec's cookie parameters and
	// credential header parameters, which auth checks instead.
	IgnoredCredentialParameters int `json:"ignored_credential_parameters"`
}

type validationSettingsView struct {
	RejectStatus            int    `json:"reject_status"`
	RejectUnknownOperations bool   `json:"reject_unknown_operations"`
	ValidateContentType     bool   `json:"validate_content_type"`
	ValidateNonJSONBodies   bool   `json:"validate_non_json_bodies"`
	MaxBodyBytes            int64  `json:"max_body_bytes"`
	MaxJSONDepth            int    `json:"max_json_depth"`
	Timeout                 string `json:"timeout"`
}

// listValidation serves GET /admin/v1/validation: every route that
// validates requests, the spec it checks them against (as loaded at
// startup or by the last reload), its settings, and its counts since
// the gateway started.
func (s *Server) listValidation(w http.ResponseWriter, _ *http.Request) {
	routes := []validationRouteView{}
	for _, rv := range s.gw.Validation() {
		spec, cfg := rv.Validator.Spec(), rv.Validator.Config()
		routes = append(routes, validationRouteView{
			Route:   rv.Route,
			RouteID: routeID(rv.Route),
			Mode:    cfg.EffectiveMode(),
			Spec: validationSpecView{
				File: spec.Path, Title: spec.Title, Version: spec.Version, OpenAPI: spec.OpenAPI,
				Operations: spec.Operations, SHA256: spec.Digest, LoadedAt: spec.LoadedAt.UTC(),
				IgnoredCredentialParameters: spec.IgnoredParameters,
			},
			Settings: validationSettingsView{
				RejectStatus:            cfg.RejectStatus,
				RejectUnknownOperations: cfg.RejectUnknownOperations,
				ValidateContentType:     cfg.ValidateContentType,
				ValidateNonJSONBodies:   cfg.ValidateNonJSONBodies,
				MaxBodyBytes:            cfg.MaxBodyBytes,
				MaxJSONDepth:            cfg.MaxJSONDepth,
				Timeout:                 cfg.Timeout.String(),
			},
			Counters: rv.Stats.Snapshot(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"routes":  routes,
		"reasons": validation.Reasons(),
	})
}

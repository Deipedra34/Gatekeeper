package admin

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"

	"gatekeeper/internal/split"
)

// Traffic split actions, for POST /admin/v1/routes/{route}/split.
const (
	splitSet      = "set"
	splitPause    = "pause"
	splitResume   = "resume"
	splitPromote  = "promote"
	splitRollback = "rollback"
)

// splitRequest is the body of POST /admin/v1/routes/{route}/split.
type splitRequest struct {
	Action string `json:"action"`
	// Weights, for set: every variant's new weight, adding up to 100.
	Weights map[string]int `json:"weights"`
	// Variant, for promote and rollback. Defaults to the rollout's
	// variant, or with two variants to the one that isn't the baseline.
	Variant string `json:"variant"`
	// Reason is recorded with a rollback.
	Reason string `json:"reason"`
	// Force gives traffic to a variant that's cooling down after an
	// automatic rollback.
	Force bool `json:"force"`
}

// maxSplitReason caps the operator-supplied rollback reason.
const maxSplitReason = 200

// routeID identifies a route in admin paths: the first 12 hex
// characters of its label's SHA-256. Stable for as long as the label is,
// and URL-safe, which a label like "/" is not.
func routeID(label string) string {
	sum := sha256.Sum256([]byte(label))
	return hex.EncodeToString(sum[:])[:12]
}

// findSplit resolves the {route} path segment to a live split route: the
// route's id (see GET /admin/v1/routes), its label URL-escaped
// ("%2Fapi"), or a path prefix without its leading slash ("api"). It
// answers 404 or 409 itself when there's none.
func (s *Server) findSplit(w http.ResponseWriter, r *http.Request) (*split.Route, bool) {
	name := r.PathValue("route")
	for _, rt := range s.gw.Config().Routes {
		l := rt.Label()
		if l != name && l != "/"+name && routeID(l) != name {
			continue
		}
		if sr, ok := s.gw.TrafficSplit(l); ok {
			return sr, true
		}
		writeError(w, http.StatusConflict, codeConflict, "route "+l+" has no traffic_split")
		return nil, false
	}
	writeError(w, http.StatusNotFound, codeNotFound, "no route "+name+"; use a route's id from GET /admin/v1/routes, or its path prefix with the slashes escaped (%2Fapi)")
	return nil, false
}

// getSplit serves GET /admin/v1/routes/{route}/split: the route's
// current weights, rollout, and last rollback.
func (s *Server) getSplit(w http.ResponseWriter, r *http.Request) {
	sr, ok := s.findSplit(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, sr.Status())
}

// postSplit serves POST /admin/v1/routes/{route}/split: set weights,
// pause or resume the rollout, promote a variant, or roll one back.
// ?dry_run=true checks the request and reports the route as it is,
// changing nothing.
func (s *Server) postSplit(w http.ResponseWriter, r *http.Request) {
	var req splitRequest
	if !decodeBody(w, r, &req) {
		return
	}
	sr, ok := s.findSplit(w, r)
	if !ok {
		return
	}

	var apply func() error
	switch req.Action {
	case splitSet:
		weights, msg := splitWeights(sr, req.Weights)
		if msg != "" {
			writeError(w, http.StatusBadRequest, codeBadRequest, msg)
			return
		}
		apply = func() error { return sr.SetWeights(weights, req.Force) }
	case splitPause:
		apply = sr.Pause
	case splitResume:
		apply = func() error { return sr.Resume(req.Force) }
	case splitPromote, splitRollback:
		i, msg := splitVariant(sr, req.Variant)
		if msg != "" {
			writeError(w, http.StatusBadRequest, codeBadRequest, msg)
			return
		}
		if req.Action == splitPromote {
			apply = func() error { return sr.Promote(i, req.Force) }
			break
		}
		reason := req.Reason
		if len(reason) > maxSplitReason {
			reason = reason[:maxSplitReason]
		}
		if reason == "" {
			reason = "rolled back through the admin API"
		}
		apply = func() error {
			done, err := sr.Rollback(i, reason)
			if err == nil && !done {
				return errNothingToRollBack
			}
			return err
		}
	case "":
		writeError(w, http.StatusBadRequest, codeBadRequest, `say what to do: {"action": "set" | "pause" | "resume" | "promote" | "rollback"}`)
		return
	default:
		writeError(w, http.StatusBadRequest, codeBadRequest, "unknown action "+req.Action+`; use set, pause, resume, promote, or rollback`)
		return
	}

	if dryRun(r) {
		writeJSON(w, http.StatusOK, map[string]any{"action": req.Action, "dry_run": true, "split": sr.Status()})
		return
	}
	if err := apply(); err != nil {
		writeSplitError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"action": req.Action, "dry_run": false, "split": sr.Status()})
}

var errNothingToRollBack = errors.New("that variant has no traffic to roll back")

// writeSplitError answers a refused split action.
func writeSplitError(w http.ResponseWriter, err error) {
	var cd *split.CooldownError
	switch {
	case errors.As(err, &cd):
		writeError(w, http.StatusConflict, codeConflict, err.Error()+` (send "force": true)`)
	case errors.Is(err, split.ErrInvalidWeights):
		writeError(w, http.StatusBadRequest, codeBadRequest, "weights must give every variant 0-100 and add up to 100")
	case errors.Is(err, split.ErrNoRollout):
		writeError(w, http.StatusConflict, codeConflict, "no rollout is running on this route")
	case errors.Is(err, split.ErrNothingToResume):
		writeError(w, http.StatusConflict, codeConflict, "nothing to resume: the route already follows its configured weights")
	case errors.Is(err, split.ErrBaseline):
		writeError(w, http.StatusConflict, codeConflict, "the baseline can't be rolled back; promote another variant instead")
	case errors.Is(err, errNothingToRollBack):
		writeError(w, http.StatusConflict, codeConflict, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, codeInternal, "the action failed")
	}
}

// splitWeights turns a name -> weight map into the route's weights,
// requiring every variant to be listed.
func splitWeights(sr *split.Route, m map[string]int) (split.Weights, string) {
	names := sr.Names()
	if len(m) == 0 {
		return nil, `set needs weights for every variant: {"action": "set", "weights": {"` + strings.Join(names, `": 90, "`) + `": 10}}`
	}
	w := make(split.Weights, len(names))
	for name, weight := range m {
		i, ok := sr.Index(name)
		if !ok {
			return nil, "no variant " + name + "; this route has " + strings.Join(names, ", ")
		}
		w[i] = weight
	}
	if len(m) != len(names) {
		return nil, "list every variant's weight: " + strings.Join(names, ", ")
	}
	return w, ""
}

// splitVariant resolves the variant a promote or rollback names, or the
// default one: the rollout's, or the only one besides the baseline.
func splitVariant(sr *split.Route, name string) (int, string) {
	if name != "" {
		i, ok := sr.Index(name)
		if !ok {
			return 0, "no variant " + name + "; this route has " + strings.Join(sr.Names(), ", ")
		}
		return i, ""
	}
	if ro := sr.Rollout(); ro != nil {
		i, _ := sr.Index(ro.Variant)
		return i, ""
	}
	if names := sr.Names(); len(names) == 2 {
		return 1 - sr.Baseline(), ""
	}
	return 0, `say which variant: {"variant": "canary"}`
}

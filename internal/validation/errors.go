package validation

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
)

// Limits on what a result reports, so a request with thousands of
// faults (or huge property names) can't make the error body or the log
// line large.
const (
	maxViolations   = 20
	maxFieldSegment = 64
	maxFieldLen     = 256
)

// collect turns what openapi3filter.ValidateRequest returned into
// violations, and the reason to report for them.
//
// Messages are written here from the spec's schema — its type, bounds,
// pattern, format — and never taken from kin-openapi's error text or
// built from the request's values, so nothing the client sent (a
// credential pasted into the wrong field, say) is echoed back or logged.
func collect(err error) (reason string, out []Violation, truncated bool) {
	c := collector{}
	c.add(err)
	return c.reason, c.out, c.truncated
}

type collector struct {
	reason    string
	out       []Violation
	seen      map[Violation]bool
	truncated bool
}

func (c *collector) add(err error) {
	if me, ok := err.(openapi3.MultiError); ok {
		for _, e := range me {
			c.add(e)
		}
		return
	}
	var re *openapi3filter.RequestError
	switch {
	case err == nil:
	case errors.As(err, &re):
		c.requestError(re)
	default:
		c.note(ReasonParameter, Violation{In: "request", Message: "does not match the API specification"})
	}
}

func (c *collector) requestError(re *openapi3filter.RequestError) {
	switch {
	case re.Parameter != nil:
		c.parameterError(re.Parameter, re.Err)
	case re.RequestBody != nil:
		c.bodyError(re.Err)
	default:
		c.note(ReasonParameter, Violation{In: "request", Message: "does not match the API specification"})
	}
}

// bodyError adds the violations of a body that failed with err.
func (c *collector) bodyError(err error) {
	var perr *openapi3filter.ParseError
	switch {
	case errors.Is(err, openapi3filter.ErrInvalidRequired):
		c.note(ReasonBody, Violation{In: "body", Message: "is required"})
	case hasSchemaError(err):
		walkSchemaErrors(err, func(se *openapi3.SchemaError) {
			c.note(ReasonBody, Violation{In: "body", Field: joinField("", se.JSONPointer()), Message: schemaMessage(se)})
		})
	case errors.As(err, &perr):
		c.note(ReasonBody, Violation{In: "body", Message: "is not well-formed for its Content-Type"})
	default:
		c.note(ReasonBody, Violation{In: "body", Message: "does not match the API specification"})
	}
}

// parameterError adds the violations of parameter p, which failed with
// err.
func (c *collector) parameterError(p *openapi3.Parameter, err error) {
	in, name := p.In, cleanSegment(p.Name)
	var perr *openapi3filter.ParseError
	switch {
	case errors.Is(err, openapi3filter.ErrInvalidRequired):
		c.note(ReasonParameter, Violation{In: in, Field: name, Message: "is required"})
	case errors.Is(err, openapi3filter.ErrInvalidEmptyValue):
		c.note(ReasonParameter, Violation{In: in, Field: name, Message: "must not be empty"})
	case hasSchemaError(err):
		walkSchemaErrors(err, func(se *openapi3.SchemaError) {
			c.note(ReasonParameter, Violation{In: in, Field: joinField(name, se.JSONPointer()), Message: schemaMessage(se)})
		})
	case errors.As(err, &perr):
		msg := "could not be parsed"
		if p.Schema != nil && p.Schema.Value != nil {
			if t := typeNames(p.Schema.Value); t != "" {
				msg = "must be " + article(t)
			}
		}
		c.note(ReasonParameter, Violation{In: in, Field: name, Message: msg})
	default:
		c.note(ReasonParameter, Violation{In: in, Field: name, Message: "is invalid"})
	}
}

// note records v, found for reason; the first reason noted, in the
// precedence order of the Reason constants, is the result's.
func (c *collector) note(reason string, v Violation) {
	if c.reason == "" || reasonRank(reason) < reasonRank(c.reason) {
		c.reason = reason
	}
	if c.seen == nil {
		c.seen = map[Violation]bool{}
	}
	if c.seen[v] {
		return
	}
	if len(c.out) >= maxViolations {
		c.truncated = true
		return
	}
	c.seen[v] = true
	c.out = append(c.out, v)
}

// reasonOrder is the precedence of reasons: a request failing several
// ways is reported under the first that applies.
var reasonOrder = reasonNames[:]

func reasonRank(reason string) int {
	for i, r := range reasonOrder {
		if r == reason {
			return i
		}
	}
	return len(reasonOrder)
}

func hasSchemaError(err error) bool {
	var se *openapi3.SchemaError
	return errors.As(err, &se)
}

// walkSchemaErrors calls visit for each schema error in err, descending
// into errors that only group others (a property's, an item's, a $ref's)
// so each failing value is reported where it is. oneOf, anyOf, and not
// are reported as themselves: their alternatives' errors would only
// confuse.
func walkSchemaErrors(err error, visit func(*openapi3.SchemaError)) {
	switch e := err.(type) {
	case openapi3.MultiError:
		for _, sub := range e {
			walkSchemaErrors(sub, visit)
		}
		return
	case *openapi3.SchemaError:
		if e.Origin != nil && !isCombinator(e.SchemaField) {
			var me openapi3.MultiError
			if errors.As(e.Origin, &me) && len(me) > 0 {
				walkSchemaErrors(me, visit)
				return
			}
		}
		visit(e)
		return
	}
	var se *openapi3.SchemaError
	if errors.As(err, &se) {
		walkSchemaErrors(se, visit)
	}
}

func isCombinator(field string) bool {
	return field == "oneOf" || field == "anyOf" || field == "not"
}

// schemaMessage says what se's value fails, in terms of its schema.
func schemaMessage(se *openapi3.SchemaError) string {
	s := se.Schema
	if s == nil {
		return "does not match the schema"
	}
	switch se.SchemaField {
	case "type":
		if t := typeNames(s); t != "" {
			return "must be " + article(t)
		}
		return "has the wrong type"
	case "nullable":
		return "must not be null"
	case "enum":
		return "must be one of the allowed values"
	case "required":
		return "is required"
	case "format":
		return fmt.Sprintf("must be a valid %s", s.Format)
	case "pattern":
		return fmt.Sprintf("must match the pattern %s", s.Pattern)
	case "minimum":
		if s.Min != nil {
			if s.ExclusiveMin.Bool != nil && *s.ExclusiveMin.Bool {
				return "must be greater than " + number(*s.Min)
			}
			return "must be at least " + number(*s.Min)
		}
	case "maximum":
		if s.Max != nil {
			if s.ExclusiveMax.Bool != nil && *s.ExclusiveMax.Bool {
				return "must be less than " + number(*s.Max)
			}
			return "must be at most " + number(*s.Max)
		}
	case "exclusiveMinimum":
		if b := s.ExclusiveMin.Value; b != nil {
			return "must be greater than " + number(*b)
		}
		if s.Min != nil {
			return "must be greater than " + number(*s.Min)
		}
	case "exclusiveMaximum":
		if b := s.ExclusiveMax.Value; b != nil {
			return "must be less than " + number(*b)
		}
		if s.Max != nil {
			return "must be less than " + number(*s.Max)
		}
	case "multipleOf":
		if s.MultipleOf != nil {
			return "must be a multiple of " + number(*s.MultipleOf)
		}
	case "minLength":
		return fmt.Sprintf("must be at least %d characters long", s.MinLength)
	case "maxLength":
		if s.MaxLength != nil {
			return fmt.Sprintf("must be at most %d characters long", *s.MaxLength)
		}
	case "minItems":
		return fmt.Sprintf("must have at least %d items", s.MinItems)
	case "maxItems":
		if s.MaxItems != nil {
			return fmt.Sprintf("must have at most %d items", *s.MaxItems)
		}
	case "uniqueItems":
		return "must not contain duplicate items"
	case "minProperties":
		return fmt.Sprintf("must have at least %d properties", s.MinProps)
	case "maxProperties":
		if s.MaxProps != nil {
			return fmt.Sprintf("must have at most %d properties", *s.MaxProps)
		}
	case "properties", "additionalProperties", "unevaluatedProperties":
		return "has a property the schema does not allow"
	case "readOnly":
		return "is read-only and must not be sent"
	case "oneOf":
		return "must match exactly one of the allowed schemas"
	case "anyOf":
		return "must match at least one of the allowed schemas"
	case "allOf":
		return "must match all of the required schemas"
	case "not":
		return "must not match the excluded schema"
	case "discriminator":
		return "has a missing or unknown discriminator value"
	case "const":
		return "must be the allowed value"
	}
	return "does not match the schema"
}

// typeNames lists the JSON types s allows, "integer" or "string or null".
func typeNames(s *openapi3.Schema) string {
	if s.Type == nil {
		return ""
	}
	return strings.Join(s.Type.Slice(), " or ")
}

func article(typ string) string {
	switch typ[0] {
	case 'a', 'e', 'i', 'o', 'u':
		return "an " + typ
	}
	return "a " + typ
}

func number(f float64) string { return strconv.FormatFloat(f, 'g', -1, 64) }

// joinField is a parameter or body field's name: base followed by the
// JSON pointer of the failing value within it, if any.
func joinField(base string, pointer []string) string {
	var b strings.Builder
	b.WriteString(base)
	for _, seg := range pointer {
		if b.Len() >= maxFieldLen {
			b.WriteString("/...")
			break
		}
		b.WriteByte('/')
		b.WriteString(escapePointer(cleanSegment(seg)))
	}
	return b.String()
}

func escapePointer(seg string) string {
	if !strings.ContainsAny(seg, "~/") {
		return seg
	}
	return strings.NewReplacer("~", "~0", "/", "~1").Replace(seg)
}

// cleanSegment makes a name from the spec or the request (a property
// name in the client's JSON) safe to put in an error body and a log
// line: control characters and invalid UTF-8 become "?", and it's cut
// to maxFieldSegment bytes.
func cleanSegment(s string) string {
	clean := true
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == 0x7f || c >= utf8.RuneSelf {
			clean = false
			break
		}
	}
	if clean && len(s) <= maxFieldSegment {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= maxFieldSegment {
			b.WriteString("...")
			break
		}
		if r < 0x20 || r == 0x7f || r == utf8.RuneError {
			r = '?'
		}
		b.WriteRune(r)
	}
	return b.String()
}

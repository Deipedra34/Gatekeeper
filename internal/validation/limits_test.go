package validation

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gatekeeper/internal/config"
)

// countingReader counts the bytes read from it, and hides any WriterTo
// or length the reader has, like a network body.
type countingReader struct {
	r    io.Reader
	read int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read += n
	return n, err
}

func bigItem(n int) string {
	return `{"name":"hammer","price":1,"meta":{"pad":"` + strings.Repeat("x", n) + `"}}`
}

func TestCheck_BodyLargerThanTheLimit(t *testing.T) {
	const limit = 512
	v := newValidator(t, config.RouteValidation{MaxBodyBytes: limit})
	body := bigItem(4 * limit)

	t.Run("declared length", func(t *testing.T) {
		req := postItem(body)
		src := &countingReader{r: strings.NewReader(body)}
		req.Body = io.NopCloser(src)
		res := check(v, req)
		require.Equal(t, Invalid, res.Outcome)
		assert.Equal(t, ReasonBodyTooLarge, res.Reason)
		assert.Equal(t, []Violation{{In: "body", Message: "is larger than the 512 bytes this route validates"}}, res.Violations)
		assert.Zero(t, src.read, "a Content-Length over the limit isn't read at all")
		assert.Equal(t, body, readAll(t, req))
	})

	t.Run("chunked", func(t *testing.T) {
		req := postItem("")
		src := &countingReader{r: strings.NewReader(body)}
		req.Body, req.ContentLength = io.NopCloser(src), -1
		res := check(v, req)
		require.Equal(t, Invalid, res.Outcome)
		assert.Equal(t, ReasonBodyTooLarge, res.Reason)
		assert.LessOrEqual(t, src.read, limit+512, "reading stops just past the limit")
		assert.Equal(t, body, readAll(t, req), "what was read goes back in front of the rest: nothing lost")
	})

	t.Run("at the limit", func(t *testing.T) {
		exact := bigItem(limit - len(bigItem(0)))
		require.Len(t, exact, limit)
		req := postItem(exact)
		assert.Equal(t, Passed, check(v, req).Outcome)
		assert.Equal(t, exact, readAll(t, req))
	})
}

func TestCheck_DeeplyNestedJSONIsRejectedBeforeDecoding(t *testing.T) {
	nested := func(depth int) string {
		return `{"name":"hammer","price":1,"meta":` + strings.Repeat(`{"a":`, depth) + `1` + strings.Repeat(`}`, depth) + `}`
	}
	v := newValidator(t, config.RouteValidation{MaxJSONDepth: 8})

	decoded := false
	defer swapValidateRequest(func(ctx context.Context, in *openapi3filter.RequestValidationInput) error {
		decoded = true
		return openapi3filter.ValidateRequest(ctx, in)
	})()

	req := postItem(nested(8))
	res := check(v, req)
	require.Equal(t, Invalid, res.Outcome)
	assert.Equal(t, ReasonBody, res.Reason)
	assert.Equal(t, []Violation{{In: "body", Message: "nests objects and arrays deeper than 8 levels"}}, res.Violations)
	assert.False(t, decoded, "never handed to the decoder")
	assert.Equal(t, nested(8), readAll(t, req))

	assert.Equal(t, Passed, check(v, postItem(nested(6))).Outcome, "the item and meta objects plus 6 levels inside make 8")

	attack := strings.Repeat("[", 100000)
	res = check(newValidator(t, config.RouteValidation{}), postItem(attack))
	assert.Equal(t, ReasonBody, res.Reason, "100,000 levels cost one pass over the bytes")
}

func TestNestsDeeper(t *testing.T) {
	for _, tc := range []struct {
		json  string
		max   int
		deep  bool
		label string
	}{
		{`{"a":[1,{"b":2}]}`, 3, false, "three levels"},
		{`{"a":[1,{"b":2}]}`, 2, true, "over two"},
		{`"[[[[[["`, 1, false, "brackets in a string"},
		{`{"a\"[[[":1}`, 1, false, "brackets after an escaped quote"},
		{`{"a\\":[[1]]}`, 2, true, "an escaped backslash ends the string"},
		{`[[[[]]]]`, 3, true, "arrays count"},
		{`[]`, 1, false, "empty array"},
	} {
		assert.Equal(t, tc.deep, nestsDeeper([]byte(tc.json), tc.max), tc.label)
	}
	data := []byte(strings.Repeat(`{"a":["b",{"c":1}]},`, 10000))
	assert.Zero(t, testing.AllocsPerRun(20, func() { nestsDeeper(data, 32) }), "one pass, no allocations")
}

// swapValidateRequest replaces kin-openapi's check for a test and
// returns the function that puts it back.
func swapValidateRequest(f func(context.Context, *openapi3filter.RequestValidationInput) error) func() {
	orig := validateRequest
	validateRequest = f
	return func() { validateRequest = orig }
}

func TestCheck_Timeout(t *testing.T) {
	release := make(chan struct{})
	finished := make(chan struct{})
	defer swapValidateRequest(func(ctx context.Context, in *openapi3filter.RequestValidationInput) error {
		defer close(finished)
		<-release // a check far slower than the timeout
		return nil
	})()

	v := newValidator(t, config.RouteValidation{Timeout: config.Duration{Duration: 20 * time.Millisecond}})
	req := postItem(validItem)
	start := time.Now()
	res := check(v, req)
	took := time.Since(start)

	require.Equal(t, Invalid, res.Outcome)
	assert.Equal(t, ReasonTimeout, res.Reason)
	assert.Equal(t, []Violation{{In: "request", Message: "could not be validated within the time limit"}}, res.Violations)
	assert.Less(t, took, time.Second, "Check gives up at the timeout")
	assert.Equal(t, validItem, readAll(t, req), "the body is the backend's to read, whatever the abandoned check does")

	close(release)
	<-finished // the abandoned check runs to completion without blocking
}

func TestCheck_ClientGoneCountsAsTimeout(t *testing.T) {
	defer swapValidateRequest(func(ctx context.Context, in *openapi3filter.RequestValidationInput) error {
		<-ctx.Done()
		return nil
	})()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	v := newValidator(t, config.RouteValidation{})
	res := v.Check(ctx, request(http.MethodGet, "/v1/items", "", ""))
	assert.Equal(t, ReasonTimeout, res.Reason)
}

func TestCheck_ValidatorPanicIsRecovered(t *testing.T) {
	defer swapValidateRequest(func(context.Context, *openapi3filter.RequestValidationInput) error {
		panic("kin-openapi bug")
	})()
	v := newValidator(t, config.RouteValidation{})
	res := check(v, request(http.MethodGet, "/v1/items", "", ""))
	require.Equal(t, Invalid, res.Outcome)
	assert.Equal(t, ReasonInternal, res.Reason)
	assert.Equal(t, http.StatusInternalServerError, res.Status(http.StatusBadRequest))
}

func TestCheck_SafeForConcurrentUse(t *testing.T) {
	v := newValidator(t, config.RouteValidation{RejectUnknownOperations: true})
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				switch (i + j) % 4 {
				case 0:
					req := postItem(validItem)
					assert.Equal(t, Passed, check(v, req).Outcome)
					assert.Equal(t, validItem, readAll(t, req))
				case 1:
					assert.Equal(t, Invalid, check(v, postItem(`{"price":"x"}`)).Outcome)
				case 2:
					assert.Equal(t, Invalid, check(v, request(http.MethodGet, "/v1/items?limit=0", "", "")).Outcome)
				case 3:
					assert.Equal(t, Invalid, check(v, request(http.MethodGet, "/v1/none", "", "")).Outcome)
				}
			}
		}(i)
	}
	wg.Wait()
}

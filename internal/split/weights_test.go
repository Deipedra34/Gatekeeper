package split

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWeights_PickRanges(t *testing.T) {
	w := Weights{90, 10}
	assert.Equal(t, 0, w.Pick(0))
	assert.Equal(t, 0, w.Pick(8999))
	assert.Equal(t, 1, w.Pick(9000))
	assert.Equal(t, 1, w.Pick(9999))

	w = Weights{0, 100}
	assert.Equal(t, 1, w.Pick(0), "a zero-weight variant owns nothing")

	w = Weights{50, 0, 50}
	for b := 0; b < Buckets; b += 37 {
		assert.NotEqual(t, 1, w.Pick(b))
	}
	assert.Equal(t, -1, Weights{0, 0}.Pick(5))
}

func TestWeights_DistributionMatchesWeights(t *testing.T) {
	for _, w := range []Weights{{90, 10}, {50, 50}, {1, 99}, {33, 33, 34}, {95, 5}} {
		t.Run(fmt.Sprint(w), func(t *testing.T) {
			const n = 100000
			counts := make([]int, len(w))
			for i := range n {
				counts[w.Pick(Bucket("/api", fmt.Sprintf("client-%d", i)))]++
			}
			for i, c := range counts {
				// Within one percentage point of the configured share.
				assert.InDelta(t, float64(w[i])/100, float64(c)/n, 0.01, "variant %d got %d", i, c)
			}
		})
	}
}

func TestWeights_GrowingTheLastVariantOnlyMovesClientsTowardIt(t *testing.T) {
	steps := []Weights{{95, 5}, {75, 25}, {50, 50}, {0, 100}}
	for i := range 20000 {
		b := Bucket("/api", fmt.Sprint(i))
		onCanary := false
		for _, w := range steps {
			got := w.Pick(b) == 1
			assert.False(t, onCanary && !got, "client %d left the canary as it grew", i)
			onCanary = got
		}
	}
}

func TestWeights_WithShare(t *testing.T) {
	assert.Equal(t, Weights{75, 25}, Weights{90, 10}.WithShare(1, 25, 0))
	assert.Equal(t, Weights{0, 100}, Weights{90, 10}.WithShare(1, 100, 0))
	// The others keep their proportions: 60:30 of the remaining 50.
	got := Weights{60, 30, 10}.WithShare(2, 50, 0)
	assert.Equal(t, Weights{33, 17, 50}, got, "largest remainder: 33.3 and 16.7")
	assert.Equal(t, 100, got[0]+got[1]+got[2])
	// Nobody else has weight: the baseline takes the rest.
	assert.Equal(t, Weights{95, 0, 5}, Weights{0, 0, 100}.WithShare(2, 5, 0))

	for share := 0; share <= 100; share++ {
		w := Weights{33, 33, 34}.WithShare(1, share, 0)
		assert.Equal(t, 100, w[0]+w[1]+w[2], "share %d", share)
		assert.Equal(t, share, w[1])
	}
}

func TestWeights_WithoutAndOnly(t *testing.T) {
	assert.Equal(t, Weights{100, 0}, Weights{90, 10}.Without(1, 0))
	assert.Equal(t, Weights{70, 30, 0}, Weights{50, 30, 20}.Without(2, 0))
	assert.Equal(t, Weights{90, 10}, Weights{90, 10}.Without(0, 0), "the fallback can't give its share to itself")
	assert.Equal(t, Weights{0, 100, 0}, Weights{50, 30, 20}.Only(1))
	assert.True(t, Weights{1, 2}.Equal(Weights{1, 2}))
	assert.False(t, Weights{1, 2}.Equal(Weights{2, 1}))
}

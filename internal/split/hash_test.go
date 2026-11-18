package split

import (
	"fmt"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBucket_IsStable(t *testing.T) {
	// Pinned values: if these change, every sticky client in every
	// deployment would move on upgrade.
	assert.Equal(t, 4608, Bucket("", ""))
	assert.Equal(t, 4767, Bucket("/api", "203.0.113.7"))
	assert.Equal(t, 1984, Bucket("/api", "key:alice"))
}

func TestBucket_InRange(t *testing.T) {
	for i := range 10000 {
		b := Bucket("salt", fmt.Sprint(i))
		assert.True(t, b >= 0 && b < Buckets, "bucket %d", b)
	}
}

func TestBucket_SaltSeparatesRoutes(t *testing.T) {
	same := 0
	for i := range 1000 {
		id := fmt.Sprintf("10.0.%d.%d", i/256, i%256)
		if Bucket("/a", id)/1000 == Bucket("/b", id)/1000 {
			same++
		}
	}
	// Independent routes agree on the tenth of the space about 10% of
	// the time, not always.
	assert.Less(t, same, 200)
}

func TestBucket_SpreadsSequentialAddresses(t *testing.T) {
	// Sequential IPs and keys — the inputs most likely to be similar —
	// must still spread evenly over the space.
	const n = 100000
	var counts [10]int
	for i := range n {
		counts[Bucket("/api", fmt.Sprintf("10.%d.%d.%d", i>>16, (i>>8)&255, i&255))*10/Buckets]++
	}
	for d, c := range counts {
		assert.InDelta(t, n/10, c, n/10*0.05, "decile %d", d)
	}

	// A chi-square check over 100 cells.
	var cells [100]float64
	for i := range n {
		cells[Bucket("/api", fmt.Sprintf("user-%d", i))*100/Buckets]++
	}
	chi := 0.0
	for _, c := range cells {
		chi += math.Pow(c-n/100, 2) / (n / 100)
	}
	assert.Less(t, chi, 150.0, "99 degrees of freedom: ~135 is the 99th percentile")
}

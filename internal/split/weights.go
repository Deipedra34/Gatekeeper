package split

// Weights are a route's variant weights, in config order, as whole
// percentages adding up to 100.
type Weights []int

// Pick returns the index of the variant owning bucket. Variants own
// consecutive ranges in config order: with [90, 10], buckets 0-8999 are
// the first variant's and 9000-9999 the second's. Raising the last
// variant's weight therefore only ever moves clients from the variants
// before it to it, never between unrelated variants. A variant with
// weight 0 owns nothing. Returns -1 only if every weight is 0.
func (w Weights) Pick(bucket int) int {
	end := 0
	for i, wt := range w {
		end += wt * (Buckets / 100)
		if bucket < end {
			return i
		}
	}
	// Rounding can't leave a gap (weights are whole percentages), but if
	// the weights fall short of 100 the rest belongs to the last variant
	// with any weight.
	for i := len(w) - 1; i >= 0; i-- {
		if w[i] > 0 {
			return i
		}
	}
	return -1
}

// Clone returns a copy of w.
func (w Weights) Clone() Weights { return append(Weights(nil), w...) }

// Equal reports whether w and o are the same weights.
func (w Weights) Equal(o Weights) bool {
	if len(w) != len(o) {
		return false
	}
	for i := range w {
		if w[i] != o[i] {
			return false
		}
	}
	return true
}

// WithShare returns weights where variant i has share, and the other
// variants split the remaining 100-share in proportion to their weights
// in base (largest remainder first, ties to the earlier variant). If
// none of them has any weight in base, the remainder all goes to
// fallback.
func (w Weights) WithShare(i, share, fallback int) Weights {
	out := make(Weights, len(w))
	out[i] = share
	rest := 100 - share
	total := 0
	for j, wt := range w {
		if j != i {
			total += wt
		}
	}
	if total == 0 {
		if fallback != i {
			out[fallback] += rest
		}
		return out
	}
	type rem struct{ idx, frac int }
	var rems []rem
	given := 0
	for j, wt := range w {
		if j == i {
			continue
		}
		out[j] = rest * wt / total
		given += out[j]
		rems = append(rems, rem{j, rest * wt % total})
	}
	for left := rest - given; left > 0; left-- {
		best := 0
		for k := range rems {
			if rems[k].frac > rems[best].frac {
				best = k
			}
		}
		out[rems[best].idx]++
		rems[best].frac = -1
	}
	return out
}

// Without returns weights where variant i has nothing and its share has
// gone to fallback.
func (w Weights) Without(i, fallback int) Weights {
	out := w.Clone()
	if i == fallback {
		return out
	}
	out[fallback] += out[i]
	out[i] = 0
	return out
}

// Only returns weights giving variant i everything.
func (w Weights) Only(i int) Weights {
	out := make(Weights, len(w))
	out[i] = 100
	return out
}

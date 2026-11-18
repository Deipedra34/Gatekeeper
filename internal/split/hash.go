// Package split implements traffic splitting: assigning each request of
// a split route to one of its variants by weight, keeping a client on the
// same variant, explicit overrides and match rules, gradual rollouts,
// and automatic rollback when a variant does worse than the baseline.
package split

import "hash/fnv"

// Buckets is how many slots the hash space is divided into. A variant
// with weight w owns w percent of them: 100 buckets per percentage
// point.
const Buckets = 10000

// Bucket maps identity to a bucket in [0, Buckets). The mapping depends
// only on salt and identity — never on the config, the variants, their
// weights, or the process — so a client keeps its bucket across reloads,
// restarts, and instances, and only a weight change moves it (and then
// only if its bucket changes hands).
//
// It's FNV-1a (fixed by its spec, unlike Go's map hash) followed by a
// 64-bit finalizer, since FNV alone leaves similar inputs (10.0.0.1,
// 10.0.0.2) in nearby states.
func Bucket(salt, identity string) int {
	h := fnv.New64a()
	_, _ = h.Write([]byte(salt))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(identity))
	return int(mix64(h.Sum64()) % Buckets)
}

// mix64 is the splitmix64 finalizer: every input bit affects every
// output bit.
func mix64(x uint64) uint64 {
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}

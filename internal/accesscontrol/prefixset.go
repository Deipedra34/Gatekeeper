package accesscontrol

import (
	"encoding/binary"
	"fmt"
	"math"
	"net/netip"
	"slices"
)

// PrefixSet is a compiled access list: a set of IPv4 and IPv6 prefixes
// answering "is this address in any of them?" in O(log n) with no
// allocation.
//
// Each prefix is turned into the closed range of addresses it covers.
// The ranges are sorted and overlapping or adjacent ones merged, which
// leaves a list of disjoint ranges in ascending order — so a lookup is
// one binary search for the first range ending at or after the address,
// then a check that it also starts at or before it. Nested or
// duplicated entries ("10.0.0.0/8" and "10.1.2.3") cost nothing extra at
// lookup time. See docs/adr/0009-ip-access-control.md.
//
// The zero value and a nil *PrefixSet are both empty sets.
type PrefixSet struct {
	v4      []range4
	v6      []range6
	entries int
}

type range4 struct{ lo, hi uint32 }

// u128 is a 128-bit unsigned integer, the numeric form of an IPv6
// address.
type u128 struct{ hi, lo uint64 }

func (a u128) less(b u128) bool { return a.hi < b.hi || (a.hi == b.hi && a.lo < b.lo) }

func (a u128) addOne() (u128, bool) {
	if a.lo != math.MaxUint64 {
		return u128{a.hi, a.lo + 1}, false
	}
	if a.hi != math.MaxUint64 {
		return u128{a.hi + 1, 0}, false
	}
	return u128{}, true // overflow
}

type range6 struct{ lo, hi u128 }

// EntryError reports which entry of a list failed to parse.
type EntryError struct {
	Index int
	Err   error
}

func (e *EntryError) Error() string { return fmt.Sprintf("entry %d: %v", e.Index, e.Err) }
func (e *EntryError) Unwrap() error { return e.Err }

// NewPrefixSet compiles entries (see ParseEntry). An invalid entry fails
// the whole set with an *EntryError naming it.
func NewPrefixSet(entries []string) (*PrefixSet, error) {
	prefixes := make([]netip.Prefix, 0, len(entries))
	for i, e := range entries {
		p, err := ParseEntry(e)
		if err != nil {
			return nil, &EntryError{Index: i, Err: err}
		}
		prefixes = append(prefixes, p)
	}
	return NewPrefixSetFromPrefixes(prefixes), nil
}

// MustPrefixSet is NewPrefixSet for lists known to be valid, such as
// ones already checked by config validation. It panics on an invalid
// entry.
func MustPrefixSet(entries []string) *PrefixSet {
	s, err := NewPrefixSet(entries)
	if err != nil {
		panic("accesscontrol: " + err.Error())
	}
	return s
}

// NewPrefixSetFromPrefixes compiles already-parsed prefixes.
func NewPrefixSetFromPrefixes(prefixes []netip.Prefix) *PrefixSet {
	s := &PrefixSet{entries: len(prefixes)}
	for _, p := range prefixes {
		p = p.Masked()
		a := p.Addr()
		if a.Is4() {
			lo := binary.BigEndian.Uint32(a.AsSlice())
			var host uint32
			if n := 32 - p.Bits(); n == 32 {
				host = math.MaxUint32
			} else {
				host = 1<<n - 1
			}
			s.v4 = append(s.v4, range4{lo, lo | host})
			continue
		}
		b := a.As16()
		lo := u128{binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])}
		host := hostMask6(128 - p.Bits())
		s.v6 = append(s.v6, range6{lo, u128{lo.hi | host.hi, lo.lo | host.lo}})
	}
	s.v4 = merge4(s.v4)
	s.v6 = merge6(s.v6)
	return s
}

// hostMask6 has the low n bits set.
func hostMask6(n int) u128 {
	switch {
	case n <= 0:
		return u128{}
	case n >= 128:
		return u128{math.MaxUint64, math.MaxUint64}
	case n > 64:
		return u128{1<<(n-64) - 1, math.MaxUint64}
	case n == 64:
		return u128{0, math.MaxUint64}
	default:
		return u128{0, 1<<n - 1}
	}
}

func merge4(rs []range4) []range4 {
	if len(rs) == 0 {
		return nil
	}
	slices.SortFunc(rs, func(a, b range4) int {
		switch {
		case a.lo < b.lo:
			return -1
		case a.lo > b.lo:
			return 1
		}
		return 0
	})
	out := rs[:1]
	for _, r := range rs[1:] {
		last := &out[len(out)-1]
		if last.hi == math.MaxUint32 || r.lo <= last.hi+1 {
			last.hi = max(last.hi, r.hi)
			continue
		}
		out = append(out, r)
	}
	return slices.Clip(out)
}

func merge6(rs []range6) []range6 {
	if len(rs) == 0 {
		return nil
	}
	slices.SortFunc(rs, func(a, b range6) int {
		switch {
		case a.lo.less(b.lo):
			return -1
		case b.lo.less(a.lo):
			return 1
		}
		return 0
	})
	out := rs[:1]
	for _, r := range rs[1:] {
		last := &out[len(out)-1]
		next, overflow := last.hi.addOne()
		if overflow || !next.less(r.lo) { // r.lo <= last.hi+1
			if last.hi.less(r.hi) {
				last.hi = r.hi
			}
			continue
		}
		out = append(out, r)
	}
	return slices.Clip(out)
}

// Contains reports whether a is in the set. IPv4-mapped IPv6 addresses
// match IPv4 entries; zones are ignored.
func (s *PrefixSet) Contains(a netip.Addr) bool {
	if s == nil || !a.IsValid() {
		return false
	}
	a = a.Unmap()
	if a.Is4() {
		b := a.As4()
		v := binary.BigEndian.Uint32(b[:])
		rs := s.v4
		i, j := 0, len(rs)
		for i < j { // first range with hi >= v
			h := int(uint(i+j) >> 1)
			if rs[h].hi < v {
				i = h + 1
			} else {
				j = h
			}
		}
		return i < len(rs) && rs[i].lo <= v
	}
	b := a.As16()
	v := u128{binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])}
	rs := s.v6
	i, j := 0, len(rs)
	for i < j {
		h := int(uint(i+j) >> 1)
		if rs[h].hi.less(v) {
			i = h + 1
		} else {
			j = h
		}
	}
	return i < len(rs) && !v.less(rs[i].lo)
}

// Len is the number of entries the set was compiled from.
func (s *PrefixSet) Len() int {
	if s == nil {
		return 0
	}
	return s.entries
}

// Empty reports whether the set matches no address at all.
func (s *PrefixSet) Empty() bool {
	return s == nil || (len(s.v4) == 0 && len(s.v6) == 0)
}

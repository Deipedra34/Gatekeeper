package store

import (
	"testing"
	"time"
)

func TestMemoryStore_Conformance(t *testing.T) {
	testStoreConformance(t, func() (Store, func(time.Duration)) {
		return NewMemoryStore(), time.Sleep
	})
}

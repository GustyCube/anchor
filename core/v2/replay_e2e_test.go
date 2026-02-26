package v2_test

import (
	"testing"
	"time"

	"github.com/ignyte-solutions/ignyte-anchor-protocol/core/v2"
)

func TestInMemoryReplayCacheDetectsReplay(t *testing.T) {
	cache := v2.NewInMemoryReplayCache()
	if replay := cache.MarkAndCheck("action-1"); replay {
		t.Fatal("first call should not be replay")
	}
	if replay := cache.MarkAndCheck("action-1"); !replay {
		t.Fatal("second call should be replay")
	}
}

func TestInMemoryReplayCacheDistinguishesIDs(t *testing.T) {
	cache := v2.NewInMemoryReplayCache()
	cache.MarkAndCheck("action-1")
	if replay := cache.MarkAndCheck("action-2"); replay {
		t.Fatal("different action ID should not be replay")
	}
}

func TestWindowReplayCacheEvictsExpiredEntries(t *testing.T) {
	cache := v2.NewInMemoryWindowReplayCache()
	ref := time.Date(2026, 2, 15, 12, 0, 0, 0, time.UTC)
	window := 5 * time.Minute

	if replay := cache.MarkAndCheckWithinWindow("action-1", ref, ref, window); replay {
		t.Fatal("first call should not be replay")
	}
	if replay := cache.MarkAndCheckWithinWindow("action-1", ref, ref.Add(1*time.Second), window); !replay {
		t.Fatal("within window should be replay")
	}
	if replay := cache.MarkAndCheckWithinWindow("action-1", ref, ref.Add(10*time.Minute), window); replay {
		t.Fatal("after window should not be replay (evicted)")
	}
}

func TestWindowReplayCacheDefaultsToFiveMinuteWindow(t *testing.T) {
	cache := v2.NewInMemoryWindowReplayCache()
	ref := time.Date(2026, 2, 15, 12, 0, 0, 0, time.UTC)

	cache.MarkAndCheckWithinWindow("action-1", ref, ref, 0)
	if replay := cache.MarkAndCheckWithinWindow("action-1", ref, ref.Add(1*time.Minute), 0); !replay {
		t.Fatal("within default 5-min window should be replay")
	}
	if replay := cache.MarkAndCheckWithinWindow("action-1", ref, ref.Add(6*time.Minute), 0); replay {
		t.Fatal("after default 5-min window should not be replay")
	}
}

func TestWindowReplayCacheMarkAndCheckFallsBackTo24h(t *testing.T) {
	cache := v2.NewInMemoryWindowReplayCache()
	if replay := cache.MarkAndCheck("action-1"); replay {
		t.Fatal("first call should not be replay")
	}
	if replay := cache.MarkAndCheck("action-1"); !replay {
		t.Fatal("second call should be replay via MarkAndCheck")
	}
}

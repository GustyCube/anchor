package v2_test

import (
	"testing"
	"time"

	"github.com/BennettSchwartz/anchor/core/v2"
)

func TestWindowReplayCacheRejectsReplayEvenWithStaleActionTimestamp(t *testing.T) {
	cache := v2.NewInMemoryWindowReplayCache()
	referenceTime := time.Date(2026, 2, 15, 12, 0, 0, 0, time.UTC)
	staleActionTimestamp := referenceTime.Add(-2 * time.Hour)

	if replay := cache.MarkAndCheckWithinWindow("action-1", staleActionTimestamp, referenceTime, 5*time.Minute); replay {
		t.Fatal("first action should not be replay")
	}
	if replay := cache.MarkAndCheckWithinWindow("action-1", staleActionTimestamp, referenceTime.Add(1*time.Second), 5*time.Minute); !replay {
		t.Fatal("second action should be replay even when action timestamp is stale")
	}
}

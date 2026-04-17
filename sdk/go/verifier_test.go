package protocolgo

import (
	"testing"

	"github.com/BennettSchwartz/anchor/core/v2"
)

func TestOfflineVerifyRequiresReferenceTime(t *testing.T) {
	result := OfflineVerify(OfflineVerifyInput{})
	if result.Decision != v2.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if len(result.ReasonCodes) != 1 || result.ReasonCodes[0] != v2.ReasonCodeReferenceTimeMissing {
		t.Fatalf("expected only ERR_REFERENCE_TIME_MISSING, got %v", result.ReasonCodes)
	}
}

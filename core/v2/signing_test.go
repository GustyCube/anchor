package v2_test

import (
	"encoding/json"
	"testing"
	"time"

	anchorcrypto "github.com/ignyte-solutions/ignyte-anchor-protocol/core/crypto"
	"github.com/ignyte-solutions/ignyte-anchor-protocol/core/v2"
)

func TestSignCapabilityProducesDeterministicID(t *testing.T) {
	issuerPub, issuerPriv, _ := anchorcrypto.GenerateEd25519KeyPair()
	agentPub, _, _ := anchorcrypto.GenerateEd25519KeyPair()
	issuerID, _ := anchorcrypto.DeriveIDFromPublicKey(issuerPub)
	agentID, _ := anchorcrypto.DeriveIDFromPublicKey(agentPub)
	issuedAt := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	cap1 := makeUnsignedCapability(issuerID, agentID, issuedAt)
	cap2 := makeUnsignedCapability(issuerID, agentID, issuedAt)

	if err := v2.SignCapability(&cap1, issuerPriv); err != nil {
		t.Fatalf("sign cap1: %v", err)
	}
	if err := v2.SignCapability(&cap2, issuerPriv); err != nil {
		t.Fatalf("sign cap2: %v", err)
	}
	if cap1.CapabilityID != cap2.CapabilityID {
		t.Fatalf("expected same capability ID, got %s and %s", cap1.CapabilityID, cap2.CapabilityID)
	}
	if cap1.CapabilityID == "" {
		t.Fatal("expected non-empty capability ID")
	}
}

func TestSignCapabilityNormalizesActionOrder(t *testing.T) {
	issuerPub, issuerPriv, _ := anchorcrypto.GenerateEd25519KeyPair()
	agentPub, _, _ := anchorcrypto.GenerateEd25519KeyPair()
	issuerID, _ := anchorcrypto.DeriveIDFromPublicKey(issuerPub)
	agentID, _ := anchorcrypto.DeriveIDFromPublicKey(agentPub)
	issuedAt := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	cap1 := makeUnsignedCapability(issuerID, agentID, issuedAt)
	cap1.AllowedActions = []string{"z:Action", "a:Action"}

	cap2 := makeUnsignedCapability(issuerID, agentID, issuedAt)
	cap2.AllowedActions = []string{"a:Action", "z:Action"}

	if err := v2.SignCapability(&cap1, issuerPriv); err != nil {
		t.Fatalf("sign cap1: %v", err)
	}
	if err := v2.SignCapability(&cap2, issuerPriv); err != nil {
		t.Fatalf("sign cap2: %v", err)
	}
	if cap1.CapabilityID != cap2.CapabilityID {
		t.Fatal("expected same capability ID regardless of action order")
	}
}

func TestSignCapabilityRejectsNilPointer(t *testing.T) {
	_, priv, _ := anchorcrypto.GenerateEd25519KeyPair()
	if err := v2.SignCapability(nil, priv); err == nil {
		t.Fatal("expected error for nil capability")
	}
}

func TestVerifyCapabilitySignatureDetectsTampering(t *testing.T) {
	issuerPub, issuerPriv, _ := anchorcrypto.GenerateEd25519KeyPair()
	agentPub, _, _ := anchorcrypto.GenerateEd25519KeyPair()
	issuerID, _ := anchorcrypto.DeriveIDFromPublicKey(issuerPub)
	agentID, _ := anchorcrypto.DeriveIDFromPublicKey(agentPub)
	issuedAt := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	cap := makeUnsignedCapability(issuerID, agentID, issuedAt)
	if err := v2.SignCapability(&cap, issuerPriv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	valid, err := v2.VerifyCapabilitySignature(cap, issuerPub)
	if err != nil {
		t.Fatalf("verify valid: %v", err)
	}
	if !valid {
		t.Fatal("expected valid signature")
	}

	cap.Audience = "tampered-audience"
	valid, _ = v2.VerifyCapabilitySignature(cap, issuerPub)
	if valid {
		t.Fatal("expected invalid signature after tampering")
	}
}

func TestVerifyCapabilitySignatureRejectsWrongKey(t *testing.T) {
	issuerPub, issuerPriv, _ := anchorcrypto.GenerateEd25519KeyPair()
	agentPub, _, _ := anchorcrypto.GenerateEd25519KeyPair()
	otherPub, _, _ := anchorcrypto.GenerateEd25519KeyPair()
	issuerID, _ := anchorcrypto.DeriveIDFromPublicKey(issuerPub)
	agentID, _ := anchorcrypto.DeriveIDFromPublicKey(agentPub)
	issuedAt := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	cap := makeUnsignedCapability(issuerID, agentID, issuedAt)
	if err := v2.SignCapability(&cap, issuerPriv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	valid, err := v2.VerifyCapabilitySignature(cap, otherPub)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if valid {
		t.Fatal("expected invalid signature for wrong issuer key")
	}
}

func TestSignActionProducesDeterministicID(t *testing.T) {
	_, agentPriv, _ := anchorcrypto.GenerateEd25519KeyPair()
	agentPub, _, _ := anchorcrypto.GenerateEd25519KeyPair()
	agentID, _ := anchorcrypto.DeriveIDFromPublicKey(agentPub)
	ts := time.Date(2026, 2, 15, 10, 5, 0, 0, time.UTC)

	a1 := makeUnsignedAction(agentID, "cap-id-1", ts)
	a2 := makeUnsignedAction(agentID, "cap-id-1", ts)

	// Using the same private key for both
	if err := v2.SignAction(&a1, agentPriv); err != nil {
		t.Fatalf("sign a1: %v", err)
	}
	if err := v2.SignAction(&a2, agentPriv); err != nil {
		t.Fatalf("sign a2: %v", err)
	}
	if a1.ActionID != a2.ActionID {
		t.Fatalf("expected same action ID, got %s and %s", a1.ActionID, a2.ActionID)
	}
	if a1.ActionID == "" {
		t.Fatal("expected non-empty action ID")
	}
}

func TestSignActionRejectsNilPointer(t *testing.T) {
	_, priv, _ := anchorcrypto.GenerateEd25519KeyPair()
	if err := v2.SignAction(nil, priv); err == nil {
		t.Fatal("expected error for nil action")
	}
}

func TestVerifyActionSignatureDetectsTampering(t *testing.T) {
	agentPub, agentPriv, _ := anchorcrypto.GenerateEd25519KeyPair()
	agentID, _ := anchorcrypto.DeriveIDFromPublicKey(agentPub)
	ts := time.Date(2026, 2, 15, 10, 5, 0, 0, time.UTC)

	action := makeUnsignedAction(agentID, "cap-id-1", ts)
	if err := v2.SignAction(&action, agentPriv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	valid, err := v2.VerifyActionSignature(action, agentPub)
	if err != nil {
		t.Fatalf("verify valid: %v", err)
	}
	if !valid {
		t.Fatal("expected valid action signature")
	}

	action.ActionPayload = json.RawMessage(`{"tampered":true}`)
	valid, _ = v2.VerifyActionSignature(action, agentPub)
	if valid {
		t.Fatal("expected invalid signature after tampering payload")
	}
}

func TestSignAndVerifyFullCapabilityActionLifecycle(t *testing.T) {
	issuerPub, issuerPriv, _ := anchorcrypto.GenerateEd25519KeyPair()
	agentPub, agentPriv, _ := anchorcrypto.GenerateEd25519KeyPair()
	issuerID, _ := anchorcrypto.DeriveIDFromPublicKey(issuerPub)
	agentID, _ := anchorcrypto.DeriveIDFromPublicKey(agentPub)
	issuedAt := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	cap := makeUnsignedCapability(issuerID, agentID, issuedAt)
	if err := v2.SignCapability(&cap, issuerPriv); err != nil {
		t.Fatalf("sign capability: %v", err)
	}
	capValid, err := v2.VerifyCapabilitySignature(cap, issuerPub)
	if err != nil || !capValid {
		t.Fatalf("capability signature invalid: err=%v valid=%v", err, capValid)
	}

	action := makeUnsignedAction(agentID, cap.CapabilityID, issuedAt.Add(2*time.Minute))
	if err := v2.SignAction(&action, agentPriv); err != nil {
		t.Fatalf("sign action: %v", err)
	}
	actValid, err := v2.VerifyActionSignature(action, agentPub)
	if err != nil || !actValid {
		t.Fatalf("action signature invalid: err=%v valid=%v", err, actValid)
	}

	if action.CapabilityID != cap.CapabilityID {
		t.Fatal("action capability binding mismatch")
	}
}

func TestComputeCapabilityIDIsDeterministic(t *testing.T) {
	issuerPub, _, _ := anchorcrypto.GenerateEd25519KeyPair()
	agentPub, _, _ := anchorcrypto.GenerateEd25519KeyPair()
	issuerID, _ := anchorcrypto.DeriveIDFromPublicKey(issuerPub)
	agentID, _ := anchorcrypto.DeriveIDFromPublicKey(agentPub)
	issuedAt := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	cap := makeUnsignedCapability(issuerID, agentID, issuedAt)
	id1, err := v2.ComputeCapabilityID(cap)
	if err != nil {
		t.Fatalf("compute cap id 1: %v", err)
	}
	id2, err := v2.ComputeCapabilityID(cap)
	if err != nil {
		t.Fatalf("compute cap id 2: %v", err)
	}
	if id1 != id2 {
		t.Fatal("expected deterministic capability ID")
	}
}

func TestComputeActionIDIsDeterministic(t *testing.T) {
	agentPub, _, _ := anchorcrypto.GenerateEd25519KeyPair()
	agentID, _ := anchorcrypto.DeriveIDFromPublicKey(agentPub)
	ts := time.Date(2026, 2, 15, 10, 5, 0, 0, time.UTC)

	action := makeUnsignedAction(agentID, "cap-id-1", ts)
	id1, err := v2.ComputeActionID(action)
	if err != nil {
		t.Fatalf("compute action id 1: %v", err)
	}
	id2, err := v2.ComputeActionID(action)
	if err != nil {
		t.Fatalf("compute action id 2: %v", err)
	}
	if id1 != id2 {
		t.Fatal("expected deterministic action ID")
	}
}

func makeUnsignedCapability(issuerID, agentID string, issuedAt time.Time) v2.Capability {
	return v2.Capability{
		Version:        v2.Version,
		IssuerID:       issuerID,
		IssuerKID:      "k1",
		AgentID:        agentID,
		Audience:       "test:prod:svc",
		AllowedActions: []string{"svc:DoThing"},
		Constraints: v2.ConstraintSet{
			ResourceLimits:         map[string]int64{"svc:items": 5},
			SpendLimits:            map[string]int64{"usd_cents": 100},
			APIScopes:              []string{"test:svc"},
			RateLimits:             map[string]int64{"requests_per_minute": 10},
			EnvironmentConstraints: []string{"prod"},
		},
		Delegation:      v2.Delegation{Depth: 0, MaxDepth: 1},
		PolicyHash:      "policy-hash-test",
		TransparencyRef: "tr-log://test",
		IssuedAt:        issuedAt,
		ExpiresAt:       issuedAt.Add(30 * time.Minute),
		Nonce:           "nonce-test",
	}
}

func makeUnsignedAction(agentID, capabilityID string, ts time.Time) v2.ActionEnvelope {
	return v2.ActionEnvelope{
		AgentID:       agentID,
		CapabilityID:  capabilityID,
		Audience:      "test:prod:svc",
		ActionType:    "svc:DoThing",
		ActionPayload: json.RawMessage(`{"item":"widget"}`),
		ConstraintEvidence: v2.ConstraintEvidence{
			ResourceUsage: map[string]int64{"svc:items": 1},
			SpendUsage:    map[string]int64{"usd_cents": 10},
			RateUsage:     map[string]int64{"requests_per_minute": 1},
			Environment:   "prod",
			APIScope:      "test:svc",
		},
		Timestamp: ts,
	}
}

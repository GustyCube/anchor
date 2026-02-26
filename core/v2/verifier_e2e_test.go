package v2_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	anchorcrypto "github.com/ignyte-solutions/ignyte-anchor-protocol/core/crypto"
	"github.com/ignyte-solutions/ignyte-anchor-protocol/core/v2"
)

// TestE2E_FullProtocolLifecycle exercises the complete protocol flow:
// key generation -> capability issuance -> action signing -> trust bundle -> verification.
func TestE2E_FullProtocolLifecycle(t *testing.T) {
	issuerPub, issuerPriv, _ := anchorcrypto.GenerateEd25519KeyPair()
	agentPub, agentPriv, _ := anchorcrypto.GenerateEd25519KeyPair()
	issuerID, _ := anchorcrypto.DeriveIDFromPublicKey(issuerPub)
	agentID, _ := anchorcrypto.DeriveIDFromPublicKey(agentPub)
	issuedAt := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	cap := v2.Capability{
		Version:        v2.Version,
		IssuerID:       issuerID,
		IssuerKID:      "k1",
		AgentID:        agentID,
		Audience:       "cloud:prod:storage",
		AllowedActions: []string{"storage:Upload", "storage:Download"},
		Constraints: v2.ConstraintSet{
			ResourceLimits:         map[string]int64{"storage:objects": 10},
			SpendLimits:            map[string]int64{"usd_cents": 500},
			APIScopes:              []string{"cloud:storage"},
			RateLimits:             map[string]int64{"requests_per_minute": 20},
			EnvironmentConstraints: []string{"prod"},
		},
		Delegation:      v2.Delegation{Depth: 0, MaxDepth: 1},
		PolicyHash:      "policy-v2-hash",
		TransparencyRef: "tr-log://entry-100",
		IssuedAt:        issuedAt,
		ExpiresAt:       issuedAt.Add(30 * time.Minute),
		Nonce:           "nonce-full-e2e",
	}
	if err := v2.SignCapability(&cap, issuerPriv); err != nil {
		t.Fatalf("sign capability: %v", err)
	}

	action := v2.ActionEnvelope{
		AgentID:       agentID,
		CapabilityID:  cap.CapabilityID,
		Audience:      "cloud:prod:storage",
		ActionType:    "storage:Upload",
		ActionPayload: json.RawMessage(`{"bucket":"data","key":"report.csv"}`),
		ConstraintEvidence: v2.ConstraintEvidence{
			ResourceUsage: map[string]int64{"storage:objects": 1},
			SpendUsage:    map[string]int64{"usd_cents": 10},
			RateUsage:     map[string]int64{"requests_per_minute": 1},
			Environment:   "prod",
			APIScope:      "cloud:storage",
		},
		ChallengeNonce: "nonce-e2e-challenge",
		Timestamp:      issuedAt.Add(2 * time.Minute),
	}
	if err := v2.SignAction(&action, agentPriv); err != nil {
		t.Fatalf("sign action: %v", err)
	}

	bundle := v2.TrustBundle{
		BundleID:           "bundle-e2e",
		IssuedAt:           issuedAt,
		ExpiresAt:          issuedAt.Add(24 * time.Hour),
		SignerPublicKeyKID: "bundle-signer-e2e",
		Issuers: []v2.TrustBundleIssuer{{
			IssuerID:      issuerID,
			IssuerKID:     "k1",
			PublicKey:     anchorcrypto.PublicKeyToBase64(issuerPub),
			ValidFrom:     issuedAt.Add(-1 * time.Hour),
			ValidUntil:    issuedAt.Add(24 * time.Hour),
			AssuranceTier: "ORG_VERIFIED",
		}},
	}
	if err := v2.SignTrustBundle(&bundle, issuerPriv); err != nil {
		t.Fatalf("sign trust bundle: %v", err)
	}

	engine := v2.NewEngine()
	result := engine.Verify(v2.VerifyRequest{
		Capability:         cap,
		Action:             action,
		AgentPublicKey:     agentPub,
		ReferenceTime:      action.Timestamp,
		ExpectedAudience:   "cloud:prod:storage",
		ExpectedPolicyHash: "policy-v2-hash",
		KeyResolver:        v2.TrustBundleKeyResolver{Bundle: bundle},
		ReplayCache:        v2.NewInMemoryReplayCache(),
	})
	if result.Decision != v2.DecisionAuthorized {
		t.Fatalf("expected AUTHORIZED, got %s reasons=%v", result.Decision, result.Reasons)
	}
	if result.ReplayStatus != v2.ReplayStatusFresh {
		t.Fatalf("expected FRESH, got %s", result.ReplayStatus)
	}
	if result.PolicyHashSeen != "policy-v2-hash" {
		t.Fatalf("expected policy hash 'policy-v2-hash', got %s", result.PolicyHashSeen)
	}
}

func TestE2E_VerifyRejectsExpiredCapability(t *testing.T) {
	f := buildE2EFixture(t, e2eInput{})
	engine := v2.NewEngine()

	result := engine.Verify(v2.VerifyRequest{
		Capability:     f.capability,
		Action:         f.action,
		AgentPublicKey: f.agentPublicKey,
		ReferenceTime:  f.capability.ExpiresAt.Add(1 * time.Minute),
		KeyResolver:    f.keyResolver,
	})
	if result.Decision != v2.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !hasReasonCode(result.ReasonCodes, v2.ReasonCodeCapabilityExpired) {
		t.Fatalf("expected capability expired reason, got %v", result.ReasonCodes)
	}
}

func TestE2E_VerifyRejectsCapabilityNotYetValid(t *testing.T) {
	f := buildE2EFixture(t, e2eInput{})
	engine := v2.NewEngine()

	result := engine.Verify(v2.VerifyRequest{
		Capability:     f.capability,
		Action:         f.action,
		AgentPublicKey: f.agentPublicKey,
		ReferenceTime:  f.capability.IssuedAt.Add(-1 * time.Minute),
		KeyResolver:    f.keyResolver,
	})
	if result.Decision != v2.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !hasReasonCode(result.ReasonCodes, v2.ReasonCodeCapabilityNotYetValid) {
		t.Fatalf("expected capability not yet valid reason, got %v", result.ReasonCodes)
	}
}

func TestE2E_VerifyRejectsAgentMismatch(t *testing.T) {
	f := buildE2EFixture(t, e2eInput{})
	differentAgentPub, _, _ := anchorcrypto.GenerateEd25519KeyPair()
	engine := v2.NewEngine()

	result := engine.Verify(v2.VerifyRequest{
		Capability:     f.capability,
		Action:         f.action,
		AgentPublicKey: differentAgentPub,
		ReferenceTime:  f.referenceTime,
		KeyResolver:    f.keyResolver,
	})
	if result.Decision != v2.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !hasReasonCode(result.ReasonCodes, v2.ReasonCodeAgentMismatch) {
		t.Fatalf("expected agent mismatch reason, got %v", result.ReasonCodes)
	}
}

func TestE2E_VerifyRejectsCapabilityBindingMismatch(t *testing.T) {
	f := buildE2EFixture(t, e2eInput{})
	f.action.CapabilityID = "wrong-capability-id"
	engine := v2.NewEngine()

	result := engine.Verify(v2.VerifyRequest{
		Capability:     f.capability,
		Action:         f.action,
		AgentPublicKey: f.agentPublicKey,
		ReferenceTime:  f.referenceTime,
		KeyResolver:    f.keyResolver,
	})
	if result.Decision != v2.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !hasReasonCode(result.ReasonCodes, v2.ReasonCodeCapabilityBindingMismatch) {
		t.Fatalf("expected capability binding mismatch reason, got %v", result.ReasonCodes)
	}
}

func TestE2E_VerifyRejectsActionNotAllowed(t *testing.T) {
	f := buildE2EFixture(t, e2eInput{actionType: "storage:Delete"})
	engine := v2.NewEngine()

	result := engine.Verify(v2.VerifyRequest{
		Capability:     f.capability,
		Action:         f.action,
		AgentPublicKey: f.agentPublicKey,
		ReferenceTime:  f.referenceTime,
		KeyResolver:    f.keyResolver,
	})
	if result.Decision != v2.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !hasReasonCode(result.ReasonCodes, v2.ReasonCodeActionNotAllowed) {
		t.Fatalf("expected action not allowed reason, got %v", result.ReasonCodes)
	}
}

func TestE2E_VerifyRejectsConstraintViolationResourceExceeded(t *testing.T) {
	f := buildE2EFixture(t, e2eInput{resourceUsage: map[string]int64{"storage:objects": 999}})
	engine := v2.NewEngine()

	result := engine.Verify(v2.VerifyRequest{
		Capability:     f.capability,
		Action:         f.action,
		AgentPublicKey: f.agentPublicKey,
		ReferenceTime:  f.referenceTime,
		KeyResolver:    f.keyResolver,
	})
	if result.Decision != v2.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !hasReasonCode(result.ReasonCodes, v2.ReasonCodeConstraintViolation) {
		t.Fatalf("expected constraint violation reason, got %v", result.ReasonCodes)
	}
}

func TestE2E_VerifyRejectsConstraintViolationSpendExceeded(t *testing.T) {
	f := buildE2EFixture(t, e2eInput{spendUsage: map[string]int64{"usd_cents": 999999}})
	engine := v2.NewEngine()

	result := engine.Verify(v2.VerifyRequest{
		Capability:     f.capability,
		Action:         f.action,
		AgentPublicKey: f.agentPublicKey,
		ReferenceTime:  f.referenceTime,
		KeyResolver:    f.keyResolver,
	})
	if result.Decision != v2.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !hasReasonCode(result.ReasonCodes, v2.ReasonCodeConstraintViolation) {
		t.Fatalf("expected constraint violation reason, got %v", result.ReasonCodes)
	}
}

func TestE2E_VerifyRejectsConstraintViolationRateExceeded(t *testing.T) {
	f := buildE2EFixture(t, e2eInput{rateUsage: map[string]int64{"requests_per_minute": 999}})
	engine := v2.NewEngine()

	result := engine.Verify(v2.VerifyRequest{
		Capability:     f.capability,
		Action:         f.action,
		AgentPublicKey: f.agentPublicKey,
		ReferenceTime:  f.referenceTime,
		KeyResolver:    f.keyResolver,
	})
	if result.Decision != v2.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !hasReasonCode(result.ReasonCodes, v2.ReasonCodeConstraintViolation) {
		t.Fatalf("expected constraint violation reason, got %v", result.ReasonCodes)
	}
}

func TestE2E_VerifyRejectsConstraintViolationWrongAPIScope(t *testing.T) {
	f := buildE2EFixture(t, e2eInput{apiScope: "wrong:scope"})
	engine := v2.NewEngine()

	result := engine.Verify(v2.VerifyRequest{
		Capability:     f.capability,
		Action:         f.action,
		AgentPublicKey: f.agentPublicKey,
		ReferenceTime:  f.referenceTime,
		KeyResolver:    f.keyResolver,
	})
	if result.Decision != v2.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !hasReasonCode(result.ReasonCodes, v2.ReasonCodeConstraintViolation) {
		t.Fatalf("expected constraint violation reason, got %v", result.ReasonCodes)
	}
}

func TestE2E_VerifyRejectsConstraintViolationWrongEnvironment(t *testing.T) {
	f := buildE2EFixture(t, e2eInput{environment: "staging"})
	engine := v2.NewEngine()

	result := engine.Verify(v2.VerifyRequest{
		Capability:     f.capability,
		Action:         f.action,
		AgentPublicKey: f.agentPublicKey,
		ReferenceTime:  f.referenceTime,
		KeyResolver:    f.keyResolver,
	})
	if result.Decision != v2.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !hasReasonCode(result.ReasonCodes, v2.ReasonCodeConstraintViolation) {
		t.Fatalf("expected constraint violation reason, got %v", result.ReasonCodes)
	}
}

func TestE2E_VerifyRejectsConstraintViolationUnpermittedResource(t *testing.T) {
	f := buildE2EFixture(t, e2eInput{resourceUsage: map[string]int64{"unknown:resource": 1}})
	engine := v2.NewEngine()

	result := engine.Verify(v2.VerifyRequest{
		Capability:     f.capability,
		Action:         f.action,
		AgentPublicKey: f.agentPublicKey,
		ReferenceTime:  f.referenceTime,
		KeyResolver:    f.keyResolver,
	})
	if result.Decision != v2.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !hasReasonCode(result.ReasonCodes, v2.ReasonCodeConstraintViolation) {
		t.Fatalf("expected constraint violation reason, got %v", result.ReasonCodes)
	}
}

func TestE2E_VerifyRejectsReferenceTimeMissing(t *testing.T) {
	f := buildE2EFixture(t, e2eInput{})
	engine := v2.NewEngine()

	result := engine.Verify(v2.VerifyRequest{
		Capability:     f.capability,
		Action:         f.action,
		AgentPublicKey: f.agentPublicKey,
		KeyResolver:    f.keyResolver,
	})
	if result.Decision != v2.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !hasReasonCode(result.ReasonCodes, v2.ReasonCodeReferenceTimeMissing) {
		t.Fatalf("expected reference time missing reason, got %v", result.ReasonCodes)
	}
}

func TestE2E_VerifyRejectsIssuerKeyMissingNoResolver(t *testing.T) {
	f := buildE2EFixture(t, e2eInput{})
	engine := v2.NewEngine()

	result := engine.Verify(v2.VerifyRequest{
		Capability:     f.capability,
		Action:         f.action,
		AgentPublicKey: f.agentPublicKey,
		ReferenceTime:  f.referenceTime,
	})
	if result.Decision != v2.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !hasReasonCode(result.ReasonCodes, v2.ReasonCodeIssuerKeyMissing) {
		t.Fatalf("expected issuer key missing reason, got %v", result.ReasonCodes)
	}
}

func TestE2E_VerifyWithDirectIssuerPublicKey(t *testing.T) {
	f := buildE2EFixture(t, e2eInput{})
	engine := v2.NewEngine()

	result := engine.Verify(v2.VerifyRequest{
		Capability:      f.capability,
		Action:          f.action,
		AgentPublicKey:  f.agentPublicKey,
		IssuerPublicKey: f.issuerPublicKey,
		ReferenceTime:   f.referenceTime,
	})
	if result.Decision != v2.DecisionAuthorized {
		t.Fatalf("expected AUTHORIZED with direct key, got %s reasons=%v", result.Decision, result.Reasons)
	}
}

func TestE2E_VerifyRejectsIssuerMismatchWithDirectKey(t *testing.T) {
	f := buildE2EFixture(t, e2eInput{})
	wrongIssuerPub, _, _ := anchorcrypto.GenerateEd25519KeyPair()
	engine := v2.NewEngine()

	result := engine.Verify(v2.VerifyRequest{
		Capability:      f.capability,
		Action:          f.action,
		AgentPublicKey:  f.agentPublicKey,
		IssuerPublicKey: wrongIssuerPub,
		ReferenceTime:   f.referenceTime,
	})
	if result.Decision != v2.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !hasReasonCode(result.ReasonCodes, v2.ReasonCodeIssuerMismatch) {
		t.Fatalf("expected issuer mismatch reason, got %v", result.ReasonCodes)
	}
}

func TestE2E_VerifyReplayStatusUnknownWhenNoCacheProvided(t *testing.T) {
	f := buildE2EFixture(t, e2eInput{})
	engine := v2.NewEngine()

	result := engine.Verify(v2.VerifyRequest{
		Capability:     f.capability,
		Action:         f.action,
		AgentPublicKey: f.agentPublicKey,
		ReferenceTime:  f.referenceTime,
		KeyResolver:    f.keyResolver,
	})
	if result.Decision != v2.DecisionAuthorized {
		t.Fatalf("expected AUTHORIZED, got %s", result.Decision)
	}
	if result.ReplayStatus != v2.ReplayStatusUnknown {
		t.Fatalf("expected UNKNOWN replay status without cache, got %s", result.ReplayStatus)
	}
}

func TestE2E_VerifyWithWindowedReplayCache(t *testing.T) {
	f := buildE2EFixture(t, e2eInput{})
	engine := v2.NewEngine()
	cache := v2.NewInMemoryWindowReplayCache()

	first := engine.Verify(v2.VerifyRequest{
		Capability:     f.capability,
		Action:         f.action,
		AgentPublicKey: f.agentPublicKey,
		ReferenceTime:  f.referenceTime,
		KeyResolver:    f.keyResolver,
		ReplayCache:    cache,
		ReplayWindow:   2 * time.Minute,
	})
	if first.Decision != v2.DecisionAuthorized {
		t.Fatalf("first verify should authorize, got %s reasons=%v", first.Decision, first.Reasons)
	}

	second := engine.Verify(v2.VerifyRequest{
		Capability:     f.capability,
		Action:         f.action,
		AgentPublicKey: f.agentPublicKey,
		ReferenceTime:  f.referenceTime.Add(1 * time.Second),
		KeyResolver:    f.keyResolver,
		ReplayCache:    cache,
		ReplayWindow:   2 * time.Minute,
	})
	if second.Decision != v2.DecisionRejected {
		t.Fatalf("within window should reject replay, got %s", second.Decision)
	}

	third := engine.Verify(v2.VerifyRequest{
		Capability:     f.capability,
		Action:         f.action,
		AgentPublicKey: f.agentPublicKey,
		ReferenceTime:  f.referenceTime.Add(5 * time.Minute),
		KeyResolver:    f.keyResolver,
		ReplayCache:    cache,
		ReplayWindow:   2 * time.Minute,
	})
	if third.Decision != v2.DecisionAuthorized {
		t.Fatalf("after window should authorize, got %s reasons=%v", third.Decision, third.Reasons)
	}
}

func TestE2E_VerifyTrustBundleExpired(t *testing.T) {
	issuerPub, issuerPriv, _ := anchorcrypto.GenerateEd25519KeyPair()
	agentPub, agentPriv, _ := anchorcrypto.GenerateEd25519KeyPair()
	issuerID, _ := anchorcrypto.DeriveIDFromPublicKey(issuerPub)
	agentID, _ := anchorcrypto.DeriveIDFromPublicKey(agentPub)
	issuedAt := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	cap := buildE2ECap(issuerID, agentID, issuedAt, issuedAt.Add(24*time.Hour))
	if err := v2.SignCapability(&cap, issuerPriv); err != nil {
		t.Fatalf("sign cap: %v", err)
	}
	action := buildE2EAction(agentID, cap.CapabilityID, issuedAt.Add(2*time.Minute))
	if err := v2.SignAction(&action, agentPriv); err != nil {
		t.Fatalf("sign action: %v", err)
	}
	bundle := v2.TrustBundle{
		BundleID:           "bundle-expired",
		IssuedAt:           issuedAt,
		ExpiresAt:          issuedAt.Add(1 * time.Hour),
		SignerPublicKeyKID: "signer-k",
		Issuers: []v2.TrustBundleIssuer{{
			IssuerID:      issuerID,
			IssuerKID:     "k1",
			PublicKey:     anchorcrypto.PublicKeyToBase64(issuerPub),
			ValidFrom:     issuedAt.Add(-1 * time.Hour),
			ValidUntil:    issuedAt.Add(24 * time.Hour),
			AssuranceTier: "ORG_VERIFIED",
		}},
	}
	if err := v2.SignTrustBundle(&bundle, issuerPriv); err != nil {
		t.Fatalf("sign bundle: %v", err)
	}

	engine := v2.NewEngine()
	result := engine.Verify(v2.VerifyRequest{
		Capability:     cap,
		Action:         action,
		AgentPublicKey: agentPub,
		ReferenceTime:  issuedAt.Add(2 * time.Hour),
		KeyResolver:    v2.TrustBundleKeyResolver{Bundle: bundle},
	})
	if result.Decision != v2.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if !hasReasonCode(result.ReasonCodes, v2.ReasonCodeTrustBundleExpired) {
		t.Fatalf("expected trust bundle expired reason, got %v", result.ReasonCodes)
	}
}

func TestE2E_VerifyMultipleRejectionReasons(t *testing.T) {
	f := buildE2EFixture(t, e2eInput{actionType: "storage:Delete", environment: "staging"})
	engine := v2.NewEngine()

	result := engine.Verify(v2.VerifyRequest{
		Capability:         f.capability,
		Action:             f.action,
		AgentPublicKey:     f.agentPublicKey,
		ReferenceTime:      f.referenceTime,
		KeyResolver:        f.keyResolver,
		ExpectedPolicyHash: "wrong-hash",
	})
	if result.Decision != v2.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
	if len(result.ReasonCodes) < 2 {
		t.Fatalf("expected multiple rejection reasons, got %v", result.ReasonCodes)
	}
}

func TestE2E_ValidateTrustBundleAtRejectsInvalidSignature(t *testing.T) {
	signerPub, signerPriv, _ := anchorcrypto.GenerateEd25519KeyPair()
	otherPub, _, _ := anchorcrypto.GenerateEd25519KeyPair()
	issuedAt := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	bundle := v2.TrustBundle{
		BundleID:           "bundle-sig-test",
		IssuedAt:           issuedAt,
		ExpiresAt:          issuedAt.Add(1 * time.Hour),
		SignerPublicKeyKID: "signer-k",
		Issuers: []v2.TrustBundleIssuer{{
			IssuerID:      "issuer-1",
			IssuerKID:     "k1",
			PublicKey:     anchorcrypto.PublicKeyToBase64(signerPub),
			ValidFrom:     issuedAt,
			ValidUntil:    issuedAt.Add(1 * time.Hour),
			AssuranceTier: "ORG_VERIFIED",
		}},
	}
	if err := v2.SignTrustBundle(&bundle, signerPriv); err != nil {
		t.Fatalf("sign bundle: %v", err)
	}

	err := v2.ValidateTrustBundleAt(bundle, otherPub, issuedAt.Add(5*time.Minute))
	if err == nil {
		t.Fatal("expected error for wrong signer key")
	}
}

func TestE2E_ValidateTrustBundleAtRejectsExpired(t *testing.T) {
	signerPub, signerPriv, _ := anchorcrypto.GenerateEd25519KeyPair()
	issuedAt := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	bundle := v2.TrustBundle{
		BundleID:           "bundle-exp-test",
		IssuedAt:           issuedAt,
		ExpiresAt:          issuedAt.Add(1 * time.Hour),
		SignerPublicKeyKID: "signer-k",
	}
	if err := v2.SignTrustBundle(&bundle, signerPriv); err != nil {
		t.Fatalf("sign bundle: %v", err)
	}

	err := v2.ValidateTrustBundleAt(bundle, signerPub, issuedAt.Add(2*time.Hour))
	if err == nil {
		t.Fatal("expected error for expired bundle")
	}
}

func TestE2E_SignTrustBundleRejectsNil(t *testing.T) {
	_, priv, _ := anchorcrypto.GenerateEd25519KeyPair()
	if err := v2.SignTrustBundle(nil, priv); err == nil {
		t.Fatal("expected error for nil bundle")
	}
}

func TestE2E_SignTrustBundleRejectsInvalidFields(t *testing.T) {
	_, priv, _ := anchorcrypto.GenerateEd25519KeyPair()
	bundle := v2.TrustBundle{}
	if err := v2.SignTrustBundle(&bundle, priv); err == nil {
		t.Fatal("expected error for empty bundle")
	}
}

func TestE2E_TrustBundleKeyResolverReturnsNotFoundForUnknownIssuer(t *testing.T) {
	signerPub, signerPriv, _ := anchorcrypto.GenerateEd25519KeyPair()
	issuedAt := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	bundle := v2.TrustBundle{
		BundleID:           "bundle-nf",
		IssuedAt:           issuedAt,
		ExpiresAt:          issuedAt.Add(1 * time.Hour),
		SignerPublicKeyKID: "signer-k",
		Issuers: []v2.TrustBundleIssuer{{
			IssuerID:      "known-issuer",
			IssuerKID:     "k1",
			PublicKey:     anchorcrypto.PublicKeyToBase64(signerPub),
			ValidFrom:     issuedAt,
			ValidUntil:    issuedAt.Add(1 * time.Hour),
			AssuranceTier: "ORG_VERIFIED",
		}},
	}
	if err := v2.SignTrustBundle(&bundle, signerPriv); err != nil {
		t.Fatalf("sign bundle: %v", err)
	}

	resolver := v2.TrustBundleKeyResolver{Bundle: bundle}
	_, found, err := resolver.Resolve("unknown-issuer", "k1", issuedAt.Add(5*time.Minute))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Fatal("expected not found for unknown issuer")
	}
}

func TestE2E_InMemoryTrustBundleCacheGetPut(t *testing.T) {
	cache := v2.NewInMemoryTrustBundleCache()
	if _, ok := cache.Get(); ok {
		t.Fatal("expected empty cache initially")
	}

	bundle := v2.TrustBundle{BundleID: "cached-bundle"}
	cache.Put(bundle)
	got, ok := cache.Get()
	if !ok {
		t.Fatal("expected bundle in cache after put")
	}
	if got.BundleID != "cached-bundle" {
		t.Fatalf("expected cached-bundle, got %s", got.BundleID)
	}
}

func TestE2E_StaticRevocationList(t *testing.T) {
	revoked := v2.StaticRevocationList{Revoked: map[string]struct{}{"cap-1": {}}}
	if !revoked.IsRevoked("cap-1") {
		t.Fatal("expected cap-1 to be revoked")
	}
	if revoked.IsRevoked("cap-2") {
		t.Fatal("expected cap-2 to not be revoked")
	}
	empty := v2.StaticRevocationList{}
	if empty.IsRevoked("cap-1") {
		t.Fatal("expected nil revocation list to not revoke anything")
	}
}

func TestE2E_StaticChallengePolicy(t *testing.T) {
	policy := v2.StaticChallengePolicy{Required: map[string]struct{}{"high:risk": {}}}
	if !policy.RequiresChallenge("high:risk") {
		t.Fatal("expected high:risk to require challenge")
	}
	if policy.RequiresChallenge("low:risk") {
		t.Fatal("expected low:risk to not require challenge")
	}
	empty := v2.StaticChallengePolicy{}
	if empty.RequiresChallenge("any") {
		t.Fatal("expected nil policy to not require challenge")
	}
}

func TestE2E_FuncPolicyEvaluatorNilSafe(t *testing.T) {
	var eval v2.FuncPolicyEvaluator
	codes, reasons := eval.Evaluate(v2.Capability{}, v2.ActionEnvelope{})
	if codes != nil || reasons != nil {
		t.Fatal("expected nil func evaluator to return nil")
	}
}

func TestE2E_FuncTransparencyVerifierNilSafe(t *testing.T) {
	var verifier v2.FuncTransparencyVerifier
	if err := verifier.Verify("ref", "cap"); err != nil {
		t.Fatalf("expected nil func verifier to succeed: %v", err)
	}
}

// --- E2E fixture helpers ---

type e2eInput struct {
	actionType    string
	environment   string
	apiScope      string
	resourceUsage map[string]int64
	spendUsage    map[string]int64
	rateUsage     map[string]int64
}

type e2eFixture struct {
	capability     v2.Capability
	action         v2.ActionEnvelope
	agentPublicKey []byte
	issuerPublicKey []byte
	referenceTime  time.Time
	keyResolver    v2.IssuerKeyResolver
}

func buildE2EFixture(t *testing.T, input e2eInput) e2eFixture {
	t.Helper()
	issuerPub, issuerPriv, _ := anchorcrypto.GenerateEd25519KeyPair()
	agentPub, agentPriv, _ := anchorcrypto.GenerateEd25519KeyPair()
	issuerID, _ := anchorcrypto.DeriveIDFromPublicKey(issuerPub)
	agentID, _ := anchorcrypto.DeriveIDFromPublicKey(agentPub)
	issuedAt := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	if input.actionType == "" {
		input.actionType = "storage:Upload"
	}
	if input.environment == "" {
		input.environment = "prod"
	}
	if input.apiScope == "" {
		input.apiScope = "cloud:storage"
	}
	if input.resourceUsage == nil {
		input.resourceUsage = map[string]int64{"storage:objects": 1}
	}
	if input.spendUsage == nil {
		input.spendUsage = map[string]int64{"usd_cents": 10}
	}
	if input.rateUsage == nil {
		input.rateUsage = map[string]int64{"requests_per_minute": 1}
	}

	cap := buildE2ECap(issuerID, agentID, issuedAt, issuedAt.Add(30*time.Minute))
	if err := v2.SignCapability(&cap, issuerPriv); err != nil {
		t.Fatalf("sign cap: %v", err)
	}

	action := v2.ActionEnvelope{
		AgentID:       agentID,
		CapabilityID:  cap.CapabilityID,
		Audience:      "cloud:prod:storage",
		ActionType:    input.actionType,
		ActionPayload: json.RawMessage(`{"bucket":"data","key":"file.txt"}`),
		ConstraintEvidence: v2.ConstraintEvidence{
			ResourceUsage: input.resourceUsage,
			SpendUsage:    input.spendUsage,
			RateUsage:     input.rateUsage,
			Environment:   input.environment,
			APIScope:      input.apiScope,
		},
		Timestamp: issuedAt.Add(2 * time.Minute),
	}
	if err := v2.SignAction(&action, agentPriv); err != nil {
		t.Fatalf("sign action: %v", err)
	}

	bundle := v2.TrustBundle{
		BundleID:           "bundle-e2e-fixture",
		IssuedAt:           issuedAt,
		ExpiresAt:          issuedAt.Add(24 * time.Hour),
		SignerPublicKeyKID: "signer-k",
		Issuers: []v2.TrustBundleIssuer{{
			IssuerID:      issuerID,
			IssuerKID:     "k1",
			PublicKey:     anchorcrypto.PublicKeyToBase64(issuerPub),
			ValidFrom:     issuedAt.Add(-1 * time.Hour),
			ValidUntil:    issuedAt.Add(24 * time.Hour),
			AssuranceTier: "ORG_VERIFIED",
		}},
	}
	if err := v2.SignTrustBundle(&bundle, issuerPriv); err != nil {
		t.Fatalf("sign bundle: %v", err)
	}

	return e2eFixture{
		capability:      cap,
		action:          action,
		agentPublicKey:  bytes.Clone(agentPub),
		issuerPublicKey: bytes.Clone(issuerPub),
		referenceTime:   action.Timestamp,
		keyResolver:     v2.TrustBundleKeyResolver{Bundle: bundle},
	}
}

func buildE2ECap(issuerID, agentID string, issuedAt, expiresAt time.Time) v2.Capability {
	return v2.Capability{
		Version:        v2.Version,
		IssuerID:       issuerID,
		IssuerKID:      "k1",
		AgentID:        agentID,
		Audience:       "cloud:prod:storage",
		AllowedActions: []string{"storage:Upload", "storage:Download"},
		Constraints: v2.ConstraintSet{
			ResourceLimits:         map[string]int64{"storage:objects": 10},
			SpendLimits:            map[string]int64{"usd_cents": 500},
			APIScopes:              []string{"cloud:storage"},
			RateLimits:             map[string]int64{"requests_per_minute": 20},
			EnvironmentConstraints: []string{"prod"},
		},
		Delegation:      v2.Delegation{Depth: 0, MaxDepth: 1},
		PolicyHash:      "policy-v2-hash",
		TransparencyRef: "tr-log://entry-e2e",
		IssuedAt:        issuedAt,
		ExpiresAt:       expiresAt,
		Nonce:           "nonce-e2e",
	}
}

func buildE2EAction(agentID, capabilityID string, ts time.Time) v2.ActionEnvelope {
	return v2.ActionEnvelope{
		AgentID:       agentID,
		CapabilityID:  capabilityID,
		Audience:      "cloud:prod:storage",
		ActionType:    "storage:Upload",
		ActionPayload: json.RawMessage(`{"bucket":"data","key":"file.txt"}`),
		ConstraintEvidence: v2.ConstraintEvidence{
			ResourceUsage: map[string]int64{"storage:objects": 1},
			SpendUsage:    map[string]int64{"usd_cents": 10},
			RateUsage:     map[string]int64{"requests_per_minute": 1},
			Environment:   "prod",
			APIScope:      "cloud:storage",
		},
		Timestamp: ts,
	}
}

func hasReasonCode(codes []v2.ReasonCode, target v2.ReasonCode) bool {
	for _, code := range codes {
		if code == target {
			return true
		}
	}
	return false
}

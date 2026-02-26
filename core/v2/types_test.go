package v2_test

import (
	"testing"
	"time"

	"github.com/ignyte-solutions/ignyte-anchor-protocol/core/v2"
)

func TestConstraintSetValidateRejectsNilFields(t *testing.T) {
	cases := []struct {
		name       string
		constraint v2.ConstraintSet
	}{
		{"nil resource_limits", v2.ConstraintSet{
			SpendLimits: map[string]int64{}, APIScopes: []string{}, RateLimits: map[string]int64{}, EnvironmentConstraints: []string{},
		}},
		{"nil spend_limits", v2.ConstraintSet{
			ResourceLimits: map[string]int64{}, APIScopes: []string{}, RateLimits: map[string]int64{}, EnvironmentConstraints: []string{},
		}},
		{"nil api_scopes", v2.ConstraintSet{
			ResourceLimits: map[string]int64{}, SpendLimits: map[string]int64{}, RateLimits: map[string]int64{}, EnvironmentConstraints: []string{},
		}},
		{"nil rate_limits", v2.ConstraintSet{
			ResourceLimits: map[string]int64{}, SpendLimits: map[string]int64{}, APIScopes: []string{}, EnvironmentConstraints: []string{},
		}},
		{"nil environment_constraints", v2.ConstraintSet{
			ResourceLimits: map[string]int64{}, SpendLimits: map[string]int64{}, APIScopes: []string{}, RateLimits: map[string]int64{},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.constraint.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestConstraintSetValidateAcceptsComplete(t *testing.T) {
	c := v2.ConstraintSet{
		ResourceLimits:         map[string]int64{"items": 1},
		SpendLimits:            map[string]int64{"usd": 1},
		APIScopes:              []string{"api"},
		RateLimits:             map[string]int64{"rpm": 1},
		EnvironmentConstraints: []string{"prod"},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestDelegationValidateRejectsInvalid(t *testing.T) {
	cases := []struct {
		name string
		d    v2.Delegation
	}{
		{"negative depth", v2.Delegation{Depth: -1, MaxDepth: 1}},
		{"negative max_depth", v2.Delegation{Depth: 0, MaxDepth: -1}},
		{"depth exceeds max", v2.Delegation{Depth: 2, MaxDepth: 1}},
		{"missing parent at depth > 0", v2.Delegation{Depth: 1, MaxDepth: 2}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.d.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestDelegationValidateAcceptsValid(t *testing.T) {
	cases := []struct {
		name string
		d    v2.Delegation
	}{
		{"zero depth", v2.Delegation{Depth: 0, MaxDepth: 1}},
		{"depth with parent", v2.Delegation{Depth: 1, MaxDepth: 2, ParentCapabilityID: "parent-cap"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.d.Validate(); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestCapabilityValidateUnsignedRejectsIncomplete(t *testing.T) {
	issuedAt := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)
	validConstraints := v2.ConstraintSet{
		ResourceLimits:         map[string]int64{"x": 1},
		SpendLimits:            map[string]int64{"x": 1},
		APIScopes:              []string{"x"},
		RateLimits:             map[string]int64{"x": 1},
		EnvironmentConstraints: []string{"prod"},
	}

	cases := []struct {
		name string
		cap  v2.Capability
	}{
		{"wrong version", v2.Capability{
			Version: 99, IssuerID: "i", IssuerKID: "k", AgentID: "a", Audience: "aud",
			AllowedActions: []string{"x"}, Constraints: validConstraints,
			Delegation: v2.Delegation{MaxDepth: 1}, PolicyHash: "p",
			IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(time.Hour), Nonce: "n",
		}},
		{"missing issuer_id", v2.Capability{
			Version: v2.Version, IssuerKID: "k", AgentID: "a", Audience: "aud",
			AllowedActions: []string{"x"}, Constraints: validConstraints,
			Delegation: v2.Delegation{MaxDepth: 1}, PolicyHash: "p",
			IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(time.Hour), Nonce: "n",
		}},
		{"missing issuer_kid", v2.Capability{
			Version: v2.Version, IssuerID: "i", AgentID: "a", Audience: "aud",
			AllowedActions: []string{"x"}, Constraints: validConstraints,
			Delegation: v2.Delegation{MaxDepth: 1}, PolicyHash: "p",
			IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(time.Hour), Nonce: "n",
		}},
		{"missing agent_id", v2.Capability{
			Version: v2.Version, IssuerID: "i", IssuerKID: "k", Audience: "aud",
			AllowedActions: []string{"x"}, Constraints: validConstraints,
			Delegation: v2.Delegation{MaxDepth: 1}, PolicyHash: "p",
			IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(time.Hour), Nonce: "n",
		}},
		{"missing audience", v2.Capability{
			Version: v2.Version, IssuerID: "i", IssuerKID: "k", AgentID: "a",
			AllowedActions: []string{"x"}, Constraints: validConstraints,
			Delegation: v2.Delegation{MaxDepth: 1}, PolicyHash: "p",
			IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(time.Hour), Nonce: "n",
		}},
		{"empty allowed_actions", v2.Capability{
			Version: v2.Version, IssuerID: "i", IssuerKID: "k", AgentID: "a", Audience: "aud",
			AllowedActions: []string{}, Constraints: validConstraints,
			Delegation: v2.Delegation{MaxDepth: 1}, PolicyHash: "p",
			IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(time.Hour), Nonce: "n",
		}},
		{"missing policy_hash", v2.Capability{
			Version: v2.Version, IssuerID: "i", IssuerKID: "k", AgentID: "a", Audience: "aud",
			AllowedActions: []string{"x"}, Constraints: validConstraints,
			Delegation: v2.Delegation{MaxDepth: 1},
			IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(time.Hour), Nonce: "n",
		}},
		{"missing nonce", v2.Capability{
			Version: v2.Version, IssuerID: "i", IssuerKID: "k", AgentID: "a", Audience: "aud",
			AllowedActions: []string{"x"}, Constraints: validConstraints,
			Delegation: v2.Delegation{MaxDepth: 1}, PolicyHash: "p",
			IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(time.Hour),
		}},
		{"zero issued_at", v2.Capability{
			Version: v2.Version, IssuerID: "i", IssuerKID: "k", AgentID: "a", Audience: "aud",
			AllowedActions: []string{"x"}, Constraints: validConstraints,
			Delegation: v2.Delegation{MaxDepth: 1}, PolicyHash: "p",
			ExpiresAt: issuedAt.Add(time.Hour), Nonce: "n",
		}},
		{"expires_at before issued_at", v2.Capability{
			Version: v2.Version, IssuerID: "i", IssuerKID: "k", AgentID: "a", Audience: "aud",
			AllowedActions: []string{"x"}, Constraints: validConstraints,
			Delegation: v2.Delegation{MaxDepth: 1}, PolicyHash: "p",
			IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(-time.Hour), Nonce: "n",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.cap.ValidateUnsigned(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestConstraintEvidenceValidateRejectsIncomplete(t *testing.T) {
	cases := []struct {
		name string
		e    v2.ConstraintEvidence
	}{
		{"nil resource_usage", v2.ConstraintEvidence{
			SpendUsage: map[string]int64{}, RateUsage: map[string]int64{}, Environment: "prod", APIScope: "api",
		}},
		{"nil spend_usage", v2.ConstraintEvidence{
			ResourceUsage: map[string]int64{}, RateUsage: map[string]int64{}, Environment: "prod", APIScope: "api",
		}},
		{"nil rate_usage", v2.ConstraintEvidence{
			ResourceUsage: map[string]int64{}, SpendUsage: map[string]int64{}, Environment: "prod", APIScope: "api",
		}},
		{"empty environment", v2.ConstraintEvidence{
			ResourceUsage: map[string]int64{}, SpendUsage: map[string]int64{}, RateUsage: map[string]int64{}, APIScope: "api",
		}},
		{"empty api_scope", v2.ConstraintEvidence{
			ResourceUsage: map[string]int64{}, SpendUsage: map[string]int64{}, RateUsage: map[string]int64{}, Environment: "prod",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.e.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestActionEnvelopeValidateUnsignedRejectsIncomplete(t *testing.T) {
	ts := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)
	validEvidence := v2.ConstraintEvidence{
		ResourceUsage: map[string]int64{"x": 1},
		SpendUsage:    map[string]int64{"x": 1},
		RateUsage:     map[string]int64{"x": 1},
		Environment:   "prod",
		APIScope:      "api",
	}

	cases := []struct {
		name   string
		action v2.ActionEnvelope
	}{
		{"missing agent_id", v2.ActionEnvelope{
			CapabilityID: "c", Audience: "a", ActionType: "t", ActionPayload: []byte(`{}`),
			ConstraintEvidence: validEvidence, Timestamp: ts,
		}},
		{"missing capability_id", v2.ActionEnvelope{
			AgentID: "a", Audience: "a", ActionType: "t", ActionPayload: []byte(`{}`),
			ConstraintEvidence: validEvidence, Timestamp: ts,
		}},
		{"missing audience", v2.ActionEnvelope{
			AgentID: "a", CapabilityID: "c", ActionType: "t", ActionPayload: []byte(`{}`),
			ConstraintEvidence: validEvidence, Timestamp: ts,
		}},
		{"missing action_type", v2.ActionEnvelope{
			AgentID: "a", CapabilityID: "c", Audience: "a", ActionPayload: []byte(`{}`),
			ConstraintEvidence: validEvidence, Timestamp: ts,
		}},
		{"empty action_payload", v2.ActionEnvelope{
			AgentID: "a", CapabilityID: "c", Audience: "a", ActionType: "t",
			ConstraintEvidence: validEvidence, Timestamp: ts,
		}},
		{"zero timestamp", v2.ActionEnvelope{
			AgentID: "a", CapabilityID: "c", Audience: "a", ActionType: "t", ActionPayload: []byte(`{}`),
			ConstraintEvidence: validEvidence,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.action.ValidateUnsigned(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestTrustBundleValidateRejectsIncomplete(t *testing.T) {
	issuedAt := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	cases := []struct {
		name   string
		bundle v2.TrustBundle
	}{
		{"missing bundle_id", v2.TrustBundle{
			IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(time.Hour),
			Signature: "sig", SignerPublicKeyKID: "kid",
		}},
		{"zero issued_at", v2.TrustBundle{
			BundleID: "b", ExpiresAt: issuedAt.Add(time.Hour),
			Signature: "sig", SignerPublicKeyKID: "kid",
		}},
		{"expires_at before issued_at", v2.TrustBundle{
			BundleID: "b", IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(-time.Hour),
			Signature: "sig", SignerPublicKeyKID: "kid",
		}},
		{"missing signature", v2.TrustBundle{
			BundleID: "b", IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(time.Hour),
			SignerPublicKeyKID: "kid",
		}},
		{"missing signer_public_key_kid", v2.TrustBundle{
			BundleID: "b", IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(time.Hour),
			Signature: "sig",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.bundle.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

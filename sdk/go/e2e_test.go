package protocolgo_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	anchorcrypto "github.com/ignyte-solutions/ignyte-anchor-protocol/core/crypto"
	"github.com/ignyte-solutions/ignyte-anchor-protocol/core/v2"
	protocolgo "github.com/ignyte-solutions/ignyte-anchor-protocol/sdk/go"
)

func TestOfflineVerifyFullAuthorizedLifecycle(t *testing.T) {
	issuerPub, issuerPriv, _ := anchorcrypto.GenerateEd25519KeyPair()
	agentPub, agentPriv, _ := anchorcrypto.GenerateEd25519KeyPair()
	issuerID, _ := anchorcrypto.DeriveIDFromPublicKey(issuerPub)
	agentID, _ := anchorcrypto.DeriveIDFromPublicKey(agentPub)
	issuedAt := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	cap := protocolgo.Capability{
		Version:        protocolgo.Version,
		IssuerID:       issuerID,
		IssuerKID:      "k1",
		AgentID:        agentID,
		Audience:       "api:prod:service",
		AllowedActions: []string{"service:Execute"},
		Constraints: protocolgo.ConstraintSet{
			ResourceLimits:         map[string]int64{"items": 5},
			SpendLimits:            map[string]int64{"usd_cents": 100},
			APIScopes:              []string{"api:service"},
			RateLimits:             map[string]int64{"rpm": 10},
			EnvironmentConstraints: []string{"prod"},
		},
		Delegation:      protocolgo.Delegation{Depth: 0, MaxDepth: 1},
		PolicyHash:      "sdk-policy-hash",
		TransparencyRef: "tr-log://sdk-entry",
		IssuedAt:        issuedAt,
		ExpiresAt:       issuedAt.Add(30 * time.Minute),
		Nonce:           "sdk-nonce",
	}
	if err := protocolgo.SignCapability(&cap, issuerPriv); err != nil {
		t.Fatalf("sign capability: %v", err)
	}

	action := protocolgo.ActionEnvelope{
		AgentID:       agentID,
		CapabilityID:  cap.CapabilityID,
		Audience:      "api:prod:service",
		ActionType:    "service:Execute",
		ActionPayload: json.RawMessage(`{"operation":"run"}`),
		ConstraintEvidence: protocolgo.ConstraintEvidence{
			ResourceUsage: map[string]int64{"items": 1},
			SpendUsage:    map[string]int64{"usd_cents": 5},
			RateUsage:     map[string]int64{"rpm": 1},
			Environment:   "prod",
			APIScope:      "api:service",
		},
		Timestamp: issuedAt.Add(2 * time.Minute),
	}
	if err := protocolgo.SignAction(&action, agentPriv); err != nil {
		t.Fatalf("sign action: %v", err)
	}

	bundle := protocolgo.TrustBundle{
		BundleID:           "sdk-bundle",
		IssuedAt:           issuedAt,
		ExpiresAt:          issuedAt.Add(24 * time.Hour),
		SignerPublicKeyKID: "signer-sdk",
		Issuers: []protocolgo.TrustBundleIssuer{{
			IssuerID:      issuerID,
			IssuerKID:     "k1",
			PublicKey:     anchorcrypto.PublicKeyToBase64(issuerPub),
			ValidFrom:     issuedAt.Add(-1 * time.Hour),
			ValidUntil:    issuedAt.Add(24 * time.Hour),
			AssuranceTier: "ORG_VERIFIED",
		}},
	}
	if err := protocolgo.SignTrustBundle(&bundle, issuerPriv); err != nil {
		t.Fatalf("sign trust bundle: %v", err)
	}

	result := protocolgo.OfflineVerify(protocolgo.OfflineVerifyInput{
		Capability:         cap,
		Action:             action,
		AgentPublicKey:     agentPub,
		ReferenceTime:      action.Timestamp,
		ExpectedAudience:   "api:prod:service",
		ExpectedPolicyHash: "sdk-policy-hash",
		KeyResolver:        protocolgo.TrustBundleKeyResolver{Bundle: bundle},
		ReplayCache:        protocolgo.NewInMemoryReplayCache(),
	})
	if result.Decision != protocolgo.DecisionAuthorized {
		t.Fatalf("expected AUTHORIZED, got %s reasons=%v", result.Decision, result.Reasons)
	}
	if result.ReplayStatus != protocolgo.ReplayStatusFresh {
		t.Fatalf("expected FRESH replay status, got %s", result.ReplayStatus)
	}
	if result.PolicyHashSeen != "sdk-policy-hash" {
		t.Fatalf("expected policy hash sdk-policy-hash, got %s", result.PolicyHashSeen)
	}
}

func TestOfflineVerifyRejectsExpiredCapability(t *testing.T) {
	issuerPub, issuerPriv, _ := anchorcrypto.GenerateEd25519KeyPair()
	agentPub, agentPriv, _ := anchorcrypto.GenerateEd25519KeyPair()
	issuerID, _ := anchorcrypto.DeriveIDFromPublicKey(issuerPub)
	agentID, _ := anchorcrypto.DeriveIDFromPublicKey(agentPub)
	issuedAt := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	cap := protocolgo.Capability{
		Version:        protocolgo.Version,
		IssuerID:       issuerID,
		IssuerKID:      "k1",
		AgentID:        agentID,
		Audience:       "api:prod:svc",
		AllowedActions: []string{"svc:Do"},
		Constraints: protocolgo.ConstraintSet{
			ResourceLimits:         map[string]int64{"x": 1},
			SpendLimits:            map[string]int64{"x": 1},
			APIScopes:              []string{"api:svc"},
			RateLimits:             map[string]int64{"x": 1},
			EnvironmentConstraints: []string{"prod"},
		},
		Delegation: protocolgo.Delegation{Depth: 0, MaxDepth: 1},
		PolicyHash: "p", TransparencyRef: "t",
		IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(10 * time.Minute),
		Nonce: "n",
	}
	if err := protocolgo.SignCapability(&cap, issuerPriv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	action := protocolgo.ActionEnvelope{
		AgentID: agentID, CapabilityID: cap.CapabilityID, Audience: "api:prod:svc",
		ActionType: "svc:Do", ActionPayload: json.RawMessage(`{}`),
		ConstraintEvidence: protocolgo.ConstraintEvidence{
			ResourceUsage: map[string]int64{"x": 1}, SpendUsage: map[string]int64{"x": 1},
			RateUsage: map[string]int64{"x": 1}, Environment: "prod", APIScope: "api:svc",
		},
		Timestamp: issuedAt.Add(2 * time.Minute),
	}
	if err := protocolgo.SignAction(&action, agentPriv); err != nil {
		t.Fatalf("sign action: %v", err)
	}

	result := protocolgo.OfflineVerify(protocolgo.OfflineVerifyInput{
		Capability:      cap,
		Action:          action,
		IssuerPublicKey: issuerPub,
		AgentPublicKey:  agentPub,
		ReferenceTime:   issuedAt.Add(1 * time.Hour),
	})
	if result.Decision != v2.DecisionRejected {
		t.Fatalf("expected REJECTED, got %s", result.Decision)
	}
}

func TestOfflineVerifyRejectsReplayViaSDK(t *testing.T) {
	issuerPub, issuerPriv, _ := anchorcrypto.GenerateEd25519KeyPair()
	agentPub, agentPriv, _ := anchorcrypto.GenerateEd25519KeyPair()
	issuerID, _ := anchorcrypto.DeriveIDFromPublicKey(issuerPub)
	agentID, _ := anchorcrypto.DeriveIDFromPublicKey(agentPub)
	issuedAt := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	cap := protocolgo.Capability{
		Version: protocolgo.Version, IssuerID: issuerID, IssuerKID: "k1",
		AgentID: agentID, Audience: "api:prod:svc", AllowedActions: []string{"svc:Do"},
		Constraints: protocolgo.ConstraintSet{
			ResourceLimits: map[string]int64{"x": 1}, SpendLimits: map[string]int64{"x": 1},
			APIScopes: []string{"api:svc"}, RateLimits: map[string]int64{"x": 1},
			EnvironmentConstraints: []string{"prod"},
		},
		Delegation: protocolgo.Delegation{MaxDepth: 1}, PolicyHash: "p",
		TransparencyRef: "t", IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(30 * time.Minute),
		Nonce: "n",
	}
	if err := protocolgo.SignCapability(&cap, issuerPriv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	action := protocolgo.ActionEnvelope{
		AgentID: agentID, CapabilityID: cap.CapabilityID, Audience: "api:prod:svc",
		ActionType: "svc:Do", ActionPayload: json.RawMessage(`{}`),
		ConstraintEvidence: protocolgo.ConstraintEvidence{
			ResourceUsage: map[string]int64{"x": 1}, SpendUsage: map[string]int64{"x": 1},
			RateUsage: map[string]int64{"x": 1}, Environment: "prod", APIScope: "api:svc",
		},
		Timestamp: issuedAt.Add(2 * time.Minute),
	}
	if err := protocolgo.SignAction(&action, agentPriv); err != nil {
		t.Fatalf("sign action: %v", err)
	}

	cache := protocolgo.NewInMemoryReplayCache()
	input := protocolgo.OfflineVerifyInput{
		Capability:      cap,
		Action:          action,
		IssuerPublicKey: issuerPub,
		AgentPublicKey:  agentPub,
		ReferenceTime:   action.Timestamp,
		ReplayCache:     cache,
	}

	first := protocolgo.OfflineVerify(input)
	if first.Decision != v2.DecisionAuthorized {
		t.Fatalf("first should authorize, got %s", first.Decision)
	}
	second := protocolgo.OfflineVerify(input)
	if second.Decision != v2.DecisionRejected {
		t.Fatalf("second should reject replay, got %s", second.Decision)
	}
}

func TestNewClientRejectsInvalidInputs(t *testing.T) {
	if _, err := protocolgo.NewClient("", http.DefaultClient); err == nil {
		t.Fatal("expected error for empty baseURL")
	}
	if _, err := protocolgo.NewClient("   ", http.DefaultClient); err == nil {
		t.Fatal("expected error for blank baseURL")
	}
	if _, err := protocolgo.NewClient("http://example.com", nil); err == nil {
		t.Fatal("expected error for nil httpClient")
	}
}

func TestNewClientTrimsTrailingSlash(t *testing.T) {
	client, err := protocolgo.NewClient("http://example.com/", http.DefaultClient)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestClientPostJSONSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("expected JSON content type")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	client, err := protocolgo.NewClient(server.URL, server.Client())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	body, err := client.PostJSON(context.Background(), "/verify", []byte(`{"test":1}`), http.StatusOK)
	if err != nil {
		t.Fatalf("post json: %v", err)
	}
	if string(body) != `{"ok":true}` {
		t.Fatalf("unexpected body: %s", string(body))
	}
}

func TestClientPostJSONRejectsUnexpectedStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer server.Close()

	client, _ := protocolgo.NewClient(server.URL, server.Client())
	_, err := client.PostJSON(context.Background(), "/verify", []byte(`{}`), http.StatusOK)
	if err == nil {
		t.Fatal("expected error for unexpected status code")
	}
}

func TestClientPostJSONHandlesConnectionError(t *testing.T) {
	client, _ := protocolgo.NewClient("http://127.0.0.1:1", http.DefaultClient)
	_, err := client.PostJSON(context.Background(), "/verify", []byte(`{}`), http.StatusOK)
	if err == nil {
		t.Fatal("expected error for connection refused")
	}
}

func TestSDKTrustBundleFallbackE2E(t *testing.T) {
	signerPub, signerPriv, _ := anchorcrypto.GenerateEd25519KeyPair()
	issuedAt := time.Date(2026, 2, 15, 10, 0, 0, 0, time.UTC)

	bundle := protocolgo.TrustBundle{
		BundleID:           "sdk-fb-bundle",
		IssuedAt:           issuedAt,
		ExpiresAt:          issuedAt.Add(1 * time.Hour),
		SignerPublicKeyKID: "signer-k",
		Issuers: []protocolgo.TrustBundleIssuer{{
			IssuerID:      "issuer-1",
			IssuerKID:     "k1",
			PublicKey:     anchorcrypto.PublicKeyToBase64(signerPub),
			ValidFrom:     issuedAt,
			ValidUntil:    issuedAt.Add(1 * time.Hour),
			AssuranceTier: "ORG_VERIFIED",
		}},
	}
	if err := protocolgo.SignTrustBundle(&bundle, signerPriv); err != nil {
		t.Fatalf("sign bundle: %v", err)
	}

	cache := protocolgo.NewInMemoryTrustBundleCache()
	fetcher := &fakeFetcher{bundle: bundle}

	resolved, usedFallback, err := protocolgo.ResolveTrustBundleWithFallback(fetcher, cache, signerPub, issuedAt.Add(5*time.Minute))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if usedFallback {
		t.Fatal("expected fetched bundle, not fallback")
	}
	if resolved.BundleID != "sdk-fb-bundle" {
		t.Fatalf("wrong bundle: %s", resolved.BundleID)
	}

	fetcher.err = errors.New("network down")
	resolved2, usedFallback2, err := protocolgo.ResolveTrustBundleWithFallback(fetcher, cache, signerPub, issuedAt.Add(10*time.Minute))
	if err != nil {
		t.Fatalf("resolve fallback: %v", err)
	}
	if !usedFallback2 {
		t.Fatal("expected fallback when fetch fails")
	}
	if resolved2.BundleID != "sdk-fb-bundle" {
		t.Fatalf("wrong fallback bundle: %s", resolved2.BundleID)
	}
}

func TestSDKWindowedReplayCacheE2E(t *testing.T) {
	cache := protocolgo.NewInMemoryWindowReplayCache()
	if replay := cache.MarkAndCheck("action-sdk-1"); replay {
		t.Fatal("first should not be replay")
	}
	if replay := cache.MarkAndCheck("action-sdk-1"); !replay {
		t.Fatal("second should be replay")
	}
}

type fakeFetcher struct {
	bundle protocolgo.TrustBundle
	err    error
}

func (f *fakeFetcher) FetchLatest() (protocolgo.TrustBundle, error) {
	if f.err != nil {
		return protocolgo.TrustBundle{}, f.err
	}
	return f.bundle, nil
}

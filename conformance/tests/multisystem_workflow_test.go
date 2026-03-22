package tests

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"

	anchorcrypto "github.com/GustyCube/anchor/core/crypto"
	"github.com/GustyCube/anchor/core/v2"
)

type signedContext struct {
	capability     v2.Capability
	action         v2.ActionEnvelope
	agentPublicKey ed25519.PublicKey
	keyResolver    v2.IssuerKeyResolver
	referenceTime  time.Time
}

func TestAdvancedWorkflow_AllSystemsAuthorized(t *testing.T) {
	issuedAt := time.Date(2026, 2, 13, 11, 0, 0, 0, time.UTC)

	awsCtx := buildSignedContext(t, signedContextInput{
		IssuedAt:        issuedAt,
		ExpiresAt:       issuedAt.Add(30 * time.Minute),
		ActionTime:      issuedAt.Add(1 * time.Minute),
		Audience:        "aws:prod:s3",
		ActionType:      "s3:PutObject",
		AllowedActions:  []string{"s3:PutObject"},
		APIScope:        "aws:s3",
		Environment:     "prod",
		ActionPayload:   `{"bucket":"release-artifacts","key":"v2.2.0/manifest.json","body":"ok","region":"us-east-1"}`,
		ResourceUsage:   map[string]int64{"s3:objects": 1},
		SpendUsage:      map[string]int64{"usd_cents": 12},
		RateUsage:       map[string]int64{"requests_per_minute": 1},
		ResourceLimits:  map[string]int64{"s3:objects": 2},
		SpendLimits:     map[string]int64{"usd_cents": 500},
		RateLimits:      map[string]int64{"requests_per_minute": 5},
		ChallengeNonce:  "challenge-aws",
		DelegationDepth: 0,
		DelegationMax:   1,
	})
	socialCtx := buildSignedContext(t, signedContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(30 * time.Minute),
		ActionTime:     issuedAt.Add(2 * time.Minute),
		Audience:       "social:prod:publish",
		ActionType:     "social:PublishPost",
		AllowedActions: []string{"social:PublishPost"},
		APIScope:       "social:publish",
		Environment:    "prod",
		ActionPayload:  `{"post_id":"post_2001","account_id":"gustycube-main","content":"release 2.2.0 live","visibility":"public"}`,
		ResourceUsage:  map[string]int64{"social:posts": 1},
		SpendUsage:     map[string]int64{"usd_cents": 1},
		RateUsage:      map[string]int64{"requests_per_minute": 1},
		ResourceLimits: map[string]int64{"social:posts": 2},
		SpendLimits:    map[string]int64{"usd_cents": 20},
		RateLimits:     map[string]int64{"requests_per_minute": 10},
		DelegationMax:  1,
	})
	bankCtx := buildSignedContext(t, signedContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(30 * time.Minute),
		ActionTime:     issuedAt.Add(3 * time.Minute),
		Audience:       "bank:prod:payments",
		ActionType:     "bank:TransferFunds",
		AllowedActions: []string{"bank:TransferFunds"},
		APIScope:       "bank:payments",
		Environment:    "prod",
		ActionPayload:  `{"transfer_id":"tr_2201","from_account":"ops","to_account":"vendor","amount_cents":4200,"currency":"USD"}`,
		ResourceUsage:  map[string]int64{"bank:transfers": 1},
		SpendUsage:     map[string]int64{"usd_cents": 4200},
		RateUsage:      map[string]int64{"requests_per_minute": 1},
		ResourceLimits: map[string]int64{"bank:transfers": 2},
		SpendLimits:    map[string]int64{"usd_cents": 5000},
		RateLimits:     map[string]int64{"requests_per_minute": 10},
		DelegationMax:  1,
	})
	supportCtx := buildSignedContext(t, signedContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(30 * time.Minute),
		ActionTime:     issuedAt.Add(4 * time.Minute),
		Audience:       "support:prod:tickets",
		ActionType:     "support:CreateTicket",
		AllowedActions: []string{"support:CreateTicket"},
		APIScope:       "support:tickets",
		Environment:    "prod",
		ActionPayload:  `{"ticket_id":"sup_2201","customer_id":"cust_100","subject":"Release issue","priority":"high"}`,
		ResourceUsage:  map[string]int64{"support:tickets": 1},
		SpendUsage:     map[string]int64{"usd_cents": 1},
		RateUsage:      map[string]int64{"requests_per_minute": 1},
		ResourceLimits: map[string]int64{"support:tickets": 5},
		SpendLimits:    map[string]int64{"usd_cents": 100},
		RateLimits:     map[string]int64{"requests_per_minute": 30},
		DelegationMax:  1,
	})
	payoutCtx := buildSignedContext(t, signedContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(30 * time.Minute),
		ActionTime:     issuedAt.Add(5 * time.Minute),
		Audience:       "payments:prod:payouts",
		ActionType:     "payments:CreatePayout",
		AllowedActions: []string{"payments:CreatePayout"},
		APIScope:       "payments:payouts",
		Environment:    "prod",
		ActionPayload:  `{"payout_id":"pay_2201","amount_cents":2600,"currency":"USD"}`,
		ResourceUsage:  map[string]int64{"payments:payouts": 1},
		SpendUsage:     map[string]int64{"usd_cents": 2600},
		RateUsage:      map[string]int64{"requests_per_minute": 1},
		ResourceLimits: map[string]int64{"payments:payouts": 2},
		SpendLimits:    map[string]int64{"usd_cents": 5000},
		RateLimits:     map[string]int64{"requests_per_minute": 5},
		ChallengeNonce: "challenge-payout",
		DelegationMax:  1,
	})

	aws := newFakeAWSService()
	social := newFakeSocialService()
	bank := newFakeBankService(map[string]int64{"ops": 100000, "vendor": 0})
	support := newFakeSupportService()
	payout := newFakePayoutService()

	if result := aws.Execute(awsCtx); result.Decision != v2.DecisionAuthorized {
		t.Fatalf("aws expected AUTHORIZED, got %s reasons=%v", result.Decision, result.Reasons)
	}
	if result := social.Execute(socialCtx); result.Decision != v2.DecisionAuthorized {
		t.Fatalf("social expected AUTHORIZED, got %s reasons=%v", result.Decision, result.Reasons)
	}
	if result := bank.Execute(bankCtx); result.Decision != v2.DecisionAuthorized {
		t.Fatalf("bank expected AUTHORIZED, got %s reasons=%v", result.Decision, result.Reasons)
	}
	if result := support.Execute(supportCtx); result.Decision != v2.DecisionAuthorized {
		t.Fatalf("support expected AUTHORIZED, got %s reasons=%v", result.Decision, result.Reasons)
	}
	if result := payout.Execute(payoutCtx); result.Decision != v2.DecisionAuthorized {
		t.Fatalf("payout expected AUTHORIZED, got %s reasons=%v", result.Decision, result.Reasons)
	}
}

func TestAdvancedWorkflow_IsolatedFailure(t *testing.T) {
	issuedAt := time.Date(2026, 2, 13, 12, 0, 0, 0, time.UTC)
	socialCtx := buildSignedContext(t, signedContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(20 * time.Minute),
		ActionTime:     issuedAt.Add(1 * time.Minute),
		Audience:       "social:prod:publish",
		ActionType:     "social:PublishPost",
		AllowedActions: []string{"social:PublishPost"},
		APIScope:       "social:publish",
		Environment:    "prod",
		ActionPayload:  `{"post_id":"post_bad","account_id":"gustycube-main","content":"this is a leak","visibility":"public"}`,
		ResourceUsage:  map[string]int64{"social:posts": 1},
		SpendUsage:     map[string]int64{"usd_cents": 1},
		RateUsage:      map[string]int64{"requests_per_minute": 1},
		ResourceLimits: map[string]int64{"social:posts": 2},
		SpendLimits:    map[string]int64{"usd_cents": 20},
		RateLimits:     map[string]int64{"requests_per_minute": 10},
	})
	bankCtx := buildSignedContext(t, signedContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(20 * time.Minute),
		ActionTime:     issuedAt.Add(2 * time.Minute),
		Audience:       "bank:prod:payments",
		ActionType:     "bank:TransferFunds",
		AllowedActions: []string{"bank:TransferFunds"},
		APIScope:       "bank:payments",
		Environment:    "prod",
		ActionPayload:  `{"transfer_id":"tr_ok","from_account":"ops","to_account":"vendor","amount_cents":1000,"currency":"USD"}`,
		ResourceUsage:  map[string]int64{"bank:transfers": 1},
		SpendUsage:     map[string]int64{"usd_cents": 1000},
		RateUsage:      map[string]int64{"requests_per_minute": 1},
		ResourceLimits: map[string]int64{"bank:transfers": 2},
		SpendLimits:    map[string]int64{"usd_cents": 5000},
		RateLimits:     map[string]int64{"requests_per_minute": 10},
	})

	social := newFakeSocialService()
	bank := newFakeBankService(map[string]int64{"ops": 100000, "vendor": 0})
	socialResult := social.Execute(socialCtx)
	bankResult := bank.Execute(bankCtx)
	if socialResult.Decision != v2.DecisionRejected {
		t.Fatalf("expected social rejected, got %s", socialResult.Decision)
	}
	if !containsReasonCode(socialResult.ReasonCodes, v2.ReasonCodePolicyHookRejected) {
		t.Fatalf("expected policy hook rejection code, got %v", socialResult.ReasonCodes)
	}
	if bankResult.Decision != v2.DecisionAuthorized {
		t.Fatalf("expected bank authorized, got %s reasons=%v", bankResult.Decision, bankResult.Reasons)
	}
}

func TestAdvancedWorkflow_CrossCapabilityMisuseRejected(t *testing.T) {
	issuedAt := time.Date(2026, 2, 13, 12, 30, 0, 0, time.UTC)
	bankCtx := buildSignedContext(t, signedContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(20 * time.Minute),
		ActionTime:     issuedAt.Add(1 * time.Minute),
		Audience:       "bank:prod:payments",
		ActionType:     "social:PublishPost",
		AllowedActions: []string{"bank:TransferFunds"},
		APIScope:       "bank:payments",
		Environment:    "prod",
		ActionPayload:  `{"post_id":"bad_cross","account_id":"gustycube-main","content":"should fail","visibility":"public"}`,
		ResourceUsage:  map[string]int64{"bank:transfers": 1},
		SpendUsage:     map[string]int64{"usd_cents": 100},
		RateUsage:      map[string]int64{"requests_per_minute": 1},
		ResourceLimits: map[string]int64{"bank:transfers": 2},
		SpendLimits:    map[string]int64{"usd_cents": 5000},
		RateLimits:     map[string]int64{"requests_per_minute": 10},
	})

	social := newFakeSocialService()
	result := social.Execute(bankCtx)
	if result.Decision != v2.DecisionRejected {
		t.Fatalf("expected REJECTED for cross capability misuse, got %s", result.Decision)
	}
	if !containsReasonCode(result.ReasonCodes, v2.ReasonCodeActionNotAllowed) {
		t.Fatalf("expected action-not-allowed reason code, got %v", result.ReasonCodes)
	}
}

func TestAdvancedWorkflow_ReplayAndPolicyRejections(t *testing.T) {
	issuedAt := time.Date(2026, 2, 13, 13, 30, 0, 0, time.UTC)
	awsCtx := buildSignedContext(t, signedContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(20 * time.Minute),
		ActionTime:     issuedAt.Add(1 * time.Minute),
		Audience:       "aws:prod:s3",
		ActionType:     "s3:PutObject",
		AllowedActions: []string{"s3:PutObject"},
		APIScope:       "aws:s3",
		Environment:    "prod",
		ActionPayload:  `{"bucket":"deployments","key":"release.txt","region":"us-east-1"}`,
		ResourceUsage:  map[string]int64{"s3:objects": 1},
		SpendUsage:     map[string]int64{"usd_cents": 10},
		RateUsage:      map[string]int64{"requests_per_minute": 1},
		ResourceLimits: map[string]int64{"s3:objects": 2},
		SpendLimits:    map[string]int64{"usd_cents": 100},
		RateLimits:     map[string]int64{"requests_per_minute": 5},
	})
	aws := newFakeAWSService()
	first := aws.Execute(awsCtx)
	if first.Decision != v2.DecisionAuthorized {
		t.Fatalf("expected first aws execution authorized, got %s reasons=%v", first.Decision, first.Reasons)
	}
	second := aws.Execute(awsCtx)
	if second.Decision != v2.DecisionRejected {
		t.Fatalf("expected replay rejection, got %s", second.Decision)
	}
	if !containsReasonCode(second.ReasonCodes, v2.ReasonCodeReplayDetected) {
		t.Fatalf("expected replay reason code, got %v", second.ReasonCodes)
	}

	socialCtx := buildSignedContext(t, signedContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(20 * time.Minute),
		ActionTime:     issuedAt.Add(2 * time.Minute),
		Audience:       "social:prod:publish",
		ActionType:     "social:PublishPost",
		AllowedActions: []string{"social:PublishPost"},
		APIScope:       "social:publish",
		Environment:    "prod",
		ActionPayload:  `{"post_id":"post_9","content":"leak customer token now"}`,
		ResourceUsage:  map[string]int64{"social:posts": 1},
		SpendUsage:     map[string]int64{"usd_cents": 1},
		RateUsage:      map[string]int64{"requests_per_minute": 1},
		ResourceLimits: map[string]int64{"social:posts": 3},
		SpendLimits:    map[string]int64{"usd_cents": 20},
		RateLimits:     map[string]int64{"requests_per_minute": 10},
	})
	social := newFakeSocialService()
	socialResult := social.Execute(socialCtx)
	if socialResult.Decision != v2.DecisionRejected {
		t.Fatalf("expected social moderation rejection, got %s", socialResult.Decision)
	}
	if !containsReasonCode(socialResult.ReasonCodes, v2.ReasonCodePolicyHookRejected) {
		t.Fatalf("expected policy-hook rejection code, got %v", socialResult.ReasonCodes)
	}

	bankCtx := buildSignedContext(t, signedContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(20 * time.Minute),
		ActionTime:     issuedAt.Add(3 * time.Minute),
		Audience:       "bank:prod:payments",
		ActionType:     "bank:TransferFunds",
		AllowedActions: []string{"bank:TransferFunds"},
		APIScope:       "bank:payments",
		Environment:    "prod",
		ActionPayload:  `{"from_account":"ops","to_account":"vendor","amount_cents":999999}`,
		ResourceUsage:  map[string]int64{"bank:transfers": 1},
		SpendUsage:     map[string]int64{"usd_cents": 999999},
		RateUsage:      map[string]int64{"requests_per_minute": 1},
		ResourceLimits: map[string]int64{"bank:transfers": 2},
		SpendLimits:    map[string]int64{"usd_cents": 1000000},
		RateLimits:     map[string]int64{"requests_per_minute": 10},
	})
	bank := newFakeBankService(map[string]int64{"ops": 5000, "vendor": 0})
	bankResult := bank.Execute(bankCtx)
	if bankResult.Decision != v2.DecisionRejected {
		t.Fatalf("expected insufficient funds rejection, got %s", bankResult.Decision)
	}
	if !containsReasonCode(bankResult.ReasonCodes, v2.ReasonCodePolicyHookRejected) {
		t.Fatalf("expected policy-hook rejection code for bank, got %v", bankResult.ReasonCodes)
	}
}

func TestAdvancedWorkflow_AdditionalSystemsHealthcareAndLogistics(t *testing.T) {
	issuedAt := time.Date(2026, 2, 13, 14, 0, 0, 0, time.UTC)
	healthcareCtx := buildSignedContext(t, signedContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(20 * time.Minute),
		ActionTime:     issuedAt.Add(1 * time.Minute),
		Audience:       "healthcare:prod:ehr",
		ActionType:     "healthcare:UpdateMedication",
		AllowedActions: []string{"healthcare:UpdateMedication"},
		APIScope:       "healthcare:ehr",
		Environment:    "prod",
		ActionPayload:  `{"patient_id":"pat_1","medication":"atorvastatin","dose_mg":20}`,
		ResourceUsage:  map[string]int64{"healthcare:ehr_updates": 1},
		SpendUsage:     map[string]int64{"usd_cents": 0},
		RateUsage:      map[string]int64{"requests_per_minute": 1},
		ResourceLimits: map[string]int64{"healthcare:ehr_updates": 3},
		SpendLimits:    map[string]int64{"usd_cents": 100},
		RateLimits:     map[string]int64{"requests_per_minute": 5},
	})
	logisticsCtx := buildSignedContext(t, signedContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(20 * time.Minute),
		ActionTime:     issuedAt.Add(2 * time.Minute),
		Audience:       "logistics:prod:shipments",
		ActionType:     "logistics:CreateShipment",
		AllowedActions: []string{"logistics:CreateShipment"},
		APIScope:       "logistics:shipments",
		Environment:    "prod",
		ActionPayload:  `{"shipment_id":"shp_1","destination_country":"KP","weight_kg":2}`,
		ResourceUsage:  map[string]int64{"logistics:shipments": 1},
		SpendUsage:     map[string]int64{"usd_cents": 2500},
		RateUsage:      map[string]int64{"requests_per_minute": 1},
		ResourceLimits: map[string]int64{"logistics:shipments": 2},
		SpendLimits:    map[string]int64{"usd_cents": 5000},
		RateLimits:     map[string]int64{"requests_per_minute": 8},
	})

	healthcare := newFakeHealthcareService()
	logistics := newFakeLogisticsService()

	healthResult := healthcare.Execute(healthcareCtx)
	if healthResult.Decision != v2.DecisionAuthorized {
		t.Fatalf("expected healthcare authorized, got %s reasons=%v", healthResult.Decision, healthResult.Reasons)
	}
	logisticsResult := logistics.Execute(logisticsCtx)
	if logisticsResult.Decision != v2.DecisionRejected {
		t.Fatalf("expected logistics rejection, got %s", logisticsResult.Decision)
	}
	if !containsReasonCode(logisticsResult.ReasonCodes, v2.ReasonCodePolicyHookRejected) {
		t.Fatalf("expected policy-hook rejection code for logistics, got %v", logisticsResult.ReasonCodes)
	}
}

func TestAdvancedWorkflow_PayoutRequiresChallenge(t *testing.T) {
	issuedAt := time.Date(2026, 2, 13, 15, 0, 0, 0, time.UTC)
	payoutCtx := buildSignedContext(t, signedContextInput{
		IssuedAt:       issuedAt,
		ExpiresAt:      issuedAt.Add(20 * time.Minute),
		ActionTime:     issuedAt.Add(1 * time.Minute),
		Audience:       "payments:prod:payouts",
		ActionType:     "payments:CreatePayout",
		AllowedActions: []string{"payments:CreatePayout"},
		APIScope:       "payments:payouts",
		Environment:    "prod",
		ActionPayload:  `{"payout_id":"pay_10","amount_cents":1900,"currency":"USD"}`,
		ResourceUsage:  map[string]int64{"payments:payouts": 1},
		SpendUsage:     map[string]int64{"usd_cents": 1900},
		RateUsage:      map[string]int64{"requests_per_minute": 1},
		ResourceLimits: map[string]int64{"payments:payouts": 2},
		SpendLimits:    map[string]int64{"usd_cents": 5000},
		RateLimits:     map[string]int64{"requests_per_minute": 5},
		ChallengeNonce: "",
	})
	payout := newFakePayoutService()
	result := payout.Execute(payoutCtx)
	if result.Decision != v2.DecisionRejected {
		t.Fatalf("expected payout rejection when challenge nonce missing, got %s", result.Decision)
	}
	if !containsReasonCode(result.ReasonCodes, v2.ReasonCodeChallengeRequired) {
		t.Fatalf("expected challenge required reason code, got %v", result.ReasonCodes)
	}
}

type signedContextInput struct {
	IssuedAt        time.Time
	ExpiresAt       time.Time
	ActionTime      time.Time
	Audience        string
	ActionType      string
	AllowedActions  []string
	APIScope        string
	Environment     string
	ActionPayload   string
	ResourceUsage   map[string]int64
	SpendUsage      map[string]int64
	RateUsage       map[string]int64
	ResourceLimits  map[string]int64
	SpendLimits     map[string]int64
	RateLimits      map[string]int64
	ChallengeNonce  string
	DelegationDepth int
	DelegationMax   int
}

func buildSignedContext(t *testing.T, input signedContextInput) signedContext {
	t.Helper()
	if input.DelegationMax == 0 {
		input.DelegationMax = 1
	}
	issuerPublicKey, issuerPrivateKey, err := anchorcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate issuer keypair: %v", err)
	}
	agentPublicKey, agentPrivateKey, err := anchorcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate agent keypair: %v", err)
	}
	issuerID, err := anchorcrypto.DeriveIDFromPublicKey(issuerPublicKey)
	if err != nil {
		t.Fatalf("derive issuer id: %v", err)
	}
	agentID, err := anchorcrypto.DeriveIDFromPublicKey(agentPublicKey)
	if err != nil {
		t.Fatalf("derive agent id: %v", err)
	}
	capability := v2.Capability{
		Version:        v2.Version,
		IssuerID:       issuerID,
		IssuerKID:      "k1",
		AgentID:        agentID,
		Audience:       input.Audience,
		AllowedActions: append([]string(nil), input.AllowedActions...),
		Constraints: v2.ConstraintSet{
			ResourceLimits:         cloneMap(input.ResourceLimits),
			SpendLimits:            cloneMap(input.SpendLimits),
			APIScopes:              []string{input.APIScope},
			RateLimits:             cloneMap(input.RateLimits),
			EnvironmentConstraints: []string{input.Environment},
		},
		Delegation:      v2.Delegation{Depth: input.DelegationDepth, MaxDepth: input.DelegationMax},
		PolicyHash:      "policy-hash-fixed",
		TransparencyRef: "tr-log://test-entry",
		IssuedAt:        input.IssuedAt,
		ExpiresAt:       input.ExpiresAt,
		Nonce:           "nonce-capability",
	}
	if err := v2.SignCapability(&capability, issuerPrivateKey); err != nil {
		t.Fatalf("sign capability: %v", err)
	}
	action := v2.ActionEnvelope{
		AgentID:       agentID,
		CapabilityID:  capability.CapabilityID,
		Audience:      input.Audience,
		ActionType:    input.ActionType,
		ActionPayload: json.RawMessage(input.ActionPayload),
		ConstraintEvidence: v2.ConstraintEvidence{
			ResourceUsage: cloneMap(input.ResourceUsage),
			SpendUsage:    cloneMap(input.SpendUsage),
			RateUsage:     cloneMap(input.RateUsage),
			Environment:   input.Environment,
			APIScope:      input.APIScope,
		},
		ChallengeNonce: input.ChallengeNonce,
		Timestamp:      input.ActionTime,
	}
	if err := v2.SignAction(&action, agentPrivateKey); err != nil {
		t.Fatalf("sign action: %v", err)
	}
	bundle := v2.TrustBundle{
		BundleID:           "bundle-1",
		IssuedAt:           input.IssuedAt,
		ExpiresAt:          input.ExpiresAt.Add(2 * time.Hour),
		SignerPublicKeyKID: "bundle-signer",
		Issuers: []v2.TrustBundleIssuer{{
			IssuerID:      issuerID,
			IssuerKID:     "k1",
			PublicKey:     anchorcrypto.PublicKeyToBase64(issuerPublicKey),
			ValidFrom:     input.IssuedAt.Add(-1 * time.Hour),
			ValidUntil:    input.ExpiresAt.Add(1 * time.Hour),
			AssuranceTier: "ORG_VERIFIED",
		}},
	}
	if err := v2.SignTrustBundle(&bundle, issuerPrivateKey); err != nil {
		t.Fatalf("sign trust bundle: %v", err)
	}
	return signedContext{
		capability:     capability,
		action:         action,
		agentPublicKey: agentPublicKey,
		keyResolver:    v2.TrustBundleKeyResolver{Bundle: bundle},
		referenceTime:  input.ActionTime,
	}
}

func cloneMap(input map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(input))
	for k, v := range input {
		out[k] = v
	}
	return out
}

func containsReasonCode(codes []v2.ReasonCode, target v2.ReasonCode) bool {
	for _, code := range codes {
		if code == target {
			return true
		}
	}
	return false
}

type fakeAWSService struct {
	engine      *v2.Engine
	replayCache v2.ReplayCache
}

func newFakeAWSService() *fakeAWSService {
	return &fakeAWSService{
		engine:      v2.NewEngine(),
		replayCache: v2.NewInMemoryReplayCache(),
	}
}

func (s *fakeAWSService) Execute(ctx signedContext) v2.VerificationResult {
	result := s.engine.Verify(v2.VerifyRequest{
		Capability:     ctx.capability,
		Action:         ctx.action,
		AgentPublicKey: ctx.agentPublicKey,
		ReferenceTime:  ctx.referenceTime,
		KeyResolver:    ctx.keyResolver,
		ReplayCache:    s.replayCache,
	})
	if result.Decision != v2.DecisionAuthorized {
		return result
	}
	var payload struct {
		Region string `json:"region"`
	}
	_ = json.Unmarshal(ctx.action.ActionPayload, &payload)
	if payload.Region != "us-east-1" && payload.Region != "us-west-2" {
		result.Decision = v2.DecisionRejected
		result.ReasonCodes = append(result.ReasonCodes, v2.ReasonCodePolicyHookRejected)
		result.Reasons = append(result.Reasons, "unsupported aws region")
	}
	return result
}

type fakeSocialService struct {
	engine *v2.Engine
}

func newFakeSocialService() *fakeSocialService { return &fakeSocialService{engine: v2.NewEngine()} }

func (s *fakeSocialService) Execute(ctx signedContext) v2.VerificationResult {
	result := s.engine.Verify(v2.VerifyRequest{
		Capability:     ctx.capability,
		Action:         ctx.action,
		AgentPublicKey: ctx.agentPublicKey,
		ReferenceTime:  ctx.referenceTime,
		KeyResolver:    ctx.keyResolver,
		PolicyEvaluator: v2.FuncPolicyEvaluator(func(_ v2.Capability, action v2.ActionEnvelope) ([]v2.ReasonCode, []string) {
			if strings.Contains(strings.ToLower(string(action.ActionPayload)), "leak") {
				return []v2.ReasonCode{v2.ReasonCodePolicyHookRejected}, []string{"content failed moderation"}
			}
			return nil, nil
		}),
	})
	return result
}

type fakeBankService struct {
	engine   *v2.Engine
	balances map[string]int64
}

func newFakeBankService(balances map[string]int64) *fakeBankService {
	copyBalances := make(map[string]int64, len(balances))
	for k, v := range balances {
		copyBalances[k] = v
	}
	return &fakeBankService{engine: v2.NewEngine(), balances: copyBalances}
}

func (s *fakeBankService) Execute(ctx signedContext) v2.VerificationResult {
	result := s.engine.Verify(v2.VerifyRequest{
		Capability:     ctx.capability,
		Action:         ctx.action,
		AgentPublicKey: ctx.agentPublicKey,
		ReferenceTime:  ctx.referenceTime,
		KeyResolver:    ctx.keyResolver,
	})
	if result.Decision != v2.DecisionAuthorized {
		return result
	}
	var payload struct {
		FromAccount string `json:"from_account"`
		ToAccount   string `json:"to_account"`
		AmountCents int64  `json:"amount_cents"`
	}
	_ = json.Unmarshal(ctx.action.ActionPayload, &payload)
	if s.balances[payload.FromAccount] < payload.AmountCents {
		result.Decision = v2.DecisionRejected
		result.ReasonCodes = append(result.ReasonCodes, v2.ReasonCodePolicyHookRejected)
		result.Reasons = append(result.Reasons, "insufficient funds")
		return result
	}
	s.balances[payload.FromAccount] -= payload.AmountCents
	s.balances[payload.ToAccount] += payload.AmountCents
	return result
}

type fakeSupportService struct {
	engine *v2.Engine
}

func newFakeSupportService() *fakeSupportService { return &fakeSupportService{engine: v2.NewEngine()} }

func (s *fakeSupportService) Execute(ctx signedContext) v2.VerificationResult {
	result := s.engine.Verify(v2.VerifyRequest{
		Capability:     ctx.capability,
		Action:         ctx.action,
		AgentPublicKey: ctx.agentPublicKey,
		ReferenceTime:  ctx.referenceTime,
		KeyResolver:    ctx.keyResolver,
	})
	return result
}

type fakePayoutService struct {
	engine *v2.Engine
}

func newFakePayoutService() *fakePayoutService { return &fakePayoutService{engine: v2.NewEngine()} }

func (s *fakePayoutService) Execute(ctx signedContext) v2.VerificationResult {
	result := s.engine.Verify(v2.VerifyRequest{
		Capability:     ctx.capability,
		Action:         ctx.action,
		AgentPublicKey: ctx.agentPublicKey,
		ReferenceTime:  ctx.referenceTime,
		KeyResolver:    ctx.keyResolver,
		ChallengePolicy: v2.StaticChallengePolicy{Required: map[string]struct{}{
			"payments:CreatePayout": {},
		}},
	})
	return result
}

type fakeHealthcareService struct {
	engine *v2.Engine
}

func newFakeHealthcareService() *fakeHealthcareService {
	return &fakeHealthcareService{engine: v2.NewEngine()}
}

func (s *fakeHealthcareService) Execute(ctx signedContext) v2.VerificationResult {
	result := s.engine.Verify(v2.VerifyRequest{
		Capability:     ctx.capability,
		Action:         ctx.action,
		AgentPublicKey: ctx.agentPublicKey,
		ReferenceTime:  ctx.referenceTime,
		KeyResolver:    ctx.keyResolver,
	})
	if result.Decision != v2.DecisionAuthorized {
		return result
	}
	var payload struct {
		Medication string `json:"medication"`
	}
	_ = json.Unmarshal(ctx.action.ActionPayload, &payload)
	if strings.EqualFold(payload.Medication, "UNAPPROVED_TRIAL_DRUG") {
		result.Decision = v2.DecisionRejected
		result.ReasonCodes = append(result.ReasonCodes, v2.ReasonCodePolicyHookRejected)
		result.Reasons = append(result.Reasons, "medication not approved by policy")
	}
	return result
}

type fakeLogisticsService struct {
	engine *v2.Engine
}

func newFakeLogisticsService() *fakeLogisticsService {
	return &fakeLogisticsService{engine: v2.NewEngine()}
}

func (s *fakeLogisticsService) Execute(ctx signedContext) v2.VerificationResult {
	result := s.engine.Verify(v2.VerifyRequest{
		Capability:     ctx.capability,
		Action:         ctx.action,
		AgentPublicKey: ctx.agentPublicKey,
		ReferenceTime:  ctx.referenceTime,
		KeyResolver:    ctx.keyResolver,
	})
	if result.Decision != v2.DecisionAuthorized {
		return result
	}
	var payload struct {
		DestinationCountry string `json:"destination_country"`
	}
	_ = json.Unmarshal(ctx.action.ActionPayload, &payload)
	switch strings.ToUpper(payload.DestinationCountry) {
	case "KP", "IR", "SY":
		result.Decision = v2.DecisionRejected
		result.ReasonCodes = append(result.ReasonCodes, v2.ReasonCodePolicyHookRejected)
		result.Reasons = append(result.Reasons, "destination blocked by sanctions policy")
	}
	return result
}

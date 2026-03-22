package protocolgo

import (
	"crypto/ed25519"
	"time"

	"github.com/GustyCube/anchor/core/v2"
)

// Version indicates the current protocol major version implemented by this SDK.
const Version = v2.Version

// Core protocol types exposed without version suffixes for SDK ergonomics.
type (
	Capability         = v2.Capability
	ActionEnvelope     = v2.ActionEnvelope
	VerificationResult = v2.VerificationResult
	TrustBundle        = v2.TrustBundle
	TrustBundleIssuer  = v2.TrustBundleIssuer
	Delegation         = v2.Delegation
	ConstraintSet      = v2.ConstraintSet
	ConstraintEvidence = v2.ConstraintEvidence
	VerifyRequest      = v2.VerifyRequest
)

// Verifier extension interfaces.
type (
	RevocationChecker    = v2.RevocationChecker
	IssuerKeyResolver    = v2.IssuerKeyResolver
	ChallengePolicy      = v2.ChallengePolicy
	PolicyEvaluator      = v2.PolicyEvaluator
	TransparencyVerifier = v2.TransparencyVerifier
	ReplayCache          = v2.ReplayCache
	WindowedReplayCache  = v2.WindowedReplayCache
)

// Engine and reusable policy/cache helpers.
type (
	Engine                    = v2.Engine
	StaticRevocationList      = v2.StaticRevocationList
	StaticChallengePolicy     = v2.StaticChallengePolicy
	FuncPolicyEvaluator       = v2.FuncPolicyEvaluator
	FuncTransparencyVerifier  = v2.FuncTransparencyVerifier
	TrustBundleKeyResolver    = v2.TrustBundleKeyResolver
	InMemoryReplayCache       = v2.InMemoryReplayCache
	InMemoryWindowReplayCache = v2.InMemoryWindowReplayCache
	InMemoryTrustBundleCache  = v2.InMemoryTrustBundleCache
)

// Decision/reason enums.
type (
	VerificationDecision = v2.VerificationDecision
	ReasonCode           = v2.ReasonCode
	ReplayStatus         = v2.ReplayStatus
)

const (
	DecisionAuthorized = v2.DecisionAuthorized
	DecisionRejected   = v2.DecisionRejected

	ReplayStatusUnknown = v2.ReplayStatusUnknown
	ReplayStatusFresh   = v2.ReplayStatusFresh
	ReplayStatusReplay  = v2.ReplayStatusReplay
)

// Constructors/helpers.
func NewEngine() *Engine { return v2.NewEngine() }

func NewInMemoryReplayCache() *InMemoryReplayCache {
	return v2.NewInMemoryReplayCache()
}

func NewInMemoryWindowReplayCache() *InMemoryWindowReplayCache {
	return v2.NewInMemoryWindowReplayCache()
}

func NewInMemoryTrustBundleCache() *InMemoryTrustBundleCache {
	return v2.NewInMemoryTrustBundleCache()
}

func SignCapability(cap *Capability, issuerPrivateKey ed25519.PrivateKey) error {
	return v2.SignCapability(cap, issuerPrivateKey)
}

func VerifyCapabilitySignature(cap Capability, issuerPublicKey ed25519.PublicKey) (bool, error) {
	return v2.VerifyCapabilitySignature(cap, issuerPublicKey)
}

func SignAction(action *ActionEnvelope, agentPrivateKey ed25519.PrivateKey) error {
	return v2.SignAction(action, agentPrivateKey)
}

func VerifyActionSignature(action ActionEnvelope, agentPublicKey ed25519.PublicKey) (bool, error) {
	return v2.VerifyActionSignature(action, agentPublicKey)
}

func SignTrustBundle(bundle *TrustBundle, signerPrivateKey ed25519.PrivateKey) error {
	return v2.SignTrustBundle(bundle, signerPrivateKey)
}

func VerifyTrustBundleSignature(bundle TrustBundle, signerPublicKey ed25519.PublicKey) (bool, error) {
	return v2.VerifyTrustBundleSignature(bundle, signerPublicKey)
}

func ValidateTrustBundleAt(bundle TrustBundle, signerPublicKey ed25519.PublicKey, at time.Time) error {
	return v2.ValidateTrustBundleAt(bundle, signerPublicKey, at)
}

func ResolveTrustBundleWithFallback(fetcher v2.TrustBundleFetcher, cache v2.TrustBundleCache, signerPublicKey ed25519.PublicKey, at time.Time) (TrustBundle, bool, error) {
	return v2.ResolveTrustBundleWithFallback(fetcher, cache, signerPublicKey, at)
}

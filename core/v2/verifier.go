package v2

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sort"
	"time"

	anchorcrypto "github.com/GustyCube/anchor/core/crypto"
)

type RevocationChecker interface {
	IsRevoked(capabilityID string) bool
}

type StaticRevocationList struct {
	Revoked map[string]struct{}
}

func (s StaticRevocationList) IsRevoked(capabilityID string) bool {
	if s.Revoked == nil {
		return false
	}
	_, ok := s.Revoked[capabilityID]
	return ok
}

type IssuerKeyResolver interface {
	Resolve(issuerID, issuerKID string, at time.Time) (ed25519.PublicKey, bool, error)
}

type ChallengePolicy interface {
	RequiresChallenge(actionType string) bool
}

type StaticChallengePolicy struct {
	Required map[string]struct{}
}

func (p StaticChallengePolicy) RequiresChallenge(actionType string) bool {
	if p.Required == nil {
		return false
	}
	_, ok := p.Required[actionType]
	return ok
}

type VerifyRequest struct {
	Capability         Capability
	Action             ActionEnvelope
	AgentPublicKey     ed25519.PublicKey
	ReferenceTime      time.Time
	ExpectedAudience   string
	ExpectedPolicyHash string
	RevocationList     RevocationChecker
	ReplayCache        ReplayCache
	ReplayWindow       time.Duration
	ChallengePolicy    ChallengePolicy
	PolicyEvaluator    PolicyEvaluator
	Transparency       TransparencyVerifier
	IssuerPublicKey    ed25519.PublicKey // optional direct key
	KeyResolver        IssuerKeyResolver // optional resolver, preferred for local bundle verify
}

type Engine struct{}

func NewEngine() *Engine {
	return &Engine{}
}

func (e *Engine) Verify(req VerifyRequest) VerificationResult {
	result := VerificationResult{Decision: DecisionAuthorized, ReplayStatus: ReplayStatusUnknown}
	addReason := func(code ReasonCode, reason string) {
		result.Decision = DecisionRejected
		result.ReasonCodes = append(result.ReasonCodes, code)
		result.Reasons = append(result.Reasons, reason)
	}

	if req.ReferenceTime.IsZero() {
		addReason(ReasonCodeReferenceTimeMissing, "reference_time is required")
		return result
	}
	result.PolicyHashSeen = req.Capability.PolicyHash

	issuerPub, issuerResolved, resolverErr := e.resolveIssuerKey(req)
	if resolverErr != nil {
		switch {
		case errors.Is(resolverErr, ErrTrustBundleExpired):
			addReason(ReasonCodeTrustBundleExpired, "trust bundle expired for reference_time")
		case errors.Is(resolverErr, ErrTrustBundleSignatureInvalid):
			addReason(ReasonCodeTrustBundleSignatureInvalid, "trust bundle signature invalid")
		case errors.Is(resolverErr, ErrIssuerKeyOutOfWindow):
			addReason(ReasonCodeIssuerKeyOutOfWindow, "issuer key is outside validity window")
		default:
			addReason(ReasonCodeIssuerKeyMissing, fmt.Sprintf("issuer key resolution failed: %v", resolverErr))
		}
		return result
	}
	if !issuerResolved {
		addReason(ReasonCodeIssuerKeyMissing, "issuer key not found for issuer_id+issuer_kid")
		return result
	}

	if len(req.IssuerPublicKey) > 0 {
		derivedIssuerID, err := anchorcrypto.DeriveIDFromPublicKey(issuerPub)
		if err != nil {
			addReason(ReasonCodeCapabilityInvalid, fmt.Sprintf("invalid issuer public key: %v", err))
		} else if derivedIssuerID != req.Capability.IssuerID {
			addReason(ReasonCodeIssuerMismatch, "issuer_id does not match issuer public key")
		}
	}

	capSigValid, capErr := VerifyCapabilitySignature(req.Capability, issuerPub)
	if capErr != nil {
		addReason(ReasonCodeCapabilityInvalid, fmt.Sprintf("capability validation failed: %v", capErr))
	} else if !capSigValid {
		addReason(ReasonCodeCapabilitySignatureInvalid, "capability signature invalid")
	}

	ref := req.ReferenceTime.UTC()
	if ref.Before(req.Capability.IssuedAt.UTC()) {
		addReason(ReasonCodeCapabilityNotYetValid, "capability is not valid yet")
	}
	if ref.After(req.Capability.ExpiresAt.UTC()) {
		addReason(ReasonCodeCapabilityExpired, "capability is expired")
	}
	if req.RevocationList != nil && req.RevocationList.IsRevoked(req.Capability.CapabilityID) {
		addReason(ReasonCodeCapabilityRevoked, "capability is revoked")
	}

	agentID, agentErr := anchorcrypto.DeriveIDFromPublicKey(req.AgentPublicKey)
	if agentErr != nil {
		addReason(ReasonCodeActionInvalid, fmt.Sprintf("invalid agent public key: %v", agentErr))
	} else {
		if req.Capability.AgentID != agentID {
			addReason(ReasonCodeAgentMismatch, "capability agent_id does not match agent public key")
		}
		if req.Action.AgentID != agentID {
			addReason(ReasonCodeAgentMismatch, "action agent_id does not match agent public key")
		}
	}

	actionSigValid, actionErr := VerifyActionSignature(req.Action, req.AgentPublicKey)
	if actionErr != nil {
		addReason(ReasonCodeActionInvalid, fmt.Sprintf("action validation failed: %v", actionErr))
	} else if !actionSigValid {
		addReason(ReasonCodeActionSignatureInvalid, "action signature invalid")
	}

	if req.Action.CapabilityID != req.Capability.CapabilityID {
		addReason(ReasonCodeCapabilityBindingMismatch, "action capability_id does not match capability")
	}
	if req.Action.Audience != req.Capability.Audience {
		addReason(ReasonCodeAudienceMismatch, "action audience does not match capability audience")
	}
	if req.ExpectedAudience != "" && req.Action.Audience != req.ExpectedAudience {
		addReason(ReasonCodeAudienceMismatch, "action audience does not match expected audience")
	}
	if req.ExpectedPolicyHash != "" && req.Capability.PolicyHash != req.ExpectedPolicyHash {
		addReason(ReasonCodePolicyHashMismatch, "capability policy_hash does not match expected policy_hash")
	}
	if req.Transparency != nil && req.Capability.TransparencyRef != "" {
		if err := req.Transparency.Verify(req.Capability.TransparencyRef, req.Capability.CapabilityID); err != nil {
			addReason(ReasonCodeTransparencyInvalid, fmt.Sprintf("transparency linkage verification failed: %v", err))
		}
	}
	if req.Capability.Delegation.Depth > req.Capability.Delegation.MaxDepth {
		addReason(ReasonCodeDelegationDepthExceeded, "delegation depth exceeds max_depth")
	}
	if !contains(req.Capability.AllowedActions, req.Action.ActionType) {
		addReason(ReasonCodeActionNotAllowed, "action_type not allowed by capability")
	}

	for _, constraintReason := range verifyConstraints(req.Capability.Constraints, req.Action.ConstraintEvidence) {
		addReason(ReasonCodeConstraintViolation, constraintReason)
	}

	if req.ChallengePolicy != nil && req.ChallengePolicy.RequiresChallenge(req.Action.ActionType) && req.Action.ChallengeNonce == "" {
		addReason(ReasonCodeChallengeRequired, "challenge_nonce required for high-risk action")
	}
	if req.PolicyEvaluator != nil {
		policyCodes, policyReasons := normalizePolicyResults(req.PolicyEvaluator.Evaluate(req.Capability, req.Action))
		for i := range policyCodes {
			addReason(policyCodes[i], policyReasons[i])
		}
	}

	if req.ReplayCache != nil {
		replayDetected := false
		if windowed, ok := req.ReplayCache.(WindowedReplayCache); ok {
			window := req.ReplayWindow
			if window <= 0 {
				window = 5 * time.Minute
			}
			replayDetected = windowed.MarkAndCheckWithinWindow(req.Action.ActionID, req.Action.Timestamp, req.ReferenceTime, window)
		} else {
			replayDetected = req.ReplayCache.MarkAndCheck(req.Action.ActionID)
		}
		if replayDetected {
			result.ReplayStatus = ReplayStatusReplay
			addReason(ReasonCodeReplayDetected, "replay detected for action_id")
		} else {
			result.ReplayStatus = ReplayStatusFresh
		}
	}

	return result
}

func (e *Engine) resolveIssuerKey(req VerifyRequest) (ed25519.PublicKey, bool, error) {
	if len(req.IssuerPublicKey) > 0 {
		return req.IssuerPublicKey, true, nil
	}
	if req.KeyResolver == nil {
		return nil, false, nil
	}
	return req.KeyResolver.Resolve(req.Capability.IssuerID, req.Capability.IssuerKID, req.ReferenceTime)
}

func verifyConstraints(constraints ConstraintSet, evidence ConstraintEvidence) []string {
	reasons := []string{}
	if len(constraints.APIScopes) > 0 && !contains(constraints.APIScopes, evidence.APIScope) {
		reasons = append(reasons, "api_scope is not allowed by capability constraints")
	}
	if len(constraints.EnvironmentConstraints) > 0 && !contains(constraints.EnvironmentConstraints, evidence.Environment) {
		reasons = append(reasons, "environment is not allowed by capability constraints")
	}
	for _, key := range sortedKeys(evidence.ResourceUsage) {
		limit, ok := constraints.ResourceLimits[key]
		if !ok {
			reasons = append(reasons, fmt.Sprintf("resource usage for %s is not permitted", key))
			continue
		}
		if evidence.ResourceUsage[key] > limit {
			reasons = append(reasons, fmt.Sprintf("resource usage for %s exceeds limit", key))
		}
	}
	for _, key := range sortedKeys(evidence.SpendUsage) {
		limit, ok := constraints.SpendLimits[key]
		if !ok {
			reasons = append(reasons, fmt.Sprintf("spend usage for %s is not permitted", key))
			continue
		}
		if evidence.SpendUsage[key] > limit {
			reasons = append(reasons, fmt.Sprintf("spend usage for %s exceeds limit", key))
		}
	}
	for _, key := range sortedKeys(evidence.RateUsage) {
		limit, ok := constraints.RateLimits[key]
		if !ok {
			reasons = append(reasons, fmt.Sprintf("rate usage for %s is not permitted", key))
			continue
		}
		if evidence.RateUsage[key] > limit {
			reasons = append(reasons, fmt.Sprintf("rate usage for %s exceeds limit", key))
		}
	}
	return reasons
}

func contains(values []string, needle string) bool {
	for _, v := range values {
		if v == needle {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]int64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

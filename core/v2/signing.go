package v2

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/GustyCube/anchor/core/canonical"
	anchorcrypto "github.com/GustyCube/anchor/core/crypto"
)

const timestampFormat = "2006-01-02T15:04:05.000000000Z07:00"

type capabilityIDPayload struct {
	Version         int           `json:"version"`
	IssuerID        string        `json:"issuer_id"`
	IssuerKID       string        `json:"issuer_kid"`
	AgentID         string        `json:"agent_id"`
	Audience        string        `json:"audience"`
	AllowedActions  []string      `json:"allowed_actions"`
	Constraints     ConstraintSet `json:"constraints"`
	Delegation      Delegation    `json:"delegation"`
	PolicyHash      string        `json:"policy_hash"`
	TransparencyRef string        `json:"transparency_ref"`
	IssuedAt        string        `json:"issued_at"`
	ExpiresAt       string        `json:"expires_at"`
	Nonce           string        `json:"nonce"`
}

type capabilitySignaturePayload struct {
	Version         int           `json:"version"`
	CapabilityID    string        `json:"capability_id"`
	IssuerID        string        `json:"issuer_id"`
	IssuerKID       string        `json:"issuer_kid"`
	AgentID         string        `json:"agent_id"`
	Audience        string        `json:"audience"`
	AllowedActions  []string      `json:"allowed_actions"`
	Constraints     ConstraintSet `json:"constraints"`
	Delegation      Delegation    `json:"delegation"`
	PolicyHash      string        `json:"policy_hash"`
	TransparencyRef string        `json:"transparency_ref"`
	IssuedAt        string        `json:"issued_at"`
	ExpiresAt       string        `json:"expires_at"`
	Nonce           string        `json:"nonce"`
}

type actionIDPayload struct {
	AgentID            string             `json:"agent_id"`
	CapabilityID       string             `json:"capability_id"`
	Audience           string             `json:"audience"`
	ActionType         string             `json:"action_type"`
	ActionPayload      []byte             `json:"action_payload"`
	ConstraintEvidence ConstraintEvidence `json:"constraint_evidence"`
	ChallengeNonce     string             `json:"challenge_nonce,omitempty"`
	Timestamp          string             `json:"timestamp"`
}

type actionSignaturePayload struct {
	ActionID           string             `json:"action_id"`
	AgentID            string             `json:"agent_id"`
	CapabilityID       string             `json:"capability_id"`
	Audience           string             `json:"audience"`
	ActionType         string             `json:"action_type"`
	ActionPayload      []byte             `json:"action_payload"`
	ConstraintEvidence ConstraintEvidence `json:"constraint_evidence"`
	ChallengeNonce     string             `json:"challenge_nonce,omitempty"`
	Timestamp          string             `json:"timestamp"`
}

func normalizeCapability(cap Capability) Capability {
	allowedActions := append([]string(nil), cap.AllowedActions...)
	sort.Strings(allowedActions)
	cap.AllowedActions = allowedActions
	return cap
}

func ComputeCapabilityID(cap Capability) (string, error) {
	cap = normalizeCapability(cap)
	if err := cap.ValidateUnsigned(); err != nil {
		return "", err
	}
	payload := capabilityIDPayload{
		Version:         cap.Version,
		IssuerID:        cap.IssuerID,
		IssuerKID:       cap.IssuerKID,
		AgentID:         cap.AgentID,
		Audience:        cap.Audience,
		AllowedActions:  cap.AllowedActions,
		Constraints:     cap.Constraints,
		Delegation:      cap.Delegation,
		PolicyHash:      cap.PolicyHash,
		TransparencyRef: cap.TransparencyRef,
		IssuedAt:        cap.IssuedAt.UTC().Format(timestampFormat),
		ExpiresAt:       cap.ExpiresAt.UTC().Format(timestampFormat),
		Nonce:           cap.Nonce,
	}
	data, err := canonical.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("canonical capability id payload: %w", err)
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

func SignCapability(cap *Capability, issuerPrivateKey ed25519.PrivateKey) error {
	if cap == nil {
		return fmt.Errorf("capability is required")
	}
	normalized := normalizeCapability(*cap)
	capID, err := ComputeCapabilityID(normalized)
	if err != nil {
		return err
	}
	normalized.CapabilityID = capID
	payload := capabilitySignaturePayload{
		Version:         normalized.Version,
		CapabilityID:    normalized.CapabilityID,
		IssuerID:        normalized.IssuerID,
		IssuerKID:       normalized.IssuerKID,
		AgentID:         normalized.AgentID,
		Audience:        normalized.Audience,
		AllowedActions:  normalized.AllowedActions,
		Constraints:     normalized.Constraints,
		Delegation:      normalized.Delegation,
		PolicyHash:      normalized.PolicyHash,
		TransparencyRef: normalized.TransparencyRef,
		IssuedAt:        normalized.IssuedAt.UTC().Format(timestampFormat),
		ExpiresAt:       normalized.ExpiresAt.UTC().Format(timestampFormat),
		Nonce:           normalized.Nonce,
	}
	data, err := canonical.Marshal(payload)
	if err != nil {
		return fmt.Errorf("canonical capability signature payload: %w", err)
	}
	sig, err := anchorcrypto.SignBytes(issuerPrivateKey, data)
	if err != nil {
		return err
	}
	normalized.Signature = sig
	*cap = normalized
	return nil
}

func VerifyCapabilitySignature(cap Capability, issuerPublicKey ed25519.PublicKey) (bool, error) {
	if cap.Signature == "" {
		return false, fmt.Errorf("capability signature is required")
	}
	normalized := normalizeCapability(cap)
	if err := normalized.ValidateUnsigned(); err != nil {
		return false, err
	}
	recomputedID, err := ComputeCapabilityID(normalized)
	if err != nil {
		return false, err
	}
	if normalized.CapabilityID == "" || normalized.CapabilityID != recomputedID {
		return false, nil
	}
	payload := capabilitySignaturePayload{
		Version:         normalized.Version,
		CapabilityID:    normalized.CapabilityID,
		IssuerID:        normalized.IssuerID,
		IssuerKID:       normalized.IssuerKID,
		AgentID:         normalized.AgentID,
		Audience:        normalized.Audience,
		AllowedActions:  normalized.AllowedActions,
		Constraints:     normalized.Constraints,
		Delegation:      normalized.Delegation,
		PolicyHash:      normalized.PolicyHash,
		TransparencyRef: normalized.TransparencyRef,
		IssuedAt:        normalized.IssuedAt.UTC().Format(timestampFormat),
		ExpiresAt:       normalized.ExpiresAt.UTC().Format(timestampFormat),
		Nonce:           normalized.Nonce,
	}
	data, err := canonical.Marshal(payload)
	if err != nil {
		return false, fmt.Errorf("canonical capability verify payload: %w", err)
	}
	return anchorcrypto.VerifySignature(issuerPublicKey, data, normalized.Signature)
}

func normalizeActionPayload(payload []byte) ([]byte, error) {
	return canonical.MarshalRawJSON(payload)
}

func ComputeActionID(action ActionEnvelope) (string, error) {
	if err := action.ValidateUnsigned(); err != nil {
		return "", err
	}
	canonicalPayload, err := normalizeActionPayload(action.ActionPayload)
	if err != nil {
		return "", fmt.Errorf("canonical action payload: %w", err)
	}
	payload := actionIDPayload{
		AgentID:            action.AgentID,
		CapabilityID:       action.CapabilityID,
		Audience:           action.Audience,
		ActionType:         action.ActionType,
		ActionPayload:      canonicalPayload,
		ConstraintEvidence: action.ConstraintEvidence,
		ChallengeNonce:     action.ChallengeNonce,
		Timestamp:          action.Timestamp.UTC().Format(timestampFormat),
	}
	data, err := canonical.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("canonical action id payload: %w", err)
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

func SignAction(action *ActionEnvelope, agentPrivateKey ed25519.PrivateKey) error {
	if action == nil {
		return fmt.Errorf("action is required")
	}
	if err := action.ValidateUnsigned(); err != nil {
		return err
	}
	canonicalPayload, err := normalizeActionPayload(action.ActionPayload)
	if err != nil {
		return err
	}
	action.ActionPayload = canonicalPayload
	actionID, err := ComputeActionID(*action)
	if err != nil {
		return err
	}
	action.ActionID = actionID
	payload := actionSignaturePayload{
		ActionID:           action.ActionID,
		AgentID:            action.AgentID,
		CapabilityID:       action.CapabilityID,
		Audience:           action.Audience,
		ActionType:         action.ActionType,
		ActionPayload:      action.ActionPayload,
		ConstraintEvidence: action.ConstraintEvidence,
		ChallengeNonce:     action.ChallengeNonce,
		Timestamp:          action.Timestamp.UTC().Format(timestampFormat),
	}
	data, err := canonical.Marshal(payload)
	if err != nil {
		return fmt.Errorf("canonical action signature payload: %w", err)
	}
	sig, err := anchorcrypto.SignBytes(agentPrivateKey, data)
	if err != nil {
		return err
	}
	action.AgentSignature = sig
	return nil
}

func VerifyActionSignature(action ActionEnvelope, agentPublicKey ed25519.PublicKey) (bool, error) {
	if action.AgentSignature == "" {
		return false, fmt.Errorf("agent signature is required")
	}
	if err := action.ValidateUnsigned(); err != nil {
		return false, err
	}
	canonicalPayload, err := normalizeActionPayload(action.ActionPayload)
	if err != nil {
		return false, err
	}
	action.ActionPayload = canonicalPayload
	recomputedID, err := ComputeActionID(action)
	if err != nil {
		return false, err
	}
	if action.ActionID == "" || action.ActionID != recomputedID {
		return false, nil
	}
	payload := actionSignaturePayload{
		ActionID:           action.ActionID,
		AgentID:            action.AgentID,
		CapabilityID:       action.CapabilityID,
		Audience:           action.Audience,
		ActionType:         action.ActionType,
		ActionPayload:      action.ActionPayload,
		ConstraintEvidence: action.ConstraintEvidence,
		ChallengeNonce:     action.ChallengeNonce,
		Timestamp:          action.Timestamp.UTC().Format(timestampFormat),
	}
	data, err := canonical.Marshal(payload)
	if err != nil {
		return false, fmt.Errorf("canonical action verify payload: %w", err)
	}
	return anchorcrypto.VerifySignature(agentPublicKey, data, action.AgentSignature)
}

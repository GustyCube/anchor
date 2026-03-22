package v2

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/GustyCube/anchor/core/canonical"
	anchorcrypto "github.com/GustyCube/anchor/core/crypto"
)

var (
	ErrTrustBundleExpired          = errors.New("trust bundle expired")
	ErrTrustBundleSignatureInvalid = errors.New("trust bundle signature invalid")
	ErrIssuerKeyOutOfWindow        = errors.New("issuer key is outside validity window")
	ErrNoTrustBundleAvailable      = errors.New("no trust bundle available")
)

type trustBundleSignaturePayload struct {
	BundleID           string              `json:"bundle_id"`
	IssuedAt           string              `json:"issued_at"`
	ExpiresAt          string              `json:"expires_at"`
	Issuers            []TrustBundleIssuer `json:"issuers"`
	RevocationPointers []string            `json:"revocation_pointers"`
	SignerPublicKeyKID string              `json:"signer_public_key_kid"`
}

func SignTrustBundle(bundle *TrustBundle, signerPrivateKey ed25519.PrivateKey) error {
	if bundle == nil {
		return fmt.Errorf("trust bundle is required")
	}
	if bundle.BundleID == "" {
		return fmt.Errorf("bundle_id is required")
	}
	if bundle.IssuedAt.IsZero() || bundle.ExpiresAt.IsZero() {
		return fmt.Errorf("issued_at and expires_at are required")
	}
	if !bundle.ExpiresAt.After(bundle.IssuedAt) {
		return fmt.Errorf("expires_at must be after issued_at")
	}
	if bundle.SignerPublicKeyKID == "" {
		return fmt.Errorf("signer_public_key_kid is required")
	}
	payload := trustBundleSignaturePayload{
		BundleID:           bundle.BundleID,
		IssuedAt:           bundle.IssuedAt.UTC().Format(timestampFormat),
		ExpiresAt:          bundle.ExpiresAt.UTC().Format(timestampFormat),
		Issuers:            bundle.Issuers,
		RevocationPointers: bundle.RevocationPointers,
		SignerPublicKeyKID: bundle.SignerPublicKeyKID,
	}
	data, err := canonical.Marshal(payload)
	if err != nil {
		return fmt.Errorf("canonical trust bundle signature payload: %w", err)
	}
	sig, err := anchorcrypto.SignBytes(signerPrivateKey, data)
	if err != nil {
		return err
	}
	bundle.Signature = sig
	return nil
}

func VerifyTrustBundleSignature(bundle TrustBundle, signerPublicKey ed25519.PublicKey) (bool, error) {
	if err := bundle.Validate(); err != nil {
		return false, err
	}
	payload := trustBundleSignaturePayload{
		BundleID:           bundle.BundleID,
		IssuedAt:           bundle.IssuedAt.UTC().Format(timestampFormat),
		ExpiresAt:          bundle.ExpiresAt.UTC().Format(timestampFormat),
		Issuers:            bundle.Issuers,
		RevocationPointers: bundle.RevocationPointers,
		SignerPublicKeyKID: bundle.SignerPublicKeyKID,
	}
	data, err := canonical.Marshal(payload)
	if err != nil {
		return false, fmt.Errorf("canonical trust bundle verify payload: %w", err)
	}
	return anchorcrypto.VerifySignature(signerPublicKey, data, bundle.Signature)
}

type TrustBundleKeyResolver struct {
	Bundle TrustBundle
}

func (r TrustBundleKeyResolver) Resolve(issuerID, issuerKID string, at time.Time) (ed25519.PublicKey, bool, error) {
	if at.After(r.Bundle.ExpiresAt) {
		return nil, false, ErrTrustBundleExpired
	}
	for _, issuer := range r.Bundle.Issuers {
		if issuer.IssuerID != issuerID || issuer.IssuerKID != issuerKID {
			continue
		}
		if at.Before(issuer.ValidFrom) || at.After(issuer.ValidUntil) {
			return nil, false, ErrIssuerKeyOutOfWindow
		}
		pk, err := anchorcrypto.PublicKeyFromBase64(issuer.PublicKey)
		if err != nil {
			return nil, false, err
		}
		return pk, true, nil
	}
	return nil, false, nil
}

type TrustBundleFetcher interface {
	FetchLatest() (TrustBundle, error)
}

type TrustBundleCache interface {
	Get() (TrustBundle, bool)
	Put(TrustBundle)
}

type InMemoryTrustBundleCache struct {
	mu     sync.Mutex
	bundle TrustBundle
	has    bool
}

func NewInMemoryTrustBundleCache() *InMemoryTrustBundleCache {
	return &InMemoryTrustBundleCache{}
}

func (c *InMemoryTrustBundleCache) Get() (TrustBundle, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.has {
		return TrustBundle{}, false
	}
	return c.bundle, true
}

func (c *InMemoryTrustBundleCache) Put(bundle TrustBundle) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bundle = bundle
	c.has = true
}

func ValidateTrustBundleAt(bundle TrustBundle, signerPublicKey ed25519.PublicKey, at time.Time) error {
	if err := bundle.Validate(); err != nil {
		return err
	}
	validSignature, err := VerifyTrustBundleSignature(bundle, signerPublicKey)
	if err != nil {
		return err
	}
	if !validSignature {
		return ErrTrustBundleSignatureInvalid
	}
	if at.Before(bundle.IssuedAt) || at.After(bundle.ExpiresAt) {
		return ErrTrustBundleExpired
	}
	return nil
}

func ResolveTrustBundleWithFallback(fetcher TrustBundleFetcher, cache TrustBundleCache, signerPublicKey ed25519.PublicKey, at time.Time) (TrustBundle, bool, error) {
	if fetcher != nil {
		bundle, err := fetcher.FetchLatest()
		if err == nil {
			if verifyErr := ValidateTrustBundleAt(bundle, signerPublicKey, at); verifyErr == nil {
				if cache != nil {
					cache.Put(bundle)
				}
				return bundle, false, nil
			}
		}
	}
	if cache != nil {
		if cached, ok := cache.Get(); ok {
			if err := ValidateTrustBundleAt(cached, signerPublicKey, at); err != nil {
				return TrustBundle{}, false, err
			}
			return cached, true, nil
		}
	}
	return TrustBundle{}, false, ErrNoTrustBundleAvailable
}

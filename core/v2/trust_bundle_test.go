package v2_test

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	anchorcrypto "github.com/BennettSchwartz/anchor/core/crypto"
	"github.com/BennettSchwartz/anchor/core/v2"
)

func TestSignAndVerifyTrustBundle(t *testing.T) {
	signerPublic, signerPrivate, err := anchorcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate signer keypair: %v", err)
	}
	issuedAt := time.Date(2026, 2, 13, 6, 0, 0, 0, time.UTC)
	bundle := v2.TrustBundle{
		BundleID:           "bundle-1",
		IssuedAt:           issuedAt,
		ExpiresAt:          issuedAt.Add(1 * time.Hour),
		SignerPublicKeyKID: "signer-k1",
		Issuers: []v2.TrustBundleIssuer{
			{
				IssuerID:      "issuer-1",
				IssuerKID:     "k1",
				PublicKey:     anchorcrypto.PublicKeyToBase64(signerPublic),
				ValidFrom:     issuedAt,
				ValidUntil:    issuedAt.Add(1 * time.Hour),
				AssuranceTier: "ORG_VERIFIED",
			},
		},
		RevocationPointers: []string{"https://revocations.example.com/list.json"},
	}
	if err := v2.SignTrustBundle(&bundle, signerPrivate); err != nil {
		t.Fatalf("sign bundle: %v", err)
	}
	valid, err := v2.VerifyTrustBundleSignature(bundle, signerPublic)
	if err != nil {
		t.Fatalf("verify bundle: %v", err)
	}
	if !valid {
		t.Fatal("expected trust bundle signature valid")
	}
}

func TestResolveTrustBundleWithFallbackUsesFetchedBundle(t *testing.T) {
	signerPublic, signerPrivate, err := anchorcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate signer keypair: %v", err)
	}
	issuedAt := time.Date(2026, 2, 13, 6, 0, 0, 0, time.UTC)
	bundle := makeSignedBundle(t, signerPrivate, signerPublic, issuedAt)
	cache := v2.NewInMemoryTrustBundleCache()
	fetcher := staticBundleFetcher{bundle: bundle}

	resolved, usedFallback, err := v2.ResolveTrustBundleWithFallback(fetcher, cache, signerPublic, issuedAt.Add(5*time.Minute))
	if err != nil {
		t.Fatalf("resolve trust bundle: %v", err)
	}
	if usedFallback {
		t.Fatal("expected fetched bundle without fallback")
	}
	if resolved.BundleID != bundle.BundleID {
		t.Fatalf("expected fetched bundle id %s, got %s", bundle.BundleID, resolved.BundleID)
	}
	if _, ok := cache.Get(); !ok {
		t.Fatal("expected fetched bundle to be cached")
	}
}

func TestResolveTrustBundleWithFallbackUsesCacheWhenFetchFails(t *testing.T) {
	signerPublic, signerPrivate, err := anchorcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate signer keypair: %v", err)
	}
	issuedAt := time.Date(2026, 2, 13, 6, 0, 0, 0, time.UTC)
	cachedBundle := makeSignedBundle(t, signerPrivate, signerPublic, issuedAt)
	cache := v2.NewInMemoryTrustBundleCache()
	cache.Put(cachedBundle)
	fetcher := staticBundleFetcher{err: errors.New("network unavailable")}

	resolved, usedFallback, err := v2.ResolveTrustBundleWithFallback(fetcher, cache, signerPublic, issuedAt.Add(10*time.Minute))
	if err != nil {
		t.Fatalf("resolve trust bundle with fallback: %v", err)
	}
	if !usedFallback {
		t.Fatal("expected cached fallback bundle")
	}
	if resolved.BundleID != cachedBundle.BundleID {
		t.Fatalf("expected fallback bundle id %s, got %s", cachedBundle.BundleID, resolved.BundleID)
	}
}

func TestResolveTrustBundleWithFallbackRejectsExpiredCache(t *testing.T) {
	signerPublic, signerPrivate, err := anchorcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate signer keypair: %v", err)
	}
	issuedAt := time.Date(2026, 2, 13, 6, 0, 0, 0, time.UTC)
	cachedBundle := makeSignedBundle(t, signerPrivate, signerPublic, issuedAt)
	cache := v2.NewInMemoryTrustBundleCache()
	cache.Put(cachedBundle)
	fetcher := staticBundleFetcher{err: errors.New("network unavailable")}

	_, _, err = v2.ResolveTrustBundleWithFallback(fetcher, cache, signerPublic, issuedAt.Add(2*time.Hour))
	if !errors.Is(err, v2.ErrTrustBundleExpired) {
		t.Fatalf("expected trust bundle expired error, got %v", err)
	}
}

type staticBundleFetcher struct {
	bundle v2.TrustBundle
	err    error
}

func (f staticBundleFetcher) FetchLatest() (v2.TrustBundle, error) {
	if f.err != nil {
		return v2.TrustBundle{}, f.err
	}
	return f.bundle, nil
}

func makeSignedBundle(t *testing.T, signerPrivate ed25519.PrivateKey, issuerPublic ed25519.PublicKey, issuedAt time.Time) v2.TrustBundle {
	t.Helper()
	bundle := v2.TrustBundle{
		BundleID:           "bundle-1",
		IssuedAt:           issuedAt,
		ExpiresAt:          issuedAt.Add(1 * time.Hour),
		SignerPublicKeyKID: "signer-k1",
		Issuers: []v2.TrustBundleIssuer{
			{
				IssuerID:      "issuer-1",
				IssuerKID:     "k1",
				PublicKey:     anchorcrypto.PublicKeyToBase64(issuerPublic),
				ValidFrom:     issuedAt,
				ValidUntil:    issuedAt.Add(1 * time.Hour),
				AssuranceTier: "ORG_VERIFIED",
			},
		},
		RevocationPointers: []string{"https://revocations.example.com/list.json"},
	}
	if err := v2.SignTrustBundle(&bundle, signerPrivate); err != nil {
		t.Fatalf("sign bundle: %v", err)
	}
	return bundle
}

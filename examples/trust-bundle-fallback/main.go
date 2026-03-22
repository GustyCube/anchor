package main

import (
	"errors"
	"fmt"
	"log"
	"time"

	anchorcrypto "github.com/GustyCube/anchor/core/crypto"
	protocolgo "github.com/GustyCube/anchor/sdk/go"
)

func main() {
	referenceTime := time.Date(2026, 2, 16, 16, 0, 0, 0, time.UTC)

	registryPub, registryPriv, err := anchorcrypto.GenerateEd25519KeyPair()
	must("generate registry keypair", err)
	issuerPub, _, err := anchorcrypto.GenerateEd25519KeyPair()
	must("generate issuer keypair", err)
	issuerID, err := anchorcrypto.DeriveIDFromPublicKey(issuerPub)
	must("derive issuer id", err)

	bundle := protocolgo.TrustBundle{
		BundleID:           "bundle-fallback-demo",
		IssuedAt:           referenceTime.Add(-5 * time.Minute),
		ExpiresAt:          referenceTime.Add(2 * time.Hour),
		SignerPublicKeyKID: "registry-k1",
		Issuers: []protocolgo.TrustBundleIssuer{
			{
				IssuerID:      issuerID,
				IssuerKID:     "issuer-k1",
				PublicKey:     anchorcrypto.PublicKeyToBase64(issuerPub),
				ValidFrom:     referenceTime.Add(-5 * time.Minute),
				ValidUntil:    referenceTime.Add(2 * time.Hour),
				AssuranceTier: "ORG_VERIFIED",
			},
		},
		RevocationPointers: []string{"https://registry.example/revocations/latest"},
	}
	must("sign trust bundle", protocolgo.SignTrustBundle(&bundle, registryPriv))

	cache := protocolgo.NewInMemoryTrustBundleCache()
	fetcher := &toggleFetcher{bundle: bundle}

	freshBundle, usedFallback, err := protocolgo.ResolveTrustBundleWithFallback(fetcher, cache, registryPub, referenceTime)
	must("resolve fetched bundle", err)
	fmt.Printf("step=fetch used_fallback=%t bundle_id=%s\n", usedFallback, freshBundle.BundleID)

	fetcher.fail = true
	cachedBundle, usedFallback, err := protocolgo.ResolveTrustBundleWithFallback(fetcher, cache, registryPub, referenceTime.Add(1*time.Minute))
	must("resolve cached bundle after fetch failure", err)
	fmt.Printf("step=fallback used_fallback=%t bundle_id=%s\n", usedFallback, cachedBundle.BundleID)

	resolver := protocolgo.TrustBundleKeyResolver{Bundle: cachedBundle}
	issuerKey, ok, err := resolver.Resolve(issuerID, "issuer-k1", referenceTime.Add(1*time.Minute))
	must("resolve issuer key", err)
	fmt.Printf("issuer_key_resolved=%t key_length=%d\n", ok, len(issuerKey))
}

type toggleFetcher struct {
	bundle protocolgo.TrustBundle
	fail   bool
}

func (f *toggleFetcher) FetchLatest() (protocolgo.TrustBundle, error) {
	if f.fail {
		return protocolgo.TrustBundle{}, errors.New("simulated network failure")
	}
	return f.bundle, nil
}

func must(op string, err error) {
	if err != nil {
		log.Fatalf("%s: %v", op, err)
	}
}

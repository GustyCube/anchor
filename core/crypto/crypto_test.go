package crypto_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"

	anchorcrypto "github.com/ignyte-solutions/ignyte-anchor-protocol/core/crypto"
)

func TestGenerateEd25519KeyPairProducesValidKeys(t *testing.T) {
	pub, priv, err := anchorcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("expected public key size %d, got %d", ed25519.PublicKeySize, len(pub))
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("expected private key size %d, got %d", ed25519.PrivateKeySize, len(priv))
	}
}

func TestGenerateEd25519KeyPairProducesUniqueKeys(t *testing.T) {
	pub1, _, err := anchorcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate first key pair: %v", err)
	}
	pub2, _, err := anchorcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate second key pair: %v", err)
	}
	if string(pub1) == string(pub2) {
		t.Fatal("expected unique public keys from separate generations")
	}
}

func TestDeriveIDFromPublicKeyIsDeterministic(t *testing.T) {
	pub, _, err := anchorcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	id1, err := anchorcrypto.DeriveIDFromPublicKey(pub)
	if err != nil {
		t.Fatalf("derive id first: %v", err)
	}
	id2, err := anchorcrypto.DeriveIDFromPublicKey(pub)
	if err != nil {
		t.Fatalf("derive id second: %v", err)
	}
	if id1 != id2 {
		t.Fatalf("expected deterministic id, got %s and %s", id1, id2)
	}
	if len(id1) != 64 {
		t.Fatalf("expected sha256 hex string (64 chars), got %d chars", len(id1))
	}
}

func TestDeriveIDFromPublicKeyRejectsInvalidLength(t *testing.T) {
	_, err := anchorcrypto.DeriveIDFromPublicKey([]byte("short"))
	if err == nil {
		t.Fatal("expected error for short public key")
	}
}

func TestDeriveIDDiffersAcrossKeys(t *testing.T) {
	pub1, _, _ := anchorcrypto.GenerateEd25519KeyPair()
	pub2, _, _ := anchorcrypto.GenerateEd25519KeyPair()
	id1, _ := anchorcrypto.DeriveIDFromPublicKey(pub1)
	id2, _ := anchorcrypto.DeriveIDFromPublicKey(pub2)
	if id1 == id2 {
		t.Fatal("expected different IDs for different keys")
	}
}

func TestPublicKeyBase64RoundTrip(t *testing.T) {
	pub, _, err := anchorcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	encoded := anchorcrypto.PublicKeyToBase64(pub)
	decoded, err := anchorcrypto.PublicKeyFromBase64(encoded)
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	if string(pub) != string(decoded) {
		t.Fatal("public key round-trip mismatch")
	}
}

func TestPrivateKeyBase64RoundTrip(t *testing.T) {
	_, priv, err := anchorcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	encoded := anchorcrypto.PrivateKeyToBase64(priv)
	decoded, err := anchorcrypto.PrivateKeyFromBase64(encoded)
	if err != nil {
		t.Fatalf("decode private key: %v", err)
	}
	if string(priv) != string(decoded) {
		t.Fatal("private key round-trip mismatch")
	}
}

func TestPublicKeyFromBase64RejectsInvalidInput(t *testing.T) {
	if _, err := anchorcrypto.PublicKeyFromBase64("not-valid-base64!!!"); err == nil {
		t.Fatal("expected error for invalid base64")
	}
	shortKey := base64.StdEncoding.EncodeToString([]byte("short"))
	if _, err := anchorcrypto.PublicKeyFromBase64(shortKey); err == nil {
		t.Fatal("expected error for wrong key size")
	}
}

func TestPrivateKeyFromBase64RejectsInvalidInput(t *testing.T) {
	if _, err := anchorcrypto.PrivateKeyFromBase64("not-valid-base64!!!"); err == nil {
		t.Fatal("expected error for invalid base64")
	}
	shortKey := base64.StdEncoding.EncodeToString([]byte("short"))
	if _, err := anchorcrypto.PrivateKeyFromBase64(shortKey); err == nil {
		t.Fatal("expected error for wrong key size")
	}
}

func TestSignAndVerifyBytesRoundTrip(t *testing.T) {
	pub, priv, err := anchorcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	message := []byte("hello anchor protocol")
	sig, err := anchorcrypto.SignBytes(priv, message)
	if err != nil {
		t.Fatalf("sign bytes: %v", err)
	}
	valid, err := anchorcrypto.VerifySignature(pub, message, sig)
	if err != nil {
		t.Fatalf("verify signature: %v", err)
	}
	if !valid {
		t.Fatal("expected valid signature")
	}
}

func TestVerifySignatureRejectsTamperedMessage(t *testing.T) {
	pub, priv, _ := anchorcrypto.GenerateEd25519KeyPair()
	sig, _ := anchorcrypto.SignBytes(priv, []byte("original"))
	valid, err := anchorcrypto.VerifySignature(pub, []byte("tampered"), sig)
	if err != nil {
		t.Fatalf("verify signature: %v", err)
	}
	if valid {
		t.Fatal("expected invalid signature for tampered message")
	}
}

func TestVerifySignatureRejectsWrongKey(t *testing.T) {
	_, priv, _ := anchorcrypto.GenerateEd25519KeyPair()
	otherPub, _, _ := anchorcrypto.GenerateEd25519KeyPair()
	msg := []byte("test message")
	sig, _ := anchorcrypto.SignBytes(priv, msg)
	valid, err := anchorcrypto.VerifySignature(otherPub, msg, sig)
	if err != nil {
		t.Fatalf("verify signature: %v", err)
	}
	if valid {
		t.Fatal("expected invalid signature for wrong public key")
	}
}

func TestSignBytesRejectsInvalidPrivateKey(t *testing.T) {
	_, err := anchorcrypto.SignBytes([]byte("short"), []byte("msg"))
	if err == nil {
		t.Fatal("expected error for invalid private key")
	}
}

func TestVerifySignatureRejectsInvalidPublicKey(t *testing.T) {
	_, priv, _ := anchorcrypto.GenerateEd25519KeyPair()
	sig, _ := anchorcrypto.SignBytes(priv, []byte("msg"))
	_, err := anchorcrypto.VerifySignature([]byte("short"), []byte("msg"), sig)
	if err == nil {
		t.Fatal("expected error for invalid public key")
	}
}

func TestVerifySignatureRejectsInvalidSignatureBase64(t *testing.T) {
	pub, _, _ := anchorcrypto.GenerateEd25519KeyPair()
	_, err := anchorcrypto.VerifySignature(pub, []byte("msg"), "not-valid-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64 signature")
	}
}

func TestVerifySignatureRejectsWrongLengthSignature(t *testing.T) {
	pub, _, _ := anchorcrypto.GenerateEd25519KeyPair()
	shortSig := base64.StdEncoding.EncodeToString([]byte("short"))
	_, err := anchorcrypto.VerifySignature(pub, []byte("msg"), shortSig)
	if err == nil {
		t.Fatal("expected error for wrong-length signature")
	}
}

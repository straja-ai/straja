package trust

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func buildTrustKey(t *testing.T, priv ed25519.PrivateKey, claims TrustClaims) string {
	t.Helper()

	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	sig := ed25519.Sign(priv, payload)
	joined := append(payload, sig...)
	return "STRAJA-TRUST-" + base64.RawURLEncoding.EncodeToString(joined)
}

func TestVerifyTrustKey_Success(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	want := TrustClaims{
		Iss:   "straja.ai",
		Sub:   "trust",
		Tier:  "free",
		Email: "test@example.com",
		Iat:   123,
		Jti:   "abc",
	}

	key := buildTrustKey(t, priv, want)

	got, err := VerifyTrustKey(key, pub)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if got.Email != want.Email || got.Tier != want.Tier || got.Jti != want.Jti {
		t.Fatalf("claims mismatch: got %+v want %+v", got, want)
	}
}

func TestVerifyTrustKey_InvalidPrefix(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	claims := TrustClaims{Iss: "straja.ai", Sub: "trust"}
	key := buildTrustKey(t, priv, claims)

	_, err := VerifyTrustKey("BADPREFIX-"+key, pub)
	if err == nil {
		t.Fatalf("expected prefix error, got nil")
	}
}

func TestVerifyTrustKey_InvalidSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	claims := TrustClaims{Iss: "straja.ai", Sub: "trust"}
	key := buildTrustKey(t, priv, claims)

	// Corrupt the decoded payload so the signature definitely fails.
	raw := strings.TrimPrefix(key, "STRAJA-TRUST-")
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	if len(decoded) == 0 {
		t.Fatalf("decoded key empty")
	}
	decoded[len(decoded)-1] ^= 0xFF
	badKey := "STRAJA-TRUST-" + base64.RawURLEncoding.EncodeToString(decoded)

	_, err = VerifyTrustKey(badKey, pub)
	if err == nil {
		t.Fatalf("expected verification error, got nil")
	}
}

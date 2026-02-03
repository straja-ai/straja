package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func buildLicenseKey(t *testing.T, priv ed25519.PrivateKey, claims LicenseClaims) string {
	t.Helper()

	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	sig := ed25519.Sign(priv, payload)
	joined := append(payload, sig...)
	return "STRAJA-FREE-" + base64.RawURLEncoding.EncodeToString(joined)
}

func TestVerifyLicenseKey_Success(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	want := LicenseClaims{
		Iss:   "straja.ai",
		Sub:   "license",
		Tier:  "free",
		Email: "test@example.com",
		Iat:   123,
		Jti:   "abc",
	}

	key := buildLicenseKey(t, priv, want)

	got, err := VerifyLicenseKey(key, pub)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if got.Email != want.Email || got.Tier != want.Tier || got.Jti != want.Jti {
		t.Fatalf("claims mismatch: got %+v want %+v", got, want)
	}
}

func TestVerifyLicenseKey_InvalidPrefix(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	claims := LicenseClaims{Iss: "straja.ai", Sub: "license"}
	key := buildLicenseKey(t, priv, claims)

	_, err := VerifyLicenseKey("BADPREFIX-"+key, pub)
	if err == nil {
		t.Fatalf("expected prefix error, got nil")
	}
}

func TestVerifyLicenseKey_InvalidSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	claims := LicenseClaims{Iss: "straja.ai", Sub: "license"}
	key := buildLicenseKey(t, priv, claims)

	// Corrupt the decoded payload so the signature definitely fails.
	raw := strings.TrimPrefix(key, "STRAJA-FREE-")
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	if len(decoded) == 0 {
		t.Fatalf("decoded key empty")
	}
	decoded[len(decoded)-1] ^= 0xFF
	badKey := "STRAJA-FREE-" + base64.RawURLEncoding.EncodeToString(decoded)

	_, err = VerifyLicenseKey(badKey, pub)
	if err == nil {
		t.Fatalf("expected verification error, got nil")
	}
}

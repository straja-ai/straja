package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// TODO: replace with the real base64-encoded Ed25519 public key from the license issuer.
const licensePublicKeyBase64 = "_Y-tXDrvMzV_Ctv1eKBo-YhIg1LGlqDuaiEkhfjiJVQ"

var (
	ErrMissingPublicKey = errors.New("license public key is not configured")
)

// LicenseClaims represents the payload embedded in a signed license key.
type LicenseClaims struct {
	Iss   string `json:"iss"`
	Sub   string `json:"sub"`
	Tier  string `json:"tier"`
	Email string `json:"email"`
	Iat   int64  `json:"iat"`
	Jti   string `json:"jti"`
}

// DefaultPublicKey decodes the embedded base64-encoded Ed25519 public key.
func DefaultPublicKey() ([]byte, error) {
	// Allow override via env to avoid recompiling when rotating the key.
	if envVal := strings.TrimSpace(os.Getenv("STRAJA_LICENSE_PUBLIC_KEY")); envVal != "" {
		if pk, err := decodePublicKey(envVal); err == nil {
			return pk, nil
		}
	}

	if strings.TrimSpace(licensePublicKeyBase64) == "" {
		return nil, ErrMissingPublicKey
	}
	return decodePublicKey(licensePublicKeyBase64)
}

// VerifyLicenseKey performs offline verification of the license key.
func VerifyLicenseKey(key string, publicKey []byte) (*LicenseClaims, error) {
	const prefix = "STRAJA-FREE-"
	if !strings.HasPrefix(key, prefix) {
		return nil, fmt.Errorf("license key missing required prefix %q", prefix)
	}

	payloadAndSigB64 := strings.TrimPrefix(key, prefix)
	payloadAndSig, err := base64.RawURLEncoding.DecodeString(payloadAndSigB64)
	if err != nil {
		return nil, fmt.Errorf("decode license payload: %w", err)
	}

	if len(payloadAndSig) <= ed25519.SignatureSize {
		return nil, errors.New("license payload too short")
	}

	payloadBytes := payloadAndSig[:len(payloadAndSig)-ed25519.SignatureSize]
	sig := payloadAndSig[len(payloadAndSig)-ed25519.SignatureSize:]

	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length: %d", len(publicKey))
	}

	if !ed25519.Verify(publicKey, payloadBytes, sig) {
		return nil, errors.New("license signature verification failed")
	}

	var claims LicenseClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("decode license claims: %w", err)
	}

	if claims.Iss != "straja.ai" || claims.Sub != "license" {
		return nil, errors.New("license claims issuer/subject mismatch")
	}

	return &claims, nil
}

func decodePublicKey(v string) ([]byte, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, ErrMissingPublicKey
	}
	decoders := []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
	}
	for _, dec := range decoders {
		if b, err := dec(v); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("unable to decode public key: invalid base64")
}

package trust

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

// TODO: replace with the real base64-encoded Ed25519 public key from the trust issuer.
const trustPublicKeyBase64 = "_Y-tXDrvMzV_Ctv1eKBo-YhIg1LGlqDuaiEkhfjiJVQ"

var (
	ErrMissingPublicKey = errors.New("trust public key is not configured")
)

// TrustClaims represents the payload embedded in a signed trust key.
type TrustClaims struct {
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
	if envVal := strings.TrimSpace(os.Getenv("STRAJA_TRUST_PUBLIC_KEY")); envVal != "" {
		if pk, err := decodePublicKey(envVal); err == nil {
			return pk, nil
		}
	}

	if strings.TrimSpace(trustPublicKeyBase64) == "" {
		return nil, ErrMissingPublicKey
	}
	return decodePublicKey(trustPublicKeyBase64)
}

// VerifyTrustKey performs offline verification of the trust key.
func VerifyTrustKey(key string, publicKey []byte) (*TrustClaims, error) {
	const prefix = "STRAJA-TRUST-"
	if !strings.HasPrefix(key, prefix) {
		return nil, fmt.Errorf("trust key missing required prefix %q", prefix)
	}

	payloadAndSigB64 := strings.TrimPrefix(key, prefix)
	payloadAndSig, err := base64.RawURLEncoding.DecodeString(payloadAndSigB64)
	if err != nil {
		return nil, fmt.Errorf("decode trust payload: %w", err)
	}

	if len(payloadAndSig) <= ed25519.SignatureSize {
		return nil, errors.New("trust payload too short")
	}

	payloadBytes := payloadAndSig[:len(payloadAndSig)-ed25519.SignatureSize]
	sig := payloadAndSig[len(payloadAndSig)-ed25519.SignatureSize:]

	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length: %d", len(publicKey))
	}

	if !ed25519.Verify(publicKey, payloadBytes, sig) {
		return nil, errors.New("trust signature verification failed")
	}

	var claims TrustClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("decode trust claims: %w", err)
	}

	if claims.Iss != "straja.ai" || claims.Sub != "trust" {
		return nil, errors.New("trust claims issuer/subject mismatch")
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

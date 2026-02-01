package consoleauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type Claims struct {
	ProjectID string `json:"project_id"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

var errInvalidToken = errors.New("invalid console session token")

func IssueConsoleSession(projectID string, ttl time.Duration, secret string) (string, time.Time, error) {
	if projectID == "" || strings.TrimSpace(secret) == "" {
		return "", time.Time{}, errInvalidToken
	}
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	now := time.Now().UTC()
	exp := now.Add(ttl)

	claims := Claims{
		ProjectID: projectID,
		IssuedAt:  now.Unix(),
		ExpiresAt: exp.Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", time.Time{}, err
	}

	encoded := base64.RawURLEncoding.EncodeToString(payload)
	sig := sign(encoded, secret)
	return encoded + "." + sig, exp, nil
}

func VerifyConsoleSession(token string, secret string) (string, time.Time, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return "", time.Time{}, errInvalidToken
	}
	payloadB64 := parts[0]
	sig := parts[1]
	if !verify(payloadB64, sig, secret) {
		return "", time.Time{}, errInvalidToken
	}
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return "", time.Time{}, errInvalidToken
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", time.Time{}, errInvalidToken
	}
	if claims.ProjectID == "" {
		return "", time.Time{}, errInvalidToken
	}
	exp := time.Unix(claims.ExpiresAt, 0).UTC()
	if time.Now().UTC().After(exp) {
		return "", time.Time{}, errInvalidToken
	}
	return claims.ProjectID, exp, nil
}

func sign(payload string, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func verify(payload, sig, secret string) bool {
	if strings.TrimSpace(secret) == "" {
		return false
	}
	expected := sign(payload, secret)
	return hmac.Equal([]byte(expected), []byte(sig))
}

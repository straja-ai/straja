package strajaguard

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/straja-ai/straja/internal/redact"
)

// TODO: replace with the real base64-encoded Ed25519 public key used to sign manifests.
const manifestPublicKeyBase64 = "dVGYro4CAM0jPHlI/4p8y+7Azmf7h0NNpxTsEvPnVC4="

// BundleInfo contains download URLs for a StrajaGuard bundle.
type BundleInfo struct {
	Version         string `json:"version"`
	ManifestURL     string `json:"manifest_url"`
	SignatureURL    string `json:"signature_url"`
	FileBaseURL     string `json:"file_base_url"`
	UpdateAvailable bool   `json:"update_available"`
}

// ManifestFile describes one file entry in manifest.json.
type ManifestFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// Manifest mirrors manifest.json.
type Manifest struct {
	Model     string         `json:"model"`
	Version   string         `json:"version"`
	CreatedAt string         `json:"created_at"`
	Files     []ManifestFile `json:"files"`
}

// ManifestSignature holds manifest.sig contents.
type ManifestSignature struct {
	Algorithm string `json:"algorithm"`
	Signature string `json:"signature"`
}

func wrapRedactedError(msg string, err error) error {
	if err == nil {
		return errors.New(strings.TrimSpace(msg))
	}
	return fmt.Errorf("%s: %s", strings.TrimSpace(msg), redact.String(err.Error()))
}

// ValidationResult represents the outcome of a license validate call.
type ValidationResult struct {
	LatestVersion string
	BundleInfo    BundleInfo
	BundleToken   string
}

// LicenseValidationOutcome classifies validation responses.
type LicenseValidationOutcome string

const (
	ValidateOK             LicenseValidationOutcome = "validate_ok"
	ValidateInvalidLicense LicenseValidationOutcome = "validate_invalid_license"
	ValidateNetworkError   LicenseValidationOutcome = "validate_network_error"
	ValidateOtherError     LicenseValidationOutcome = "validate_other_error"
)

// ValidateLicense contacts straja-site to validate the license and obtain bundle metadata.
func ValidateLicense(ctx context.Context, baseURL, licenseKey, currentVersion, family string, timeoutSeconds int) (*ValidationResult, LicenseValidationOutcome, error) {
	baseURL = strings.TrimSuffix(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil, ValidateOtherError, errors.New("license server base url is empty")
	}
	if strings.TrimSpace(licenseKey) == "" {
		return nil, ValidateOtherError, errors.New("license key is empty")
	}
	family = normalizeBundleFamily(family)
	if timeoutSeconds <= 0 {
		timeoutSeconds = 10
	}

	validateURL := baseURL + "/api/license/validate"
	var current *string
	if strings.TrimSpace(currentVersion) != "" {
		cv := strings.TrimSpace(currentVersion)
		current = &cv
	}

	if ctx == nil {
		ctx = context.Background()
	}
	timeout := time.Duration(timeoutSeconds) * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	body := struct {
		LicenseKey string `json:"license_key"`
		ClientID   string `json:"client_id"`
		Bundles    map[string]struct {
			CurrentVersion *string `json:"current_version"`
		} `json:"bundles"`
	}{
		LicenseKey: licenseKey,
		ClientID:   "",
		Bundles: map[string]struct {
			CurrentVersion *string `json:"current_version"`
		}{},
	}
	for _, key := range bundleFamilyVariants(family) {
		body.Bundles[key] = struct {
			CurrentVersion *string `json:"current_version"`
		}{CurrentVersion: current}
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return nil, ValidateOtherError, fmt.Errorf("marshal license payload: %w", err)
	}

	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, validateURL, bytes.NewReader(payload))
	if err != nil {
		return nil, ValidateOtherError, fmt.Errorf("build license request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, ValidateNetworkError, fmt.Errorf("license validate request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, ValidateInvalidLicense, fmt.Errorf("license validate failed with status %s", resp.Status)
	}
	if resp.StatusCode >= 500 {
		return nil, ValidateNetworkError, fmt.Errorf("license validate failed with status %s", resp.Status)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, ValidateOtherError, fmt.Errorf("license validate failed with status %s", resp.Status)
	}

	var lr licenseValidateResponse
	if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
		return nil, ValidateOtherError, fmt.Errorf("decode license validate response: %w", err)
	}

	if strings.ToLower(strings.TrimSpace(lr.Status)) != "ok" {
		msg := lr.Message
		if msg == "" {
			msg = "license status not ok"
		}
		return nil, ValidateInvalidLicense, errors.New(msg)
	}

	model, ok := lookupModelInfo(lr.License.Models, family)
	if !ok || !model.Enabled {
		return nil, ValidateInvalidLicense, errors.New("strajaguard model not enabled on license")
	}

	info, ok := lookupBundleInfo(lr.Bundles, family)
	if !ok {
		return nil, ValidateOtherError, errors.New("bundle info missing in license response")
	}
	info.Version = strings.TrimSpace(info.Version)
	info.ManifestURL = strings.TrimSpace(info.ManifestURL)
	info.SignatureURL = strings.TrimSpace(info.SignatureURL)
	info.FileBaseURL = strings.TrimSpace(info.FileBaseURL)

	if info.Version == "" || info.ManifestURL == "" || info.SignatureURL == "" || info.FileBaseURL == "" {
		return nil, ValidateOtherError, errors.New("bundle info incomplete in license response")
	}
	if strings.TrimSpace(lr.BundleToken) == "" {
		return nil, ValidateOtherError, errors.New("bundle token missing in license response")
	}

	return &ValidationResult{
		LatestVersion: model.LatestVersion,
		BundleInfo:    info,
		BundleToken:   lr.BundleToken,
	}, ValidateOK, nil
}

// DownloadAndInstallStrajaGuardBundle downloads, verifies, and atomically installs a bundle.
func DownloadAndInstallStrajaGuardBundle(ctx context.Context, destDir string, info BundleInfo, token string, versionFileName string, timeoutSeconds int) error {
	if strings.TrimSpace(destDir) == "" {
		return errors.New("destDir is empty")
	}
	if strings.TrimSpace(token) == "" {
		return errors.New("bundle token is empty")
	}
	if timeoutSeconds <= 0 {
		timeoutSeconds = 30
	}

	if ctx == nil {
		ctx = context.Background()
	}
	timeout := time.Duration(timeoutSeconds) * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	client := &http.Client{Timeout: timeout}
	pk, err := manifestPublicKey()
	if err != nil {
		return fmt.Errorf("load manifest public key: %w", err)
	}

	manifestBytes, manifest, err := downloadManifest(ctx, client, info.ManifestURL, token)
	if err != nil {
		return err
	}

	sigEncoded, sigAlgorithm, sigRawBytes, err := downloadSignature(ctx, client, info.SignatureURL, token)
	if err != nil {
		return err
	}

	if err := verifyManifest(manifestBytes, manifest.Version, sigEncoded, sigAlgorithm, pk); err != nil {
		return err
	}

	if manifest.Version != info.Version {
		return fmt.Errorf("manifest version mismatch: expected %s, got %s", info.Version, manifest.Version)
	}

	parent := filepath.Dir(destDir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("create bundle parent dir: %w", err)
	}

	tmpDir, err := os.MkdirTemp(parent, "strajaguard_v1-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := downloadBundleFiles(ctx, client, tmpDir, manifest.Files, info.FileBaseURL, token); err != nil {
		return err
	}

	if err := os.WriteFile(filepath.Join(tmpDir, "manifest.json"), manifestBytes, 0o644); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "manifest.sig"), sigRawBytes, 0o644); err != nil {
		return fmt.Errorf("write manifest signature: %w", err)
	}
	if versionFileName == "" {
		versionFileName = "version"
	}
	if err := os.WriteFile(filepath.Join(tmpDir, versionFileName), []byte(info.Version), 0o644); err != nil {
		return fmt.Errorf("write version file: %w", err)
	}

	backup := destDir + ".bak"
	if _, statErr := os.Stat(destDir); statErr == nil {
		_ = os.RemoveAll(backup)
		if err := os.Rename(destDir, backup); err != nil {
			return fmt.Errorf("backup existing bundle: %w", err)
		}
	}

	if err := os.Rename(tmpDir, destDir); err != nil {
		if _, restoreErr := os.Stat(backup); restoreErr == nil {
			_ = os.Rename(backup, destDir)
		}
		return fmt.Errorf("install new bundle: %w", err)
	}

	_ = os.RemoveAll(backup)
	return nil
}

// ReadLocalBundleVersion returns the local bundle version if present.
func ReadLocalBundleVersion(bundleDir, versionFileName string) (string, error) {
	if versionFileName == "" {
		versionFileName = "version"
	}
	data, err := os.ReadFile(filepath.Join(bundleDir, versionFileName))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// BundleFilesPresent checks that the key files exist on disk for the given family.
func BundleFilesPresent(bundleDir, family string) bool {
	family = normalizeBundleFamily(family)
	switch family {
	case "strajaguard_v1_specialists":
		for _, name := range []string{"prompt_injection", "jailbreak", "pii_ner"} {
			if !specialistDirLooksValid(filepath.Join(bundleDir, name)) {
				return false
			}
		}
		return true
	default:
		required := []string{
			"strajaguard_v1.onnx",
			"label_map.json",
			"thresholds.yaml",
			filepath.Join("tokenizer", "vocab.txt"),
		}
		for _, p := range required {
			if _, err := os.Stat(filepath.Join(bundleDir, p)); err != nil {
				return false
			}
		}
		return true
	}
}

func manifestPublicKey() ([]byte, error) {
	if envVal := strings.TrimSpace(os.Getenv("STRAJAGUARD_MANIFEST_PUBLIC_KEY")); envVal != "" {
		if pk, err := decodeKey(envVal); err == nil {
			return pk, nil
		}
	}
	return decodeKey(manifestPublicKeyBase64)
}

func decodeKey(v string) ([]byte, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, errors.New("public key missing")
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
	return nil, errors.New("unable to decode manifest public key")
}

func downloadManifest(ctx context.Context, client *http.Client, url, token string) ([]byte, *Manifest, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, wrapRedactedError("build manifest request", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, wrapRedactedError("download manifest", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, nil, fmt.Errorf("download manifest status: %s: %s", resp.Status, strings.TrimSpace(string(errBody)))
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("read manifest body: %w", err)
	}

	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, nil, fmt.Errorf("decode manifest: %w", err)
	}
	return data, &manifest, nil
}

func downloadSignature(ctx context.Context, client *http.Client, url, token string) (string, string, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", "", nil, wrapRedactedError("build manifest signature request", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return "", "", nil, wrapRedactedError("download manifest signature", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return "", "", nil, fmt.Errorf("download manifest signature status: %s: %s", resp.Status, strings.TrimSpace(string(errBody)))
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", nil, fmt.Errorf("read manifest signature: %w", err)
	}

	var sig ManifestSignature
	if err := json.Unmarshal(data, &sig); err == nil && strings.TrimSpace(sig.Signature) != "" {
		return strings.TrimSpace(sig.Signature), sig.Algorithm, data, nil
	}

	// Fallback: treat the body as a raw base64/hex signature string.
	return strings.TrimSpace(string(data)), "ed25519", data, nil
}

func verifyManifest(manifestBytes []byte, manifestVersion string, sigEncoded string, sigAlgorithm string, pk []byte) error {
	redact.Logf("strajaguard verifying manifest version=%s", manifestVersion)

	if len(pk) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid manifest public key length: %d", len(pk))
	}

	alg := strings.ToLower(strings.TrimSpace(sigAlgorithm))
	if alg == "" {
		alg = "ed25519"
	}
	if alg != "ed25519" {
		return fmt.Errorf("unsupported signature algorithm %q", alg)
	}

	sigBytes, err := decodeSignature(sigEncoded)
	if err != nil {
		redact.Logf("strajaguard manifest signature parse failed version=%s: %v", manifestVersion, err)
		return fmt.Errorf("decode signature: %w", err)
	}

	if len(sigBytes) != ed25519.SignatureSize {
		err := fmt.Errorf("manifest signature invalid length: got %d, want %d", len(sigBytes), ed25519.SignatureSize)
		redact.Logf("strajaguard manifest signature parse failed version=%s: %v", manifestVersion, err)
		return err
	}

	if !ed25519.Verify(pk, manifestBytes, sigBytes) {
		redact.Logf("strajaguard manifest signature verify failed version=%s", manifestVersion)
		return errors.New("manifest signature verification failed")
	}
	redact.Logf("strajaguard manifest signature verified version=%s", manifestVersion)
	return nil
}

func decodeSignature(v string) ([]byte, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, errors.New("signature is empty")
	}
	isHex := len(v)%2 == 0
	if isHex {
		isHex = true
		for i := 0; i < len(v); i++ {
			if !strings.Contains("0123456789abcdefABCDEF", string(v[i])) {
				isHex = false
				break
			}
		}
	}

	var (
		hexBytes []byte
		b64Bytes []byte
		hexErr   error
		b64Err   error
	)

	if isHex {
		hexBytes, hexErr = hex.DecodeString(v)
		if hexErr == nil && len(hexBytes) == ed25519.SignatureSize {
			return hexBytes, nil
		}
	}

	if b, err := base64.StdEncoding.DecodeString(v); err == nil {
		b64Bytes = b
	} else if b, err := base64.RawStdEncoding.DecodeString(v); err == nil {
		b64Bytes = b
	} else {
		b64Err = err
	}

	if len(b64Bytes) == ed25519.SignatureSize {
		return b64Bytes, nil
	}
	if len(hexBytes) == ed25519.SignatureSize {
		return hexBytes, nil
	}

	if len(b64Bytes) > 0 && len(hexBytes) > 0 {
		return nil, fmt.Errorf("unable to decode signature to 64 bytes (hex=%d, base64=%d)", len(hexBytes), len(b64Bytes))
	}
	if len(b64Bytes) > 0 {
		return nil, fmt.Errorf("unable to decode signature to 64 bytes (base64=%d)", len(b64Bytes))
	}
	if len(hexBytes) > 0 {
		return nil, fmt.Errorf("unable to decode signature to 64 bytes (hex=%d)", len(hexBytes))
	}
	return nil, fmt.Errorf("unable to decode signature (hexErr=%v, b64Err=%v)", hexErr, b64Err)
}

func downloadBundleFiles(ctx context.Context, client *http.Client, baseDir string, files []ManifestFile, baseURL, token string) error {
	if strings.TrimSpace(baseURL) == "" {
		return errors.New("file base url is empty")
	}
	baseURL = strings.TrimSpace(baseURL)
	for _, f := range files {
		redact.Logf("strajaguard downloading %s (%d bytes)", f.Path, f.Size)
		localPath, err := resolveBundlePath(baseDir, filepath.FromSlash(f.Path))
		if err != nil {
			return fmt.Errorf("manifest path %s rejected: %w", f.Path, err)
		}
		if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
			return fmt.Errorf("create dir for %s: %w", f.Path, err)
		}

		remote := baseURL + url.QueryEscape(f.Path)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, remote, nil)
		if err != nil {
			return wrapRedactedError("build file request for "+f.Path, err)
		}
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := client.Do(req)
		if err != nil {
			return wrapRedactedError("download file "+f.Path, err)
		}
		if resp.StatusCode != http.StatusOK {
			errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
			resp.Body.Close()
			return fmt.Errorf("download file %s status: %s: %s", f.Path, resp.Status, strings.TrimSpace(string(errBody)))
		}

		dst, err := os.Create(localPath)
		if err != nil {
			resp.Body.Close()
			return fmt.Errorf("create local file %s: %w", localPath, err)
		}

		h := sha256.New()
		prog := newProgressLogger(f.Path, f.Size)
		n, err := io.Copy(io.MultiWriter(dst, h), io.TeeReader(resp.Body, prog))
		resp.Body.Close()
		closeErr := dst.Close()
		prog.Finish()
		if err != nil {
			return fmt.Errorf("write file %s: %w", f.Path, err)
		}
		if closeErr != nil {
			return fmt.Errorf("close file %s: %w", f.Path, closeErr)
		}

		if n != f.Size && f.Size > 0 {
			return fmt.Errorf("size mismatch for %s: expected %d, got %d", f.Path, f.Size, n)
		}

		sum := hex.EncodeToString(h.Sum(nil))
		if f.SHA256 != "" && !strings.EqualFold(sum, f.SHA256) {
			return fmt.Errorf("sha256 mismatch for %s: expected %s, got %s", f.Path, f.SHA256, sum)
		}
	}
	return nil
}

func resolveBundlePath(baseDir, rel string) (string, error) {
	base := filepath.Clean(baseDir)
	if rel == "" {
		return "", errors.New("empty path")
	}
	if strings.HasPrefix(rel, "/") || strings.Contains(rel, `:\`) {
		return "", errors.New("absolute paths not allowed")
	}
	target := filepath.Join(base, rel)
	normalized := filepath.Clean(target)
	if !strings.HasPrefix(normalized, base) {
		return "", errors.New("path escapes bundle dir")
	}
	return normalized, nil
}

type licenseValidateResponse struct {
	Status      string         `json:"status"`
	Message     string         `json:"message"`
	License     licenseSection `json:"license"`
	Bundles     bundleSection  `json:"bundles"`
	BundleToken string         `json:"bundle_token"`
}

type licenseSection struct {
	Tier       string               `json:"tier"`
	ValidUntil string               `json:"valid_until"`
	Models     map[string]modelInfo `json:"models"`
}

type modelInfo struct {
	Enabled       bool   `json:"enabled"`
	LatestVersion string `json:"latest_version"`
}

type bundleSection map[string]BundleInfo

func normalizeBundleFamily(family string) string {
	family = strings.TrimSpace(family)
	if family == "" {
		return "strajaguard_v1"
	}
	return strings.Trim(family, "/")
}

func bundleFamilyVariants(family string) []string {
	normalized := normalizeBundleFamily(family)
	seen := map[string]struct{}{}
	var out []string
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" {
			return
		}
		if _, ok := seen[v]; ok {
			return
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	add(normalized)
	add(normalized + "/")
	add(normalized + "//")
	return out
}

func lookupModelInfo(models map[string]modelInfo, family string) (modelInfo, bool) {
	if len(models) == 0 {
		return modelInfo{}, false
	}
	family = normalizeBundleFamily(family)
	if v, ok := models[family]; ok {
		return v, true
	}
	for k, v := range models {
		if normalizeBundleFamily(k) == family {
			return v, true
		}
	}
	return modelInfo{}, false
}

func lookupBundleInfo(bundles map[string]BundleInfo, family string) (BundleInfo, bool) {
	if len(bundles) == 0 {
		return BundleInfo{}, false
	}
	family = normalizeBundleFamily(family)
	if v, ok := bundles[family]; ok {
		return v, true
	}
	for k, v := range bundles {
		if normalizeBundleFamily(k) == family {
			return v, true
		}
	}
	return BundleInfo{}, false
}

type progressLogger struct {
	name       string
	total      int64
	downloaded int64
	step       int64
	next       int64
	start      time.Time
}

func newProgressLogger(name string, total int64) *progressLogger {
	step := total / 20 // aim for ~5% increments
	if step <= 0 {
		step = 1 << 20 // 1MB steps for unknown/very small totals
	}
	return &progressLogger{
		name:  name,
		total: total,
		step:  step,
		next:  step,
		start: time.Now(),
	}
}

func (p *progressLogger) Write(b []byte) (int, error) {
	n := len(b)
	p.downloaded += int64(n)
	if p.downloaded >= p.next {
		percent := int64(0)
		if p.total > 0 {
			percent = p.downloaded * 100 / p.total
		}
		redact.Logf("strajaguard download progress %s: %d/%d bytes (%d%%)", p.name, p.downloaded, p.total, percent)
		p.next += p.step
	}
	return n, nil
}

func (p *progressLogger) Finish() {
	if p == nil {
		return
	}
	duration := time.Since(p.start).Round(time.Second)
	redact.Logf("strajaguard download complete %s: %d bytes in %s", p.name, p.downloaded, duration)
}

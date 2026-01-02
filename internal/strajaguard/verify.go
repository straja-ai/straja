package strajaguard

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// VerifyBundleIntegrity validates signature + hashes for a local bundle.
func VerifyBundleIntegrity(baseDir, version string) error {
	if strings.TrimSpace(baseDir) == "" || strings.TrimSpace(version) == "" {
		return fmt.Errorf("bundle dir or version missing")
	}
	dir := filepath.Join(baseDir, version)

	manifestPath := filepath.Join(dir, "manifest.json")
	sigPath := filepath.Join(dir, "manifest.sig")
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}

	var manifest Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return fmt.Errorf("decode manifest: %w", err)
	}
	if manifest.Version != version {
		return fmt.Errorf("manifest version mismatch: expected %s got %s", version, manifest.Version)
	}

	sigEncoded, sigAlg, rawSig, err := readSignatureFile(sigPath)
	if err != nil {
		return err
	}

	pk, err := manifestPublicKey()
	if err != nil {
		return fmt.Errorf("load manifest public key: %w", err)
	}
	if err := verifyManifest(manifestBytes, manifest.Version, sigEncoded, sigAlg, pk); err != nil {
		return err
	}

	for _, f := range manifest.Files {
		local, err := resolveBundlePath(dir, filepath.FromSlash(f.Path))
		if err != nil {
			return fmt.Errorf("resolve path %s: %w", f.Path, err)
		}
		info, err := os.Stat(local)
		if err != nil {
			return fmt.Errorf("stat %s: %w", f.Path, err)
		}
		if f.Size > 0 && info.Size() != f.Size {
			return fmt.Errorf("size mismatch for %s: expected %d got %d", f.Path, f.Size, info.Size())
		}
		h := sha256.New()
		fh, err := os.Open(local)
		if err != nil {
			return fmt.Errorf("open %s: %w", f.Path, err)
		}
		if _, err := io.Copy(h, fh); err != nil {
			fh.Close()
			return fmt.Errorf("hash %s: %w", f.Path, err)
		}
		fh.Close()
		sum := hex.EncodeToString(h.Sum(nil))
		if f.SHA256 != "" && !strings.EqualFold(sum, f.SHA256) {
			return fmt.Errorf("sha256 mismatch for %s: expected %s got %s", f.Path, f.SHA256, sum)
		}
	}

	// also ensure manifest.sig is readable to avoid unused warning
	_ = rawSig
	return nil
}

func readSignatureFile(path string) (encoded string, alg string, raw []byte, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", nil, fmt.Errorf("read manifest signature: %w", err)
	}
	raw = data
	var sig ManifestSignature
	if jsonErr := json.Unmarshal(data, &sig); jsonErr == nil && strings.TrimSpace(sig.Signature) != "" {
		return strings.TrimSpace(sig.Signature), sig.Algorithm, raw, nil
	}
	return strings.TrimSpace(string(data)), "ed25519", raw, nil
}

package updater

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultOwner   = "straja-ai"
	defaultRepo    = "straja"
	githubAPIBase  = "https://api.github.com"
	githubSiteBase = "https://github.com"
)

type Client struct {
	Owner      string
	Repository string
	HTTPClient *http.Client
}

type CheckResult struct {
	CurrentVersion  string
	LatestVersion   string
	Comparable      bool
	UpdateAvailable bool
}

type ApplyOptions struct {
	CurrentVersion string
	TargetVersion  string
	InstallDir     string
	PreserveConfig bool
}

type ApplyResult struct {
	FromVersion string
	ToVersion   string
	Asset       string
	InstallDir  string
	Applied     bool
}

func NewDefaultClient() *Client {
	return &Client{
		Owner:      defaultOwner,
		Repository: defaultRepo,
		HTTPClient: &http.Client{Timeout: 60 * time.Second},
	}
}

func (c *Client) Check(ctx context.Context, currentVersion string) (CheckResult, error) {
	latest, err := c.LatestReleaseTag(ctx)
	if err != nil {
		return CheckResult{}, err
	}
	updateAvailable, comparable := compareVersions(currentVersion, latest)
	return CheckResult{
		CurrentVersion:  strings.TrimSpace(currentVersion),
		LatestVersion:   latest,
		Comparable:      comparable,
		UpdateAvailable: updateAvailable,
	}, nil
}

func (c *Client) LatestReleaseTag(ctx context.Context) (string, error) {
	type latestReleaseResponse struct {
		TagName string `json:"tag_name"`
	}
	if ctx == nil {
		ctx = context.Background()
	}
	url := fmt.Sprintf("%s/repos/%s/%s/releases/latest", githubAPIBase, c.owner(), c.repository())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "straja-updater")
	resp, err := c.http().Do(req)
	if err != nil {
		return "", fmt.Errorf("query latest release: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("query latest release failed: status=%d body=%q", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var payload latestReleaseResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", fmt.Errorf("decode latest release response: %w", err)
	}
	tag := strings.TrimSpace(payload.TagName)
	if tag == "" {
		return "", errors.New("latest release tag is empty")
	}
	return tag, nil
}

func (c *Client) Apply(ctx context.Context, opts ApplyOptions) (ApplyResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	target := strings.TrimSpace(opts.TargetVersion)
	if target == "" {
		latest, err := c.LatestReleaseTag(ctx)
		if err != nil {
			return ApplyResult{}, err
		}
		target = latest
	}

	current := strings.TrimSpace(opts.CurrentVersion)
	if available, comparable := compareVersions(current, target); comparable && !available {
		installDir, err := normalizeInstallDir(opts.InstallDir)
		if err != nil {
			return ApplyResult{}, err
		}
		return ApplyResult{
			FromVersion: current,
			ToVersion:   target,
			InstallDir:  installDir,
			Applied:     false,
		}, nil
	}

	asset, err := AssetName(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return ApplyResult{}, err
	}

	installDir, err := normalizeInstallDir(opts.InstallDir)
	if err != nil {
		return ApplyResult{}, err
	}

	tmpRoot, err := os.MkdirTemp("", "straja-update-*")
	if err != nil {
		return ApplyResult{}, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpRoot)

	assetPath := filepath.Join(tmpRoot, asset)
	if _, err := c.downloadReleaseAsset(ctx, target, asset, assetPath); err != nil {
		return ApplyResult{}, err
	}
	if err := c.verifyAssetChecksum(ctx, target, asset, assetPath); err != nil {
		return ApplyResult{}, err
	}

	stageDir := filepath.Join(tmpRoot, "stage")
	if err := os.MkdirAll(stageDir, 0o755); err != nil {
		return ApplyResult{}, fmt.Errorf("create stage dir: %w", err)
	}
	if err := extractArchive(assetPath, stageDir); err != nil {
		return ApplyResult{}, err
	}

	packageDir, err := locatePackageDir(stageDir)
	if err != nil {
		return ApplyResult{}, err
	}
	if err := verifyPackageContents(packageDir); err != nil {
		return ApplyResult{}, err
	}

	if err := applyPackage(packageDir, installDir, opts.PreserveConfig); err != nil {
		return ApplyResult{}, err
	}

	return ApplyResult{
		FromVersion: current,
		ToVersion:   target,
		Asset:       asset,
		InstallDir:  installDir,
		Applied:     true,
	}, nil
}

func normalizeInstallDir(installDir string) (string, error) {
	trimmed := strings.TrimSpace(installDir)
	if trimmed != "" {
		return filepath.Clean(trimmed), nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve current executable: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		resolved = exe
	}
	return filepath.Dir(resolved), nil
}

func (c *Client) verifyAssetChecksum(ctx context.Context, tag, asset, assetPath string) error {
	url := c.releaseAssetURL(tag, "checksums.txt")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "straja-updater")
	resp, err := c.http().Do(req)
	if err != nil {
		return fmt.Errorf("download checksums.txt: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("download checksums.txt failed: status=%d body=%q", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read checksums.txt: %w", err)
	}
	sumByAsset := parseChecksums(string(body))
	expected, ok := sumByAsset[asset]
	if !ok {
		return fmt.Errorf("checksums.txt does not contain %s", asset)
	}
	got, err := fileSHA256(assetPath)
	if err != nil {
		return err
	}
	if !strings.EqualFold(expected, got) {
		return fmt.Errorf("checksum mismatch for %s: expected=%s got=%s", asset, expected, got)
	}
	return nil
}

func (c *Client) downloadReleaseAsset(ctx context.Context, tag, asset, destinationPath string) (string, error) {
	url := c.releaseAssetURL(tag, asset)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "straja-updater")
	resp, err := c.http().Do(req)
	if err != nil {
		return "", fmt.Errorf("download asset %s: %w", asset, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("download asset %s failed: status=%d body=%q", asset, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	out, err := os.Create(destinationPath)
	if err != nil {
		return "", fmt.Errorf("create %s: %w", destinationPath, err)
	}
	defer out.Close()
	h := sha256.New()
	mw := io.MultiWriter(out, h)
	if _, err := io.Copy(mw, resp.Body); err != nil {
		return "", fmt.Errorf("save %s: %w", asset, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (c *Client) owner() string {
	if strings.TrimSpace(c.Owner) != "" {
		return strings.TrimSpace(c.Owner)
	}
	return defaultOwner
}

func (c *Client) repository() string {
	if strings.TrimSpace(c.Repository) != "" {
		return strings.TrimSpace(c.Repository)
	}
	return defaultRepo
}

func (c *Client) http() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return &http.Client{Timeout: 60 * time.Second}
}

func (c *Client) releaseAssetURL(tag, name string) string {
	return fmt.Sprintf("%s/%s/%s/releases/download/%s/%s", githubSiteBase, c.owner(), c.repository(), tag, name)
}

func AssetName(goos, goarch string) (string, error) {
	normalizedArch := goarch
	switch goarch {
	case "x86_64":
		normalizedArch = "amd64"
	case "aarch64":
		normalizedArch = "arm64"
	}

	switch goos {
	case "linux", "darwin":
		if normalizedArch != "amd64" && normalizedArch != "arm64" {
			return "", fmt.Errorf("unsupported architecture: %s", goarch)
		}
		return fmt.Sprintf("straja_%s_%s.tar.gz", goos, normalizedArch), nil
	case "windows":
		if normalizedArch != "amd64" {
			return "", fmt.Errorf("unsupported windows architecture: %s", goarch)
		}
		return "straja_windows_amd64.zip", nil
	default:
		return "", fmt.Errorf("unsupported operating system: %s", goos)
	}
}

func compareVersions(current, latest string) (updateAvailable bool, comparable bool) {
	curParts, ok := normalizeVersion(current)
	if !ok {
		return false, false
	}
	latestParts, ok := normalizeVersion(latest)
	if !ok {
		return false, false
	}
	for i := 0; i < 3; i++ {
		if curParts[i] == latestParts[i] {
			continue
		}
		return curParts[i] < latestParts[i], true
	}
	return false, true
}

func normalizeVersion(v string) ([3]int, bool) {
	var out [3]int
	s := strings.TrimSpace(v)
	if s == "" {
		return out, false
	}
	s = strings.TrimPrefix(s, "v")
	if idx := strings.IndexAny(s, "-+"); idx >= 0 {
		s = s[:idx]
	}
	parts := strings.Split(s, ".")
	if len(parts) < 3 {
		return out, false
	}
	for i := 0; i < 3; i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

func parseChecksums(content string) map[string]string {
	result := map[string]string{}
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			continue
		}
		sum := strings.ToLower(fields[0])
		name := strings.TrimPrefix(fields[len(fields)-1], "*")
		if len(sum) != 64 {
			continue
		}
		result[name] = sum
	}
	return result
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func extractArchive(assetPath, destination string) error {
	switch {
	case strings.HasSuffix(assetPath, ".tar.gz"):
		return extractTarGz(assetPath, destination)
	case strings.HasSuffix(assetPath, ".zip"):
		return extractZip(assetPath, destination)
	default:
		return fmt.Errorf("unsupported archive format: %s", assetPath)
	}
}

func extractTarGz(assetPath, destination string) error {
	f, err := os.Open(assetPath)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("open gzip stream: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read tar entry: %w", err)
		}
		targetPath, err := secureJoin(destination, hdr.Name)
		if err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			mode := os.FileMode(hdr.Mode).Perm()
			if mode == 0 {
				mode = 0o755
			}
			if err := os.MkdirAll(targetPath, mode); err != nil {
				return fmt.Errorf("create dir %s: %w", targetPath, err)
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
				return fmt.Errorf("create parent dir %s: %w", filepath.Dir(targetPath), err)
			}
			mode := os.FileMode(hdr.Mode).Perm()
			if mode == 0 {
				mode = 0o644
			}
			out, err := os.OpenFile(targetPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
			if err != nil {
				return fmt.Errorf("create file %s: %w", targetPath, err)
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return fmt.Errorf("write file %s: %w", targetPath, err)
			}
			if err := out.Close(); err != nil {
				return fmt.Errorf("close file %s: %w", targetPath, err)
			}
		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
				return fmt.Errorf("create parent dir %s: %w", filepath.Dir(targetPath), err)
			}
			_ = os.Remove(targetPath)
			if err := os.Symlink(hdr.Linkname, targetPath); err != nil {
				return fmt.Errorf("create symlink %s -> %s: %w", targetPath, hdr.Linkname, err)
			}
		default:
			continue
		}
	}
}

func extractZip(assetPath, destination string) error {
	zr, err := zip.OpenReader(assetPath)
	if err != nil {
		return fmt.Errorf("open zip archive: %w", err)
	}
	defer zr.Close()
	for _, f := range zr.File {
		targetPath, err := secureJoin(destination, f.Name)
		if err != nil {
			return err
		}
		mode := f.Mode()
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(targetPath, 0o755); err != nil {
				return fmt.Errorf("create dir %s: %w", targetPath, err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
			return fmt.Errorf("create parent dir %s: %w", filepath.Dir(targetPath), err)
		}
		if mode&os.ModeSymlink != 0 {
			rc, err := f.Open()
			if err != nil {
				return fmt.Errorf("open symlink payload %s: %w", f.Name, err)
			}
			targetBytes, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return fmt.Errorf("read symlink payload %s: %w", f.Name, err)
			}
			_ = os.Remove(targetPath)
			if err := os.Symlink(string(targetBytes), targetPath); err != nil {
				return fmt.Errorf("create symlink %s: %w", targetPath, err)
			}
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("open file %s: %w", f.Name, err)
		}
		writeMode := mode.Perm()
		if writeMode == 0 {
			writeMode = 0o644
		}
		out, err := os.OpenFile(targetPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, writeMode)
		if err != nil {
			rc.Close()
			return fmt.Errorf("create file %s: %w", targetPath, err)
		}
		if _, err := io.Copy(out, rc); err != nil {
			out.Close()
			rc.Close()
			return fmt.Errorf("write file %s: %w", targetPath, err)
		}
		if err := out.Close(); err != nil {
			rc.Close()
			return fmt.Errorf("close file %s: %w", targetPath, err)
		}
		if err := rc.Close(); err != nil {
			return fmt.Errorf("close source file %s: %w", f.Name, err)
		}
	}
	return nil
}

func secureJoin(root, name string) (string, error) {
	cleaned := filepath.Clean(name)
	if cleaned == "." {
		return root, nil
	}
	if strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) || cleaned == ".." || filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("archive contains invalid path: %s", name)
	}
	target := filepath.Join(root, cleaned)
	cleanRoot := filepath.Clean(root)
	if target != cleanRoot && !strings.HasPrefix(target, cleanRoot+string(filepath.Separator)) {
		return "", fmt.Errorf("archive path escapes destination: %s", name)
	}
	return target, nil
}

func locatePackageDir(stageDir string) (string, error) {
	primary := filepath.Join(stageDir, "straja")
	if stat, err := os.Stat(primary); err == nil && stat.IsDir() {
		return primary, nil
	}
	entries, err := os.ReadDir(stageDir)
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		candidate := filepath.Join(stageDir, entry.Name())
		if err := verifyPackageContents(candidate); err == nil {
			return candidate, nil
		}
	}
	return "", errors.New("release archive does not contain a valid straja package directory")
}

func verifyPackageContents(packageDir string) error {
	binaryName := "straja"
	if runtime.GOOS == "windows" {
		binaryName = "straja.exe"
	}
	path := filepath.Join(packageDir, binaryName)
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("missing %s in extracted package", binaryName)
	}
	return nil
}

func applyPackage(srcDir, dstDir string, preserveConfig bool) error {
	backupRoot, err := os.MkdirTemp(dstDir, ".straja-update-backup-*")
	if err != nil {
		return fmt.Errorf("create backup dir: %w", err)
	}

	created := map[string]struct{}{}
	backedUp := map[string]struct{}{}

	rollback := func() {
		createdList := make([]string, 0, len(created))
		for path := range created {
			createdList = append(createdList, path)
		}
		sort.Slice(createdList, func(i, j int) bool {
			return len(createdList[i]) > len(createdList[j])
		})
		for _, path := range createdList {
			_ = os.RemoveAll(path)
		}
		_ = restoreBackup(backupRoot, dstDir)
	}

	err = filepath.WalkDir(srcDir, func(srcPath string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(srcDir, srcPath)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if preserveConfig && rel == "straja.yaml" {
			dstPath := filepath.Join(dstDir, rel)
			if _, err := os.Stat(dstPath); err == nil {
				return nil
			}
		}

		dstPath := filepath.Join(dstDir, rel)
		if d.IsDir() {
			return os.MkdirAll(dstPath, 0o755)
		}
		if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
			return err
		}

		if _, err := os.Lstat(dstPath); err == nil {
			if _, already := backedUp[dstPath]; !already {
				backupPath := filepath.Join(backupRoot, rel)
				if err := copyNode(dstPath, backupPath); err != nil {
					return fmt.Errorf("backup %s: %w", dstPath, err)
				}
				backedUp[dstPath] = struct{}{}
			}
		} else if errors.Is(err, os.ErrNotExist) {
			created[dstPath] = struct{}{}
		} else {
			return err
		}

		if err := installNode(srcPath, dstPath); err != nil {
			return fmt.Errorf("install %s: %w", rel, err)
		}
		return nil
	})
	if err != nil {
		rollback()
		_ = os.RemoveAll(backupRoot)
		return err
	}
	if err := os.RemoveAll(backupRoot); err != nil {
		return fmt.Errorf("cleanup backup dir: %w", err)
	}
	return nil
}

func restoreBackup(backupRoot, dstDir string) error {
	return filepath.WalkDir(backupRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(backupRoot, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		dstPath := filepath.Join(dstDir, rel)
		if d.IsDir() {
			return os.MkdirAll(dstPath, 0o755)
		}
		return installNode(path, dstPath)
	})
}

func installNode(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	mode := info.Mode()
	switch {
	case mode&os.ModeSymlink != 0:
		target, err := os.Readlink(src)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		_ = os.RemoveAll(dst)
		return os.Symlink(target, dst)
	case mode.IsRegular():
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		srcFile, err := os.Open(src)
		if err != nil {
			return err
		}
		defer srcFile.Close()

		tmpFile, err := os.CreateTemp(filepath.Dir(dst), ".straja-update-*")
		if err != nil {
			return err
		}
		tmpName := tmpFile.Name()
		success := false
		defer func() {
			if !success {
				_ = os.Remove(tmpName)
			}
		}()
		if _, err := io.Copy(tmpFile, srcFile); err != nil {
			tmpFile.Close()
			return err
		}
		if err := tmpFile.Chmod(mode.Perm()); err != nil {
			tmpFile.Close()
			return err
		}
		if err := tmpFile.Close(); err != nil {
			return err
		}
		if err := os.Rename(tmpName, dst); err != nil {
			return err
		}
		success = true
		return nil
	default:
		return fmt.Errorf("unsupported file type: %s", src)
	}
}

func copyNode(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	mode := info.Mode()
	switch {
	case mode.IsDir():
		return os.MkdirAll(dst, mode.Perm())
	case mode&os.ModeSymlink != 0:
		target, err := os.Readlink(src)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		_ = os.RemoveAll(dst)
		return os.Symlink(target, dst)
	case mode.IsRegular():
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		in, err := os.Open(src)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode.Perm())
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	default:
		return fmt.Errorf("unsupported backup type: %s", src)
	}
}

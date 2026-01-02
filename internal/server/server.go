package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/straja-ai/straja/internal/activation"
	"github.com/straja-ai/straja/internal/auth"
	"github.com/straja-ai/straja/internal/config"
	"github.com/straja-ai/straja/internal/console"
	"github.com/straja-ai/straja/internal/inference"
	"github.com/straja-ai/straja/internal/intel"
	"github.com/straja-ai/straja/internal/license"
	"github.com/straja-ai/straja/internal/mockprovider"
	"github.com/straja-ai/straja/internal/policy"
	"github.com/straja-ai/straja/internal/provider"
	"github.com/straja-ai/straja/internal/redact"
	"github.com/straja-ai/straja/internal/strajaguard"
)

// Server wraps the HTTP server components for Straja.
type Server struct {
	mux               *http.ServeMux
	cfg               *config.Config
	auth              *auth.Auth
	policy            policy.Engine
	providers         map[string]provider.Provider // name -> provider
	defaultProvider   string                       // name of default provider
	activation        activation.Emitter
	loggingLevel      string
	projectProviders  map[string]string // project ID -> provider name
	licenseClaims     *license.LicenseClaims
	intelEnabled      bool
	licenseKey        string
	intelStatus       string
	intelMeta         *strajaguard.ValidationMeta
	intelBundleVer    string
	strajaGuardStatus string
	strajaGuardMeta   *strajaguard.ValidationMeta
	httpClient        *http.Client
	inFlightLimiter   chan struct{}
	strajaGuardModel  *strajaguard.StrajaGuardModel
	activeBundleVer   string
	requireML         bool
	allowRegexOnly    bool
}

func isNetworkyError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "timeout"),
		strings.Contains(msg, "deadline"),
		strings.Contains(msg, "temporary"),
		strings.Contains(msg, "connection reset"),
		strings.Contains(msg, "connection refused"),
		strings.Contains(msg, "dial tcp"),
		strings.Contains(msg, "tls handshake"),
		strings.Contains(msg, "503"),
		strings.Contains(msg, "502"):
		return true
	default:
		return false
	}
}

type consoleProject struct {
	ID       string `json:"id"`
	Provider string `json:"provider"`
}

func (s *Server) handleConsoleProjects(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	projects := make([]consoleProject, 0, len(s.cfg.Projects))
	for _, p := range s.cfg.Projects {
		projects = append(projects, consoleProject{
			ID:       p.ID,
			Provider: p.Provider,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(projects); err != nil {
		redact.Logf("failed to write console projects: %v", err)
	}
}

type consoleChatRequest struct {
	ProjectID string        `json:"project_id"`
	Model     string        `json:"model"`
	Messages  []chatMessage `json:"messages"`
}

func (s *Server) handleConsoleChat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.cfg.Server.MaxRequestBodyBytes > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, s.cfg.Server.MaxRequestBodyBytes)
	}

	var reqBody consoleChatRequest
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		if isRequestTooLarge(err) {
			writeOpenAIError(w, http.StatusRequestEntityTooLarge, "Request body too large", "invalid_request_error")
			return
		}
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if reqBody.ProjectID == "" {
		http.Error(w, "missing project_id", http.StatusBadRequest)
		return
	}

	// lookup provider for this project
	providerName := s.projectProviders[reqBody.ProjectID]
	if providerName == "" {
		providerName = s.defaultProvider
	}
	prov, ok := s.providers[providerName]
	if !ok {
		redact.Logf("no provider %q for project %q (console)", providerName, reqBody.ProjectID)
		writeOpenAIError(w, http.StatusInternalServerError, "Straja misconfiguration: unknown provider for project", "configuration_error")
		return
	}

	// Reuse the same normalization as /v1/chat/completions:
	infReq := normalizeToInferenceRequest(reqBody.ProjectID, &chatCompletionRequest{
		Model:    reqBody.Model,
		Messages: reqBody.Messages,
	})
	infReq.Timings = &inference.Timings{}
	decision := "allow"
	defer logTimingDebug(reqBody.ProjectID, providerName, decision, infReq.Timings)

	if err := s.validateChatRequest(infReq, providerName); err != nil {
		decision = "blocked_request"
		writeOpenAIError(w, http.StatusBadRequest, err.Error(), "invalid_request_error")
		return
	}

	ctx := r.Context()
	if s.cfg.Server.UpstreamTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.cfg.Server.UpstreamTimeout)
		defer cancel()
	}

	// Policy + provider + activation, same flow as handleChatCompletions:

	prePolicyStart := time.Now()
	if err := s.policy.BeforeModel(ctx, infReq); err != nil {
		if infReq.Timings != nil {
			infReq.Timings.PrePolicy = time.Since(prePolicyStart)
		}
		decision = "blocked_before"
		s.emitActivation(ctx, w, infReq, nil, providerName, activation.DecisionBlockedBefore)
		writeOpenAIError(w, http.StatusForbidden, "Blocked by Straja policy (before model)", "policy_error")
		return
	}
	if infReq.Timings != nil {
		infReq.Timings.PrePolicy = time.Since(prePolicyStart)
	}

	providerStart := time.Now()
	infResp, err := prov.ChatCompletion(ctx, infReq)
	if infReq.Timings != nil {
		infReq.Timings.Provider = time.Since(providerStart)
	}
	if err != nil {
		redact.Logf("provider %q error (console): %v", providerName, err)
		decision = "error_provider"
		s.emitActivation(ctx, w, infReq, nil, providerName, activation.DecisionErrorProvider)
		writeOpenAIError(w, http.StatusBadGateway, "Upstream provider error", "provider_error")
		return
	}

	postPolicyStart := time.Now()
	if err := s.policy.AfterModel(ctx, infReq, infResp); err != nil {
		if infReq.Timings != nil {
			infReq.Timings.PostPolicy = time.Since(postPolicyStart)
		}
		decision = "blocked_after"
		s.emitActivation(ctx, w, infReq, infResp, providerName, activation.DecisionBlockedAfter)
		writeOpenAIError(w, http.StatusForbidden, "Blocked by Straja policy (after model)", "policy_error")
		return
	}
	if infReq.Timings != nil {
		infReq.Timings.PostPolicy = time.Since(postPolicyStart)
	}

	s.emitActivation(ctx, w, infReq, infResp, providerName, activation.DecisionAllow)

	respBody := buildChatCompletionResponse(infReq, infResp)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(respBody); err != nil {
		redact.Logf("failed to write console response: %v", err)
	}
}

// New creates a new Straja server with all routes registered.
func New(cfg *config.Config, authz *auth.Auth) *Server {
	mux := http.NewServeMux()

	// Resolve license key with env override (env wins; placeholder treated as empty).
	licenseKey := strings.TrimSpace(cfg.ResolvedLicenseKey)
	envName := strings.TrimSpace(cfg.Intelligence.LicenseKeyEnv)
	redact.Logf("license: using %s set=%t", envName, licenseKey != "")
	sgLicenseKey := strings.TrimSpace(cfg.ResolvedStrajaGuardLicenseKey)
	sgSource := strings.TrimSpace(cfg.ResolvedStrajaGuardSource)
	if sgSource == "" {
		sgSource = "intelligence.license_key"
	}
	redact.Logf("strajaguard: license key resolved set=%t source=%s", sgLicenseKey != "", sgSource)

	// Build intelligence engine (bundle-backed regex or noop) with offline license verification.
	var (
		intelEngine    intel.Engine = intel.NewRegexBundle(cfg.Policy)
		licenseClaims  *license.LicenseClaims
		intelEnabled   = cfg.Intelligence.Enabled
		intelStatus    = "online_validated"
		intelBundleVer string
	)

	if !intelEnabled {
		redact.Logf("intelligence disabled via config; running in routing-only mode")
		intelEngine = intel.NewNoop()
		intelStatus = "disabled_missing_license"
	} else {
		if strings.TrimSpace(licenseKey) == "" {
			redact.Logf("license key not provided; running regex-only (no ML bundle)")
			intelStatus = "disabled_missing_license"
		} else {
			pubKey, err := license.DefaultPublicKey()
			if err != nil {
				redact.Logf("license public key unavailable: %v; running regex-only", err)
				intelStatus = "offline_cached_bundle"
			} else {
				claims, err := license.VerifyLicenseKey(licenseKey, pubKey)
				if err != nil {
					redact.Logf("license verification failed: %v; running regex-only", err)
					intelStatus = "offline_cached_bundle"
				} else {
					licenseClaims = claims
					intelEngine = intel.NewRegexBundle(cfg.Policy)
					intelStatus = "online_validated"
				}
			}
		}
	}
	if intelEngine != nil {
		intelBundleVer = strings.TrimSpace(intelEngine.Status().BundleVersion)
	}

	// Build StrajaGuard model (optional, offline-first)
	var (
		sgModel             *strajaguard.StrajaGuardModel
		activeBundleVersion string
		intelMeta           *strajaguard.ValidationMeta
		sgStatus            string
		sgMeta              *strajaguard.ValidationMeta
	)
	sgStatus = "disabled_missing_bundle"
	strajaGuardDir := cfg.Security.BundleDir
	if cfg.Intel.StrajaGuardV1.IntelDir != "" {
		strajaGuardDir = filepath.Join(cfg.Intel.StrajaGuardV1.IntelDir, "strajaguard_v1")
		cfg.Security.BundleDir = strajaGuardDir
	}

	if !cfg.Security.Enabled || !cfg.Intel.StrajaGuardV1.Enabled {
		redact.Logf("strajaguard disabled via config; running regex-only")
		sgStatus = "disabled_missing_bundle"
	} else {
		rt := strajaguard.ResolveRuntime(strajaguard.RuntimeConfig{
			MaxSessions:  cfg.StrajaGuard.MaxSessions,
			IntraThreads: cfg.StrajaGuard.IntraThreads,
			InterThreads: cfg.StrajaGuard.InterThreads,
		})
		redact.Logf("strajaguard runtime: max_sessions=%d intra_threads=%d inter_threads=%d source=max_sessions=%s intra=%s inter=%s",
			rt.MaxSessions, rt.IntraThreads, rt.InterThreads,
			rt.MaxSessionsSource, rt.IntraSource, rt.InterSource)

		allowRegexOnly := cfg.Intel.StrajaGuardV1.AllowRegexOnly
		requireML := cfg.Intel.StrajaGuardV1.RequireML
		mustExit := requireML && !allowRegexOnly
		fail := func(format string, args ...interface{}) {
			if mustExit {
				redact.Fatalf(format, args...)
			}
			redact.Logf(format, args...)
		}

		state, _ := strajaguard.LoadBundleState(strajaGuardDir)
		currentVersion := strings.TrimSpace(state.CurrentVersion)
		var cachedMeta *strajaguard.ValidationMeta
		if meta, err := strajaguard.LoadValidationMeta(strajaGuardDir); err == nil {
			cachedMeta = &meta
		}

		if sgLicenseKey == "" {
			if currentVersion != "" {
				if integErr := strajaguard.VerifyBundleIntegrity(strajaGuardDir, currentVersion); integErr == nil {
					if model, loadErr := strajaguard.LoadModel(filepath.Join(strajaGuardDir, currentVersion), cfg.Security.SeqLen, rt); loadErr == nil {
						sgModel = model
						activeBundleVersion = currentVersion
						sgStatus = "offline_cached_bundle"
						if cachedMeta != nil {
							sgMeta = cachedMeta
						}
						redact.Logf("strajaguard: using offline cached bundle version=%s (license key missing)", currentVersion)
					} else {
						sgStatus = "disabled_invalid_bundle"
						redact.Logf("strajaguard: cached bundle present but failed to load: %v", loadErr)
					}
				} else {
					sgStatus = "disabled_invalid_bundle"
					redact.Logf("strajaguard: cached bundle failed integrity: %v", integErr)
				}
			} else {
				sgStatus = "disabled_missing_license"
			}
		} else if err := os.MkdirAll(strajaGuardDir, 0o755); err != nil {
			fail("strajaguard: cannot create bundle dir %s: %v; running regex-only", strajaGuardDir, err)
		} else {
			ctx := context.Background()

			valRes, outcome, err := strajaguard.ValidateLicense(ctx, cfg.Intel.StrajaGuardV1.LicenseServerBaseURL, sgLicenseKey, currentVersion, cfg.Intel.StrajaGuardV1.LicenseValidateTimeoutSeconds)
			if err == nil && valRes != nil && outcome == strajaguard.ValidateOK {
				redact.Logf("strajaguard: license validate returned version=%s update_available=%t", valRes.BundleInfo.Version, valRes.BundleInfo.UpdateAvailable)
				dir, err := strajaguard.EnsureStrajaGuardVersion(ctx, strajaGuardDir, valRes.BundleInfo.Version, valRes.BundleInfo.ManifestURL, valRes.BundleInfo.SignatureURL, valRes.BundleInfo.FileBaseURL, valRes.BundleToken, cfg.Intel.StrajaGuardV1.BundleDownloadTimeoutSeconds)
				if err != nil {
					redact.Logf("strajaguard: bundle version=%s verification failed: %v", valRes.BundleInfo.Version, err)
				} else if model, loadErr := strajaguard.LoadModel(dir, cfg.Security.SeqLen, rt); loadErr != nil {
					redact.Logf("strajaguard: bundle version=%s downloaded but failed to load: %v", valRes.BundleInfo.Version, loadErr)
				} else {
					state.PreviousVersion = state.CurrentVersion
					state.CurrentVersion = valRes.BundleInfo.Version
					_ = strajaguard.SaveBundleState(strajaGuardDir, state)
					fp := licenseFingerprint(sgLicenseKey)
					meta := strajaguard.ValidationMeta{
						Version:            state.CurrentVersion,
						LastValidatedAt:    time.Now().UTC().Format(time.RFC3339),
						LicenseFingerprint: fp,
						Source:             "online",
					}
					if err := strajaguard.SaveValidationMeta(strajaGuardDir, meta); err == nil {
						sgMeta = &meta
					}
					sgModel = model
					activeBundleVersion = state.CurrentVersion
					sgStatus = "online_validated"
					redact.Logf("strajaguard: bundle version=%s verified and activated", state.CurrentVersion)
					redact.Logf("strajaguard: pool_size=%d intra_threads=%d inter_threads=%d seq_len=%d",
						sgModel.PoolSize(), sgModel.IntraThreads(), sgModel.InterThreads(), cfg.Security.SeqLen)
				}
			} else {
				switch outcome {
				case strajaguard.ValidateInvalidLicense:
					redact.Logf("strajaguard: license invalid; refusing cached bundle; ml disabled")
					sgStatus = "disabled_invalid_license"
				case strajaguard.ValidateNetworkError:
					redact.Logf("strajaguard: license validate failed: %v", err)
					if currentVersion != "" {
						if integErr := strajaguard.VerifyBundleIntegrity(strajaGuardDir, currentVersion); integErr == nil {
							model, loadErr := strajaguard.LoadModel(filepath.Join(strajaGuardDir, currentVersion), cfg.Security.SeqLen, rt)
							if loadErr != nil {
								sgStatus = "disabled_invalid_bundle"
							} else {
								sgModel = model
								activeBundleVersion = currentVersion
								sgStatus = "offline_cached_bundle"
								if cachedMeta != nil {
									sgMeta = cachedMeta
								}
								redact.Logf("strajaguard: using offline cached bundle version=%s (reason=validate_network_error)", currentVersion)
							}
						} else {
							sgStatus = "disabled_invalid_bundle"
						}
					} else {
						sgStatus = "disabled_missing_bundle"
					}
				default:
					redact.Logf("strajaguard: license validate failed (other): %v; cached bundle not used", err)
					sgStatus = "disabled_invalid_license"
				}
			}

			if sgModel != nil {
				if dur, err := sgModel.Warmup("hello"); err != nil {
					if mustExit {
						redact.Fatalf("strajaguard: warmup inference failed: %v", err)
					}
					redact.Logf("strajaguard: warmup inference failed: %v; running regex-only", err)
					sgModel = nil
					activeBundleVersion = ""
					sgStatus = "disabled_invalid_bundle"
				} else {
					redact.Logf("strajaguard: warmup inference ok duration_ms=%.2f", float64(dur.Microseconds())/1000)
				}
			}
		}
	}

	// Build policy engine (consumes intelEngine)
	pol := policy.NewBasic(cfg.Policy, cfg.Security, intelEngine, sgModel)

	// Build providers
	provs, provErr := buildProviderRegistry(cfg)
	if provErr != nil {
		redact.Logf("warning: failed to build providers from config: %v", provErr)
		redact.Logf("falling back to echo provider")
		provs = map[string]provider.Provider{
			"echo": provider.NewEcho(),
		}
		if cfg.DefaultProvider == "" {
			cfg.DefaultProvider = "echo"
		}
	}

	// Build project → provider map
	projectProviders := make(map[string]string)
	for _, p := range cfg.Projects {
		providerName := p.Provider
		if providerName == "" {
			providerName = cfg.DefaultProvider
		}
		projectProviders[p.ID] = providerName
	}

	var limiter chan struct{}
	if cfg.Server.MaxInFlightRequests > 0 {
		limiter = make(chan struct{}, cfg.Server.MaxInFlightRequests)
	}

	licenseHTTPTimeout := time.Duration(cfg.Intel.StrajaGuardV1.LicenseValidateTimeoutSeconds) * time.Second
	if licenseHTTPTimeout <= 0 {
		licenseHTTPTimeout = 10 * time.Second
	}

	s := &Server{
		mux:               mux,
		cfg:               cfg,
		auth:              authz,
		policy:            pol,
		providers:         provs,
		defaultProvider:   cfg.DefaultProvider,
		activation:        activation.NewStdout(),
		loggingLevel:      strings.ToLower(cfg.Logging.ActivationLevel),
		projectProviders:  projectProviders,
		licenseClaims:     licenseClaims,
		intelEnabled:      intelEnabled,
		licenseKey:        licenseKey,
		intelStatus:       intelStatus,
		intelMeta:         intelMeta,
		intelBundleVer:    intelBundleVer,
		httpClient:        &http.Client{Timeout: licenseHTTPTimeout},
		inFlightLimiter:   limiter,
		strajaGuardModel:  sgModel,
		activeBundleVer:   activeBundleVersion,
		strajaGuardStatus: sgStatus,
		strajaGuardMeta:   sgMeta,
		requireML:         cfg.Intel.StrajaGuardV1.RequireML,
		allowRegexOnly:    cfg.Intel.StrajaGuardV1.AllowRegexOnly,
	}

	bundleTimeout := time.Duration(cfg.Intel.StrajaGuardV1.BundleDownloadTimeoutSeconds) * time.Second
	if bundleTimeout <= 0 {
		bundleTimeout = 30 * time.Second
	}

	redact.Logf("gateway hardening: read_header_timeout=%s read_timeout=%s write_timeout=%s idle_timeout=%s max_body_bytes=%d max_nonstream_response_bytes=%d max_in_flight=%d upstream_timeout=%s license_validate_timeout=%s bundle_download_timeout=%s require_ml=%t allow_regex_only=%t",
		cfg.Server.ReadHeaderTimeout,
		cfg.Server.ReadTimeout,
		cfg.Server.WriteTimeout,
		cfg.Server.IdleTimeout,
		cfg.Server.MaxRequestBodyBytes,
		cfg.Server.MaxNonStreamResponseBytes,
		cfg.Server.MaxInFlightRequests,
		cfg.Server.UpstreamTimeout,
		licenseHTTPTimeout,
		bundleTimeout,
		cfg.Intel.StrajaGuardV1.RequireML,
		cfg.Intel.StrajaGuardV1.AllowRegexOnly,
	)

	// Routes
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/readyz", s.handleReady)
	mux.HandleFunc("/v1/chat/completions", s.wrapHandler(s.handleChatCompletions, handlerOptions{limitBody: true, useLimiter: true}))

	// Serve console + static
	mux.Handle("/console/", console.Handler())
	mux.Handle("/console", http.RedirectHandler("/console/", http.StatusMovedPermanently))
	mux.HandleFunc("/console/api/projects", s.handleConsoleProjects)
	mux.HandleFunc("/console/api/chat", s.wrapHandler(s.handleConsoleChat, handlerOptions{limitBody: true, useLimiter: true}))

	if s.intelEnabled {
		if err := s.ValidateLicenseOnline(context.Background()); err != nil {
			redact.Logf("license online validation failed (continuing with offline-verified license): %v", err)
		}
	}

	return s
}

// ValidateLicenseOnline optionally validates the license key once at startup.
func (s *Server) ValidateLicenseOnline(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	url := strings.TrimSpace(s.cfg.Intelligence.LicenseServerURL)
	if url == "" || strings.TrimSpace(s.licenseKey) == "" {
		return nil
	}

	client := s.httpClient
	if client == nil {
		client = http.DefaultClient
	}

	if client.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, client.Timeout)
		defer cancel()
	}

	payload := struct {
		LicenseKey     string `json:"license_key"`
		GatewayVersion string `json:"gateway_version,omitempty"`
	}{
		LicenseKey:     s.licenseKey,
		GatewayVersion: os.Getenv("STRAJA_VERSION"),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal license payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build license request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		redact.Logf("license online validation warning: %v", err)
		return err
	}
	defer resp.Body.Close()

	var res struct {
		Status  string `json:"status"`
		Tier    string `json:"tier"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		redact.Logf("license online validation decode error: %v", err)
		return err
	}

	status := strings.ToLower(strings.TrimSpace(res.Status))
	if status == "ok" || status == "active" {
		if res.Tier != "" && s.licenseClaims != nil {
			s.licenseClaims.Tier = res.Tier
		}
		s.intelStatus = "enabled"
		return nil
	}

	// Any non-ok status disables intelligence for this run.
	reason := res.Message
	if reason == "" {
		reason = fmt.Sprintf("license status=%s", res.Status)
	}
	s.disableIntelligence(reason)
	return nil
}

func (s *Server) disableIntelligence(reason string) {
	if !s.intelEnabled {
		return
	}
	redact.Logf("disabling intelligence: %s", reason)
	s.intelEnabled = false
	s.licenseClaims = nil
	s.policy = policy.NewBasic(s.cfg.Policy, s.cfg.Security, intel.NewRegexBundle(s.cfg.Policy), s.strajaGuardModel)
	s.intelStatus = "regex_only_invalid_license"
}

// buildProviderRegistry constructs all configured providers.
func buildProviderRegistry(cfg *config.Config) (map[string]provider.Provider, error) {
	if len(cfg.Providers) == 0 {
		return nil, errors.New("no providers configured")
	}

	reg := make(map[string]provider.Provider, len(cfg.Providers))

	for name, pcfg := range cfg.Providers {
		switch pcfg.Type {
		case "openai":
			apiKey := strings.TrimSpace(os.Getenv(pcfg.APIKeyEnv))
			if apiKey == "" {
				apiKey = strings.TrimSpace(pcfg.APIKey)
			}
			if apiKey == "" {
				return nil, fmt.Errorf("provider %q: api key missing (env %s empty)", name, pcfg.APIKeyEnv)
			}
			reg[name] = provider.NewOpenAI(pcfg.BaseURL, apiKey, cfg.Server.UpstreamTimeout, cfg.Server.MaxNonStreamResponseBytes)
		case "mock":
			addr := mockHostPortFromBaseURL(pcfg.BaseURL)
			_, baseURL, err := mockprovider.StartMockProvider(addr)
			if err != nil {
				return nil, fmt.Errorf("provider %q: start mock provider: %w", name, err)
			}
			if baseURL == "" {
				baseURL = strings.TrimSpace(pcfg.BaseURL)
			}
			if baseURL == "" {
				baseURL = "http://127.0.0.1:18080"
			}
			reg[name] = provider.NewOpenAI(baseURL, os.Getenv(pcfg.APIKeyEnv), cfg.Server.UpstreamTimeout, cfg.Server.MaxNonStreamResponseBytes)
			redact.Logf("provider %q using mock upstream at %s", name, baseURL)
		default:
			return nil, fmt.Errorf("provider %q: unsupported type %q", name, pcfg.Type)
		}
	}

	if cfg.DefaultProvider == "" {
		return nil, errors.New("default_provider is empty")
	}
	if _, ok := reg[cfg.DefaultProvider]; !ok {
		return nil, fmt.Errorf("default_provider %q not found in providers map", cfg.DefaultProvider)
	}

	return reg, nil
}

func mockHostPortFromBaseURL(base string) string {
	base = strings.TrimSpace(base)
	if base == "" {
		return ""
	}

	u, err := url.Parse(base)
	if err != nil {
		return ""
	}
	if u.Host != "" {
		return u.Host
	}
	return ""
}

type handlerOptions struct {
	limitBody  bool
	useLimiter bool
}

func (s *Server) wrapHandler(h http.HandlerFunc, opts handlerOptions) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if opts.limitBody && s.cfg.Server.MaxRequestBodyBytes > 0 {
			r.Body = http.MaxBytesReader(w, r.Body, s.cfg.Server.MaxRequestBodyBytes)
		}

		if opts.useLimiter && s.inFlightLimiter != nil {
			select {
			case s.inFlightLimiter <- struct{}{}:
				defer func() { <-s.inFlightLimiter }()
			default:
				writeOpenAIError(w, http.StatusTooManyRequests, "Too many requests", "rate_limit_exceeded")
				return
			}
		}

		h(w, r)
	}
}

// Start runs the HTTP server on the given address.
func (s *Server) Start(addr string) error {
	if addr == "" {
		addr = s.cfg.Server.Addr
	}

	server := &http.Server{
		Addr:              addr,
		Handler:           s.mux,
		ReadHeaderTimeout: s.cfg.Server.ReadHeaderTimeout,
		ReadTimeout:       s.cfg.Server.ReadTimeout,
		WriteTimeout:      s.cfg.Server.WriteTimeout,
		IdleTimeout:       s.cfg.Server.IdleTimeout,
	}

	redact.Logf("Straja Gateway running on %s (read_header_timeout=%s, read_timeout=%s, write_timeout=%s, idle_timeout=%s)", addr, s.cfg.Server.ReadHeaderTimeout, s.cfg.Server.ReadTimeout, s.cfg.Server.WriteTimeout, s.cfg.Server.IdleTimeout)
	return server.ListenAndServe()
}

// --- Handlers ---

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

type readinessResponse struct {
	Status              string `json:"status"`
	Mode                string `json:"mode"`
	ActiveBundleVersion string `json:"active_bundle_version,omitempty"`
	Reason              string `json:"reason,omitempty"`
	IntelStatus         string `json:"intel_status,omitempty"`
	StrajaGuardStatus   string `json:"strajaguard_status,omitempty"`
	IntelLastValidated  string `json:"intel_last_validated_at,omitempty"`
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	resp, ready := s.readiness()
	w.Header().Set("Content-Type", "application/json")
	if !ready {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) readiness() (readinessResponse, bool) {
	mode := "regex_only"
	if s.strajaGuardModel != nil {
		mode = "ml"
	}

	resp := readinessResponse{
		Status:              "ready",
		Mode:                mode,
		ActiveBundleVersion: s.activeBundleVer,
		IntelStatus:         s.intelStatus,
		StrajaGuardStatus:   s.strajaGuardStatus,
	}

	if s.intelMeta != nil {
		resp.IntelLastValidated = s.intelMeta.LastValidatedAt
	} else if s.strajaGuardMeta != nil {
		resp.IntelLastValidated = s.strajaGuardMeta.LastValidatedAt
	}

	if s.cfg == nil {
		resp.Status = "not_ready"
		resp.Reason = "config_not_loaded"
		return resp, false
	}
	if len(s.providers) == 0 {
		resp.Status = "not_ready"
		resp.Reason = "no_providers_configured"
		return resp, false
	}
	if len(s.projectProviders) == 0 {
		resp.Status = "not_ready"
		resp.Reason = "no_projects_configured"
		return resp, false
	}

	if s.requireML && s.strajaGuardModel == nil {
		resp.Status = "not_ready"
		resp.Reason = "strajaguard_ml_inactive"
		return resp, false
	}

	return resp, true
}

// --- OpenAI-style request/response types for the HTTP layer ---

type chatCompletionRequest struct {
	Model    string        `json:"model"`
	Messages []chatMessage `json:"messages"`
	Stream   bool          `json:"stream,omitempty"`
	// Later we'll add: user, tools, etc.
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatCompletionResponse struct {
	ID                string                 `json:"id"`
	Object            string                 `json:"object"`
	Created           int64                  `json:"created"`
	Model             string                 `json:"model"`
	Choices           []chatCompletionChoice `json:"choices"`
	Usage             chatCompletionUsage    `json:"usage"`
	SystemFingerprint *string                `json:"system_fingerprint,omitempty"`
}

type chatCompletionChoice struct {
	Index        int         `json:"index"`
	Message      chatMessage `json:"message"`
	FinishReason string      `json:"finish_reason"`
	Logprobs     interface{} `json:"logprobs,omitempty"`
}

type chatCompletionUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

type openAIErrorBody struct {
	Error openAIErrorDetail `json:"error"`
}

type openAIErrorDetail struct {
	Message string      `json:"message"`
	Type    string      `json:"type"`
	Code    interface{} `json:"code,omitempty"`
}

func (s *Server) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.cfg.Server.MaxRequestBodyBytes > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, s.cfg.Server.MaxRequestBodyBytes)
	}

	// Auth: extract API key and map to project
	apiKey, ok := parseBearerToken(r.Header.Get("Authorization"))
	if !ok || apiKey == "" {
		writeOpenAIError(w, http.StatusUnauthorized, "Invalid or missing API key", "authentication_error")
		return
	}

	project, ok := s.auth.Lookup(apiKey)
	if !ok {
		writeOpenAIError(w, http.StatusUnauthorized, "Invalid API key", "authentication_error")
		return
	}

	var reqBody chatCompletionRequest
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		if isRequestTooLarge(err) {
			writeOpenAIError(w, http.StatusRequestEntityTooLarge, "Request body too large", "invalid_request_error")
			return
		}
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	if s.cfg.Server.UpstreamTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.cfg.Server.UpstreamTimeout)
		defer cancel()
	}

	// Determine provider for this project
	providerName := project.Provider
	if providerName == "" {
		providerName = s.defaultProvider
	}

	prov, ok := s.providers[providerName]
	if !ok {
		redact.Logf("no provider %q for project %q", providerName, project.ID)
		writeOpenAIError(w, http.StatusInternalServerError, "Straja misconfiguration: unknown provider for project", "configuration_error")
		return
	}

	// 1) Normalize HTTP/OpenAI request → internal inference.Request
	infReq := normalizeToInferenceRequest(project.ID, &reqBody)
	infReq.Timings = &inference.Timings{}
	decision := "allow"
	defer logTimingDebug(project.ID, providerName, decision, infReq.Timings)

	if err := s.validateChatRequest(infReq, providerName); err != nil {
		decision = "blocked_request"
		writeOpenAIError(w, http.StatusBadRequest, err.Error(), "invalid_request_error")
		return
	}

	// 2) Before-model block
	prePolicyStart := time.Now()
	if err := s.policy.BeforeModel(ctx, infReq); err != nil {
		if infReq.Timings != nil {
			infReq.Timings.PrePolicy = time.Since(prePolicyStart)
		}
		decision = "blocked_before"
		s.emitActivation(ctx, w, infReq, nil, providerName, activation.DecisionBlockedBefore)
		writeOpenAIError(w, http.StatusForbidden, "Blocked by Straja policy (before model)", "policy_error")
		return
	}
	if infReq.Timings != nil {
		infReq.Timings.PrePolicy = time.Since(prePolicyStart)
	}

	// 3) Provider error
	providerStart := time.Now()
	infResp, err := prov.ChatCompletion(ctx, infReq)
	if infReq.Timings != nil {
		infReq.Timings.Provider = time.Since(providerStart)
	}
	if err != nil {
		redact.Logf("provider %q error: %v", providerName, err)
		decision = "error_provider"
		s.emitActivation(ctx, w, infReq, nil, providerName, activation.DecisionErrorProvider)
		writeOpenAIError(w, http.StatusBadGateway, "Upstream provider error", "provider_error")
		return
	}

	// 4) After-model block
	postPolicyStart := time.Now()
	if err := s.policy.AfterModel(ctx, infReq, infResp); err != nil {
		if infReq.Timings != nil {
			infReq.Timings.PostPolicy = time.Since(postPolicyStart)
		}
		decision = "blocked_after"
		s.emitActivation(ctx, w, infReq, infResp, providerName, activation.DecisionBlockedAfter)
		writeOpenAIError(w, http.StatusForbidden, "Blocked by Straja policy (after model)", "policy_error")
		return
	}
	if infReq.Timings != nil {
		infReq.Timings.PostPolicy = time.Since(postPolicyStart)
	}

	// 5) Success
	s.emitActivation(ctx, w, infReq, infResp, providerName, activation.DecisionAllow)

	respBody := buildChatCompletionResponse(infReq, infResp)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(respBody); err != nil {
		redact.Logf("failed to write response: %v", err)
	}
}

// normalizeToInferenceRequest converts the HTTP/OpenAI payload into our internal representation.
func normalizeToInferenceRequest(projectID string, req *chatCompletionRequest) *inference.Request {
	msgs := make([]inference.Message, 0, len(req.Messages))
	for _, m := range req.Messages {
		msgs = append(msgs, inference.Message{
			Role:    m.Role,
			Content: m.Content,
		})
	}

	return &inference.Request{
		ProjectID: projectID,
		Model:     req.Model,
		UserID:    "", // later: could be taken from request body or headers
		Messages:  msgs,
	}
}

func (s *Server) validateChatRequest(req *inference.Request, providerName string) error {
	if req == nil || s == nil || s.cfg == nil {
		return errors.New("request invalid")
	}
	maxMsgs := s.cfg.Server.MaxMessages
	if maxMsgs > 0 && len(req.Messages) > maxMsgs {
		return errors.New("Request too large")
	}
	maxChars := s.cfg.Server.MaxTotalMessageChars
	if maxChars > 0 {
		total := 0
		for _, m := range req.Messages {
			total += len(m.Content)
			if total > maxChars {
				return errors.New("Request too large")
			}
		}
	}

	if !s.isModelAllowed(req.Model, req.ProjectID, providerName) {
		return errors.New("Model not allowed")
	}
	return nil
}

func (s *Server) isModelAllowed(model, projectID, providerName string) bool {
	if model == "" {
		return true
	}
	// project allowlist wins, then provider allowlist.
	for _, p := range s.cfg.Projects {
		if p.ID == projectID && len(p.AllowedModels) > 0 {
			return containsString(p.AllowedModels, model)
		}
	}
	if provCfg, ok := s.cfg.Providers[providerName]; ok && len(provCfg.AllowedModels) > 0 {
		return containsString(provCfg.AllowedModels, model)
	}
	return true
}

func containsString(list []string, value string) bool {
	for _, v := range list {
		if strings.TrimSpace(v) == strings.TrimSpace(value) {
			return true
		}
	}
	return false
}

// buildChatCompletionResponse converts an internal inference.Response into OpenAI-style JSON.
func buildChatCompletionResponse(req *inference.Request, resp *inference.Response) chatCompletionResponse {
	return chatCompletionResponse{
		ID:      "chatcmpl-straja-skeleton", // later: generate nicer IDs if you want
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   req.Model,
		Choices: []chatCompletionChoice{
			{
				Index: 0,
				Message: chatMessage{
					Role:    resp.Message.Role,
					Content: resp.Message.Content,
				},
				FinishReason: "stop",
				// Logprobs left as nil → serializes as null or omitted depending on client
			},
		},
		Usage: chatCompletionUsage{
			PromptTokens:     resp.Usage.PromptTokens,
			CompletionTokens: resp.Usage.CompletionTokens,
			TotalTokens:      resp.Usage.TotalTokens,
		},
		// SystemFingerprint: nil for now
	}
}

func logTimingDebug(projectID, providerName, decision string, t *inference.Timings) {
	if t == nil {
		return
	}

	redact.Logf("debug: timings project=%s provider=%s decision=%s pre_policy_ms=%.2f provider_ms=%.2f post_policy_ms=%.2f strajaguard_ms=%.2f",
		projectID,
		providerName,
		decision,
		durationMs(t.PrePolicy),
		durationMs(t.Provider),
		durationMs(t.PostPolicy),
		durationMs(t.StrajaGuard),
	)
}

func durationMs(d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return float64(d.Microseconds()) / 1000
}

// parseBearerToken extracts the token from an Authorization: Bearer header.
func parseBearerToken(h string) (string, bool) {
	if h == "" {
		return "", false
	}
	parts := strings.Fields(h)
	if len(parts) != 2 {
		return "", false
	}
	if !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	return parts[1], true
}

func isRequestTooLarge(err error) bool {
	if err == nil {
		return false
	}
	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "request body too large")
}

// writeOpenAIError writes an OpenAI-style error JSON.
func writeOpenAIError(w http.ResponseWriter, status int, message, typ string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(openAIErrorBody{
		Error: openAIErrorDetail{
			Message: message,
			Type:    typ,
		},
	})
}

// emitActivation builds and sends an activation event via the configured emitter.
func (s *Server) emitActivation(ctx context.Context, w http.ResponseWriter, req *inference.Request, resp *inference.Response, providerName string, decision activation.Decision) {
	if s.activation == nil || req == nil {
		return
	}

	promptPreview, completionPreview := s.buildPreviews(req, resp)

	var policyDecisions []activation.PolicyDecision
	for _, hit := range req.PolicyDecisions {
		policyDecisions = append(policyDecisions, activation.PolicyDecision{
			Category:   hit.Category,
			Action:     hit.Action,
			Confidence: hit.Confidence,
			Sources:    append([]string(nil), hit.Sources...),
		})
	}

	var sgPayload *activation.StrajaGuardPayload
	if len(req.SecurityScores) > 0 || len(req.SecurityFlags) > 0 {
		scores := make(map[string]float32, len(req.SecurityScores))
		for k, v := range req.SecurityScores {
			scores[k] = v
		}
		sgPayload = &activation.StrajaGuardPayload{
			Model:  "strajaguard_v1",
			Scores: scores,
			Flags:  append([]string(nil), req.SecurityFlags...),
		}
	}
	if s.strajaGuardModel == nil || strings.HasPrefix(s.strajaGuardStatus, "disabled") {
		sgPayload = nil
	}

	ev := &activation.Event{
		Timestamp:            time.Now().UTC(),
		ProjectID:            req.ProjectID,
		Provider:             providerName,
		Model:                req.Model,
		Decision:             decision,
		PromptPreview:        promptPreview,
		CompletionPreview:    completionPreview,
		PolicyHits:           append([]string(nil), req.PolicyHits...),
		IntelStatus:          s.intelStatus,
		IntelBundleVersion:   s.intelBundleVer,
		PolicyDecisions:      policyDecisions,
		StrajaGuard:          sgPayload,
		StrajaGuardStatus:    s.strajaGuardStatus,
		StrajaGuardBundleVer: s.activeBundleVer,
	}
	if s.intelMeta != nil {
		ev.IntelLastValidatedAt = s.intelMeta.LastValidatedAt
	}
	if s.strajaGuardMeta != nil && ev.IntelLastValidatedAt == "" {
		ev.IntelLastValidatedAt = s.strajaGuardMeta.LastValidatedAt
	}
	ev.PromptPreview = redact.String(ev.PromptPreview)
	ev.CompletionPreview = redact.String(ev.CompletionPreview)

	// Emit via configured emitter (stdout, later webhooks, etc.)
	s.activation.Emit(ctx, ev)

	// Also expose activation to clients via header so the console can show it
	if w != nil {
		if b, err := json.Marshal(ev); err == nil {
			w.Header().Set("X-Straja-Activation", redact.String(string(b)))
		}
	}
}

var (
	emailRegex = regexp.MustCompile(`(?i)[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	tokenRegex = regexp.MustCompile(`[A-Za-z0-9_\-]{20,}`)
)

func (s *Server) buildPreviews(req *inference.Request, resp *inference.Response) (string, string) {
	level := s.loggingLevel
	if level == "" {
		level = "metadata"
	}

	var promptPreview, completionPreview string

	switch level {
	case "full":
		if len(req.Messages) > 0 {
			last := req.Messages[len(req.Messages)-1]
			promptPreview = redact.String(truncate(last.Content, 500))
		}
		if resp != nil {
			completionPreview = redact.String(truncate(resp.Message.Content, 500))
		}
	case "redacted":
		if len(req.Messages) > 0 {
			last := req.Messages[len(req.Messages)-1]
			promptPreview = redact.String(truncate(simpleRedact(last.Content), 500))
		}
		if resp != nil {
			completionPreview = redact.String(truncate(simpleRedact(resp.Message.Content), 500))
		}
	default: // "metadata"
		// no previews
	}

	return promptPreview, completionPreview
}

func simpleRedact(s string) string {
	s = emailRegex.ReplaceAllString(s, "[REDACTED_EMAIL]")
	s = tokenRegex.ReplaceAllString(s, "[REDACTED_TOKEN]")
	return s
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

func isPlaceholderLicenseKey(k string) bool {
	k = strings.TrimSpace(strings.ToUpper(k))
	if k == "" {
		return true
	}
	samples := []string{
		"STRAJA-FREE-XXXX",
		"STRAJA-FREE-XXXX…",
		"STRAJA-FREE-XXXX-PLACEHOLDER",
	}
	for _, s := range samples {
		if k == s {
			return true
		}
	}
	return false
}

func licenseFingerprint(k string) string {
	k = strings.TrimSpace(k)
	if k == "" {
		return ""
	}
	h := sha256.Sum256([]byte(k))
	return hex.EncodeToString(h[:])[:8]
}

func reasonForFallback(err error) string {
	if err == nil {
		return "validate_failed_network"
	}
	if strings.Contains(strings.ToLower(err.Error()), "invalid") || strings.Contains(strings.ToLower(err.Error()), "unknown") || strings.Contains(strings.ToLower(err.Error()), "unauthorized") {
		return "invalid_license"
	}
	if isNetworkyError(err) {
		return "validate_failed_network"
	}
	return "validate_failed"
}

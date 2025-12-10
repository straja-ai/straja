package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
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
	"github.com/straja-ai/straja/internal/policy"
	"github.com/straja-ai/straja/internal/provider"
	"github.com/straja-ai/straja/internal/strajaguard"
)

// Server wraps the HTTP server components for Straja.
type Server struct {
	mux              *http.ServeMux
	cfg              *config.Config
	auth             *auth.Auth
	policy           policy.Engine
	providers        map[string]provider.Provider // name -> provider
	defaultProvider  string                       // name of default provider
	activation       activation.Emitter
	loggingLevel     string
	projectProviders map[string]string // project ID -> provider name
	licenseClaims    *license.LicenseClaims
	intelEnabled     bool
	licenseKey       string
	intelStatus      string
	httpClient       *http.Client
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
		log.Printf("failed to write console projects: %v", err)
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

	var reqBody consoleChatRequest
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
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
		log.Printf("no provider %q for project %q (console)", providerName, reqBody.ProjectID)
		writeOpenAIError(w, http.StatusInternalServerError, "Straja misconfiguration: unknown provider for project", "configuration_error")
		return
	}

	// Reuse the same normalization as /v1/chat/completions:
	infReq := normalizeToInferenceRequest(reqBody.ProjectID, &chatCompletionRequest{
		Model:    reqBody.Model,
		Messages: reqBody.Messages,
	})

	ctx := r.Context()

	// Policy + provider + activation, same flow as handleChatCompletions:

	if err := s.policy.BeforeModel(ctx, infReq); err != nil {
		s.emitActivation(ctx, w, infReq, nil, providerName, activation.DecisionBlockedBefore)
		writeOpenAIError(w, http.StatusForbidden, "Blocked by Straja policy (before model)", "policy_error")
		return
	}

	infResp, err := prov.ChatCompletion(ctx, infReq)
	if err != nil {
		log.Printf("provider %q error (console): %v", providerName, err)
		s.emitActivation(ctx, w, infReq, nil, providerName, activation.DecisionErrorProvider)
		writeOpenAIError(w, http.StatusBadGateway, "Upstream provider error", "provider_error")
		return
	}

	if err := s.policy.AfterModel(ctx, infReq, infResp); err != nil {
		s.emitActivation(ctx, w, infReq, infResp, providerName, activation.DecisionBlockedAfter)
		writeOpenAIError(w, http.StatusForbidden, "Blocked by Straja policy (after model)", "policy_error")
		return
	}

	s.emitActivation(ctx, w, infReq, infResp, providerName, activation.DecisionAllow)

	respBody := buildChatCompletionResponse(infReq, infResp)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(respBody); err != nil {
		log.Printf("failed to write console response: %v", err)
	}
}

// New creates a new Straja server with all routes registered.
func New(cfg *config.Config, authz *auth.Auth) *Server {
	mux := http.NewServeMux()

	// Resolve license key with env override (env wins; placeholder treated as empty).
	licenseKey := strings.TrimSpace(cfg.Intelligence.LicenseKey)
	envName := strings.TrimSpace(cfg.Intelligence.LicenseKeyEnv)
	envVal := ""
	if envName != "" {
		envVal = strings.TrimSpace(os.Getenv(envName))
	}
	if envVal != "" {
		licenseKey = envVal
	}
	if isPlaceholderLicenseKey(licenseKey) {
		licenseKey = ""
	}

	// Build intelligence engine (bundle-backed regex or noop) with offline license verification.
	var (
		intelEngine   intel.Engine
		licenseClaims *license.LicenseClaims
		intelEnabled  = cfg.Intelligence.Enabled
		intelStatus   = "enabled"
	)

	if !intelEnabled {
		log.Printf("intelligence disabled via config; running in routing-only mode")
		intelEngine = intel.NewNoop()
		intelStatus = "disabled_config"
	} else {
		if strings.TrimSpace(licenseKey) == "" {
			log.Printf("license key not provided; disabling intelligence (routing-only mode)")
			intelEngine = intel.NewNoop()
			intelEnabled = false
			intelStatus = "disabled_missing_license"
		} else {
			pubKey, err := license.DefaultPublicKey()
			if err != nil {
				log.Printf("license public key unavailable: %v; disabling intelligence (routing-only mode)", err)
				intelEngine = intel.NewNoop()
				intelEnabled = false
				intelStatus = "disabled_missing_public_key"
			} else {
				claims, err := license.VerifyLicenseKey(licenseKey, pubKey)
				if err != nil {
					log.Printf("license verification failed: %v; disabling intelligence (routing-only mode)", err)
					intelEngine = intel.NewNoop()
					intelEnabled = false
					intelStatus = "disabled_invalid_license"
				} else {
					licenseClaims = claims
					intelEngine = intel.NewRegexBundle(cfg.Policy)
					intelStatus = "enabled"
				}
			}
		}
	}

	// Build StrajaGuard model (optional)
	var (
		sgModel             *strajaguard.StrajaGuardModel
		activeBundleVersion string
	)
	strajaGuardDir := cfg.Security.BundleDir
	if cfg.Intel.StrajaGuardV1.IntelDir != "" {
		strajaGuardDir = filepath.Join(cfg.Intel.StrajaGuardV1.IntelDir, "strajaguard_v1")
		cfg.Security.BundleDir = strajaGuardDir
	}

	if !cfg.Security.Enabled {
		log.Printf("strajaguard disabled via security config; running regex-only")
	} else if !cfg.Intel.StrajaGuardV1.Enabled {
		log.Printf("strajaguard disabled via intel config; running regex-only")
	} else {
		allowRegexOnly := cfg.Intel.StrajaGuardV1.AllowRegexOnly
		updateOnStart := cfg.Intel.StrajaGuardV1.UpdateOnStart
		sgLicenseKey := strings.TrimSpace(cfg.Intel.StrajaGuardV1.LicenseKey)
		if envName := strings.TrimSpace(cfg.Intelligence.LicenseKeyEnv); envName != "" {
			if envVal := strings.TrimSpace(os.Getenv(envName)); envVal != "" {
				sgLicenseKey = envVal
			}
		}
		if isPlaceholderLicenseKey(sgLicenseKey) {
			sgLicenseKey = ""
		}

		if sgLicenseKey == "" {
			log.Printf("strajaguard license key not provided; running regex-only")
		} else {
			ctx := context.Background()
			if err := os.MkdirAll(strajaGuardDir, 0o755); err != nil {
				if allowRegexOnly {
					log.Printf("strajaguard: cannot create bundle dir %s: %v; running regex-only", strajaGuardDir, err)
				} else {
					log.Fatalf("strajaguard: cannot create bundle dir %s: %v", strajaGuardDir, err)
				}
			} else {
				state := strajaguard.BundleState{}
				skipLicense := false

				loadedState, err := strajaguard.LoadBundleState(strajaGuardDir)
				if err == nil {
					state = loadedState
					if strings.TrimSpace(state.CurrentVersion) != "" {
						versionDir := filepath.Join(strajaGuardDir, state.CurrentVersion)
						if _, statErr := os.Stat(versionDir); statErr == nil {
							log.Printf("strajaguard: loading existing bundle current_version=%s", state.CurrentVersion)
							model, loadErr := strajaguard.LoadModel(versionDir, cfg.Security.SeqLen)
							if loadErr != nil {
								if allowRegexOnly {
									log.Printf("strajaguard: failed to load existing bundle version=%s: %v; running regex-only (skipping startup download)", state.CurrentVersion, loadErr)
									skipLicense = true
								} else {
									log.Fatalf("strajaguard: failed to load existing bundle version=%s: %v", state.CurrentVersion, loadErr)
								}
							} else {
								sgModel = model
								activeBundleVersion = state.CurrentVersion
							}
						} else {
							log.Printf("strajaguard: state current_version=%s but directory missing; will fetch version from license server", state.CurrentVersion)
						}
					} else {
						log.Printf("strajaguard: no current_version in state; will fetch version from license server")
					}
				} else if errors.Is(err, strajaguard.ErrBundleStateNotFound) {
					log.Printf("strajaguard: no existing bundle; will fetch version from license server")
				} else {
					log.Printf("strajaguard: load bundle state failed: %v; treating as fresh install", err)
				}

				if !skipLicense {
					valRes, err := strajaguard.ValidateLicense(ctx, cfg.Intel.StrajaGuardV1.LicenseServerBaseURL, sgLicenseKey, state.CurrentVersion, cfg.Intel.StrajaGuardV1.RequestTimeoutSeconds)
					if err != nil {
						if sgModel != nil {
							log.Printf("strajaguard: license validate failed: %v; continuing with existing bundle current_version=%s", err, activeBundleVersion)
						} else if allowRegexOnly {
							log.Printf("strajaguard: license validate failed and no active bundle: %v; running regex-only", err)
						} else {
							log.Fatalf("strajaguard: license validate failed and no active bundle: %v", err)
						}
					} else {
						log.Printf("strajaguard: license validate returned version=%s update_available=%t", valRes.BundleInfo.Version, valRes.BundleInfo.UpdateAvailable)
						currentVersion := strings.TrimSpace(state.CurrentVersion)

						// Fresh install: no current bundle on disk.
						if currentVersion == "" {
							dir, err := strajaguard.EnsureStrajaGuardVersion(ctx, strajaGuardDir, valRes.BundleInfo.Version, valRes.BundleInfo.ManifestURL, valRes.BundleInfo.SignatureURL, valRes.BundleInfo.FileBaseURL, valRes.BundleToken, cfg.Intel.StrajaGuardV1.RequestTimeoutSeconds)
							if err != nil {
								if allowRegexOnly {
									log.Printf("strajaguard: bundle version=%s verification failed: %v; running regex-only", valRes.BundleInfo.Version, err)
								} else {
									log.Fatalf("strajaguard: bundle version=%s verification failed: %v", valRes.BundleInfo.Version, err)
								}
							} else if model, loadErr := strajaguard.LoadModel(dir, cfg.Security.SeqLen); loadErr != nil {
								if allowRegexOnly {
									log.Printf("strajaguard: bundle version=%s downloaded but failed to load: %v; running regex-only", valRes.BundleInfo.Version, loadErr)
								} else {
									log.Fatalf("strajaguard: bundle version=%s downloaded but failed to load: %v", valRes.BundleInfo.Version, loadErr)
								}
							} else {
								state.PreviousVersion = ""
								state.CurrentVersion = valRes.BundleInfo.Version
								if err := strajaguard.SaveBundleState(strajaGuardDir, state); err != nil {
									log.Printf("strajaguard: failed to save bundle state for version=%s: %v", state.CurrentVersion, err)
								} else {
									sgModel = model
									activeBundleVersion = state.CurrentVersion
									log.Printf("strajaguard: bundle version=%s verified and activated; previous_version=%s", state.CurrentVersion, state.PreviousVersion)
								}
							}
						} else if updateOnStart && valRes.BundleInfo.UpdateAvailable && valRes.BundleInfo.Version != currentVersion {
							dir, err := strajaguard.EnsureStrajaGuardVersion(ctx, strajaGuardDir, valRes.BundleInfo.Version, valRes.BundleInfo.ManifestURL, valRes.BundleInfo.SignatureURL, valRes.BundleInfo.FileBaseURL, valRes.BundleToken, cfg.Intel.StrajaGuardV1.RequestTimeoutSeconds)
							if err != nil {
								log.Printf("strajaguard: bundle version=%s verification failed: %v; keeping current_version=%s", valRes.BundleInfo.Version, err, currentVersion)
							} else if model, loadErr := strajaguard.LoadModel(dir, cfg.Security.SeqLen); loadErr != nil {
								log.Printf("strajaguard: bundle version=%s installed but failed to load: %v; keeping current_version=%s", valRes.BundleInfo.Version, loadErr, currentVersion)
							} else {
								state.PreviousVersion = currentVersion
								state.CurrentVersion = valRes.BundleInfo.Version
								if err := strajaguard.SaveBundleState(strajaGuardDir, state); err != nil {
									log.Printf("strajaguard: failed to save bundle state for version=%s: %v; keeping current_version=%s", state.CurrentVersion, err, currentVersion)
								} else {
									sgModel = model
									activeBundleVersion = state.CurrentVersion
									log.Printf("strajaguard: bundle version=%s verified and activated; previous_version=%s", state.CurrentVersion, state.PreviousVersion)
								}
							}
						} else if valRes.BundleInfo.UpdateAvailable && !updateOnStart {
							log.Printf("strajaguard: update available version=%s but STRAJA_UPDATE_ON_START is disabled; continuing with current_version=%s", valRes.BundleInfo.Version, currentVersion)
						}
					}
				}
			}
		}
	}

	// Build policy engine (consumes intelEngine)
	pol := policy.NewBasic(cfg.Policy, cfg.Security, intelEngine, sgModel)

	// Build providers
	provs, provErr := buildProviderRegistry(cfg)
	if provErr != nil {
		log.Printf("warning: failed to build providers from config: %v", provErr)
		log.Printf("falling back to echo provider")
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

	s := &Server{
		mux:              mux,
		cfg:              cfg,
		auth:             authz,
		policy:           pol,
		providers:        provs,
		defaultProvider:  cfg.DefaultProvider,
		activation:       activation.NewStdout(),
		loggingLevel:     strings.ToLower(cfg.Logging.ActivationLevel),
		projectProviders: projectProviders,
		licenseClaims:    licenseClaims,
		intelEnabled:     intelEnabled,
		licenseKey:       licenseKey,
		intelStatus:      intelStatus,
		httpClient:       http.DefaultClient,
	}

	// Routes
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/v1/chat/completions", s.handleChatCompletions)

	// Serve console + static
	mux.Handle("/console/", console.Handler())
	mux.Handle("/console", http.RedirectHandler("/console/", http.StatusMovedPermanently))
	mux.HandleFunc("/console/api/projects", s.handleConsoleProjects)
	mux.HandleFunc("/console/api/chat", s.handleConsoleChat)

	if s.intelEnabled {
		if err := s.ValidateLicenseOnline(context.Background()); err != nil {
			log.Printf("license online validation failed (continuing with offline-verified license): %v", err)
		}
	}

	return s
}

// ValidateLicenseOnline optionally validates the license key once at startup.
func (s *Server) ValidateLicenseOnline(ctx context.Context) error {
	url := strings.TrimSpace(s.cfg.Intelligence.LicenseServerURL)
	if url == "" || strings.TrimSpace(s.licenseKey) == "" {
		return nil
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

	client := s.httpClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("license online validation warning: %v", err)
		return err
	}
	defer resp.Body.Close()

	var res struct {
		Status  string `json:"status"`
		Tier    string `json:"tier"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		log.Printf("license online validation decode error: %v", err)
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
	log.Printf("disabling intelligence: %s", reason)
	s.intelEnabled = false
	s.licenseClaims = nil
	s.policy = policy.NewBasic(s.cfg.Policy, s.cfg.Security, intel.NewNoop(), nil)
	s.intelStatus = "disabled_license_invalid"
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
			apiKey := os.Getenv(pcfg.APIKeyEnv)
			if apiKey == "" {
				return nil, fmt.Errorf("provider %q: environment variable %s is empty", name, pcfg.APIKeyEnv)
			}
			reg[name] = provider.NewOpenAI(pcfg.BaseURL, apiKey)
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

// Start runs the HTTP server on the given address.
func (s *Server) Start(addr string) error {
	log.Printf("Straja Gateway running on %s", addr)
	return http.ListenAndServe(addr, s.mux)
}

// --- Handlers ---

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "ok")
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
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// Determine provider for this project
	providerName := project.Provider
	if providerName == "" {
		providerName = s.defaultProvider
	}

	prov, ok := s.providers[providerName]
	if !ok {
		log.Printf("no provider %q for project %q", providerName, project.ID)
		writeOpenAIError(w, http.StatusInternalServerError, "Straja misconfiguration: unknown provider for project", "configuration_error")
		return
	}

	// 1) Normalize HTTP/OpenAI request → internal inference.Request
	infReq := normalizeToInferenceRequest(project.ID, &reqBody)

	// 2) Before-model block
	if err := s.policy.BeforeModel(ctx, infReq); err != nil {
		s.emitActivation(ctx, w, infReq, nil, providerName, activation.DecisionBlockedBefore)
		writeOpenAIError(w, http.StatusForbidden, "Blocked by Straja policy (before model)", "policy_error")
		return
	}

	// 3) Provider error
	infResp, err := prov.ChatCompletion(ctx, infReq)
	if err != nil {
		log.Printf("provider %q error: %v", providerName, err)
		s.emitActivation(ctx, w, infReq, nil, providerName, activation.DecisionErrorProvider)
		writeOpenAIError(w, http.StatusBadGateway, "Upstream provider error", "provider_error")
		return
	}

	// 4) After-model block
	if err := s.policy.AfterModel(ctx, infReq, infResp); err != nil {
		s.emitActivation(ctx, w, infReq, infResp, providerName, activation.DecisionBlockedAfter)
		writeOpenAIError(w, http.StatusForbidden, "Blocked by Straja policy (after model)", "policy_error")
		return
	}

	// 5) Success
	s.emitActivation(ctx, w, infReq, infResp, providerName, activation.DecisionAllow)

	respBody := buildChatCompletionResponse(infReq, infResp)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(respBody); err != nil {
		log.Printf("failed to write response: %v", err)
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

	ev := &activation.Event{
		Timestamp:         time.Now().UTC(),
		ProjectID:         req.ProjectID,
		Provider:          providerName,
		Model:             req.Model,
		Decision:          decision,
		PromptPreview:     promptPreview,
		CompletionPreview: completionPreview,
		PolicyHits:        append([]string(nil), req.PolicyHits...),
		IntelStatus:       s.intelStatus,
		PolicyDecisions:   policyDecisions,
		StrajaGuard:       sgPayload,
	}

	// Emit via configured emitter (stdout, later webhooks, etc.)
	s.activation.Emit(ctx, ev)

	// Also expose activation to clients via header so the console can show it
	if w != nil {
		if b, err := json.Marshal(ev); err == nil {
			w.Header().Set("X-Straja-Activation", string(b))
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
			promptPreview = truncate(last.Content, 500)
		}
		if resp != nil {
			completionPreview = truncate(resp.Message.Content, 500)
		}
	case "redacted":
		if len(req.Messages) > 0 {
			last := req.Messages[len(req.Messages)-1]
			promptPreview = truncate(simpleRedact(last.Content), 500)
		}
		if resp != nil {
			completionPreview = truncate(simpleRedact(resp.Message.Content), 500)
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

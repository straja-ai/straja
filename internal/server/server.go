package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/straja-ai/straja-gateway/internal/activation"
	"github.com/straja-ai/straja-gateway/internal/auth"
	"github.com/straja-ai/straja-gateway/internal/config"
	"github.com/straja-ai/straja-gateway/internal/console"
	"github.com/straja-ai/straja-gateway/internal/consoleauth"
	"github.com/straja-ai/straja-gateway/internal/inference"
	"github.com/straja-ai/straja-gateway/internal/intel"
	"github.com/straja-ai/straja-gateway/internal/mockprovider"
	"github.com/straja-ai/straja-gateway/internal/policy"
	"github.com/straja-ai/straja-gateway/internal/provider"
	"github.com/straja-ai/straja-gateway/internal/redact"
	"github.com/straja-ai/straja-gateway/internal/strajaguard"
	"github.com/straja-ai/straja-gateway/internal/telemetry"
	"github.com/straja-ai/straja-gateway/internal/trust"
	"go.opentelemetry.io/otel/trace"
)

var version = "dev"

const robotsTxt = `User-agent: *
Disallow: /console
Disallow: /console/
Disallow: /v1/
Disallow: /api/
Disallow: /
`

// Server wraps the HTTP server components for Straja.
type Server struct {
	mux                                *http.ServeMux
	cfg                                *config.Config
	auth                               *auth.Auth
	configPath                         string
	policy                             policy.Engine
	providers                          map[string]provider.Provider // name -> provider
	defaultProvider                    string                       // name of default provider
	requestStore                       *requestStore
	activationEmitter                  *activation.Emitter
	loggingLevel                       string
	securityThresholds                 map[string]float32
	telemetry                          *telemetry.Provider
	projectProviders                   map[string]string // project ID -> provider name
	trustClaims                        *trust.TrustClaims
	intelEnabled                       bool
	trustKey                           string
	intelStatus                        string
	intelMeta                          *strajaguard.ValidationMeta
	intelBundleVer                     string
	strajaGuardStatus                  string
	strajaGuardReason                  string
	strajaGuardMeta                    *strajaguard.ValidationMeta
	httpClient                         *http.Client
	inFlightLimiter                    chan struct{}
	ipLimiter                          *ipRateLimiter
	strajaGuardModel                   *strajaguard.StrajaGuardModel
	specialistsEngine                  strajaguard.SpecialistsEngine
	activeBundleVer                    string
	strajaGuardFamily                  string
	strajaGuardSpecialistsConfigSource string
	requireML                          bool
	allowRegexOnly                     bool
	providerTypes                      map[string]string
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

func (s *Server) strajaGuardEnabled() bool {
	if s == nil {
		return false
	}
	if s.strajaGuardModel != nil {
		return true
	}
	return specialistsEngineHealthy(s.specialistsEngine)
}

func specialistsEngineHealthy(engine strajaguard.SpecialistsEngine) bool {
	if engine == nil {
		return false
	}
	healthChecker, ok := engine.(interface{ HealthCheck() error })
	if !ok {
		return true
	}
	return healthChecker.HealthCheck() == nil
}

func normalizeSpecialistsConfigSource(source string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return ""
	}
	if strings.HasPrefix(source, "file:") {
		return "file"
	}
	if strings.HasPrefix(source, "bundle:") {
		return "bundle"
	}
	if source == "embedded_default" {
		return "embedded"
	}
	return source
}

func resolveConfigRelativePath(configPath, p string) string {
	p = strings.TrimSpace(p)
	if p == "" || filepath.IsAbs(p) {
		return p
	}

	configPath = strings.TrimSpace(configPath)
	if configPath == "" {
		return p
	}
	if abs, err := filepath.Abs(configPath); err == nil {
		configPath = abs
	}

	baseDir := filepath.Dir(configPath)
	if strings.TrimSpace(baseDir) == "" {
		return filepath.Clean(p)
	}
	return filepath.Clean(filepath.Join(baseDir, p))
}

func setConsoleRobotsHeader(w http.ResponseWriter) {
	w.Header().Set(console.RobotsTagHeader, console.RobotsTagValue)
}

func handleRobots(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(robotsTxt))
}

type consoleProject struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Provider string `json:"provider"`
}

func formatConsoleProjectLabel(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	parts := strings.FieldsFunc(id, func(r rune) bool {
		return r == '_' || r == '-' || r == '.'
	})
	if len(parts) == 0 {
		return id
	}
	for i, part := range parts {
		if part == "" {
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + strings.ToLower(part[1:])
	}
	return strings.Join(parts, " ")
}

func (s *Server) handleConsoleProjects(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	setConsoleRobotsHeader(w)

	projects := make([]consoleProject, 0, len(s.cfg.Projects))
	for _, p := range s.cfg.Projects {
		projects = append(projects, consoleProject{
			ID:       p.ID,
			Label:    formatConsoleProjectLabel(p.ID),
			Provider: p.Provider,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(projects); err != nil {
		redact.Logf("failed to write console projects: %v", err)
	}
}

// New creates a new Straja server with all routes registered.
func New(cfg *config.Config, authz *auth.Auth, configPath string) *Server {
	mux := http.NewServeMux()

	// robots.txt served at root so crawlers see demo protections before any auth/other routes.
	mux.HandleFunc("/robots.txt", handleRobots)

	// Resolve trust key with env override (env wins; placeholder treated as empty).
	trustKey := strings.TrimSpace(cfg.ResolvedTrustKey)
	envName := strings.TrimSpace(cfg.Intelligence.TrustKeyEnv)
	redact.Logf("trust: using %s set=%t", envName, trustKey != "")
	sgTrustKey := strings.TrimSpace(cfg.ResolvedStrajaGuardTrustKey)
	sgSource := strings.TrimSpace(cfg.ResolvedStrajaGuardSource)
	if sgSource == "" {
		sgSource = "intelligence.trust_key"
	}
	redact.Logf("strajaguard: trust key resolved set=%t source=%s", sgTrustKey != "", sgSource)

	// Build intelligence engine (bundle-backed regex or noop) with offline trust verification.
	var (
		intelEngine    intel.Engine = intel.NewRegexBundle(cfg.Policy)
		trustClaims    *trust.TrustClaims
		intelEnabled   = cfg.Intelligence.Enabled
		intelStatus    = "online_validated"
		intelBundleVer string
	)

	if !intelEnabled {
		redact.Logf("intelligence disabled via config; running in routing-only mode")
		intelEngine = intel.NewNoop()
		intelStatus = "disabled_missing_trust_key"
	} else {
		if strings.TrimSpace(trustKey) == "" {
			redact.Logf("Trust key missing or invalid. Required to verify signed intelligence bundles. running regex-only (no ML bundle)")
			intelStatus = "disabled_missing_trust_key"
		} else {
			pubKey, err := trust.DefaultPublicKey()
			if err != nil {
				redact.Logf("trust public key unavailable: %v; running regex-only", err)
				intelStatus = "offline_cached_bundle"
			} else {
				claims, err := trust.VerifyTrustKey(trustKey, pubKey)
				if err != nil {
					redact.Logf("Trust key missing or invalid. Required to verify signed intelligence bundles. verification error: %v; running regex-only", err)
					intelStatus = "offline_cached_bundle"
				} else {
					trustClaims = claims
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
		sgSpecialists       strajaguard.SpecialistsEngine
		sgSpecialistsSource string
		activeBundleVersion string
		intelMeta           *strajaguard.ValidationMeta
		sgStatus            string
		sgReason            string
		sgMeta              *strajaguard.ValidationMeta
	)
	cfg.Intel.StrajaGuardV1.IntelDir = resolveConfigRelativePath(configPath, cfg.Intel.StrajaGuardV1.IntelDir)
	cfg.Security.BundleDir = resolveConfigRelativePath(configPath, cfg.Security.BundleDir)
	cfg.StrajaGuard.Specialists.ConfigPath = resolveConfigRelativePath(configPath, cfg.StrajaGuard.Specialists.ConfigPath)

	sgStatus = "disabled_missing_bundle"
	sgFamily := config.ResolveStrajaGuardFamily(cfg)
	strajaGuardDir := cfg.Security.BundleDir

	if !cfg.Security.Enabled || !cfg.Intel.StrajaGuardV1.Enabled {
		redact.Logf("strajaguard disabled via config; running regex-only")
		sgStatus = "disabled_missing_bundle"
		sgReason = "missing_bundle"
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

		if sgTrustKey == "" {
			_, sgStatus, sgReason = sgFallbackDecision(false, strajaguard.ValidateOtherError, "")
		} else if err := os.MkdirAll(strajaGuardDir, 0o755); err != nil {
			sgReason = "invalid_bundle"
			fail("strajaguard: cannot create bundle dir %s: %v; running regex-only", strajaGuardDir, err)
		} else {
			ctx := context.Background()

			valRes, outcome, err := strajaguard.ValidateTrust(ctx, cfg.Intel.StrajaGuardV1.TrustServerBaseURL, sgTrustKey, currentVersion, sgFamily, cfg.Intel.StrajaGuardV1.TrustValidateTimeoutSeconds)
			if err != nil || outcome != strajaguard.ValidateOK {
				redact.Logf("strajaguard: trust validate failed outcome=%s err=%v family=%s current_version=%s", outcome, err, sgFamily, currentVersion)
			}
			if err == nil && valRes != nil && outcome == strajaguard.ValidateOK {
				redact.Logf("strajaguard: trust validate returned version=%s update_available=%t", valRes.BundleInfo.Version, valRes.BundleInfo.UpdateAvailable)
				dir, err := strajaguard.EnsureStrajaGuardVersion(ctx, strajaGuardDir, sgFamily, valRes.BundleInfo.Version, valRes.BundleInfo.ManifestURL, valRes.BundleInfo.SignatureURL, valRes.BundleInfo.FileBaseURL, valRes.BundleToken, cfg.Intel.StrajaGuardV1.BundleDownloadTimeoutSeconds)
				if err != nil {
					redact.Logf("strajaguard: bundle version=%s verification failed: %v", valRes.BundleInfo.Version, err)
					sgStatus = "disabled_invalid_bundle"
					sgReason = "invalid_bundle"
				} else {
					loadFailed := false
					switch sgFamily {
					case "strajaguard_v1_specialists":
						engine, src, loadErr := strajaguard.LoadSpecialistsEngine(dir, cfg.Security.SeqLen, rt, cfg.StrajaGuard.Specialists.ConfigPath)
						if loadErr != nil {
							redact.Logf("strajaguard: specialists bundle version=%s downloaded but failed to load: %v", valRes.BundleInfo.Version, loadErr)
							sgStatus = "disabled_invalid_bundle"
							sgReason = "invalid_bundle"
							loadFailed = true
							break
						}
						sgSpecialists = engine
						sgSpecialistsSource = src
					default:
						model, loadErr := strajaguard.LoadModel(dir, cfg.Security.SeqLen, rt)
						if loadErr != nil {
							redact.Logf("strajaguard: bundle version=%s downloaded but failed to load: %v", valRes.BundleInfo.Version, loadErr)
							sgStatus = "disabled_invalid_bundle"
							sgReason = "invalid_bundle"
							loadFailed = true
							break
						}
						sgModel = model
					}

					if !loadFailed {
						state.PreviousVersion = state.CurrentVersion
						state.CurrentVersion = valRes.BundleInfo.Version
						_ = strajaguard.SaveBundleState(strajaGuardDir, state)
						fp := trustFingerprint(sgTrustKey)
						meta := strajaguard.ValidationMeta{
							Version:          state.CurrentVersion,
							LastValidatedAt:  time.Now().UTC().Format(time.RFC3339),
							TrustFingerprint: fp,
							Source:           "online",
						}
						if err := strajaguard.SaveValidationMeta(strajaGuardDir, meta); err == nil {
							sgMeta = &meta
						}
						activeBundleVersion = state.CurrentVersion
						sgStatus = "online_validated"
						sgReason = "online_ok"
						redact.Logf("strajaguard: bundle version=%s verified and activated", state.CurrentVersion)
						switch sgFamily {
						case "strajaguard_v1_specialists":
							redact.Logf("strajaguard: specialists loaded seq_len=%d", cfg.Security.SeqLen)
						default:
							redact.Logf("strajaguard: pool_size=%d intra_threads=%d inter_threads=%d seq_len=%d",
								sgModel.PoolSize(), sgModel.IntraThreads(), sgModel.InterThreads(), cfg.Security.SeqLen)
						}
					}
				}
			} else {
				switch outcome {
				case strajaguard.ValidateInvalidTrust:
					_, sgStatus, sgReason = sgFallbackDecision(true, outcome, currentVersion)
				case strajaguard.ValidateNetworkError:
					allowCache, nextStatus, nextReason := sgFallbackDecision(true, outcome, currentVersion)
					sgStatus, sgReason = nextStatus, nextReason
					if !allowCache {
						break
					}
					if integErr := strajaguard.VerifyBundleIntegrity(strajaGuardDir, currentVersion); integErr == nil {
						bundleDir := filepath.Join(strajaGuardDir, currentVersion)
						switch sgFamily {
						case "strajaguard_v1_specialists":
							engine, src, loadErr := strajaguard.LoadSpecialistsEngine(bundleDir, cfg.Security.SeqLen, rt, cfg.StrajaGuard.Specialists.ConfigPath)
							if loadErr != nil {
								sgStatus = "disabled_invalid_bundle"
								sgReason = "invalid_bundle"
							} else {
								sgSpecialists = engine
								sgSpecialistsSource = src
								activeBundleVersion = currentVersion
								sgStatus = "offline_cached_bundle"
								sgReason = "network_error"
								if cachedMeta != nil {
									sgMeta = cachedMeta
								}
								redact.Logf("strajaguard: using offline cached bundle version=%s (reason=validate_network_error)", currentVersion)
							}
						default:
							model, loadErr := strajaguard.LoadModel(bundleDir, cfg.Security.SeqLen, rt)
							if loadErr != nil {
								sgStatus = "disabled_invalid_bundle"
								sgReason = "invalid_bundle"
							} else {
								sgModel = model
								activeBundleVersion = currentVersion
								sgStatus = "offline_cached_bundle"
								sgReason = "network_error"
								if cachedMeta != nil {
									sgMeta = cachedMeta
								}
								redact.Logf("strajaguard: using offline cached bundle version=%s (reason=validate_network_error)", currentVersion)
							}
						}
					} else {
						sgStatus = "disabled_invalid_bundle"
						sgReason = "invalid_bundle"
					}
				default:
					_, sgStatus, sgReason = sgFallbackDecision(true, outcome, currentVersion)
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
					sgReason = "invalid_bundle"
				} else {
					redact.Logf("strajaguard: warmup inference ok duration_ms=%.2f", float64(dur.Microseconds())/1000)
				}
			} else if sgSpecialists != nil {
				if warmable, ok := sgSpecialists.(interface {
					Warmup(sample string) (time.Duration, error)
				}); ok {
					if dur, err := warmable.Warmup("hello"); err != nil {
						if mustExit {
							redact.Fatalf("strajaguard: specialists warmup inference failed: %v", err)
						}
						redact.Logf("strajaguard: specialists warmup inference failed: %v; running regex-only", err)
						sgSpecialists = nil
						activeBundleVersion = ""
						sgStatus = "disabled_invalid_bundle"
						sgReason = "invalid_bundle"
					} else {
						redact.Logf("strajaguard: specialists warmup inference ok duration_ms=%.2f", float64(dur.Microseconds())/1000)
					}
				}
			}
		}
	}

	redact.Logf("strajaguard: status=%s reason=%s active_version=%s cache_dir=%s", sgStatus, sgReason, activeBundleVersion, strajaGuardDir)

	telProvider, _ := telemetry.NewProvider(context.Background(), telemetry.Config{
		Enabled:  cfg.Telemetry.Enabled,
		Endpoint: cfg.Telemetry.Endpoint,
		Protocol: cfg.Telemetry.Protocol,
		Service:  "straja-gateway",
		Version:  version,
	})

	// Build policy engine (consumes intelEngine)
	pol := policy.NewBasic(cfg.Policy, cfg.Security, intelEngine, sgModel, sgSpecialists, telProvider.Tracer(), cfg.StrajaGuard)

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
	providerTypes := make(map[string]string, len(cfg.Providers))
	for name, p := range cfg.Providers {
		providerTypes[name] = p.Type
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
	ipLimiter := newIPRateLimiter(cfg.Server.RateLimitPerIP, cfg.Server.RateLimitPerIPBurst)

	trustHTTPTimeout := time.Duration(cfg.Intel.StrajaGuardV1.TrustValidateTimeoutSeconds) * time.Second
	if trustHTTPTimeout <= 0 {
		trustHTTPTimeout = 10 * time.Second
	}

	activationEmitter := buildActivationEmitter(cfg)

	s := &Server{
		mux:                                mux,
		cfg:                                cfg,
		auth:                               authz,
		configPath:                         configPath,
		policy:                             pol,
		providers:                          provs,
		defaultProvider:                    cfg.DefaultProvider,
		requestStore:                       newRequestStore(30 * time.Minute),
		activationEmitter:                  activationEmitter,
		loggingLevel:                       strings.ToLower(cfg.Logging.ActivationLevel),
		securityThresholds:                 buildSecurityThresholds(cfg.Security),
		telemetry:                          telProvider,
		projectProviders:                   projectProviders,
		trustClaims:                        trustClaims,
		intelEnabled:                       intelEnabled,
		trustKey:                           trustKey,
		intelStatus:                        intelStatus,
		intelMeta:                          intelMeta,
		intelBundleVer:                     intelBundleVer,
		httpClient:                         &http.Client{Timeout: trustHTTPTimeout},
		inFlightLimiter:                    limiter,
		ipLimiter:                          ipLimiter,
		strajaGuardModel:                   sgModel,
		specialistsEngine:                  sgSpecialists,
		strajaGuardSpecialistsConfigSource: sgSpecialistsSource,
		activeBundleVer:                    activeBundleVersion,
		strajaGuardFamily:                  sgFamily,
		strajaGuardStatus:                  sgStatus,
		strajaGuardReason:                  sgReason,
		strajaGuardMeta:                    sgMeta,
		requireML:                          cfg.Intel.StrajaGuardV1.RequireML,
		allowRegexOnly:                     cfg.Intel.StrajaGuardV1.AllowRegexOnly,
		providerTypes:                      providerTypes,
	}

	bundleTimeout := time.Duration(cfg.Intel.StrajaGuardV1.BundleDownloadTimeoutSeconds) * time.Second
	if bundleTimeout <= 0 {
		bundleTimeout = 30 * time.Second
	}

	redact.Logf("gateway hardening: read_header_timeout=%s read_timeout=%s write_timeout=%s idle_timeout=%s max_body_bytes=%d max_nonstream_response_bytes=%d max_in_flight=%d rate_limit_per_ip=%d rate_limit_per_ip_burst=%d upstream_timeout=%s trust_validate_timeout=%s bundle_download_timeout=%s require_ml=%t allow_regex_only=%t",
		cfg.Server.ReadHeaderTimeout,
		cfg.Server.ReadTimeout,
		cfg.Server.WriteTimeout,
		cfg.Server.IdleTimeout,
		cfg.Server.MaxRequestBodyBytes,
		cfg.Server.MaxNonStreamResponseBytes,
		cfg.Server.MaxInFlightRequests,
		cfg.Server.RateLimitPerIP,
		cfg.Server.RateLimitPerIPBurst,
		cfg.Server.UpstreamTimeout,
		trustHTTPTimeout,
		bundleTimeout,
		cfg.Intel.StrajaGuardV1.RequireML,
		cfg.Intel.StrajaGuardV1.AllowRegexOnly,
	)

	// Routes
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/readyz", s.handleReady)
	mux.HandleFunc("/v1/chat/completions", s.wrapHandler(s.handleChatCompletions, handlerOptions{limitBody: true, useLimiter: true}))
	mux.HandleFunc("/v1/messages", s.wrapHandler(s.handleClaudeMessages, handlerOptions{limitBody: true, useLimiter: true}))
	mux.HandleFunc("/v1/responses", s.wrapHandler(s.handleResponses, handlerOptions{limitBody: true, useLimiter: true}))
	mux.HandleFunc("/v1/guard/request", s.wrapHandler(s.handleGuardRequest, handlerOptions{limitBody: true, useLimiter: true}))
	mux.HandleFunc("/v1/guard/response", s.wrapHandler(s.handleGuardResponse, handlerOptions{limitBody: true, useLimiter: true}))
	mux.HandleFunc("/v1/straja/requests/", s.wrapHandler(s.handleRequestStatus, handlerOptions{limitBody: false, useLimiter: true}))
	mux.HandleFunc("/v1/toolgate/check", s.wrapHandler(s.handleToolgateCheck, handlerOptions{limitBody: true, useLimiter: true}))
	mux.HandleFunc("/v1/toolgate/explain", s.wrapHandler(s.handleToolgateExplain, handlerOptions{limitBody: true, useLimiter: true}))

	// Serve console + static
	// Note: console is for local/trusted networks only.
	mux.Handle("/console/", console.Handler(s.cfg.Console.Mode))
	mux.Handle("/console", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(console.RobotsTagHeader, console.RobotsTagValue)
		http.Redirect(w, r, "/console/", http.StatusMovedPermanently)
	}))
	mux.HandleFunc("/console/api/projects", s.handleConsoleProjects)
	mux.HandleFunc("/console/api/session", s.wrapHandler(s.handleConsoleSession, handlerOptions{limitBody: true, useLimiter: true}))
	mux.HandleFunc("/console/api/logout", s.wrapHandler(s.handleConsoleLogout, handlerOptions{limitBody: false, useLimiter: true}))
	mux.HandleFunc("/console/api/config", s.wrapHandler(s.handleConsoleConfig, handlerOptions{limitBody: true, useLimiter: true}))
	mux.HandleFunc("/console/api/reload", s.wrapHandler(s.handleConsoleReload, handlerOptions{limitBody: false, useLimiter: true}))
	if strings.EqualFold(strings.TrimSpace(s.cfg.Console.Mode), "demo") {
		// Intentionally omit /console/api/events in demo mode.
	} else {
		mux.HandleFunc("/console/api/events", s.wrapHandler(s.handleConsoleEvents, handlerOptions{limitBody: false, useLimiter: true}))
	}

	if s.intelEnabled {
		if err := s.ValidateTrustOnline(context.Background()); err != nil {
			redact.Logf("trust online validation failed (continuing with offline-verified trust): %v", err)
		}
	}

	return s
}

func buildActivationEmitter(cfg *config.Config) *activation.Emitter {
	if cfg == nil {
		return nil
	}
	if !cfg.Activation.Enabled || len(cfg.Activation.Sinks) == 0 {
		return nil
	}

	sinks := make([]activation.Sink, 0, len(cfg.Activation.Sinks))
	for _, s := range cfg.Activation.Sinks {
		switch strings.ToLower(strings.TrimSpace(s.Type)) {
		case "file_jsonl":
			sink, err := activation.NewFileSink(s.Path)
			if err != nil {
				redact.Logf("activation: skipping file_jsonl sink (%s): %v", s.Path, err)
				continue
			}
			sinks = append(sinks, sink)
		case "webhook":
			sink, err := activation.NewWebhookSink(s.URL, s.Headers, s.Timeout)
			if err != nil {
				redact.Logf("activation: skipping webhook sink (%s): %v", s.URL, err)
				continue
			}
			sinks = append(sinks, sink)
		case "telegram":
			sink, err := activation.NewTelegramSink(s)
			if err != nil {
				redact.Logf("activation: skipping telegram sink: %v", err)
				continue
			}
			sinks = append(sinks, sink)
		default:
			redact.Logf("activation: unknown sink type %q (skipping)", s.Type)
		}
	}

	if len(sinks) == 0 {
		redact.Logf("activation: enabled but no valid sinks configured; delivery disabled")
		return nil
	}

	redact.Logf("activation: emitter enabled sinks=%d queue_size=%d workers=%d", len(sinks), cfg.Activation.QueueSize, cfg.Activation.Workers)

	return activation.NewEmitter(activation.EmitterConfig{
		QueueSize:       cfg.Activation.QueueSize,
		Workers:         cfg.Activation.Workers,
		ShutdownTimeout: cfg.Activation.ShutdownTimeout,
	}, sinks)
}

func buildSecurityThresholds(cfg config.SecurityConfig) map[string]float32 {
	add := func(m map[string]float32, key string, val float32) {
		if val > 0 {
			m[key] = val
		}
	}

	out := make(map[string]float32)
	add(out, "prompt_injection.warn", cfg.PromptInj.MLWarnThreshold)
	add(out, "prompt_injection.block", cfg.PromptInj.MLBlockThreshold)
	add(out, "jailbreak.warn", cfg.Jailbreak.MLWarnThreshold)
	add(out, "jailbreak.block", cfg.Jailbreak.MLBlockThreshold)
	add(out, "data_exfil.warn", cfg.DataExfil.MLWarnThreshold)
	add(out, "data_exfil.block", cfg.DataExfil.MLBlockThreshold)
	add(out, "pii.warn", cfg.PII.MLWarnThreshold)
	add(out, "secrets.warn", cfg.Secrets.MLWarnThreshold)
	add(out, "secrets.block", cfg.Secrets.MLBlockThreshold)

	if len(out) == 0 {
		return nil
	}
	return out
}

// ValidateTrustOnline optionally validates the trust key once at startup.
func (s *Server) ValidateTrustOnline(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	url := strings.TrimSpace(s.cfg.Intelligence.TrustServerURL)
	if url == "" || strings.TrimSpace(s.trustKey) == "" {
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
		TrustKey       string `json:"trust_key"`
		GatewayVersion string `json:"gateway_version,omitempty"`
	}{
		TrustKey:       s.trustKey,
		GatewayVersion: os.Getenv("STRAJA_VERSION"),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal trust payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build trust request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		redact.Logf("trust online validation warning: %v", err)
		return err
	}
	defer resp.Body.Close()

	var res struct {
		Status  string `json:"status"`
		Tier    string `json:"tier"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		redact.Logf("trust online validation decode error: %v", err)
		return err
	}

	status := strings.ToLower(strings.TrimSpace(res.Status))
	if status == "ok" || status == "active" {
		if res.Tier != "" && s.trustClaims != nil {
			s.trustClaims.Tier = res.Tier
		}
		s.intelStatus = "enabled"
		return nil
	}

	// Any non-ok status disables intelligence for this run.
	reason := res.Message
	if reason == "" {
		reason = fmt.Sprintf("trust status=%s", res.Status)
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
	s.trustClaims = nil
	tr := trace.NewNoopTracerProvider().Tracer("noop")
	if s.telemetry != nil {
		tr = s.telemetry.Tracer()
	}
	s.policy = policy.NewBasic(s.cfg.Policy, s.cfg.Security, intel.NewRegexBundle(s.cfg.Policy), s.strajaGuardModel, s.specialistsEngine, tr, s.cfg.StrajaGuard)
	s.intelStatus = "regex_only_invalid_trust_key"
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
			if apiKey == "" && !pcfg.ForwardAuth {
				return nil, fmt.Errorf("provider %q: api key missing (env %s empty)", name, pcfg.APIKeyEnv)
			}
			reg[name] = provider.NewOpenAI(pcfg.BaseURL, apiKey, cfg.Server.UpstreamTimeout, cfg.Server.MaxNonStreamResponseBytes)
		case "claude":
			apiKey := strings.TrimSpace(os.Getenv(pcfg.APIKeyEnv))
			if apiKey == "" {
				apiKey = strings.TrimSpace(pcfg.APIKey)
			}
			if apiKey == "" && !pcfg.ForwardAuth {
				return nil, fmt.Errorf("provider %q: api key missing (env %s empty)", name, pcfg.APIKeyEnv)
			}
			reg[name] = provider.NewClaude(pcfg.BaseURL, apiKey, cfg.Server.UpstreamTimeout, cfg.Server.MaxNonStreamResponseBytes)
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

		if opts.useLimiter && s.ipLimiter != nil {
			if ip := clientIP(r); ip != "" {
				if !s.ipLimiter.Allow(ip) {
					writeOpenAIError(w, http.StatusTooManyRequests, "Too many requests", "rate_limit_exceeded")
					return
				}
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

	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ListenAndServe()
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errCh:
		s.shutdownActivation(context.Background())
		s.shutdownTelemetry(context.Background())
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case sig := <-stop:
		redact.Logf("received signal %s, shutting down gateway...", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			redact.Logf("graceful shutdown error: %v", err)
		}
		s.shutdownActivation(ctx)
		s.shutdownTelemetry(ctx)
		return nil
	}
}

func (s *Server) shutdownActivation(ctx context.Context) {
	if s.activationEmitter != nil {
		s.activationEmitter.Close(ctx)
	}
}

func (s *Server) shutdownTelemetry(ctx context.Context) {
	if s.telemetry != nil {
		s.telemetry.Shutdown(ctx)
	}
}

// --- Handlers ---

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

type readinessResponse struct {
	Status              string   `json:"status"`
	Mode                string   `json:"mode"`
	ActiveBundleVersion string   `json:"active_bundle_version,omitempty"`
	GatewayVersion      string   `json:"gateway_version,omitempty"`
	Reason              string   `json:"reason,omitempty"`
	MissingProviderKeys []string `json:"missing_provider_api_keys,omitempty"`
	IntelStatus         string   `json:"intel_status,omitempty"`
	StrajaGuardStatus   string   `json:"strajaguard_status,omitempty"`
	IntelLastValidated  string   `json:"intel_last_validated_at,omitempty"`
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(r.URL.Query().Get("project_id"))
	resp, ready := s.readinessForProject(projectID)
	w.Header().Set("Content-Type", "application/json")
	if !ready {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) readiness() (readinessResponse, bool) {
	return s.readinessForProject("")
}

func (s *Server) readinessForProject(projectID string) (readinessResponse, bool) {
	mode := "regex_only"
	specialistsHealthy := specialistsEngineHealthy(s.specialistsEngine)
	if s.strajaGuardModel != nil || specialistsHealthy {
		mode = "ml"
	}

	resp := readinessResponse{
		Status:              "ready",
		Mode:                mode,
		ActiveBundleVersion: s.activeBundleVer,
		GatewayVersion:      version,
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
	if projectID != "" {
		if _, ok := s.projectProviders[projectID]; !ok {
			resp.Status = "not_ready"
			resp.Reason = "project_not_found"
			return resp, false
		}
	}
	if missing := s.missingProjectProviderAPIKeys(projectID); len(missing) > 0 {
		resp.Status = "not_ready"
		resp.Reason = "provider_api_key_missing"
		resp.MissingProviderKeys = missing
		return resp, false
	}

	if s.requireML && s.strajaGuardModel == nil && !specialistsHealthy {
		resp.Status = "not_ready"
		resp.Reason = "strajaguard_ml_inactive"
		return resp, false
	}

	return resp, true
}

func (s *Server) missingProjectProviderAPIKeys(projectID string) []string {
	if s == nil || s.cfg == nil {
		return nil
	}
	required := map[string]struct{}{}
	if projectID != "" {
		if providerName, ok := s.projectProviders[projectID]; ok && strings.TrimSpace(providerName) != "" {
			required[strings.TrimSpace(providerName)] = struct{}{}
		}
	} else {
		for _, providerName := range s.projectProviders {
			if strings.TrimSpace(providerName) != "" {
				required[strings.TrimSpace(providerName)] = struct{}{}
			}
		}
	}
	if len(required) == 0 && strings.TrimSpace(s.defaultProvider) != "" {
		required[strings.TrimSpace(s.defaultProvider)] = struct{}{}
	}

	names := make([]string, 0, len(required))
	for name := range required {
		names = append(names, name)
	}
	sort.Strings(names)

	missing := make([]string, 0)
	for _, name := range names {
		pcfg, ok := s.cfg.Providers[name]
		if !ok {
			continue
		}
		pType := strings.ToLower(strings.TrimSpace(pcfg.Type))
		if pType != "openai" && pType != "claude" {
			continue
		}
		if pcfg.ForwardAuth {
			continue
		}
		if strings.TrimSpace(resolveProviderAPIKey(pcfg)) == "" {
			missing = append(missing, name)
		}
	}
	return missing
}

// --- OpenAI-style request/response types for the HTTP layer ---

type chatCompletionRequest struct {
	Model      string        `json:"model"`
	Messages   []chatMessage `json:"messages"`
	Tools      []chatTool    `json:"tools,omitempty"`
	ToolChoice any           `json:"tool_choice,omitempty"`
	Stream     bool          `json:"stream,omitempty"`
}

type chatMessage struct {
	Role       string         `json:"role"`
	Content    any            `json:"content,omitempty"`
	Name       string         `json:"name,omitempty"`
	ToolCalls  []chatToolCall `json:"tool_calls,omitempty"`
	ToolCallID string         `json:"tool_call_id,omitempty"`
}

type chatTool struct {
	Type     string           `json:"type"`
	Function chatToolFunction `json:"function"`
}

type chatToolFunction struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Parameters  any    `json:"parameters,omitempty"`
	Strict      bool   `json:"strict,omitempty"`
}

type chatToolCall struct {
	ID       string               `json:"id"`
	Type     string               `json:"type"`
	Function chatToolCallFunction `json:"function"`
}

type chatToolCallFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
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

	requestID := newRequestID()
	w.Header().Set("X-Straja-Request-Id", requestID)

	start := time.Now()
	ctx := r.Context()
	ctx, root := s.startSpan(ctx, "straja.request", trace.SpanKindServer, map[string]interface{}{
		"straja.version":                    version,
		"http.method":                       r.Method,
		"http.route":                        "/v1/chat/completions",
		"straja.strajaguard.enabled":        s.strajaGuardEnabled(),
		"straja.strajaguard.loaded":         s.strajaGuardEnabled(),
		"straja.strajaguard.bundle_version": s.activeBundleVer,
	})
	defer root.End()

	if s.cfg.Server.MaxRequestBodyBytes > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, s.cfg.Server.MaxRequestBodyBytes)
	}

	// Auth: resolve project from bearer or console session
	authCtx, authSpan := s.startSpan(ctx, "straja.auth", trace.SpanKindInternal, nil)
	project, authMode, ok := s.resolveAuthProject(r)
	setSpanAttrs(authSpan, map[string]interface{}{
		"straja.auth.mode": authMode,
	})
	if !ok {
		setSpanAttrs(authSpan, map[string]interface{}{"straja.auth.result": "missing"})
		authSpan.End()
		writeOpenAIError(w, http.StatusUnauthorized, "Invalid or missing API key", "authentication_error")
		return
	}
	setSpanAttrs(authSpan, map[string]interface{}{"straja.auth.result": "ok"})
	authSpan.End()

	var reqBody chatCompletionRequest
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		if isRequestTooLarge(err) {
			writeOpenAIError(w, http.StatusRequestEntityTooLarge, "Request body too large", "invalid_request_error")
			return
		}
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	if s.cfg.Server.UpstreamTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(authCtx, s.cfg.Server.UpstreamTimeout)
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
	normCtx, normSpan := s.startSpan(ctx, "straja.normalize", trace.SpanKindInternal, map[string]interface{}{
		"straja.project_id":  project.ID,
		"straja.provider_id": providerName,
	})
	infReq := normalizeToInferenceRequest(project.ID, &reqBody)
	infReq.RequestID = requestID
	s.requestStore.Start(requestID, project.ID)
	setSpanAttrs(normSpan, map[string]interface{}{
		"straja.model":  infReq.Model,
		"straja.stream": reqBody.Stream,
	})
	normSpan.End()
	infReq.Timings = &inference.Timings{}
	decision := "allow"
	statusCode := http.StatusOK
	defer logTimingDebug(project.ID, providerName, decision, infReq.Timings)
	defer func() {
		setSpanAttrs(root, map[string]interface{}{
			"straja.project_id":                 project.ID,
			"straja.provider_id":                providerName,
			"straja.provider_type":              s.providerTypes[providerName],
			"straja.model":                      infReq.Model,
			"straja.decision":                   decision,
			"straja.policy_hits_total":          len(infReq.PolicyHits),
			"straja.policy_categories":          infReq.PolicyHits,
			"straja.blocked":                    strings.HasPrefix(decision, "blocked"),
			"straja.strajaguard.bundle_version": s.activeBundleVer,
			"http.status_code":                  statusCode,
		})
		if s.telemetry != nil {
			s.telemetry.RecordRequestMetrics(decision, s.providerTypes[providerName], project.ID, float64(time.Since(start).Milliseconds()), durationMs(infReq.Timings.Provider), durationMs(infReq.Timings.StrajaGuard), len(infReq.PolicyHits))
		}
	}()

	if err := s.validateChatRequest(infReq, providerName); err != nil {
		decision = "blocked_request"
		writeOpenAIError(w, http.StatusBadRequest, err.Error(), "invalid_request_error")
		return
	}

	// 2) Before-model block
	prePolicyStart := time.Now()
	policyPreCtx, policyPreSpan := s.startSpan(normCtx, "straja.policy.pre", trace.SpanKindInternal, map[string]interface{}{
		"straja.policy.hits_total": len(infReq.PolicyHits),
	})
	if err := s.policy.BeforeModel(policyPreCtx, infReq); err != nil {
		if infReq.Timings != nil {
			infReq.Timings.PrePolicy = time.Since(prePolicyStart)
		}
		setSpanAttrs(policyPreSpan, map[string]interface{}{
			"straja.policy.result": "blocked",
		})
		policyPreSpan.End()
		decision = "blocked_before"
		statusCode = http.StatusForbidden
		s.emitActivation(ctx, w, infReq, nil, providerName, activation.DecisionBlockedBefore, activation.ModeNonStream)
		writeOpenAIError(w, http.StatusForbidden, "Blocked by Straja policy (before model)", "policy_error")
		return
	}
	if infReq.Timings != nil {
		infReq.Timings.PrePolicy = time.Since(prePolicyStart)
	}
	setSpanAttrs(policyPreSpan, map[string]interface{}{
		"straja.policy.result":     "ok",
		"straja.policy.hits_total": len(infReq.PolicyHits),
	})
	policyPreSpan.End()

	if reqBody.Stream {
		mode := activation.ModeStream
		provCfg, ok := s.cfg.Providers[providerName]
		if !ok {
			redact.Logf("no provider config %q for project %q (streaming chat)", providerName, project.ID)
			decision = "error_provider"
			statusCode = http.StatusInternalServerError
			s.emitActivation(ctx, w, infReq, nil, providerName, activation.DecisionErrorProvider, mode)
			writeOpenAIError(w, http.StatusInternalServerError, "Straja misconfiguration: unknown provider for project", "configuration_error")
			return
		}

		body, err := buildChatCompletionsUpstreamBody(infReq, true)
		if err != nil {
			decision = "blocked_request"
			statusCode = http.StatusBadRequest
			writeOpenAIError(w, http.StatusBadRequest, "invalid request payload", "invalid_request_error")
			return
		}

		providerStart := time.Now()
		upstreamResp, err := s.doChatCompletionsUpstream(ctx, provCfg, providerName, r.Header, body)
		if infReq.Timings != nil {
			infReq.Timings.Provider = time.Since(providerStart)
		}
		if err != nil {
			redact.Logf("provider %q stream error: %v", providerName, err)
			decision = "error_provider"
			statusCode = http.StatusBadGateway
			s.emitActivation(ctx, w, infReq, nil, providerName, activation.DecisionErrorProvider, mode)
			writeOpenAIError(w, http.StatusBadGateway, "Upstream provider error", "provider_error")
			return
		}
		defer upstreamResp.Body.Close()

		if upstreamResp.StatusCode >= 400 {
			decision = "error_provider"
			statusCode = upstreamResp.StatusCode
			copyHeaders(w.Header(), upstreamResp.Header, nil)
			s.emitActivation(ctx, w, infReq, nil, providerName, activation.DecisionErrorProvider, mode)
			w.WriteHeader(upstreamResp.StatusCode)
			_, _ = io.Copy(w, upstreamResp.Body)
			return
		}

		setSSEHeaders(w.Header())
		w.WriteHeader(upstreamResp.StatusCode)
		capture := newSSECapture(s.cfg.Server.MaxNonStreamResponseBytes)
		if err := copyUpstreamBodyWithCapture(w, upstreamResp.Body, capture); err != nil && !errors.Is(err, context.Canceled) {
			redact.Logf("chat completions: streaming copy failed: %v", err)
		}
		_, outputText := runPostCheckForStream(ctx, s, infReq, capture)
		_ = s.applyResponseGuard(infReq, s.evaluateResponseGuard(outputText), true)
		decision = "allow"
		statusCode = upstreamResp.StatusCode
		s.emitActivation(ctx, w, infReq, nil, providerName, activation.DecisionAllow, mode)
		return
	}

	// 3) Provider error
	providerStart := time.Now()
	provSelectCtx, provSelectSpan := s.startSpan(ctx, "straja.provider.select", trace.SpanKindInternal, map[string]interface{}{
		"straja.provider_id":   providerName,
		"straja.provider_type": s.providerTypes[providerName],
	})
	provSelectSpan.End()

	provCallCtx, provCallSpan := s.startSpan(provSelectCtx, "straja.provider.call", trace.SpanKindInternal, map[string]interface{}{
		"straja.provider_id":   providerName,
		"straja.provider_type": s.providerTypes[providerName],
	})
	infResp, err := prov.ChatCompletion(provCallCtx, infReq)
	if infReq.Timings != nil {
		infReq.Timings.Provider = time.Since(providerStart)
	}
	if err != nil {
		redact.Logf("provider %q error: %v", providerName, err)
		setSpanAttrs(provCallSpan, map[string]interface{}{
			"straja.upstream.error": err.Error(),
		})
		provCallSpan.End()
		decision = "error_provider"
		statusCode = http.StatusBadGateway
		s.emitActivation(ctx, w, infReq, nil, providerName, activation.DecisionErrorProvider, activation.ModeNonStream)
		writeOpenAIError(w, http.StatusBadGateway, "Upstream provider error", "provider_error")
		return
	}
	setSpanAttrs(provCallSpan, map[string]interface{}{
		"straja.upstream.status_code": 200,
	})
	provCallSpan.End()

	// 4) After-model block
	postPolicyStart := time.Now()
	policyPostCtx, policyPostSpan := s.startSpan(ctx, "straja.policy.post", trace.SpanKindInternal, map[string]interface{}{
		"straja.policy.hits_total": len(infReq.PolicyHits),
	})
	if err := s.policy.AfterModel(policyPostCtx, infReq, infResp); err != nil {
		if infReq.Timings != nil {
			infReq.Timings.PostPolicy = time.Since(postPolicyStart)
		}
		setSpanAttrs(policyPostSpan, map[string]interface{}{
			"straja.policy.result": "blocked",
		})
		policyPostSpan.End()
		decision = "blocked_after"
		statusCode = http.StatusForbidden
		s.emitActivation(ctx, w, infReq, infResp, providerName, activation.DecisionBlockedAfter, activation.ModeNonStream)
		writeOpenAIError(w, http.StatusForbidden, "Blocked by Straja policy (after model)", "policy_error")
		return
	}
	if infReq.Timings != nil {
		infReq.Timings.PostPolicy = time.Since(postPolicyStart)
	}
	setSpanAttrs(policyPostSpan, map[string]interface{}{
		"straja.policy.result":     "ok",
		"straja.policy.hits_total": len(infReq.PolicyHits),
	})
	policyPostSpan.End()

	_ = s.applyResponseGuard(infReq, s.evaluateResponseGuard(chatCompletionOutputText(infResp.Message)), false)

	// 5) Success
	s.emitActivation(ctx, w, infReq, infResp, providerName, activation.DecisionAllow, activation.ModeNonStream)

	_, respSpan := s.startSpan(ctx, "straja.response.encode", trace.SpanKindInternal, nil)
	respBody := buildChatCompletionResponse(infReq, infResp)
	respSpan.End()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(respBody); err != nil {
		redact.Logf("failed to write response: %v", err)
	}
}

// normalizeToInferenceRequest converts the HTTP/OpenAI payload into our internal representation.
func normalizeToInferenceRequest(projectID string, req *chatCompletionRequest) *inference.Request {
	msgs := make([]inference.Message, 0, len(req.Messages))
	for _, m := range req.Messages {
		var toolCalls []inference.ToolCall
		if len(m.ToolCalls) > 0 {
			toolCalls = make([]inference.ToolCall, 0, len(m.ToolCalls))
		}
		toolArgsText := make([]string, 0, len(m.ToolCalls))
		for _, tc := range m.ToolCalls {
			toolCalls = append(toolCalls, inference.ToolCall{
				ID:        tc.ID,
				Type:      tc.Type,
				Name:      tc.Function.Name,
				Arguments: tc.Function.Arguments,
			})
			if strings.TrimSpace(tc.Function.Arguments) != "" {
				toolArgsText = append(toolArgsText, tc.Function.Arguments)
			}
		}
		content := chatContentToText(m.Content)
		if len(toolArgsText) > 0 {
			if content != "" {
				content += "\n"
			}
			content += strings.Join(toolArgsText, "\n")
		}
		contentAny := m.Content
		if _, ok := m.Content.(string); ok {
			contentAny = nil
		}
		msgs = append(msgs, inference.Message{
			Role:       m.Role,
			Content:    content,
			ContentAny: contentAny,
			ToolCalls:  toolCalls,
			ToolCallID: m.ToolCallID,
			Name:       m.Name,
		})
	}
	var tools []inference.ToolDef
	if len(req.Tools) > 0 {
		tools = make([]inference.ToolDef, 0, len(req.Tools))
		for _, t := range req.Tools {
			tools = append(tools, inference.ToolDef{
				"type": t.Type,
				"function": map[string]any{
					"name":        t.Function.Name,
					"description": t.Function.Description,
					"parameters":  t.Function.Parameters,
					"strict":      t.Function.Strict,
				},
			})
		}
	}

	return &inference.Request{
		ProjectID:  projectID,
		Model:      req.Model,
		UserID:     "", // later: could be taken from request body or headers
		Messages:   msgs,
		Tools:      tools,
		ToolChoice: req.ToolChoice,
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
			for _, tc := range m.ToolCalls {
				total += len(tc.Arguments)
			}
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
	content := any(resp.Message.Content)
	if resp.Message.ContentAny != nil {
		content = resp.Message.ContentAny
	}
	toolCalls := make([]chatToolCall, 0, len(resp.Message.ToolCalls))
	for _, tc := range resp.Message.ToolCalls {
		toolCalls = append(toolCalls, chatToolCall{
			ID:   tc.ID,
			Type: tc.Type,
			Function: chatToolCallFunction{
				Name:      tc.Name,
				Arguments: tc.Arguments,
			},
		})
	}
	finishReason := resp.FinishReason
	if strings.TrimSpace(finishReason) == "" {
		finishReason = "stop"
	}

	return chatCompletionResponse{
		ID:      "chatcmpl-straja-skeleton", // later: generate nicer IDs if you want
		Object:  "chat.completion",
		Created: time.Now().Unix(),
		Model:   req.Model,
		Choices: []chatCompletionChoice{
			{
				Index: 0,
				Message: chatMessage{
					Role:      resp.Message.Role,
					Content:   content,
					ToolCalls: toolCalls,
				},
				FinishReason: finishReason,
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

func chatContentToText(content any) string {
	switch v := content.(type) {
	case string:
		return v
	case []any:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			obj, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if txt, ok := obj["text"].(string); ok && strings.TrimSpace(txt) != "" {
				parts = append(parts, txt)
			}
		}
		return strings.Join(parts, "\n")
	default:
		return ""
	}
}

func chatCompletionOutputText(msg inference.Message) string {
	parts := []string{}
	if strings.TrimSpace(msg.Content) != "" {
		parts = append(parts, msg.Content)
	}
	for _, tc := range msg.ToolCalls {
		if strings.TrimSpace(tc.Arguments) != "" {
			parts = append(parts, tc.Arguments)
		}
	}
	return strings.Join(parts, "\n")
}

func buildChatCompletionsUpstreamBody(req *inference.Request, stream bool) ([]byte, error) {
	chatReq := chatCompletionRequest{
		Model:      req.Model,
		Messages:   make([]chatMessage, 0, len(req.Messages)),
		Tools:      make([]chatTool, 0, len(req.Tools)),
		ToolChoice: req.ToolChoice,
		Stream:     stream,
	}
	for _, m := range req.Messages {
		msg := chatMessage{
			Role:       m.Role,
			Name:       m.Name,
			ToolCallID: m.ToolCallID,
		}
		if len(m.ToolCalls) > 0 {
			msg.ToolCalls = make([]chatToolCall, 0, len(m.ToolCalls))
			for _, tc := range m.ToolCalls {
				msg.ToolCalls = append(msg.ToolCalls, chatToolCall{
					ID:   tc.ID,
					Type: tc.Type,
					Function: chatToolCallFunction{
						Name:      tc.Name,
						Arguments: tc.Arguments,
					},
				})
			}
		}
		if m.ContentAny != nil {
			msg.Content = m.ContentAny
		} else if m.Content != "" || len(m.ToolCalls) == 0 {
			msg.Content = m.Content
		}
		chatReq.Messages = append(chatReq.Messages, msg)
	}
	for _, t := range req.Tools {
		toolType, _ := t["type"].(string)
		f, _ := t["function"].(map[string]any)
		fn := chatToolFunction{}
		if f != nil {
			if name, ok := f["name"].(string); ok {
				fn.Name = name
			}
			if desc, ok := f["description"].(string); ok {
				fn.Description = desc
			}
			if params, ok := f["parameters"]; ok {
				fn.Parameters = params
			}
			if strict, ok := f["strict"].(bool); ok {
				fn.Strict = strict
			}
		}
		chatReq.Tools = append(chatReq.Tools, chatTool{
			Type:     toolType,
			Function: fn,
		})
	}
	return json.Marshal(chatReq)
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

func (s *Server) resolveAuthProject(r *http.Request) (auth.Project, string, bool) {
	// Bearer auth takes precedence.
	apiKey, ok := parseBearerToken(r.Header.Get("Authorization"))
	if ok && apiKey != "" {
		if project, ok := s.auth.Lookup(apiKey); ok {
			return project, "api_key", true
		}
	}
	if headerKey := strings.TrimSpace(r.Header.Get("x-api-key")); headerKey != "" {
		if project, ok := s.auth.Lookup(headerKey); ok {
			return project, "x_api_key", true
		}
	}

	if !s.cfg.Console.Enabled {
		return auth.Project{}, "", false
	}
	cookieName := strings.TrimSpace(s.cfg.Console.SessionCookieName)
	if cookieName == "" {
		return auth.Project{}, "", false
	}
	cookie, err := r.Cookie(cookieName)
	if err != nil || cookie == nil || cookie.Value == "" {
		return auth.Project{}, "", false
	}
	projectID, _, err := consoleauth.VerifyConsoleSession(cookie.Value, s.cfg.Console.SessionSecret)
	if err != nil || projectID == "" {
		return auth.Project{}, "", false
	}
	if project, ok := s.lookupProjectByID(projectID); ok {
		return project, "console_session", true
	}
	return auth.Project{}, "", false
}

func (s *Server) lookupProjectByID(projectID string) (auth.Project, bool) {
	if projectID == "" {
		return auth.Project{}, false
	}
	for _, p := range s.cfg.Projects {
		if p.ID == projectID {
			return auth.Project{ID: p.ID, Provider: p.Provider}, true
		}
	}
	return auth.Project{}, false
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

func isHTTPS(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	if proto := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))); proto == "https" {
		return true
	}
	return false
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

func writeResponseGuardBlockedError(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(openAIErrorBody{
		Error: openAIErrorDetail{
			Message: "Response blocked by response_guard: unsafe instruction detected",
			Type:    "straja_response_policy_violation",
			Code:    "response_blocked",
		},
	})
}

// emitActivation builds and sends an activation event via the configured emitter.
func (s *Server) emitActivation(ctx context.Context, w http.ResponseWriter, req *inference.Request, resp *inference.Response, providerName string, decision activation.Decision, mode string) {
	if req == nil {
		return
	}

	actCtx, actSpan := s.startSpan(ctx, "straja.activation.emit", trace.SpanKindInternal, map[string]interface{}{
		"straja.activation.sinks": sinkNames(s.cfg.Activation.Sinks),
		"straja.activation.async": true,
	})
	defer actSpan.End()

	lastValidated := ""
	if s.intelMeta != nil {
		lastValidated = s.intelMeta.LastValidatedAt
	} else if s.strajaGuardMeta != nil {
		lastValidated = s.strajaGuardMeta.LastValidatedAt
	}

	ev := activation.BuildEvent(activation.BuildParams{
		Request:                            req,
		Response:                           resp,
		ProviderName:                       providerName,
		Decision:                           decision,
		LoggingLevel:                       s.loggingLevel,
		IntelStatus:                        s.intelStatus,
		IntelBundleVersion:                 s.intelBundleVer,
		IntelLastValidatedAt:               lastValidated,
		IntelCachePresent:                  s.intelMeta != nil || s.strajaGuardMeta != nil,
		StrajaGuardStatus:                  s.strajaGuardStatus,
		StrajaGuardBundleVer:               s.activeBundleVer,
		StrajaGuardModel:                   s.strajaGuardFamily,
		StrajaGuardSpecialistsConfigSource: normalizeSpecialistsConfigSource(s.strajaGuardSpecialistsConfigSource),
		SecurityThresholds:                 s.securityThresholds,
		IncludeStrajaGuard:                 s.strajaGuardEnabled() && !strings.HasPrefix(s.strajaGuardStatus, "disabled"),
		RequestID:                          req.RequestID,
		Mode:                               mode,
	})
	if ev == nil {
		return
	}

	activation.LogEvent(ev)

	if s.requestStore != nil && req.RequestID != "" {
		s.requestStore.Complete(req.RequestID, ev)
	}

	if s.activationEmitter != nil {
		s.activationEmitter.Emit(actCtx, ev)
		setSpanAttrs(actSpan, map[string]interface{}{
			"straja.activation.emit_result": "queued",
		})
		metrics := s.activationEmitter.MetricsSnapshot()
		setSpanAttrs(actSpan, map[string]interface{}{
			"straja.activation.fail_count": metrics.Dropped(),
		})
	} else {
		setSpanAttrs(actSpan, map[string]interface{}{
			"straja.activation.emit_result": "disabled",
		})
	}

	// Also expose activation to clients via header so the console can show it.
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

func (s *Server) startSpan(ctx context.Context, name string, kind trace.SpanKind, attrs map[string]interface{}) (context.Context, trace.Span) {
	tr := trace.NewNoopTracerProvider().Tracer("noop")
	if s != nil && s.telemetry != nil {
		tr = s.telemetry.Tracer()
	}
	options := []trace.SpanStartOption{}
	if kind != trace.SpanKindInternal {
		options = append(options, trace.WithSpanKind(kind))
	}
	ctx, span := tr.Start(ctx, name, options...)
	if len(attrs) > 0 {
		span.SetAttributes(telemetry.SafeAttributes(attrs)...)
	}
	return ctx, span
}

func setSpanAttrs(span trace.Span, attrs map[string]interface{}) {
	if span == nil {
		return
	}
	if len(attrs) == 0 {
		return
	}
	span.SetAttributes(telemetry.SafeAttributes(attrs)...)
}

func sinkNames(sinks []config.ActivationSinkConfig) []string {
	out := make([]string, 0, len(sinks))
	for _, s := range sinks {
		out = append(out, s.Type)
	}
	return out
}

func isPlaceholderTrustKey(k string) bool {
	k = strings.TrimSpace(strings.ToUpper(k))
	if k == "" {
		return true
	}
	samples := []string{
		"STRAJA-TRUST-XXXX",
		"STRAJA-TRUST-XXXX…",
		"STRAJA-TRUST-XXXX-PLACEHOLDER",
	}
	for _, s := range samples {
		if k == s {
			return true
		}
	}
	return false
}

func trustFingerprint(k string) string {
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
		return "invalid_trust_key"
	}
	if isNetworkyError(err) {
		return "validate_failed_network"
	}
	return "validate_failed"
}

// sgFallbackDecision determines whether cached bundles may be used and what status/reason to report.
func sgFallbackDecision(hasTrust bool, outcome strajaguard.TrustValidationOutcome, currentVersion string) (allowCache bool, status string, reason string) {
	if !hasTrust {
		return false, "disabled_missing_trust_key", "missing_trust_key"
	}

	switch outcome {
	case strajaguard.ValidateInvalidTrust:
		return false, "disabled_invalid_trust_key", "invalid_trust_key"
	case strajaguard.ValidateNetworkError:
		if strings.TrimSpace(currentVersion) != "" {
			return true, "offline_cached_bundle", "network_error"
		}
		return false, "disabled_missing_bundle", "missing_bundle"
	default:
		return false, "disabled_invalid_bundle", "invalid_bundle"
	}
}

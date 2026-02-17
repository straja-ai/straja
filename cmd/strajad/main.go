package main

import (
	"context"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/straja-ai/straja/internal/redact"
	"github.com/straja-ai/straja/internal/strajad"
)

func main() {
	def := strajad.DefaultConfig()
	defaultAddr := firstNonEmpty(os.Getenv("STRAJAD_ADDR"), def.Addr)
	defaultToken := strings.TrimSpace(os.Getenv("STRAJAD_AUTH_TOKEN"))
	defaultAuditPath := firstNonEmpty(os.Getenv("STRAJAD_AUDIT_LOG"), "./tmp/strajad/audit.jsonl")
	defaultStorePath := firstNonEmpty(os.Getenv("STRAJAD_STORE_PATH"), def.StorePath)
	defaultPresenceToken := strings.TrimSpace(os.Getenv("STRAJAD_PRESENCE_TOKEN"))
	defaultBrokerEnabled := boolFromEnv("STRAJAD_BROKER_ENABLED", def.BrokerEnabled)
	defaultBrokerProvider := firstNonEmpty(os.Getenv("STRAJAD_BROKER_PROVIDER"), def.BrokerProvider)
	defaultBrokerEndpoint := firstNonEmpty(os.Getenv("STRAJAD_BROKER_ENDPOINT"), def.BrokerEndpoint)
	defaultBrokerModel := firstNonEmpty(os.Getenv("STRAJAD_BROKER_MODEL"), def.BrokerModel)
	defaultBrokerTimeout := durationFromEnv("STRAJAD_BROKER_TIMEOUT", def.BrokerTimeout)
	defaultBrokerInstallTimeout := durationFromEnv("STRAJAD_BROKER_INSTALL_TIMEOUT", 20*time.Minute)
	defaultEmbeddingEnabled := boolFromEnv("STRAJAD_EMBEDDING_ENABLED", def.EmbeddingEnabled)
	defaultEmbeddingProvider := firstNonEmpty(os.Getenv("STRAJAD_EMBEDDING_PROVIDER"), def.EmbeddingProvider)
	defaultEmbeddingEndpoint := firstNonEmpty(os.Getenv("STRAJAD_EMBEDDING_ENDPOINT"), def.EmbeddingEndpoint)
	defaultEmbeddingModel := firstNonEmpty(os.Getenv("STRAJAD_EMBEDDING_MODEL"), def.EmbeddingModel)
	defaultEmbeddingTimeout := durationFromEnv("STRAJAD_EMBEDDING_TIMEOUT", def.EmbeddingTimeout)
	defaultRetrievalProfile := firstNonEmpty(os.Getenv("STRAJAD_RETRIEVAL_PROFILE"), def.RetrievalProfile)
	defaultRetrievalCacheTTL := durationFromEnv("STRAJAD_RETRIEVAL_CACHE_TTL", def.RetrievalCacheTTL)
	defaultRetrievalExpandedQueries := intFromEnv("STRAJAD_RETRIEVAL_EXPANDED_QUERIES", def.RetrievalExpandedQueries)
	defaultRetrievalLexicalTopN := intFromEnv("STRAJAD_RETRIEVAL_LEXICAL_TOP_N", def.RetrievalLexicalTopN)
	defaultRetrievalDenseTopN := intFromEnv("STRAJAD_RETRIEVAL_DENSE_TOP_N", def.RetrievalDenseTopN)
	defaultRetrievalCandidateCap := intFromEnv("STRAJAD_RETRIEVAL_CANDIDATE_CAP", def.RetrievalCandidateCap)
	defaultRetrievalRerankInN := intFromEnv("STRAJAD_RETRIEVAL_RERANK_IN_N", def.RetrievalRerankInN)
	defaultRetrievalRerankOutN := intFromEnv("STRAJAD_RETRIEVAL_RERANK_OUT_N", def.RetrievalRerankOutN)
	defaultRetrievalIterativePasses := intFromEnv("STRAJAD_RETRIEVAL_ITERATIVE_PASSES", def.RetrievalIterativePasses)
	defaultRetrievalSecondPassAddN := intFromEnv("STRAJAD_RETRIEVAL_SECOND_PASS_ADD_N", def.RetrievalSecondPassAddN)
	defaultRerankerEnabled := boolFromEnv("STRAJAD_RERANKER_ENABLED", def.RerankerEnabled)
	defaultRerankerProvider := firstNonEmpty(os.Getenv("STRAJAD_RERANKER_PROVIDER"), def.RerankerProvider)
	defaultRerankerEndpoint := firstNonEmpty(os.Getenv("STRAJAD_RERANKER_ENDPOINT"), def.RerankerEndpoint)
	defaultRerankerModel := firstNonEmpty(os.Getenv("STRAJAD_RERANKER_MODEL"), def.RerankerModel)
	defaultRerankerTimeout := durationFromEnv("STRAJAD_RERANKER_TIMEOUT", def.RerankerTimeout)
	defaultRerankerBatchSize := intFromEnv("STRAJAD_RERANKER_BATCH_SIZE", def.RerankerBatchSize)
	defaultANNProvider := firstNonEmpty(os.Getenv("STRAJAD_ANN_PROVIDER"), def.ANNProvider)
	defaultHNSWM := intFromEnv("STRAJAD_HNSW_M", def.HNSWM)
	defaultHNSWEfConstruction := intFromEnv("STRAJAD_HNSW_EF_CONSTRUCTION", def.HNSWEfConstruction)
	defaultHNSWEfSearch := intFromEnv("STRAJAD_HNSW_EF_SEARCH", def.HNSWEfSearch)
	defaultHNSWMaxElements := intFromEnv("STRAJAD_HNSW_MAX_ELEMENTS", def.HNSWMaxElements)
	defaultMaxRequestBodyBytes := int64FromEnv("STRAJAD_MAX_REQUEST_BODY_BYTES", def.MaxRequestBodyBytes)
	defaultMaxIngestBytes := intFromEnv("STRAJAD_MAX_INGEST_BYTES", def.MaxIngestBytes)
	defaultMaxTaskWindowBytes := intFromEnv("STRAJAD_MAX_TASK_WINDOW_BYTES", def.MaxTaskWindowBytes)
	defaultTaskWindowTTL := durationFromEnv("STRAJAD_TASK_WINDOW_TTL", def.TaskWindowTTL)
	defaultMaxReadRPM := intFromEnv("STRAJAD_MAX_READ_RPM", def.MaxReadRPM)
	defaultGoogleOAuthClientID := strings.TrimSpace(os.Getenv("STRAJAD_GOOGLE_OAUTH_CLIENT_ID"))
	defaultGoogleOAuthClientSecret := strings.TrimSpace(os.Getenv("STRAJAD_GOOGLE_OAUTH_CLIENT_SECRET"))
	defaultGoogleOAuthRedirectURL := firstNonEmpty(os.Getenv("STRAJAD_GOOGLE_OAUTH_REDIRECT_URL"), def.GoogleOAuthRedirectURL)
	defaultGoogleOAuthAuthURL := firstNonEmpty(os.Getenv("STRAJAD_GOOGLE_OAUTH_AUTH_URL"), def.GoogleOAuthAuthURL)
	defaultGoogleOAuthTokenURL := firstNonEmpty(os.Getenv("STRAJAD_GOOGLE_OAUTH_TOKEN_URL"), def.GoogleOAuthTokenURL)
	defaultGoogleDriveAPIBaseURL := firstNonEmpty(os.Getenv("STRAJAD_GOOGLE_DRIVE_API_BASE_URL"), def.GoogleDriveAPIBaseURL)

	addr := flag.String("addr", defaultAddr, "Local listen address (must be loopback host:port)")
	authToken := flag.String("auth-token", defaultToken, "Bearer token required for /mcp")
	auditPath := flag.String("audit-log", defaultAuditPath, "Audit JSONL output path")
	storePath := flag.String("store-path", defaultStorePath, "Encrypted vault store file path")
	presenceToken := flag.String("presence-token", defaultPresenceToken, "Optional token required for presence-gated collections")
	brokerEnabled := flag.Bool("broker-enabled", defaultBrokerEnabled, "Enable internal broker LLM for plan-only vault.request")
	brokerProvider := flag.String("broker-provider", defaultBrokerProvider, "Broker provider (ollama)")
	brokerEndpoint := flag.String("broker-endpoint", defaultBrokerEndpoint, "Broker endpoint URL")
	brokerModel := flag.String("broker-model", defaultBrokerModel, "Broker model name")
	brokerTimeout := flag.Duration("broker-timeout", defaultBrokerTimeout, "Broker planning timeout")
	brokerInstallModel := flag.Bool("broker-install-model", false, "Pull broker model and exit")
	brokerInstallTimeout := flag.Duration("broker-install-timeout", defaultBrokerInstallTimeout, "Timeout for broker model install")
	embeddingEnabled := flag.Bool("embedding-enabled", defaultEmbeddingEnabled, "Enable local dense embedding retrieval")
	embeddingProvider := flag.String("embedding-provider", defaultEmbeddingProvider, "Embedding provider (ollama)")
	embeddingEndpoint := flag.String("embedding-endpoint", defaultEmbeddingEndpoint, "Embedding endpoint URL")
	embeddingModel := flag.String("embedding-model", defaultEmbeddingModel, "Embedding model name")
	embeddingTimeout := flag.Duration("embedding-timeout", defaultEmbeddingTimeout, "Embedding request timeout")
	retrievalProfile := flag.String("retrieval-profile", defaultRetrievalProfile, "Retrieval profile (high_accuracy|balanced|low_resource)")
	retrievalCacheTTL := flag.Duration("retrieval-cache-ttl", defaultRetrievalCacheTTL, "Hybrid retrieval cache TTL")
	retrievalExpandedQueries := flag.Int("retrieval-expanded-queries", defaultRetrievalExpandedQueries, "Max expanded queries per request")
	retrievalLexicalTopN := flag.Int("retrieval-lexical-top-n", defaultRetrievalLexicalTopN, "Lexical candidates per expanded query")
	retrievalDenseTopN := flag.Int("retrieval-dense-top-n", defaultRetrievalDenseTopN, "Dense candidates per expanded query")
	retrievalCandidateCap := flag.Int("retrieval-candidate-cap", defaultRetrievalCandidateCap, "Merged candidate cap before rerank")
	retrievalRerankInN := flag.Int("retrieval-rerank-in-n", defaultRetrievalRerankInN, "Candidates passed into reranker")
	retrievalRerankOutN := flag.Int("retrieval-rerank-out-n", defaultRetrievalRerankOutN, "Final reranked candidate count")
	retrievalIterativePasses := flag.Int("retrieval-iterative-passes", defaultRetrievalIterativePasses, "Retrieval passes (1 or 2)")
	retrievalSecondPassAddN := flag.Int("retrieval-second-pass-add-n", defaultRetrievalSecondPassAddN, "Max additional objects from second retrieval pass")
	rerankerEnabled := flag.Bool("reranker-enabled", defaultRerankerEnabled, "Enable local model-backed reranking")
	rerankerProvider := flag.String("reranker-provider", defaultRerankerProvider, "Reranker provider (ollama)")
	rerankerEndpoint := flag.String("reranker-endpoint", defaultRerankerEndpoint, "Reranker endpoint URL")
	rerankerModel := flag.String("reranker-model", defaultRerankerModel, "Reranker model name")
	rerankerTimeout := flag.Duration("reranker-timeout", defaultRerankerTimeout, "Reranker request timeout")
	rerankerBatchSize := flag.Int("reranker-batch-size", defaultRerankerBatchSize, "Reranker batch size")
	annProvider := flag.String("ann-provider", defaultANNProvider, "ANN provider (hnswlib|lsh)")
	hnswM := flag.Int("hnsw-m", defaultHNSWM, "HNSW graph out-degree (M)")
	hnswEfConstruction := flag.Int("hnsw-ef-construction", defaultHNSWEfConstruction, "HNSW efConstruction")
	hnswEfSearch := flag.Int("hnsw-ef-search", defaultHNSWEfSearch, "HNSW efSearch")
	hnswMaxElements := flag.Int("hnsw-max-elements", defaultHNSWMaxElements, "HNSW max elements capacity")
	maxRequestBodyBytes := flag.Int64("max-request-body-bytes", defaultMaxRequestBodyBytes, "Max JSON request body bytes for MCP/UI APIs")
	maxIngestBytes := flag.Int("max-ingest-bytes", defaultMaxIngestBytes, "Max raw bytes per ingested/imported file")
	maxTaskWindowBytes := flag.Int("max-task-window-bytes", defaultMaxTaskWindowBytes, "Max cumulative bytes for read snippets per task window")
	taskWindowTTL := flag.Duration("task-window-ttl", defaultTaskWindowTTL, "Task window usage retention duration")
	maxReadRPM := flag.Int("max-read-rpm", defaultMaxReadRPM, "Max read snippet calls per minute across vault/connector read tools")
	googleOAuthClientID := flag.String("google-oauth-client-id", defaultGoogleOAuthClientID, "Google OAuth client ID for Drive login")
	googleOAuthClientSecret := flag.String("google-oauth-client-secret", defaultGoogleOAuthClientSecret, "Google OAuth client secret for Drive login")
	googleOAuthRedirectURL := flag.String("google-oauth-redirect-url", defaultGoogleOAuthRedirectURL, "Google OAuth redirect URL")
	googleOAuthAuthURL := flag.String("google-oauth-auth-url", defaultGoogleOAuthAuthURL, "Google OAuth authorize URL")
	googleOAuthTokenURL := flag.String("google-oauth-token-url", defaultGoogleOAuthTokenURL, "Google OAuth token URL")
	googleDriveAPIBaseURL := flag.String("google-drive-api-base-url", defaultGoogleDriveAPIBaseURL, "Google Drive API base URL")
	flag.Parse()

	cfg := def
	cfg.Addr = strings.TrimSpace(*addr)
	cfg.AuthToken = strings.TrimSpace(*authToken)
	cfg.AuditLogPath = strings.TrimSpace(*auditPath)
	cfg.StorePath = strings.TrimSpace(*storePath)
	cfg.PresenceToken = strings.TrimSpace(*presenceToken)
	cfg.BrokerEnabled = *brokerEnabled
	cfg.BrokerProvider = strings.TrimSpace(*brokerProvider)
	cfg.BrokerEndpoint = strings.TrimSpace(*brokerEndpoint)
	cfg.BrokerModel = strings.TrimSpace(*brokerModel)
	cfg.BrokerTimeout = *brokerTimeout
	cfg.EmbeddingEnabled = *embeddingEnabled
	cfg.EmbeddingProvider = strings.TrimSpace(*embeddingProvider)
	cfg.EmbeddingEndpoint = strings.TrimSpace(*embeddingEndpoint)
	cfg.EmbeddingModel = strings.TrimSpace(*embeddingModel)
	cfg.EmbeddingTimeout = *embeddingTimeout
	cfg.RetrievalProfile = strings.TrimSpace(*retrievalProfile)
	cfg.RetrievalCacheTTL = *retrievalCacheTTL
	cfg.RetrievalExpandedQueries = *retrievalExpandedQueries
	cfg.RetrievalLexicalTopN = *retrievalLexicalTopN
	cfg.RetrievalDenseTopN = *retrievalDenseTopN
	cfg.RetrievalCandidateCap = *retrievalCandidateCap
	cfg.RetrievalRerankInN = *retrievalRerankInN
	cfg.RetrievalRerankOutN = *retrievalRerankOutN
	cfg.RetrievalIterativePasses = *retrievalIterativePasses
	cfg.RetrievalSecondPassAddN = *retrievalSecondPassAddN
	cfg.RerankerEnabled = *rerankerEnabled
	cfg.RerankerProvider = strings.TrimSpace(*rerankerProvider)
	cfg.RerankerEndpoint = strings.TrimSpace(*rerankerEndpoint)
	cfg.RerankerModel = strings.TrimSpace(*rerankerModel)
	cfg.RerankerTimeout = *rerankerTimeout
	cfg.RerankerBatchSize = *rerankerBatchSize
	cfg.ANNProvider = strings.TrimSpace(*annProvider)
	cfg.HNSWM = *hnswM
	cfg.HNSWEfConstruction = *hnswEfConstruction
	cfg.HNSWEfSearch = *hnswEfSearch
	cfg.HNSWMaxElements = *hnswMaxElements
	cfg.MaxRequestBodyBytes = *maxRequestBodyBytes
	cfg.MaxIngestBytes = *maxIngestBytes
	cfg.MaxTaskWindowBytes = *maxTaskWindowBytes
	cfg.TaskWindowTTL = *taskWindowTTL
	cfg.MaxReadRPM = *maxReadRPM
	cfg.GoogleOAuthClientID = strings.TrimSpace(*googleOAuthClientID)
	cfg.GoogleOAuthClientSecret = strings.TrimSpace(*googleOAuthClientSecret)
	cfg.GoogleOAuthRedirectURL = strings.TrimSpace(*googleOAuthRedirectURL)
	cfg.GoogleOAuthAuthURL = strings.TrimSpace(*googleOAuthAuthURL)
	cfg.GoogleOAuthTokenURL = strings.TrimSpace(*googleOAuthTokenURL)
	cfg.GoogleDriveAPIBaseURL = strings.TrimSpace(*googleDriveAPIBaseURL)

	if *brokerInstallModel {
		ctx, cancel := context.WithTimeout(context.Background(), *brokerInstallTimeout)
		defer cancel()
		if err := strajad.InstallBrokerModel(ctx, cfg); err != nil {
			redact.Fatalf("broker model install failed: %v", err)
		}
		redact.Logf("broker model is ready: %s", cfg.BrokerModel)
		return
	}

	daemon, err := strajad.New(cfg)
	if err != nil {
		redact.Fatalf("failed to initialize strajad: %v", err)
	}
	defer func() {
		if cerr := daemon.Close(context.Background()); cerr != nil {
			redact.Logf("close warning: %v", cerr)
		}
	}()

	srv := daemon.HTTPServer()
	ready := make(chan error, 1)
	go func() {
		redact.Logf("starting strajad on %s", cfg.Addr)
		err := srv.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			ready <- err
			return
		}
		ready <- nil
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-stop:
		redact.Logf("received signal %s, shutting down", sig.String())
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			redact.Fatalf("shutdown failed: %v", err)
		}
	case err := <-ready:
		if err != nil {
			redact.Fatalf("server error: %v", err)
		}
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func boolFromEnv(name string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return v
}

func intFromEnv(name string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return n
}

func int64FromEnv(name string, fallback int64) int64 {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return fallback
	}
	return n
}

func durationFromEnv(name string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}
	return d
}

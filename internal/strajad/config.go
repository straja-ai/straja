package strajad

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const defaultToolsSchemaVersion = "straja.vault.mcp.v1alpha9"

// Config controls the Straja Vault daemon behavior.
type Config struct {
	Addr               string
	AuthToken          string
	AuditLogPath       string
	StorePath          string
	PresenceToken      string
	ToolsSchemaVersion string

	GoogleOAuthClientID     string
	GoogleOAuthClientSecret string
	GoogleOAuthRedirectURL  string
	GoogleOAuthAuthURL      string
	GoogleOAuthTokenURL     string
	GoogleDriveAPIBaseURL   string

	BrokerEnabled  bool
	BrokerProvider string
	BrokerEndpoint string
	BrokerModel    string
	BrokerTimeout  time.Duration

	EmbeddingEnabled         bool
	EmbeddingProvider        string
	EmbeddingEndpoint        string
	EmbeddingModel           string
	EmbeddingTimeout         time.Duration
	RetrievalProfile         string
	RetrievalCacheTTL        time.Duration
	RetrievalExpandedQueries int
	RetrievalLexicalTopN     int
	RetrievalDenseTopN       int
	RetrievalCandidateCap    int
	RetrievalRerankInN       int
	RetrievalRerankOutN      int
	RetrievalIterativePasses int
	RetrievalSecondPassAddN  int

	RerankerEnabled   bool
	RerankerProvider  string
	RerankerEndpoint  string
	RerankerModel     string
	RerankerTimeout   time.Duration
	RerankerBatchSize int

	ANNProvider        string
	HNSWM              int
	HNSWEfConstruction int
	HNSWEfSearch       int
	HNSWMaxElements    int

	ReadHeaderTimeout   time.Duration
	ReadTimeout         time.Duration
	WriteTimeout        time.Duration
	IdleTimeout         time.Duration
	MaxRequestBodyBytes int64

	MaxTaskChars       int
	MaxSearchResults   int
	MaxSnippetObjects  int
	MaxSnippetBytes    int
	MaxTaskWindowBytes int
	TaskWindowTTL      time.Duration
	MaxReadRPM         int
	MaxSnippetChars    int
	MaxWriteChars      int
	MaxIngestBytes     int
	MaxExtractedChars  int
	MaxReadCoverage    float64
	MaxAuditRecords    int
}

// DefaultConfig returns safe defaults for a local-only daemon.
func DefaultConfig() Config {
	return Config{
		Addr:                  "127.0.0.1:8787",
		ToolsSchemaVersion:    defaultToolsSchemaVersion,
		StorePath:             "./tmp/strajad/vault.enc",
		GoogleOAuthAuthURL:    "https://accounts.google.com/o/oauth2/v2/auth",
		GoogleOAuthTokenURL:   "https://oauth2.googleapis.com/token",
		GoogleDriveAPIBaseURL: "https://www.googleapis.com/drive/v3",

		BrokerEnabled:            false,
		BrokerProvider:           "ollama",
		BrokerEndpoint:           "http://127.0.0.1:11434",
		BrokerModel:              "phi4-mini:3.8b",
		BrokerTimeout:            4 * time.Second,
		EmbeddingEnabled:         true,
		EmbeddingProvider:        "ollama",
		EmbeddingEndpoint:        "http://127.0.0.1:11434",
		EmbeddingModel:           "nomic-embed-text",
		EmbeddingTimeout:         1400 * time.Millisecond,
		RetrievalProfile:         "high_accuracy",
		RetrievalCacheTTL:        45 * time.Second,
		RetrievalExpandedQueries: 5,
		RetrievalLexicalTopN:     200,
		RetrievalDenseTopN:       200,
		RetrievalCandidateCap:    1200,
		RetrievalRerankInN:       300,
		RetrievalRerankOutN:      20,
		RetrievalIterativePasses: 2,
		RetrievalSecondPassAddN:  15,
		RerankerEnabled:          false,
		RerankerProvider:         "ollama",
		RerankerEndpoint:         "http://127.0.0.1:11434",
		RerankerModel:            "phi4-mini:3.8b",
		RerankerTimeout:          1800 * time.Millisecond,
		RerankerBatchSize:        10,
		ANNProvider:              "hnswlib",
		HNSWM:                    32,
		HNSWEfConstruction:       200,
		HNSWEfSearch:             128,
		HNSWMaxElements:          200000,

		ReadHeaderTimeout:   5 * time.Second,
		ReadTimeout:         30 * time.Second,
		WriteTimeout:        2 * time.Minute,
		IdleTimeout:         60 * time.Second,
		MaxRequestBodyBytes: 12 * 1024 * 1024,

		MaxTaskChars:       4000,
		MaxSearchResults:   10,
		MaxSnippetObjects:  5,
		MaxSnippetBytes:    4096,
		MaxTaskWindowBytes: 16384,
		TaskWindowTTL:      10 * time.Minute,
		MaxReadRPM:         30,
		MaxSnippetChars:    512,
		MaxWriteChars:      4000,
		MaxIngestBytes:     8 * 1024 * 1024,
		MaxExtractedChars:  20000,
		MaxReadCoverage:    0.75,
		MaxAuditRecords:    200,
	}
}

func (c *Config) applyDefaults() {
	def := DefaultConfig()

	if strings.TrimSpace(c.Addr) == "" {
		c.Addr = def.Addr
	}
	if strings.TrimSpace(c.ToolsSchemaVersion) == "" {
		c.ToolsSchemaVersion = def.ToolsSchemaVersion
	}
	if strings.TrimSpace(c.StorePath) == "" {
		c.StorePath = def.StorePath
	}
	if strings.TrimSpace(c.GoogleOAuthRedirectURL) == "" {
		host := strings.TrimSpace(c.Addr)
		if host == "" {
			host = def.Addr
		}
		c.GoogleOAuthRedirectURL = "http://" + host + "/vault/api/drive/oauth/callback"
	}
	if strings.TrimSpace(c.GoogleOAuthAuthURL) == "" {
		c.GoogleOAuthAuthURL = def.GoogleOAuthAuthURL
	}
	if strings.TrimSpace(c.GoogleOAuthTokenURL) == "" {
		c.GoogleOAuthTokenURL = def.GoogleOAuthTokenURL
	}
	if strings.TrimSpace(c.GoogleDriveAPIBaseURL) == "" {
		c.GoogleDriveAPIBaseURL = def.GoogleDriveAPIBaseURL
	}
	if strings.TrimSpace(c.BrokerProvider) == "" {
		c.BrokerProvider = def.BrokerProvider
	}
	if strings.TrimSpace(c.BrokerEndpoint) == "" {
		c.BrokerEndpoint = def.BrokerEndpoint
	}
	if strings.TrimSpace(c.BrokerModel) == "" {
		c.BrokerModel = def.BrokerModel
	}
	if c.BrokerTimeout <= 0 {
		c.BrokerTimeout = def.BrokerTimeout
	}
	if strings.TrimSpace(c.EmbeddingProvider) == "" {
		c.EmbeddingProvider = def.EmbeddingProvider
	}
	if strings.TrimSpace(c.EmbeddingEndpoint) == "" {
		c.EmbeddingEndpoint = def.EmbeddingEndpoint
	}
	if strings.TrimSpace(c.EmbeddingModel) == "" {
		c.EmbeddingModel = def.EmbeddingModel
	}
	if c.EmbeddingTimeout <= 0 {
		c.EmbeddingTimeout = def.EmbeddingTimeout
	}
	c.RetrievalProfile = normalizeRetrievalProfile(c.RetrievalProfile)
	if c.RetrievalProfile == "" {
		c.RetrievalProfile = def.RetrievalProfile
	}
	// Profile presets (balanced/low_resource) override retrieval depth knobs.
	// high_accuracy is the baseline default and remains fully configurable.
	if c.RetrievalProfile != "" && c.RetrievalProfile != def.RetrievalProfile {
		applyRetrievalProfile(c)
	}
	if c.RetrievalCacheTTL <= 0 {
		c.RetrievalCacheTTL = def.RetrievalCacheTTL
	}
	if c.RetrievalExpandedQueries <= 0 {
		c.RetrievalExpandedQueries = def.RetrievalExpandedQueries
	}
	if c.RetrievalLexicalTopN <= 0 {
		c.RetrievalLexicalTopN = def.RetrievalLexicalTopN
	}
	if c.RetrievalDenseTopN <= 0 {
		c.RetrievalDenseTopN = def.RetrievalDenseTopN
	}
	if c.RetrievalCandidateCap <= 0 {
		c.RetrievalCandidateCap = def.RetrievalCandidateCap
	}
	if c.RetrievalRerankInN <= 0 {
		c.RetrievalRerankInN = def.RetrievalRerankInN
	}
	if c.RetrievalRerankOutN <= 0 {
		c.RetrievalRerankOutN = def.RetrievalRerankOutN
	}
	if c.RetrievalIterativePasses <= 0 {
		c.RetrievalIterativePasses = def.RetrievalIterativePasses
	}
	if c.RetrievalSecondPassAddN <= 0 {
		c.RetrievalSecondPassAddN = def.RetrievalSecondPassAddN
	}
	if strings.TrimSpace(c.RerankerProvider) == "" {
		c.RerankerProvider = def.RerankerProvider
	}
	if strings.TrimSpace(c.RerankerEndpoint) == "" {
		c.RerankerEndpoint = def.RerankerEndpoint
	}
	if strings.TrimSpace(c.RerankerModel) == "" {
		c.RerankerModel = def.RerankerModel
	}
	if c.RerankerTimeout <= 0 {
		c.RerankerTimeout = def.RerankerTimeout
	}
	if c.RerankerBatchSize <= 0 {
		c.RerankerBatchSize = def.RerankerBatchSize
	}
	if strings.TrimSpace(c.ANNProvider) == "" {
		c.ANNProvider = def.ANNProvider
	}
	if c.HNSWM <= 0 {
		c.HNSWM = def.HNSWM
	}
	if c.HNSWEfConstruction <= 0 {
		c.HNSWEfConstruction = def.HNSWEfConstruction
	}
	if c.HNSWEfSearch <= 0 {
		c.HNSWEfSearch = def.HNSWEfSearch
	}
	if c.HNSWMaxElements <= 0 {
		c.HNSWMaxElements = def.HNSWMaxElements
	}
	if c.ReadHeaderTimeout <= 0 {
		c.ReadHeaderTimeout = def.ReadHeaderTimeout
	}
	if c.ReadTimeout <= 0 {
		c.ReadTimeout = def.ReadTimeout
	}
	if c.WriteTimeout <= 0 {
		c.WriteTimeout = def.WriteTimeout
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = def.IdleTimeout
	}
	if c.MaxRequestBodyBytes <= 0 {
		c.MaxRequestBodyBytes = def.MaxRequestBodyBytes
	}
	if c.MaxTaskChars <= 0 {
		c.MaxTaskChars = def.MaxTaskChars
	}
	if c.MaxSearchResults <= 0 {
		c.MaxSearchResults = def.MaxSearchResults
	}
	if c.MaxSnippetObjects <= 0 {
		c.MaxSnippetObjects = def.MaxSnippetObjects
	}
	if c.MaxSnippetBytes <= 0 {
		c.MaxSnippetBytes = def.MaxSnippetBytes
	}
	if c.MaxTaskWindowBytes <= 0 {
		c.MaxTaskWindowBytes = def.MaxTaskWindowBytes
	}
	if c.TaskWindowTTL <= 0 {
		c.TaskWindowTTL = def.TaskWindowTTL
	}
	if c.MaxReadRPM <= 0 {
		c.MaxReadRPM = def.MaxReadRPM
	}
	if c.MaxSnippetChars <= 0 {
		c.MaxSnippetChars = def.MaxSnippetChars
	}
	if c.MaxWriteChars <= 0 {
		c.MaxWriteChars = def.MaxWriteChars
	}
	if c.MaxIngestBytes <= 0 {
		c.MaxIngestBytes = def.MaxIngestBytes
	}
	if c.MaxExtractedChars <= 0 {
		c.MaxExtractedChars = def.MaxExtractedChars
	}
	if c.MaxReadCoverage <= 0 {
		c.MaxReadCoverage = def.MaxReadCoverage
	}
	if c.MaxAuditRecords <= 0 {
		c.MaxAuditRecords = def.MaxAuditRecords
	}
}

// Validate ensures the daemon is configured for local-only operation with strict budgets.
func (c Config) Validate() error {
	if strings.TrimSpace(c.AuthToken) == "" {
		return errors.New("auth token is required")
	}
	if strings.TrimSpace(c.StorePath) == "" {
		return errors.New("store path is required")
	}

	host, _, err := net.SplitHostPort(c.Addr)
	if err != nil {
		return fmt.Errorf("addr must be host:port: %w", err)
	}
	if !isLoopbackHost(host) {
		return fmt.Errorf("addr must bind to loopback host, got %q", host)
	}

	if c.MaxRequestBodyBytes <= 0 {
		return errors.New("max request body bytes must be > 0")
	}
	if c.MaxTaskChars <= 0 || c.MaxSearchResults <= 0 || c.MaxSnippetObjects <= 0 || c.MaxSnippetBytes <= 0 || c.MaxSnippetChars <= 0 || c.MaxWriteChars <= 0 || c.MaxIngestBytes <= 0 || c.MaxExtractedChars <= 0 || c.MaxAuditRecords <= 0 {
		return errors.New("all budget settings must be > 0")
	}
	if c.MaxReadCoverage <= 0 || c.MaxReadCoverage > 1 {
		return errors.New("max read coverage must be in (0, 1]")
	}
	if strings.TrimSpace(c.GoogleOAuthAuthURL) == "" || strings.TrimSpace(c.GoogleOAuthTokenURL) == "" || strings.TrimSpace(c.GoogleDriveAPIBaseURL) == "" {
		return errors.New("google api endpoint settings must be non-empty")
	}
	if c.BrokerEnabled {
		if strings.TrimSpace(c.BrokerProvider) == "" {
			return errors.New("broker provider is required when broker is enabled")
		}
		if strings.TrimSpace(c.BrokerModel) == "" {
			return errors.New("broker model is required when broker is enabled")
		}
		if strings.TrimSpace(c.BrokerEndpoint) == "" {
			return errors.New("broker endpoint is required when broker is enabled")
		}
		if c.BrokerTimeout <= 0 {
			return errors.New("broker timeout must be > 0 when broker is enabled")
		}
	}
	if c.EmbeddingEnabled {
		if strings.TrimSpace(c.EmbeddingProvider) == "" {
			return errors.New("embedding provider is required when embedding is enabled")
		}
		if strings.TrimSpace(c.EmbeddingEndpoint) == "" {
			return errors.New("embedding endpoint is required when embedding is enabled")
		}
		if strings.TrimSpace(c.EmbeddingModel) == "" {
			return errors.New("embedding model is required when embedding is enabled")
		}
		if c.EmbeddingTimeout <= 0 {
			return errors.New("embedding timeout must be > 0 when embedding is enabled")
		}
	}
	if c.RerankerEnabled {
		if strings.TrimSpace(c.RerankerProvider) == "" {
			return errors.New("reranker provider is required when reranker is enabled")
		}
		if strings.TrimSpace(c.RerankerEndpoint) == "" {
			return errors.New("reranker endpoint is required when reranker is enabled")
		}
		if strings.TrimSpace(c.RerankerModel) == "" {
			return errors.New("reranker model is required when reranker is enabled")
		}
		if c.RerankerTimeout <= 0 {
			return errors.New("reranker timeout must be > 0 when reranker is enabled")
		}
		if c.RerankerBatchSize <= 0 {
			return errors.New("reranker batch size must be > 0 when reranker is enabled")
		}
	}
	if c.RetrievalCacheTTL <= 0 {
		return errors.New("retrieval cache ttl must be > 0")
	}
	if normalizeRetrievalProfile(c.RetrievalProfile) == "" {
		return errors.New("retrieval profile must be one of: high_accuracy, balanced, low_resource")
	}
	if c.RetrievalExpandedQueries <= 0 || c.RetrievalLexicalTopN <= 0 || c.RetrievalDenseTopN <= 0 || c.RetrievalCandidateCap <= 0 || c.RetrievalRerankInN <= 0 || c.RetrievalRerankOutN <= 0 || c.RetrievalIterativePasses <= 0 || c.RetrievalSecondPassAddN <= 0 {
		return errors.New("retrieval depth settings must be > 0")
	}
	if c.MaxTaskWindowBytes <= 0 {
		return errors.New("max task window bytes must be > 0")
	}
	if c.TaskWindowTTL <= 0 {
		return errors.New("task window ttl must be > 0")
	}
	if c.MaxReadRPM <= 0 {
		return errors.New("max read rpm must be > 0")
	}
	switch strings.TrimSpace(strings.ToLower(c.ANNProvider)) {
	case "", "hnswlib", "lsh":
	default:
		return errors.New("ann provider must be one of: hnswlib, lsh")
	}
	if c.HNSWM <= 0 || c.HNSWEfConstruction <= 0 || c.HNSWEfSearch <= 0 || c.HNSWMaxElements <= 0 {
		return errors.New("hnsw parameters must be > 0")
	}

	return nil
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func normalizeRetrievalProfile(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	switch v {
	case "", "high_accuracy":
		return "high_accuracy"
	case "balanced":
		return "balanced"
	case "low_resource":
		return "low_resource"
	default:
		return ""
	}
}

func applyRetrievalProfile(c *Config) {
	if c == nil {
		return
	}
	switch normalizeRetrievalProfile(c.RetrievalProfile) {
	case "balanced":
		c.RetrievalExpandedQueries = 4
		c.RetrievalLexicalTopN = 120
		c.RetrievalDenseTopN = 120
		c.RetrievalCandidateCap = 700
		c.RetrievalRerankInN = 160
		c.RetrievalRerankOutN = 14
		c.RetrievalIterativePasses = 1
		c.RetrievalSecondPassAddN = 8
	case "low_resource":
		c.RetrievalExpandedQueries = 3
		c.RetrievalLexicalTopN = 60
		c.RetrievalDenseTopN = 60
		c.RetrievalCandidateCap = 320
		c.RetrievalRerankInN = 80
		c.RetrievalRerankOutN = 10
		c.RetrievalIterativePasses = 1
		c.RetrievalSecondPassAddN = 5
	default:
		c.RetrievalExpandedQueries = 5
		c.RetrievalLexicalTopN = 200
		c.RetrievalDenseTopN = 200
		c.RetrievalCandidateCap = 1200
		c.RetrievalRerankInN = 300
		c.RetrievalRerankOutN = 20
		c.RetrievalIterativePasses = 2
		c.RetrievalSecondPassAddN = 15
	}
}

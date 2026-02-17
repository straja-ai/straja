package strajad

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/straja-ai/straja/internal/redact"
)

const (
	rpcErrInvalidRequest = -32600
	rpcErrMethodNotFound = -32601
	rpcErrInvalidParams  = -32602
	rpcErrInternal       = -32603
	rpcErrBudgetExceeded = -32010
	rpcErrVaultLocked    = -32020
	rpcErrUnlockFailed   = -32021
	rpcErrPolicyDenied   = -32030
	rpcErrNotFound       = -32040
)

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type rpcToolsCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

type toolDefinition struct {
	Name        string         `json:"name"`
	Version     string         `json:"version"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"input_schema"`
}

// Daemon is the local Vault daemon with MCP tool endpoints.
type Daemon struct {
	cfg        Config
	mux        *http.ServeMux
	store      *vaultStore
	auditor    *Auditor
	broker     plannerBroker
	mail       *mailConnector
	drive      *driveConnector
	github     *githubConnector
	web        *webConnector
	httpClient *http.Client
	oauthMu    sync.Mutex
	oauthState map[string]time.Time
	readMu     sync.Mutex
	readRates  map[string][]time.Time
	readWindow map[string]readWindowUsage
}

// New builds a local-only daemon with enforced budgets and auditing.
func New(cfg Config) (*Daemon, error) {
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	auditor, err := newAuditor(cfg.AuditLogPath, 2000)
	if err != nil {
		return nil, err
	}

	var broker plannerBroker
	if cfg.BrokerEnabled {
		var err error
		broker, err = newPlannerBroker(cfg)
		if err != nil {
			return nil, err
		}
	}
	embedder := newEmbeddingProvider(cfg)
	reranker := newRerankerProvider(cfg)

	d := &Daemon{
		cfg: cfg,
		mux: http.NewServeMux(),
		store: newVaultStore(cfg.StorePath, cfg.PresenceToken, retrievalConfig{
			maxSnippetChars:    cfg.MaxSnippetChars,
			maxReadCoverage:    cfg.MaxReadCoverage,
			cacheTTL:           cfg.RetrievalCacheTTL,
			profile:            cfg.RetrievalProfile,
			embedder:           embedder,
			reranker:           reranker,
			annProvider:        cfg.ANNProvider,
			hnswM:              cfg.HNSWM,
			hnswEfConstruction: cfg.HNSWEfConstruction,
			hnswEfSearch:       cfg.HNSWEfSearch,
			hnswMaxElements:    cfg.HNSWMaxElements,
			maxLexicalTopN:     cfg.RetrievalLexicalTopN,
			maxDenseTopN:       cfg.RetrievalDenseTopN,
			maxCandidateN:      cfg.RetrievalCandidateCap,
			maxRerankInN:       cfg.RetrievalRerankInN,
			maxRerankOutN:      cfg.RetrievalRerankOutN,
			iterativePasses:    cfg.RetrievalIterativePasses,
			secondPassAddN:     cfg.RetrievalSecondPassAddN,
			indexMeta:          defaultRetrievalIndexMeta(embedder, reranker, resolveANNVersion(cfg.ANNProvider, nil)),
		}),
		auditor: auditor,
		broker:  broker,
		mail: newMailConnector(retrievalConfig{
			maxSnippetChars: cfg.MaxSnippetChars,
			maxReadCoverage: cfg.MaxReadCoverage,
		}),
		drive: newDriveConnector(retrievalConfig{
			maxSnippetChars: cfg.MaxSnippetChars,
			maxReadCoverage: cfg.MaxReadCoverage,
		}),
		github: newGitHubConnector(retrievalConfig{
			maxSnippetChars: cfg.MaxSnippetChars,
			maxReadCoverage: cfg.MaxReadCoverage,
		}),
		web: newWebConnector(retrievalConfig{
			maxSnippetChars: cfg.MaxSnippetChars,
			maxReadCoverage: cfg.MaxReadCoverage,
		}),
		httpClient: &http.Client{Timeout: 20 * time.Second},
		oauthState: map[string]time.Time{},
		readRates:  map[string][]time.Time{},
		readWindow: map[string]readWindowUsage{},
	}
	d.routes()
	return d, nil
}

func (d *Daemon) routes() {
	d.mux.HandleFunc("/healthz", d.handleHealth)
	d.mux.HandleFunc("/readyz", d.handleReady)
	d.mux.HandleFunc("/mcp", d.handleMCP)
	d.mux.HandleFunc("/vault", d.handleVaultUI)
	d.mux.HandleFunc("/vault/", d.handleVaultUI)
	d.mux.HandleFunc("/vault/api/state", d.handleVaultUIState)
	d.mux.HandleFunc("/vault/api/unlock", d.handleVaultUIUnlock)
	d.mux.HandleFunc("/vault/api/lock", d.handleVaultUILock)
	d.mux.HandleFunc("/vault/api/collections", d.handleVaultUICollections)
	d.mux.HandleFunc("/vault/api/collections/update", d.handleVaultUICollectionUpdate)
	d.mux.HandleFunc("/vault/api/items", d.handleVaultUIItems)
	d.mux.HandleFunc("/vault/api/reindex", d.handleVaultUIReindex)
	d.mux.HandleFunc("/vault/api/connectors", d.handleVaultUIConnectors)
	d.mux.HandleFunc("/vault/api/approvals", d.handleVaultUIApprovals)
	d.mux.HandleFunc("/vault/api/drive/oauth/start", d.handleVaultUIDriveOAuthStart)
	d.mux.HandleFunc("/vault/api/drive/oauth/callback", d.handleVaultUIDriveOAuthCallback)
	d.mux.HandleFunc("/vault/api/drive/files", d.handleVaultUIDriveFiles)
	d.mux.HandleFunc("/vault/api/drive/import", d.handleVaultUIDriveImport)
	d.mux.HandleFunc("/vault/api/broker/model", d.handleVaultUIBrokerModel)
	d.mux.HandleFunc("/vault/api/broker/model/install", d.handleVaultUIBrokerModelInstall)
	d.mux.HandleFunc("/vault/api/audit", d.handleVaultUIAudit)
	d.mux.HandleFunc("/vault/api/query", d.handleVaultUIQuery)
}

// Handler returns the daemon HTTP handler for tests and embedding.
func (d *Daemon) Handler() http.Handler {
	return d.mux
}

// HTTPServer returns a preconfigured HTTP server for running the daemon.
func (d *Daemon) HTTPServer() *http.Server {
	return &http.Server{
		Addr:              d.cfg.Addr,
		Handler:           d.mux,
		ReadHeaderTimeout: d.cfg.ReadHeaderTimeout,
		ReadTimeout:       d.cfg.ReadTimeout,
		WriteTimeout:      d.cfg.WriteTimeout,
		IdleTimeout:       d.cfg.IdleTimeout,
	}
}

// Close flushes and closes daemon resources.
func (d *Daemon) Close(ctx context.Context) error {
	if d == nil {
		return nil
	}
	if d.store != nil {
		_ = d.store.Lock()
	}
	if d.auditor != nil {
		if err := d.auditor.Close(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (d *Daemon) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"module": "strajad",
	})
}

func (d *Daemon) handleReady(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	annInit := d.store.ANNInitStatus()
	writeJSON(w, http.StatusOK, map[string]any{
		"status":                     "ready",
		"module":                     "strajad",
		"mcp_path":                   "/mcp",
		"tools_schema_version":       d.cfg.ToolsSchemaVersion,
		"tool_count":                 len(d.toolDefinitions()),
		"vault_locked":               !d.store.IsUnlocked(),
		"presence_access":            d.store.HasPresenceAccess(),
		"broker_enabled":             d.cfg.BrokerEnabled,
		"broker_model":               d.cfg.BrokerModel,
		"broker_provider":            d.cfg.BrokerProvider,
		"embedding_enabled":          d.cfg.EmbeddingEnabled,
		"embedding_model":            d.cfg.EmbeddingModel,
		"embedding_provider":         d.cfg.EmbeddingProvider,
		"reranker_enabled":           d.cfg.RerankerEnabled,
		"reranker_model":             d.cfg.RerankerModel,
		"reranker_provider":          d.cfg.RerankerProvider,
		"ann_provider":               d.cfg.ANNProvider,
		"ann_version":                d.store.retrieval.indexMeta.ANNVersion,
		"ann_init_mode":              annInit.Mode,
		"ann_init_chunks":            annInit.ChunkCount,
		"ann_init_at":                annInit.At,
		"retrieval_expanded_queries": d.cfg.RetrievalExpandedQueries,
		"retrieval_lexical_top_n":    d.cfg.RetrievalLexicalTopN,
		"retrieval_dense_top_n":      d.cfg.RetrievalDenseTopN,
		"retrieval_candidate_cap":    d.cfg.RetrievalCandidateCap,
		"retrieval_rerank_in_n":      d.cfg.RetrievalRerankInN,
		"retrieval_rerank_out_n":     d.cfg.RetrievalRerankOutN,
		"retrieval_profile":          d.cfg.RetrievalProfile,
		"retrieval_iterative_passes": d.cfg.RetrievalIterativePasses,
		"retrieval_second_pass_addn": d.cfg.RetrievalSecondPassAddN,
		"max_task_window_bytes":      d.cfg.MaxTaskWindowBytes,
		"task_window_ttl_seconds":    int(d.cfg.TaskWindowTTL.Seconds()),
		"max_read_rpm":               d.cfg.MaxReadRPM,
	})
}

func (d *Daemon) handleMCP(w http.ResponseWriter, r *http.Request) {
	requestID := requestID(r)
	remote := strings.TrimSpace(r.RemoteAddr)

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isLoopbackRemoteAddr(remote) {
		d.auditDeny(r.Context(), requestID, remote, "", "", "non_loopback_remote", nil)
		http.Error(w, "forbidden: local-only endpoint", http.StatusForbidden)
		return
	}
	if !d.authorized(r) {
		d.auditDeny(r.Context(), requestID, remote, "", "", "auth_failed", nil)
		w.Header().Set("WWW-Authenticate", `Bearer realm="strajad"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, d.cfg.MaxRequestBodyBytes)
	defer r.Body.Close()

	var req rpcRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var tooLarge *http.MaxBytesError
		reason := "decode_error"
		status := http.StatusBadRequest
		if errors.As(err, &tooLarge) {
			reason = "request_body_too_large"
			status = http.StatusRequestEntityTooLarge
		}
		d.auditDeny(r.Context(), requestID, remote, "", "", reason, map[string]any{"error": redact.String(err.Error())})
		http.Error(w, "invalid request body", status)
		return
	}
	_, _ = io.Copy(io.Discard, r.Body)

	if strings.TrimSpace(req.JSONRPC) != "2.0" || strings.TrimSpace(req.Method) == "" {
		d.auditDeny(r.Context(), requestID, remote, req.Method, "", "invalid_rpc_request", nil)
		writeJSON(w, http.StatusBadRequest, rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &rpcError{
				Code:    rpcErrInvalidRequest,
				Message: "invalid request",
			},
		})
		return
	}

	result, rpcErr, toolName, reason, meta := d.dispatch(req)
	if rpcErr != nil {
		d.auditDeny(r.Context(), requestID, remote, req.Method, toolName, reason, meta)
		writeJSON(w, http.StatusOK, rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   rpcErr,
		})
		return
	}

	d.auditAllow(r.Context(), requestID, remote, req.Method, toolName, reason, meta)
	writeJSON(w, http.StatusOK, rpcResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  result,
	})
}

func (d *Daemon) dispatch(req rpcRequest) (result any, rpcErr *rpcError, toolName string, reason string, meta map[string]any) {
	switch strings.TrimSpace(req.Method) {
	case "initialize":
		return map[string]any{
			"server": map[string]any{
				"name":    "strajad",
				"version": "phase2",
			},
			"capabilities": map[string]any{
				"tools": map[string]any{},
			},
			"tools_schema_version": d.cfg.ToolsSchemaVersion,
		}, nil, "", "ok_initialize", nil
	case "tools/list":
		return map[string]any{
			"tools_schema_version": d.cfg.ToolsSchemaVersion,
			"tools":                d.toolDefinitions(),
		}, nil, "", "ok_tools_list", nil
	case "tools/call":
		var params rpcToolsCallParams
		if err := decodeArgs(req.Params, &params); err != nil {
			return nil, &rpcError{
				Code:    rpcErrInvalidParams,
				Message: "invalid tools/call params",
				Data:    map[string]any{"error": redact.String(err.Error())},
			}, "", "invalid_tool_call_params", nil
		}
		name := strings.TrimSpace(params.Name)
		if name == "" {
			return nil, &rpcError{
				Code:    rpcErrInvalidParams,
				Message: "tool name is required",
			}, "", "tool_name_required", nil
		}
		res, err, reason, meta := d.callTool(name, params.Arguments)
		if err != nil {
			return nil, err, name, reason, meta
		}
		return map[string]any{
			"tools_schema_version": d.cfg.ToolsSchemaVersion,
			"tool":                 name,
			"data":                 res,
		}, nil, name, reason, meta
	default:
		return nil, &rpcError{
			Code:    rpcErrMethodNotFound,
			Message: "method not found",
		}, "", "method_not_found", map[string]any{"method": req.Method}
	}
}

func (d *Daemon) toolDefinitions() []toolDefinition {
	version := d.cfg.ToolsSchemaVersion
	return []toolDefinition{
		{
			Name:        "vault.unlock",
			Version:     version,
			Description: "Unlock encrypted vault state for current daemon session.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"passphrase":     map[string]any{"type": "string"},
					"presence_token": map[string]any{"type": "string"},
				},
				"required": []string{"passphrase"},
			},
		},
		{
			Name:        "vault.lock",
			Version:     version,
			Description: "Lock vault and clear decrypted state from memory.",
			InputSchema: map[string]any{
				"type": "object",
			},
		},
		{
			Name:        "vault.collections",
			Version:     version,
			Description: "List or create collections/compartments with policy tiers.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"action":      map[string]any{"type": "string", "enum": []string{"list", "create"}},
					"name":        map[string]any{"type": "string"},
					"tier":        map[string]any{"type": "string", "enum": []string{vaultTierAlwaysOn, vaultTierPresenceRequired}},
					"description": map[string]any{"type": "string"},
				},
			},
		},
		{
			Name:        "vault.request",
			Version:     version,
			Description: "Plan-only entrypoint for vault tasks. Does not execute actions.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"task":       map[string]any{"type": "string"},
					"collection": map[string]any{"type": "string"},
				},
				"required": []string{"task"},
			},
		},
		{
			Name:        "vault.search",
			Version:     version,
			Description: "Return object IDs and safe summaries only.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query":      map[string]any{"type": "string"},
					"collection": map[string]any{"type": "string"},
					"limit":      map[string]any{"type": "integer", "minimum": 1},
				},
				"required": []string{"query"},
			},
		},
		{
			Name:        "vault.read_snippets",
			Version:     version,
			Description: "Snippet-first bounded read by object IDs.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"ids":                   map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"query":                 map[string]any{"type": "string"},
					"task_window_id":        map[string]any{"type": "string"},
					"max_bytes":             map[string]any{"type": "integer", "minimum": 1},
					"max_chars_per_snippet": map[string]any{"type": "integer", "minimum": 1},
				},
				"required": []string{"ids"},
			},
		},
		{
			Name:        "vault.ingest",
			Version:     version,
			Description: "Ingest text/PDF content through extraction and indexing pipeline.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"collection":     map[string]any{"type": "string"},
					"title":          map[string]any{"type": "string"},
					"content_type":   map[string]any{"type": "string", "enum": []string{"text/plain", "application/pdf"}},
					"content_base64": map[string]any{"type": "string"},
					"text":           map[string]any{"type": "string"},
				},
				"required": []string{"content_type"},
			},
		},
		{
			Name:        "vault.write",
			Version:     version,
			Description: "Create or update bounded note-like objects.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id":         map[string]any{"type": "string"},
					"collection": map[string]any{"type": "string"},
					"title":      map[string]any{"type": "string"},
					"content":    map[string]any{"type": "string"},
				},
				"required": []string{"content"},
			},
		},
		{
			Name:        "vault.delete",
			Version:     version,
			Description: "Delete an object by ID.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id": map[string]any{"type": "string"},
				},
				"required": []string{"id"},
			},
		},
		{
			Name:        "vault.audit",
			Version:     version,
			Description: "Retrieve recent audit records for transparency.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"limit": map[string]any{"type": "integer", "minimum": 1},
				},
			},
		},
		{
			Name:        "vault.connectors",
			Version:     version,
			Description: "Manage encrypted connector credentials and visibility.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"action":   map[string]any{"type": "string", "enum": []string{"list", "set_token", "clear_token"}},
					"provider": map[string]any{"type": "string", "enum": []string{"mail", "drive", "github", "web"}},
					"token":    map[string]any{"type": "string"},
				},
			},
		},
		{
			Name:        "vault.approvals",
			Version:     version,
			Description: "List and resolve queued high-risk side-effect approvals.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"action": map[string]any{"type": "string", "enum": []string{"list", "approve", "reject"}},
					"id":     map[string]any{"type": "string"},
					"status": map[string]any{"type": "string", "enum": []string{"pending", "approved", "rejected"}},
					"reason": map[string]any{"type": "string"},
					"limit":  map[string]any{"type": "integer", "minimum": 1},
				},
			},
		},
		{
			Name:        "mail.search",
			Version:     version,
			Description: "Search mail metadata and return bounded summaries only.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query":      map[string]any{"type": "string"},
					"collection": map[string]any{"type": "string"},
					"limit":      map[string]any{"type": "integer", "minimum": 1},
				},
				"required": []string{"query"},
			},
		},
		{
			Name:        "mail.read_snippets",
			Version:     version,
			Description: "Read bounded snippets from mail IDs. Never bulk by default.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"ids":                   map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"query":                 map[string]any{"type": "string"},
					"task_window_id":        map[string]any{"type": "string"},
					"max_bytes":             map[string]any{"type": "integer", "minimum": 1},
					"max_chars_per_snippet": map[string]any{"type": "integer", "minimum": 1},
				},
				"required": []string{"ids"},
			},
		},
		{
			Name:        "mail.draft",
			Version:     version,
			Description: "Create mail drafts for approval-gated side effects.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"collection": map[string]any{"type": "string"},
					"to":         map[string]any{"type": "string"},
					"subject":    map[string]any{"type": "string"},
					"body":       map[string]any{"type": "string"},
				},
				"required": []string{"to", "subject", "body"},
			},
		},
		{
			Name:        "mail.send",
			Version:     version,
			Description: "Queue a draft send request for explicit approval (no direct send).",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"draft_id": map[string]any{"type": "string"},
				},
				"required": []string{"draft_id"},
			},
		},
		{
			Name:        "drive.search",
			Version:     version,
			Description: "Search drive metadata and return bounded summaries only.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query":      map[string]any{"type": "string"},
					"collection": map[string]any{"type": "string"},
					"limit":      map[string]any{"type": "integer", "minimum": 1},
				},
				"required": []string{"query"},
			},
		},
		{
			Name:        "drive.read_snippets",
			Version:     version,
			Description: "Read bounded snippets from drive file IDs. Never bulk by default.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"ids":                   map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"query":                 map[string]any{"type": "string"},
					"task_window_id":        map[string]any{"type": "string"},
					"max_bytes":             map[string]any{"type": "integer", "minimum": 1},
					"max_chars_per_snippet": map[string]any{"type": "integer", "minimum": 1},
				},
				"required": []string{"ids"},
			},
		},
		{
			Name:        "github.search",
			Version:     version,
			Description: "Search GitHub metadata and return bounded summaries only.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query":      map[string]any{"type": "string"},
					"collection": map[string]any{"type": "string"},
					"limit":      map[string]any{"type": "integer", "minimum": 1},
				},
				"required": []string{"query"},
			},
		},
		{
			Name:        "github.read_snippets",
			Version:     version,
			Description: "Read bounded snippets from GitHub item IDs. Never bulk by default.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"ids":                   map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"query":                 map[string]any{"type": "string"},
					"task_window_id":        map[string]any{"type": "string"},
					"max_bytes":             map[string]any{"type": "integer", "minimum": 1},
					"max_chars_per_snippet": map[string]any{"type": "integer", "minimum": 1},
				},
				"required": []string{"ids"},
			},
		},
		{
			Name:        "web.search",
			Version:     version,
			Description: "Search web metadata and return bounded summaries only.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query":      map[string]any{"type": "string"},
					"collection": map[string]any{"type": "string"},
					"limit":      map[string]any{"type": "integer", "minimum": 1},
				},
				"required": []string{"query"},
			},
		},
		{
			Name:        "web.open_reader_snippet",
			Version:     version,
			Description: "Open one bounded reader snippet by web result ID or URL.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"id":                    map[string]any{"type": "string"},
					"url":                   map[string]any{"type": "string"},
					"query":                 map[string]any{"type": "string"},
					"task_window_id":        map[string]any{"type": "string"},
					"max_bytes":             map[string]any{"type": "integer", "minimum": 1},
					"max_chars_per_snippet": map[string]any{"type": "integer", "minimum": 1},
				},
			},
		},
	}
}

func (d *Daemon) callTool(name string, rawArgs json.RawMessage) (any, *rpcError, string, map[string]any) {
	switch name {
	case "vault.unlock":
		var args struct {
			Passphrase    string `json:"passphrase"`
			PresenceToken string `json:"presence_token"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			return nil, invalidParamsErr(err), "invalid_vault_unlock_args", nil
		}
		created, err := d.store.Unlock(args.Passphrase, args.PresenceToken)
		if err != nil {
			return nil, mapStoreError(err), "vault_unlock_failed", map[string]any{"error": redact.String(err.Error())}
		}
		collections, err := d.store.ListCollections()
		if err != nil {
			return nil, mapStoreError(err), "vault_unlock_list_collections_failed", nil
		}
		annStatus := d.store.ANNInitStatus()
		if strings.TrimSpace(annStatus.Mode) != "" {
			redact.Logf("vault ann init: mode=%s chunks=%d at=%s", annStatus.Mode, annStatus.ChunkCount, annStatus.At.Format(time.RFC3339))
		}
		return map[string]any{
			"status":           "unlocked",
			"created":          created,
			"presence_access":  d.store.HasPresenceAccess(),
			"collection_count": len(collections),
			"ann_init": map[string]any{
				"mode":        annStatus.Mode,
				"chunk_count": annStatus.ChunkCount,
				"at":          annStatus.At,
			},
		}, nil, "ok_vault_unlock", map[string]any{"created": created}

	case "vault.lock":
		if err := d.store.Lock(); err != nil {
			return nil, mapStoreError(err), "vault_lock_failed", map[string]any{"error": redact.String(err.Error())}
		}
		return map[string]any{
			"status": "locked",
		}, nil, "ok_vault_lock", nil

	case "vault.collections":
		var args struct {
			Action      string `json:"action"`
			Name        string `json:"name"`
			Tier        string `json:"tier"`
			Description string `json:"description"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			return nil, invalidParamsErr(err), "invalid_vault_collections_args", nil
		}
		action := strings.TrimSpace(strings.ToLower(args.Action))
		if action == "" {
			action = "list"
		}
		switch action {
		case "list":
			collections, err := d.store.ListCollections()
			if err != nil {
				return nil, mapStoreError(err), "vault_collections_list_failed", nil
			}
			return map[string]any{
				"collections": collections,
			}, nil, "ok_vault_collections_list", map[string]any{"count": len(collections)}
		case "create":
			created, err := d.store.CreateCollection(args.Name, args.Tier, args.Description)
			if err != nil {
				return nil, mapStoreError(err), "vault_collections_create_failed", nil
			}
			return map[string]any{
				"collection": created,
			}, nil, "ok_vault_collections_create", map[string]any{"name": created.Name}
		default:
			return nil, &rpcError{
				Code:    rpcErrInvalidParams,
				Message: "action must be list or create",
			}, "vault_collections_action_invalid", nil
		}

	case "vault.request":
		var args struct {
			Task       string `json:"task"`
			Collection string `json:"collection"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			return nil, invalidParamsErr(err), "invalid_vault_request_args", nil
		}
		task := strings.TrimSpace(args.Task)
		if task == "" {
			return nil, &rpcError{Code: rpcErrInvalidParams, Message: "task is required"}, "task_required", nil
		}
		if len([]byte(task)) > d.cfg.MaxTaskChars {
			return nil, budgetErr("task_too_large", "max_task_chars", d.cfg.MaxTaskChars), "budget_exceeded", map[string]any{
				"budget": "max_task_chars",
				"max":    d.cfg.MaxTaskChars,
			}
		}
		in := plannerInput{
			Task:              task,
			Collection:        args.Collection,
			VaultLocked:       !d.store.IsUnlocked(),
			PresenceAccess:    d.store.HasPresenceAccess(),
			MaxTaskChars:      d.cfg.MaxTaskChars,
			MaxSearchResults:  d.cfg.MaxSearchResults,
			MaxSnippetObjects: d.cfg.MaxSnippetObjects,
			MaxSnippetBytes:   d.cfg.MaxSnippetBytes,
			MaxSnippetChars:   d.cfg.MaxSnippetChars,
			MaxWriteChars:     d.cfg.MaxWriteChars,
			MaxIngestBytes:    d.cfg.MaxIngestBytes,
		}
		deterministicPlan := buildDeterministicPlan(in)
		plan := deterministicPlan
		brokerUsed := false
		if d.broker != nil {
			plan, brokerUsed = buildPlanWithBroker(in, deterministicPlan, d.broker)
		}
		return plan, nil, "ok_vault_request", map[string]any{
			"plan_only":    true,
			"planner_mode": plan.PlannerMode,
			"broker_used":  brokerUsed,
			"plan_id":      plan.PlanID,
			"call_count":   len(plan.RecommendedToolCalls),
		}

	case "vault.search":
		var args struct {
			Query      string `json:"query"`
			Collection string `json:"collection"`
			Limit      int    `json:"limit"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			return nil, invalidParamsErr(err), "invalid_vault_search_args", nil
		}
		if strings.TrimSpace(args.Query) == "" {
			return nil, &rpcError{Code: rpcErrInvalidParams, Message: "query is required"}, "query_required", nil
		}
		limit := args.Limit
		if limit == 0 {
			limit = minInt(3, d.cfg.MaxSearchResults)
		}
		if limit < 0 {
			return nil, &rpcError{Code: rpcErrInvalidParams, Message: "limit must be >= 1"}, "limit_invalid", nil
		}
		if limit > d.cfg.MaxSearchResults {
			return nil, budgetErr("search_result_limit_exceeded", "max_search_results", d.cfg.MaxSearchResults), "budget_exceeded", map[string]any{
				"budget":    "max_search_results",
				"max":       d.cfg.MaxSearchResults,
				"requested": limit,
			}
		}
		searchTimeout := 25 * time.Second
		if d.cfg.WriteTimeout > 0 {
			ceiling := d.cfg.WriteTimeout - (5 * time.Second)
			if ceiling > 0 && ceiling < searchTimeout {
				searchTimeout = ceiling
			}
		}
		if searchTimeout <= 0 {
			searchTimeout = 15 * time.Second
		}
		searchCtx, cancelSearch := context.WithTimeout(context.Background(), searchTimeout)
		defer cancelSearch()
		expansion := d.expandRetrievalQuery(searchCtx, args.Query, args.Collection)
		hits, coverage, err := d.searchExpandedWithIterativePasses(searchCtx, args.Query, args.Collection, limit, expansion)
		if err != nil {
			return nil, mapStoreError(err), "vault_search_failed", nil
		}
		return map[string]any{
			"results": hits,
			"query_expansion": map[string]any{
				"expanded_queries":  expansion.ExpandedQueries,
				"must_terms":        expansion.MustTerms,
				"should_terms":      expansion.ShouldTerms,
				"negative_terms":    expansion.NegativeTerms,
				"filters":           expansion.Filters,
				"inferred_filters":  expansion.InferredFilters,
				"sensitivity_flags": expansion.SensitivityFlags,
				"risk_notes":        expansion.RiskNotes,
			},
			"coverage_note": coverage,
			"budget": map[string]any{
				"max_search_results": d.cfg.MaxSearchResults,
				"requested_limit":    limit,
				"returned":           len(hits),
			},
		}, nil, "ok_vault_search", map[string]any{"returned": len(hits)}

	case "vault.read_snippets":
		var args struct {
			IDs                []string `json:"ids"`
			Query              string   `json:"query"`
			TaskWindowID       string   `json:"task_window_id"`
			MaxBytes           int      `json:"max_bytes"`
			MaxCharsPerSnippet int      `json:"max_chars_per_snippet"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			return nil, invalidParamsErr(err), "invalid_vault_read_snippets_args", nil
		}
		if rateErr := d.enforceReadRate("vault.read_snippets"); rateErr != nil {
			return nil, rateErr, "budget_exceeded", map[string]any{
				"budget": "max_read_rpm",
				"max":    d.cfg.MaxReadRPM,
			}
		}
		if len(args.IDs) == 0 {
			return nil, &rpcError{Code: rpcErrInvalidParams, Message: "ids is required"}, "ids_required", nil
		}
		if len(args.IDs) > d.cfg.MaxSnippetObjects {
			return nil, budgetErr("snippet_object_limit_exceeded", "max_snippet_objects", d.cfg.MaxSnippetObjects), "budget_exceeded", map[string]any{
				"budget":    "max_snippet_objects",
				"max":       d.cfg.MaxSnippetObjects,
				"requested": len(args.IDs),
			}
		}
		maxBytes := args.MaxBytes
		if maxBytes == 0 {
			maxBytes = d.cfg.MaxSnippetBytes
		}
		if maxBytes < 0 {
			return nil, &rpcError{Code: rpcErrInvalidParams, Message: "max_bytes must be >= 1"}, "max_bytes_invalid", nil
		}
		if maxBytes > d.cfg.MaxSnippetBytes {
			return nil, budgetErr("snippet_byte_limit_exceeded", "max_snippet_bytes", d.cfg.MaxSnippetBytes), "budget_exceeded", map[string]any{
				"budget":    "max_snippet_bytes",
				"max":       d.cfg.MaxSnippetBytes,
				"requested": maxBytes,
			}
		}
		maxChars := args.MaxCharsPerSnippet
		if maxChars == 0 {
			maxChars = d.cfg.MaxSnippetChars
		}
		if maxChars < 0 {
			return nil, &rpcError{Code: rpcErrInvalidParams, Message: "max_chars_per_snippet must be >= 1"}, "max_chars_invalid", nil
		}
		if maxChars > d.cfg.MaxSnippetChars {
			return nil, budgetErr("snippet_char_limit_exceeded", "max_snippet_chars", d.cfg.MaxSnippetChars), "budget_exceeded", map[string]any{
				"budget":    "max_snippet_chars",
				"max":       d.cfg.MaxSnippetChars,
				"requested": maxChars,
			}
		}

		hits, truncated, missing, err := d.store.ReadSnippets(args.IDs, args.Query, maxBytes, maxChars)
		if err != nil {
			return nil, mapStoreError(err), "vault_read_snippets_failed", nil
		}
		totalBytes := 0
		for _, h := range hits {
			totalBytes += h.Bytes
		}
		if windowErr := d.enforceTaskWindowReadBytes(args.TaskWindowID, totalBytes); windowErr != nil {
			return nil, windowErr, "budget_exceeded", map[string]any{
				"budget": "max_task_window_bytes",
				"max":    d.cfg.MaxTaskWindowBytes,
			}
		}
		usedBytes, remainingBytes, expiresAt := d.taskWindowUsage(args.TaskWindowID)
		return map[string]any{
			"snippets":     hits,
			"truncated":    truncated,
			"missing_ids":  missing,
			"total_bytes":  totalBytes,
			"object_count": len(hits),
			"task_window": map[string]any{
				"id":              normalizeTaskWindowID(args.TaskWindowID),
				"bytes_used":      usedBytes,
				"bytes_remaining": remainingBytes,
				"expires_at":      expiresAt,
			},
			"budget": map[string]any{
				"max_snippet_objects":     d.cfg.MaxSnippetObjects,
				"max_snippet_bytes":       d.cfg.MaxSnippetBytes,
				"requested_max_bytes":     maxBytes,
				"max_snippet_chars":       d.cfg.MaxSnippetChars,
				"requested_max_chars":     maxChars,
				"max_task_window_bytes":   d.cfg.MaxTaskWindowBytes,
				"task_window_ttl_seconds": int(d.cfg.TaskWindowTTL.Seconds()),
				"max_read_rpm":            d.cfg.MaxReadRPM,
			},
		}, nil, "ok_vault_read_snippets", map[string]any{"total_bytes": totalBytes}

	case "vault.ingest":
		var args struct {
			Collection    string `json:"collection"`
			Title         string `json:"title"`
			ContentType   string `json:"content_type"`
			ContentBase64 string `json:"content_base64"`
			Text          string `json:"text"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			return nil, invalidParamsErr(err), "invalid_vault_ingest_args", nil
		}
		if strings.TrimSpace(args.ContentType) == "" {
			return nil, &rpcError{Code: rpcErrInvalidParams, Message: "content_type is required"}, "content_type_required", nil
		}
		raw, err := decodeIngestContent(args.ContentBase64, args.Text)
		if err != nil {
			return nil, mapStoreError(err), "vault_ingest_decode_failed", nil
		}
		if len(raw) == 0 {
			return nil, &rpcError{Code: rpcErrInvalidParams, Message: "ingest content is required"}, "content_required", nil
		}
		if len(raw) > d.cfg.MaxIngestBytes {
			return nil, budgetErr("ingest_size_limit_exceeded", "max_ingest_bytes", d.cfg.MaxIngestBytes), "budget_exceeded", map[string]any{
				"budget":    "max_ingest_bytes",
				"max":       d.cfg.MaxIngestBytes,
				"requested": len(raw),
			}
		}
		obj, extractedChars, extractedTruncated, err := d.store.Ingest(args.Collection, args.Title, args.ContentType, raw, d.cfg.MaxExtractedChars)
		if err != nil {
			return nil, mapStoreError(err), "vault_ingest_failed", nil
		}
		return map[string]any{
			"id":                  obj.ID,
			"collection":          obj.Collection,
			"title":               obj.Title,
			"extracted_chars":     extractedChars,
			"extracted_truncated": extractedTruncated,
			"budget": map[string]any{
				"max_ingest_bytes":    d.cfg.MaxIngestBytes,
				"max_extracted_chars": d.cfg.MaxExtractedChars,
			},
		}, nil, "ok_vault_ingest", map[string]any{"object_id": obj.ID, "extracted_chars": extractedChars}

	case "vault.write":
		var args struct {
			ID         string `json:"id"`
			Collection string `json:"collection"`
			Title      string `json:"title"`
			Content    string `json:"content"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			return nil, invalidParamsErr(err), "invalid_vault_write_args", nil
		}
		if strings.TrimSpace(args.Content) == "" {
			return nil, &rpcError{Code: rpcErrInvalidParams, Message: "content is required"}, "content_required", nil
		}
		contentBytes := len([]byte(args.Content))
		if contentBytes > d.cfg.MaxWriteChars {
			return nil, budgetErr("write_content_limit_exceeded", "max_write_chars", d.cfg.MaxWriteChars), "budget_exceeded", map[string]any{
				"budget":    "max_write_chars",
				"max":       d.cfg.MaxWriteChars,
				"requested": contentBytes,
			}
		}
		obj, created, err := d.store.Write(args.ID, args.Collection, args.Title, args.Content)
		if err != nil {
			return nil, mapStoreError(err), "vault_write_failed", nil
		}
		op := "update"
		if created {
			op = "create"
		}
		return map[string]any{
			"operation":  op,
			"id":         obj.ID,
			"collection": obj.Collection,
			"title":      obj.Title,
			"bytes":      contentBytes,
		}, nil, "ok_vault_write", map[string]any{"object_id": obj.ID, "operation": op}

	case "vault.delete":
		var args struct {
			ID string `json:"id"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			return nil, invalidParamsErr(err), "invalid_vault_delete_args", nil
		}
		if strings.TrimSpace(args.ID) == "" {
			return nil, &rpcError{Code: rpcErrInvalidParams, Message: "id is required"}, "id_required", nil
		}
		if err := d.store.Delete(args.ID); err != nil {
			return nil, mapStoreError(err), "vault_delete_failed", nil
		}
		return map[string]any{
			"deleted": true,
			"id":      strings.TrimSpace(args.ID),
		}, nil, "ok_vault_delete", map[string]any{"object_id": strings.TrimSpace(args.ID)}

	case "vault.audit":
		var args struct {
			Limit int `json:"limit"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			return nil, invalidParamsErr(err), "invalid_vault_audit_args", nil
		}
		limit := args.Limit
		if limit == 0 {
			limit = minInt(20, d.cfg.MaxAuditRecords)
		}
		if limit < 0 {
			return nil, &rpcError{Code: rpcErrInvalidParams, Message: "limit must be >= 1"}, "audit_limit_invalid", nil
		}
		if limit > d.cfg.MaxAuditRecords {
			return nil, budgetErr("audit_limit_exceeded", "max_audit_records", d.cfg.MaxAuditRecords), "budget_exceeded", map[string]any{
				"budget":    "max_audit_records",
				"max":       d.cfg.MaxAuditRecords,
				"requested": limit,
			}
		}
		records := d.auditor.List(limit)
		return map[string]any{
			"records": records,
			"budget": map[string]any{
				"max_audit_records": d.cfg.MaxAuditRecords,
				"requested_limit":   limit,
				"returned":          len(records),
			},
		}, nil, "ok_vault_audit", map[string]any{"returned": len(records)}

	case "vault.connectors":
		var args struct {
			Action   string `json:"action"`
			Provider string `json:"provider"`
			Token    string `json:"token"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			return nil, invalidParamsErr(err), "invalid_vault_connectors_args", nil
		}
		action := strings.TrimSpace(strings.ToLower(args.Action))
		if action == "" {
			action = "list"
		}
		switch action {
		case "list":
			statuses, err := d.store.ListConnectorStatuses()
			if err != nil {
				return nil, mapStoreError(err), "vault_connectors_list_failed", nil
			}
			return map[string]any{
				"connectors": statuses,
			}, nil, "ok_vault_connectors_list", map[string]any{"count": len(statuses)}
		case "set_token":
			status, err := d.store.SetConnectorToken(args.Provider, args.Token)
			if err != nil {
				return nil, mapStoreError(err), "vault_connectors_set_token_failed", nil
			}
			return map[string]any{
				"connector": status,
				"note":      "token accepted and stored encrypted at rest",
			}, nil, "ok_vault_connectors_set_token", map[string]any{"provider": status.Provider}
		case "clear_token":
			status, err := d.store.RemoveConnectorToken(args.Provider)
			if err != nil {
				return nil, mapStoreError(err), "vault_connectors_clear_token_failed", nil
			}
			return map[string]any{
				"connector": status,
			}, nil, "ok_vault_connectors_clear_token", map[string]any{"provider": status.Provider}
		default:
			return nil, &rpcError{
				Code:    rpcErrInvalidParams,
				Message: "action must be list, set_token, or clear_token",
			}, "vault_connectors_action_invalid", nil
		}

	case "vault.approvals":
		var args struct {
			Action string `json:"action"`
			ID     string `json:"id"`
			Status string `json:"status"`
			Reason string `json:"reason"`
			Limit  int    `json:"limit"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			return nil, invalidParamsErr(err), "invalid_vault_approvals_args", nil
		}
		action := strings.TrimSpace(strings.ToLower(args.Action))
		if action == "" {
			action = "list"
		}
		switch action {
		case "list":
			limit := args.Limit
			if limit == 0 {
				limit = minInt(20, d.cfg.MaxAuditRecords)
			}
			if limit < 0 {
				return nil, &rpcError{Code: rpcErrInvalidParams, Message: "limit must be >= 1"}, "approval_limit_invalid", nil
			}
			if limit > d.cfg.MaxAuditRecords {
				return nil, budgetErr("approval_limit_exceeded", "max_audit_records", d.cfg.MaxAuditRecords), "budget_exceeded", map[string]any{
					"budget":    "max_audit_records",
					"max":       d.cfg.MaxAuditRecords,
					"requested": limit,
				}
			}
			approvals, err := d.store.ListApprovals(args.Status, limit)
			if err != nil {
				return nil, mapStoreError(err), "vault_approvals_list_failed", nil
			}
			return map[string]any{
				"approvals": approvals,
			}, nil, "ok_vault_approvals_list", map[string]any{"count": len(approvals)}
		case "approve", "reject":
			id := strings.TrimSpace(args.ID)
			if id == "" {
				return nil, &rpcError{Code: rpcErrInvalidParams, Message: "id is required"}, "approval_id_required", nil
			}
			decision := "approved"
			if action == "reject" {
				decision = "rejected"
			}
			resolved, err := d.store.ResolveApproval(id, decision, args.Reason)
			if err != nil {
				return nil, mapStoreError(err), "vault_approval_resolve_failed", map[string]any{"approval_id": id}
			}
			if resolved.Action == "mail.send" && strings.TrimSpace(resolved.ResourceID) != "" {
				_, _ = d.mail.MarkDraftApprovalDecision(resolved.ResourceID, resolved.Status, resolved.Reason)
			}
			return map[string]any{
				"approval": resolved,
				"note":     "approval recorded; Straja does not execute side effects directly",
			}, nil, "ok_vault_approval_resolve", map[string]any{"approval_id": resolved.ID, "status": resolved.Status}
		default:
			return nil, &rpcError{
				Code:    rpcErrInvalidParams,
				Message: "action must be list, approve, or reject",
			}, "vault_approvals_action_invalid", nil
		}

	case "mail.search":
		var args struct {
			Query      string `json:"query"`
			Collection string `json:"collection"`
			Limit      int    `json:"limit"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			return nil, invalidParamsErr(err), "invalid_mail_search_args", nil
		}
		if strings.TrimSpace(args.Query) == "" {
			return nil, &rpcError{Code: rpcErrInvalidParams, Message: "query is required"}, "query_required", nil
		}
		limit := args.Limit
		if limit == 0 {
			limit = minInt(3, d.cfg.MaxSearchResults)
		}
		if limit < 0 {
			return nil, &rpcError{Code: rpcErrInvalidParams, Message: "limit must be >= 1"}, "limit_invalid", nil
		}
		if limit > d.cfg.MaxSearchResults {
			return nil, budgetErr("mail_search_result_limit_exceeded", "max_search_results", d.cfg.MaxSearchResults), "budget_exceeded", map[string]any{
				"budget":    "max_search_results",
				"max":       d.cfg.MaxSearchResults,
				"requested": limit,
			}
		}
		hits, err := d.mail.Search(args.Query, args.Collection, limit, d.store.EnsureCollectionAccess)
		if err != nil {
			return nil, mapStoreError(err), "mail_search_failed", nil
		}
		return map[string]any{
			"results": hits,
			"budget": map[string]any{
				"max_search_results": d.cfg.MaxSearchResults,
				"requested_limit":    limit,
				"returned":           len(hits),
			},
		}, nil, "ok_mail_search", map[string]any{"returned": len(hits)}

	case "mail.read_snippets":
		var args struct {
			IDs                []string `json:"ids"`
			Query              string   `json:"query"`
			TaskWindowID       string   `json:"task_window_id"`
			MaxBytes           int      `json:"max_bytes"`
			MaxCharsPerSnippet int      `json:"max_chars_per_snippet"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			return nil, invalidParamsErr(err), "invalid_mail_read_snippets_args", nil
		}
		if rateErr := d.enforceReadRate("mail.read_snippets"); rateErr != nil {
			return nil, rateErr, "budget_exceeded", map[string]any{
				"budget": "max_read_rpm",
				"max":    d.cfg.MaxReadRPM,
			}
		}
		if len(args.IDs) == 0 {
			return nil, &rpcError{Code: rpcErrInvalidParams, Message: "ids is required"}, "ids_required", nil
		}
		if len(args.IDs) > d.cfg.MaxSnippetObjects {
			return nil, budgetErr("mail_snippet_object_limit_exceeded", "max_snippet_objects", d.cfg.MaxSnippetObjects), "budget_exceeded", map[string]any{
				"budget":    "max_snippet_objects",
				"max":       d.cfg.MaxSnippetObjects,
				"requested": len(args.IDs),
			}
		}
		maxBytes := args.MaxBytes
		if maxBytes == 0 {
			maxBytes = d.cfg.MaxSnippetBytes
		}
		if maxBytes < 0 {
			return nil, &rpcError{Code: rpcErrInvalidParams, Message: "max_bytes must be >= 1"}, "max_bytes_invalid", nil
		}
		if maxBytes > d.cfg.MaxSnippetBytes {
			return nil, budgetErr("mail_snippet_byte_limit_exceeded", "max_snippet_bytes", d.cfg.MaxSnippetBytes), "budget_exceeded", map[string]any{
				"budget":    "max_snippet_bytes",
				"max":       d.cfg.MaxSnippetBytes,
				"requested": maxBytes,
			}
		}
		maxChars := args.MaxCharsPerSnippet
		if maxChars == 0 {
			maxChars = d.cfg.MaxSnippetChars
		}
		if maxChars < 0 {
			return nil, &rpcError{Code: rpcErrInvalidParams, Message: "max_chars_per_snippet must be >= 1"}, "max_chars_invalid", nil
		}
		if maxChars > d.cfg.MaxSnippetChars {
			return nil, budgetErr("mail_snippet_char_limit_exceeded", "max_snippet_chars", d.cfg.MaxSnippetChars), "budget_exceeded", map[string]any{
				"budget":    "max_snippet_chars",
				"max":       d.cfg.MaxSnippetChars,
				"requested": maxChars,
			}
		}
		hits, truncated, missing, err := d.mail.ReadSnippets(args.IDs, args.Query, maxBytes, maxChars, d.store.EnsureCollectionAccess)
		if err != nil {
			return nil, mapStoreError(err), "mail_read_snippets_failed", nil
		}
		totalBytes := 0
		for _, h := range hits {
			totalBytes += h.Bytes
		}
		if windowErr := d.enforceTaskWindowReadBytes(args.TaskWindowID, totalBytes); windowErr != nil {
			return nil, windowErr, "budget_exceeded", map[string]any{
				"budget": "max_task_window_bytes",
				"max":    d.cfg.MaxTaskWindowBytes,
			}
		}
		usedBytes, remainingBytes, expiresAt := d.taskWindowUsage(args.TaskWindowID)
		return map[string]any{
			"snippets":     hits,
			"truncated":    truncated,
			"missing_ids":  missing,
			"total_bytes":  totalBytes,
			"object_count": len(hits),
			"task_window": map[string]any{
				"id":              normalizeTaskWindowID(args.TaskWindowID),
				"bytes_used":      usedBytes,
				"bytes_remaining": remainingBytes,
				"expires_at":      expiresAt,
			},
			"budget": map[string]any{
				"max_snippet_objects":     d.cfg.MaxSnippetObjects,
				"max_snippet_bytes":       d.cfg.MaxSnippetBytes,
				"requested_max_bytes":     maxBytes,
				"max_snippet_chars":       d.cfg.MaxSnippetChars,
				"requested_max_chars":     maxChars,
				"max_task_window_bytes":   d.cfg.MaxTaskWindowBytes,
				"task_window_ttl_seconds": int(d.cfg.TaskWindowTTL.Seconds()),
				"max_read_rpm":            d.cfg.MaxReadRPM,
			},
		}, nil, "ok_mail_read_snippets", map[string]any{"total_bytes": totalBytes}

	case "mail.draft":
		var args struct {
			Collection string `json:"collection"`
			To         string `json:"to"`
			Subject    string `json:"subject"`
			Body       string `json:"body"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			return nil, invalidParamsErr(err), "invalid_mail_draft_args", nil
		}
		bodyBytes := len([]byte(args.Body))
		if bodyBytes > d.cfg.MaxWriteChars {
			return nil, budgetErr("mail_draft_body_limit_exceeded", "max_write_chars", d.cfg.MaxWriteChars), "budget_exceeded", map[string]any{
				"budget":    "max_write_chars",
				"max":       d.cfg.MaxWriteChars,
				"requested": bodyBytes,
			}
		}
		draft, err := d.mail.CreateDraft(args.Collection, args.To, args.Subject, args.Body, d.store.EnsureCollectionAccess)
		if err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "required") {
				return nil, &rpcError{Code: rpcErrInvalidParams, Message: "to, subject, and body are required"}, "mail_draft_required_fields_missing", nil
			}
			return nil, mapStoreError(err), "mail_draft_failed", nil
		}
		return map[string]any{
			"draft": draft,
			"note":  "draft-first policy active; sending is blocked",
		}, nil, "ok_mail_draft", map[string]any{"draft_id": draft.ID}

	case "mail.send":
		var args struct {
			DraftID string `json:"draft_id"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			return nil, invalidParamsErr(err), "invalid_mail_send_args", nil
		}
		draftID := strings.TrimSpace(args.DraftID)
		if draftID == "" {
			return nil, &rpcError{Code: rpcErrInvalidParams, Message: "draft_id is required"}, "draft_id_required", nil
		}
		draft, err := d.mail.GetDraft(draftID, d.store.EnsureCollectionAccess)
		if err != nil {
			return nil, mapStoreError(err), "mail_send_draft_lookup_failed", nil
		}
		summary := fmt.Sprintf("Review send request for draft %s", draft.ID)
		approval, err := d.store.QueueApproval("mail.send", draft.Collection, draft.ID, summary, map[string]string{
			"to":      draft.To,
			"subject": draft.Subject,
		})
		if err != nil {
			return nil, mapStoreError(err), "mail_send_queue_failed", nil
		}
		draft, err = d.mail.MarkDraftQueuedForApproval(draft.ID, approval.ID)
		if err != nil {
			return nil, mapStoreError(err), "mail_send_mark_draft_failed", map[string]any{"approval_id": approval.ID}
		}
		return map[string]any{
			"status":   "queued_for_approval",
			"approval": approval,
			"draft":    draft,
			"note":     "use vault.approvals to approve or reject; side effects are not executed directly",
		}, nil, "ok_mail_send_queued", map[string]any{"approval_id": approval.ID, "draft_id": draft.ID}

	case "drive.search":
		var args struct {
			Query      string `json:"query"`
			Collection string `json:"collection"`
			Limit      int    `json:"limit"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			return nil, invalidParamsErr(err), "invalid_drive_search_args", nil
		}
		if strings.TrimSpace(args.Query) == "" {
			return nil, &rpcError{Code: rpcErrInvalidParams, Message: "query is required"}, "query_required", nil
		}
		limit := args.Limit
		if limit == 0 {
			limit = minInt(3, d.cfg.MaxSearchResults)
		}
		if limit < 0 {
			return nil, &rpcError{Code: rpcErrInvalidParams, Message: "limit must be >= 1"}, "limit_invalid", nil
		}
		if limit > d.cfg.MaxSearchResults {
			return nil, budgetErr("drive_search_result_limit_exceeded", "max_search_results", d.cfg.MaxSearchResults), "budget_exceeded", map[string]any{
				"budget":    "max_search_results",
				"max":       d.cfg.MaxSearchResults,
				"requested": limit,
			}
		}
		hits, err := d.drive.Search(args.Query, args.Collection, limit, d.store.EnsureCollectionAccess)
		if err != nil {
			return nil, mapStoreError(err), "drive_search_failed", nil
		}
		return map[string]any{
			"results": hits,
			"budget": map[string]any{
				"max_search_results": d.cfg.MaxSearchResults,
				"requested_limit":    limit,
				"returned":           len(hits),
			},
		}, nil, "ok_drive_search", map[string]any{"returned": len(hits)}

	case "drive.read_snippets":
		var args struct {
			IDs                []string `json:"ids"`
			Query              string   `json:"query"`
			TaskWindowID       string   `json:"task_window_id"`
			MaxBytes           int      `json:"max_bytes"`
			MaxCharsPerSnippet int      `json:"max_chars_per_snippet"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			return nil, invalidParamsErr(err), "invalid_drive_read_snippets_args", nil
		}
		if rateErr := d.enforceReadRate("drive.read_snippets"); rateErr != nil {
			return nil, rateErr, "budget_exceeded", map[string]any{
				"budget": "max_read_rpm",
				"max":    d.cfg.MaxReadRPM,
			}
		}
		if len(args.IDs) == 0 {
			return nil, &rpcError{Code: rpcErrInvalidParams, Message: "ids is required"}, "ids_required", nil
		}
		if len(args.IDs) > d.cfg.MaxSnippetObjects {
			return nil, budgetErr("drive_snippet_object_limit_exceeded", "max_snippet_objects", d.cfg.MaxSnippetObjects), "budget_exceeded", map[string]any{
				"budget":    "max_snippet_objects",
				"max":       d.cfg.MaxSnippetObjects,
				"requested": len(args.IDs),
			}
		}
		maxBytes := args.MaxBytes
		if maxBytes == 0 {
			maxBytes = d.cfg.MaxSnippetBytes
		}
		if maxBytes < 0 {
			return nil, &rpcError{Code: rpcErrInvalidParams, Message: "max_bytes must be >= 1"}, "max_bytes_invalid", nil
		}
		if maxBytes > d.cfg.MaxSnippetBytes {
			return nil, budgetErr("drive_snippet_byte_limit_exceeded", "max_snippet_bytes", d.cfg.MaxSnippetBytes), "budget_exceeded", map[string]any{
				"budget":    "max_snippet_bytes",
				"max":       d.cfg.MaxSnippetBytes,
				"requested": maxBytes,
			}
		}
		maxChars := args.MaxCharsPerSnippet
		if maxChars == 0 {
			maxChars = d.cfg.MaxSnippetChars
		}
		if maxChars < 0 {
			return nil, &rpcError{Code: rpcErrInvalidParams, Message: "max_chars_per_snippet must be >= 1"}, "max_chars_invalid", nil
		}
		if maxChars > d.cfg.MaxSnippetChars {
			return nil, budgetErr("drive_snippet_char_limit_exceeded", "max_snippet_chars", d.cfg.MaxSnippetChars), "budget_exceeded", map[string]any{
				"budget":    "max_snippet_chars",
				"max":       d.cfg.MaxSnippetChars,
				"requested": maxChars,
			}
		}
		hits, truncated, missing, err := d.drive.ReadSnippets(args.IDs, args.Query, maxBytes, maxChars, d.store.EnsureCollectionAccess)
		if err != nil {
			return nil, mapStoreError(err), "drive_read_snippets_failed", nil
		}
		totalBytes := 0
		for _, h := range hits {
			totalBytes += h.Bytes
		}
		if windowErr := d.enforceTaskWindowReadBytes(args.TaskWindowID, totalBytes); windowErr != nil {
			return nil, windowErr, "budget_exceeded", map[string]any{
				"budget": "max_task_window_bytes",
				"max":    d.cfg.MaxTaskWindowBytes,
			}
		}
		usedBytes, remainingBytes, expiresAt := d.taskWindowUsage(args.TaskWindowID)
		return map[string]any{
			"snippets":     hits,
			"truncated":    truncated,
			"missing_ids":  missing,
			"total_bytes":  totalBytes,
			"object_count": len(hits),
			"task_window": map[string]any{
				"id":              normalizeTaskWindowID(args.TaskWindowID),
				"bytes_used":      usedBytes,
				"bytes_remaining": remainingBytes,
				"expires_at":      expiresAt,
			},
			"budget": map[string]any{
				"max_snippet_objects":     d.cfg.MaxSnippetObjects,
				"max_snippet_bytes":       d.cfg.MaxSnippetBytes,
				"requested_max_bytes":     maxBytes,
				"max_snippet_chars":       d.cfg.MaxSnippetChars,
				"requested_max_chars":     maxChars,
				"max_task_window_bytes":   d.cfg.MaxTaskWindowBytes,
				"task_window_ttl_seconds": int(d.cfg.TaskWindowTTL.Seconds()),
				"max_read_rpm":            d.cfg.MaxReadRPM,
			},
		}, nil, "ok_drive_read_snippets", map[string]any{"total_bytes": totalBytes}

	case "github.search":
		var args struct {
			Query      string `json:"query"`
			Collection string `json:"collection"`
			Limit      int    `json:"limit"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			return nil, invalidParamsErr(err), "invalid_github_search_args", nil
		}
		if strings.TrimSpace(args.Query) == "" {
			return nil, &rpcError{Code: rpcErrInvalidParams, Message: "query is required"}, "query_required", nil
		}
		limit := args.Limit
		if limit == 0 {
			limit = minInt(3, d.cfg.MaxSearchResults)
		}
		if limit < 0 {
			return nil, &rpcError{Code: rpcErrInvalidParams, Message: "limit must be >= 1"}, "limit_invalid", nil
		}
		if limit > d.cfg.MaxSearchResults {
			return nil, budgetErr("github_search_result_limit_exceeded", "max_search_results", d.cfg.MaxSearchResults), "budget_exceeded", map[string]any{
				"budget":    "max_search_results",
				"max":       d.cfg.MaxSearchResults,
				"requested": limit,
			}
		}
		hits, err := d.github.Search(args.Query, args.Collection, limit, d.store.EnsureCollectionAccess)
		if err != nil {
			return nil, mapStoreError(err), "github_search_failed", nil
		}
		return map[string]any{
			"results": hits,
			"budget": map[string]any{
				"max_search_results": d.cfg.MaxSearchResults,
				"requested_limit":    limit,
				"returned":           len(hits),
			},
		}, nil, "ok_github_search", map[string]any{"returned": len(hits)}

	case "github.read_snippets":
		var args struct {
			IDs                []string `json:"ids"`
			Query              string   `json:"query"`
			TaskWindowID       string   `json:"task_window_id"`
			MaxBytes           int      `json:"max_bytes"`
			MaxCharsPerSnippet int      `json:"max_chars_per_snippet"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			return nil, invalidParamsErr(err), "invalid_github_read_snippets_args", nil
		}
		if rateErr := d.enforceReadRate("github.read_snippets"); rateErr != nil {
			return nil, rateErr, "budget_exceeded", map[string]any{
				"budget": "max_read_rpm",
				"max":    d.cfg.MaxReadRPM,
			}
		}
		if len(args.IDs) == 0 {
			return nil, &rpcError{Code: rpcErrInvalidParams, Message: "ids is required"}, "ids_required", nil
		}
		if len(args.IDs) > d.cfg.MaxSnippetObjects {
			return nil, budgetErr("github_snippet_object_limit_exceeded", "max_snippet_objects", d.cfg.MaxSnippetObjects), "budget_exceeded", map[string]any{
				"budget":    "max_snippet_objects",
				"max":       d.cfg.MaxSnippetObjects,
				"requested": len(args.IDs),
			}
		}
		maxBytes := args.MaxBytes
		if maxBytes == 0 {
			maxBytes = d.cfg.MaxSnippetBytes
		}
		if maxBytes < 0 {
			return nil, &rpcError{Code: rpcErrInvalidParams, Message: "max_bytes must be >= 1"}, "max_bytes_invalid", nil
		}
		if maxBytes > d.cfg.MaxSnippetBytes {
			return nil, budgetErr("github_snippet_byte_limit_exceeded", "max_snippet_bytes", d.cfg.MaxSnippetBytes), "budget_exceeded", map[string]any{
				"budget":    "max_snippet_bytes",
				"max":       d.cfg.MaxSnippetBytes,
				"requested": maxBytes,
			}
		}
		maxChars := args.MaxCharsPerSnippet
		if maxChars == 0 {
			maxChars = d.cfg.MaxSnippetChars
		}
		if maxChars < 0 {
			return nil, &rpcError{Code: rpcErrInvalidParams, Message: "max_chars_per_snippet must be >= 1"}, "max_chars_invalid", nil
		}
		if maxChars > d.cfg.MaxSnippetChars {
			return nil, budgetErr("github_snippet_char_limit_exceeded", "max_snippet_chars", d.cfg.MaxSnippetChars), "budget_exceeded", map[string]any{
				"budget":    "max_snippet_chars",
				"max":       d.cfg.MaxSnippetChars,
				"requested": maxChars,
			}
		}
		hits, truncated, missing, err := d.github.ReadSnippets(args.IDs, args.Query, maxBytes, maxChars, d.store.EnsureCollectionAccess)
		if err != nil {
			return nil, mapStoreError(err), "github_read_snippets_failed", nil
		}
		totalBytes := 0
		for _, h := range hits {
			totalBytes += h.Bytes
		}
		if windowErr := d.enforceTaskWindowReadBytes(args.TaskWindowID, totalBytes); windowErr != nil {
			return nil, windowErr, "budget_exceeded", map[string]any{
				"budget": "max_task_window_bytes",
				"max":    d.cfg.MaxTaskWindowBytes,
			}
		}
		usedBytes, remainingBytes, expiresAt := d.taskWindowUsage(args.TaskWindowID)
		return map[string]any{
			"snippets":     hits,
			"truncated":    truncated,
			"missing_ids":  missing,
			"total_bytes":  totalBytes,
			"object_count": len(hits),
			"task_window": map[string]any{
				"id":              normalizeTaskWindowID(args.TaskWindowID),
				"bytes_used":      usedBytes,
				"bytes_remaining": remainingBytes,
				"expires_at":      expiresAt,
			},
			"budget": map[string]any{
				"max_snippet_objects":     d.cfg.MaxSnippetObjects,
				"max_snippet_bytes":       d.cfg.MaxSnippetBytes,
				"requested_max_bytes":     maxBytes,
				"max_snippet_chars":       d.cfg.MaxSnippetChars,
				"requested_max_chars":     maxChars,
				"max_task_window_bytes":   d.cfg.MaxTaskWindowBytes,
				"task_window_ttl_seconds": int(d.cfg.TaskWindowTTL.Seconds()),
				"max_read_rpm":            d.cfg.MaxReadRPM,
			},
		}, nil, "ok_github_read_snippets", map[string]any{"total_bytes": totalBytes}

	case "web.search":
		var args struct {
			Query      string `json:"query"`
			Collection string `json:"collection"`
			Limit      int    `json:"limit"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			return nil, invalidParamsErr(err), "invalid_web_search_args", nil
		}
		if strings.TrimSpace(args.Query) == "" {
			return nil, &rpcError{Code: rpcErrInvalidParams, Message: "query is required"}, "query_required", nil
		}
		limit := args.Limit
		if limit == 0 {
			limit = minInt(3, d.cfg.MaxSearchResults)
		}
		if limit < 0 {
			return nil, &rpcError{Code: rpcErrInvalidParams, Message: "limit must be >= 1"}, "limit_invalid", nil
		}
		if limit > d.cfg.MaxSearchResults {
			return nil, budgetErr("web_search_result_limit_exceeded", "max_search_results", d.cfg.MaxSearchResults), "budget_exceeded", map[string]any{
				"budget":    "max_search_results",
				"max":       d.cfg.MaxSearchResults,
				"requested": limit,
			}
		}
		hits, err := d.web.Search(args.Query, args.Collection, limit, d.store.EnsureCollectionAccess)
		if err != nil {
			return nil, mapStoreError(err), "web_search_failed", nil
		}
		return map[string]any{
			"results": hits,
			"budget": map[string]any{
				"max_search_results": d.cfg.MaxSearchResults,
				"requested_limit":    limit,
				"returned":           len(hits),
			},
		}, nil, "ok_web_search", map[string]any{"returned": len(hits)}

	case "web.open_reader_snippet":
		var args struct {
			ID                 string `json:"id"`
			URL                string `json:"url"`
			Query              string `json:"query"`
			TaskWindowID       string `json:"task_window_id"`
			MaxBytes           int    `json:"max_bytes"`
			MaxCharsPerSnippet int    `json:"max_chars_per_snippet"`
		}
		if err := decodeArgs(rawArgs, &args); err != nil {
			return nil, invalidParamsErr(err), "invalid_web_open_reader_snippet_args", nil
		}
		if rateErr := d.enforceReadRate("web.open_reader_snippet"); rateErr != nil {
			return nil, rateErr, "budget_exceeded", map[string]any{
				"budget": "max_read_rpm",
				"max":    d.cfg.MaxReadRPM,
			}
		}
		if strings.TrimSpace(args.ID) == "" && strings.TrimSpace(args.URL) == "" {
			return nil, &rpcError{Code: rpcErrInvalidParams, Message: "id or url is required"}, "id_or_url_required", nil
		}
		maxBytes := args.MaxBytes
		if maxBytes == 0 {
			maxBytes = d.cfg.MaxSnippetBytes
		}
		if maxBytes < 0 {
			return nil, &rpcError{Code: rpcErrInvalidParams, Message: "max_bytes must be >= 1"}, "max_bytes_invalid", nil
		}
		if maxBytes > d.cfg.MaxSnippetBytes {
			return nil, budgetErr("web_snippet_byte_limit_exceeded", "max_snippet_bytes", d.cfg.MaxSnippetBytes), "budget_exceeded", map[string]any{
				"budget":    "max_snippet_bytes",
				"max":       d.cfg.MaxSnippetBytes,
				"requested": maxBytes,
			}
		}
		maxChars := args.MaxCharsPerSnippet
		if maxChars == 0 {
			maxChars = d.cfg.MaxSnippetChars
		}
		if maxChars < 0 {
			return nil, &rpcError{Code: rpcErrInvalidParams, Message: "max_chars_per_snippet must be >= 1"}, "max_chars_invalid", nil
		}
		if maxChars > d.cfg.MaxSnippetChars {
			return nil, budgetErr("web_snippet_char_limit_exceeded", "max_snippet_chars", d.cfg.MaxSnippetChars), "budget_exceeded", map[string]any{
				"budget":    "max_snippet_chars",
				"max":       d.cfg.MaxSnippetChars,
				"requested": maxChars,
			}
		}
		snippet, truncated, err := d.web.OpenReaderSnippet(args.ID, args.URL, args.Query, maxBytes, maxChars, d.store.EnsureCollectionAccess)
		if err != nil {
			return nil, mapStoreError(err), "web_open_reader_snippet_failed", nil
		}
		if windowErr := d.enforceTaskWindowReadBytes(args.TaskWindowID, snippet.Bytes); windowErr != nil {
			return nil, windowErr, "budget_exceeded", map[string]any{
				"budget": "max_task_window_bytes",
				"max":    d.cfg.MaxTaskWindowBytes,
			}
		}
		usedBytes, remainingBytes, expiresAt := d.taskWindowUsage(args.TaskWindowID)
		return map[string]any{
			"snippet":   snippet,
			"truncated": truncated,
			"task_window": map[string]any{
				"id":              normalizeTaskWindowID(args.TaskWindowID),
				"bytes_used":      usedBytes,
				"bytes_remaining": remainingBytes,
				"expires_at":      expiresAt,
			},
			"budget": map[string]any{
				"max_snippet_bytes":       d.cfg.MaxSnippetBytes,
				"requested_max_bytes":     maxBytes,
				"max_snippet_chars":       d.cfg.MaxSnippetChars,
				"requested_max_chars":     maxChars,
				"max_task_window_bytes":   d.cfg.MaxTaskWindowBytes,
				"task_window_ttl_seconds": int(d.cfg.TaskWindowTTL.Seconds()),
				"max_read_rpm":            d.cfg.MaxReadRPM,
			},
		}, nil, "ok_web_open_reader_snippet", map[string]any{"bytes": snippet.Bytes}

	default:
		return nil, &rpcError{
			Code:    rpcErrMethodNotFound,
			Message: fmt.Sprintf("unknown tool %q", name),
		}, "unknown_tool", map[string]any{"tool": name}
	}
}

func (d *Daemon) authorized(r *http.Request) bool {
	token, ok := parseBearerToken(r.Header.Get("Authorization"))
	if !ok {
		return false
	}
	expected := []byte(strings.TrimSpace(d.cfg.AuthToken))
	got := []byte(strings.TrimSpace(token))
	return subtle.ConstantTimeCompare(expected, got) == 1
}

type retrievalCoverageNote struct {
	MissingAspects  []string `json:"missing_aspects,omitempty"`
	FollowupQueries []string `json:"followup_queries,omitempty"`
	PassesUsed      int      `json:"passes_used"`
}

func (d *Daemon) searchExpandedWithIterativePasses(ctx context.Context, query, collection string, limit int, expansion queryExpansion) ([]searchHit, retrievalCoverageNote, error) {
	note := retrievalCoverageNote{
		PassesUsed: 1,
	}
	pass1Limit := maxInt(limit, d.cfg.RetrievalRerankOutN)
	hits, err := d.store.SearchExpanded(query, pass1Limit, collection, expansion)
	if err != nil {
		return nil, note, err
	}
	note.MissingAspects = inferCoverageMissingAspects(query, hits)
	if d.cfg.RetrievalIterativePasses < 2 || len(hits) == 0 {
		return trimSearchHits(hits, limit), note, nil
	}
	followups, brokerMissing := d.generateFollowupQueries(ctx, query, collection, hits)
	note.MissingAspects = dedupeStrings(append(note.MissingAspects, brokerMissing...))
	note.FollowupQueries = followups
	if len(followups) == 0 {
		return trimSearchHits(hits, limit), note, nil
	}
	note.PassesUsed = 2

	mergeCap := maxInt(1, d.cfg.RetrievalSecondPassAddN)
	merged := make(map[string]searchHit, len(hits)+mergeCap)
	for _, hit := range hits {
		merged[hit.ID] = hit
	}
	added := 0
	for _, fq := range followups {
		if added >= mergeCap {
			break
		}
		if strings.TrimSpace(fq) == "" {
			continue
		}
		exp2 := defaultQueryExpansion(fq, collection)
		h2, err2 := d.store.SearchExpanded(fq, mergeCap, collection, exp2)
		if err2 != nil {
			continue
		}
		for _, next := range h2 {
			if current, ok := merged[next.ID]; ok {
				current.Score = maxInt(current.Score, next.Score)
				current.WhyMatched = appendUniqueStrings(current.WhyMatched, next.WhyMatched...)
				current.TopSectionIDs = appendUniqueStrings(current.TopSectionIDs, next.TopSectionIDs...)
				current.EvidenceChunkIDs = appendUniqueStrings(current.EvidenceChunkIDs, next.EvidenceChunkIDs...)
				current.Confidence = maxConfidence(current.Confidence, next.Confidence)
				merged[next.ID] = current
				continue
			}
			next.WhyMatched = appendUniqueStrings(next.WhyMatched, "iterative_followup")
			merged[next.ID] = next
			added++
			if added >= mergeCap {
				break
			}
		}
	}

	rows := make([]searchHit, 0, len(merged))
	for _, row := range merged {
		rows = append(rows, row)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Score != rows[j].Score {
			return rows[i].Score > rows[j].Score
		}
		return rows[i].ID < rows[j].ID
	})
	return trimSearchHits(rows, limit), note, nil
}

func trimSearchHits(hits []searchHit, limit int) []searchHit {
	if limit <= 0 || len(hits) <= limit {
		return hits
	}
	return append([]searchHit(nil), hits[:limit]...)
}

func generateDeterministicFollowups(query string) []string {
	query = normalizeSpacing(query)
	if query == "" {
		return nil
	}
	out := []string{}
	if strings.Contains(strings.ToLower(query), " and ") {
		parts := strings.Split(query, " and ")
		for _, p := range parts {
			p = normalizeSpacing(p)
			if p != "" {
				out = append(out, p)
			}
		}
	}
	out = append(out,
		query+" key definitions",
		query+" limitations and warning conditions",
		query+" automatic deactivation conditions",
	)
	return dedupeStrings(out)
}

func (d *Daemon) generateFollowupQueries(ctx context.Context, query, collection string, hits []searchHit) ([]string, []string) {
	_ = d
	_ = ctx
	_ = collection
	_ = hits
	base := generateDeterministicFollowups(query)
	base = dedupeStrings(base)
	out := make([]string, 0, len(base))
	queryLower := strings.ToLower(normalizeSpacing(query))
	for _, q := range base {
		q = normalizeSpacing(q)
		if q == "" {
			continue
		}
		if strings.EqualFold(q, query) {
			continue
		}
		// Keep followups grounded to original intent.
		if queryLower != "" && scoreOverlap(strings.ToLower(q), queryLower) < 0.15 {
			continue
		}
		out = append(out, q)
		if len(out) >= 5 {
			break
		}
	}
	return out, nil
}

func inferCoverageMissingAspects(query string, hits []searchHit) []string {
	query = strings.ToLower(normalizeSpacing(query))
	notes := make([]string, 0, 3)
	if len(hits) == 0 {
		return []string{"no_matching_results"}
	}
	if strings.Contains(query, " and ") {
		notes = append(notes, "multi_aspect_query")
	}
	highConfidence := false
	for _, h := range hits {
		if strings.EqualFold(strings.TrimSpace(h.Confidence), "high") {
			highConfidence = true
			break
		}
	}
	if !highConfidence {
		notes = append(notes, "low_confidence_results")
	}
	return dedupeStrings(notes)
}

func maxConfidence(a, b string) string {
	rank := func(v string) int {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "high":
			return 3
		case "medium":
			return 2
		case "low":
			return 1
		default:
			return 0
		}
	}
	if rank(a) >= rank(b) {
		return a
	}
	return b
}

func (d *Daemon) auditAllow(ctx context.Context, requestID, remote, rpcMethod, tool, reason string, metadata map[string]any) {
	if d == nil || d.auditor == nil {
		return
	}
	d.auditor.Record(ctx, AuditEvent{
		RequestID:  requestID,
		RemoteAddr: remote,
		RPCMethod:  rpcMethod,
		Tool:       tool,
		Decision:   auditDecisionAllow,
		Reason:     reason,
		Metadata:   metadata,
	})
}

func (d *Daemon) auditDeny(ctx context.Context, requestID, remote, rpcMethod, tool, reason string, metadata map[string]any) {
	if d == nil || d.auditor == nil {
		return
	}
	d.auditor.Record(ctx, AuditEvent{
		RequestID:  requestID,
		RemoteAddr: remote,
		RPCMethod:  rpcMethod,
		Tool:       tool,
		Decision:   auditDecisionDeny,
		Reason:     reason,
		Metadata:   metadata,
	})
}

func mapStoreError(err error) *rpcError {
	switch {
	case errors.Is(err, errVaultLocked):
		return &rpcError{Code: rpcErrVaultLocked, Message: "vault_locked"}
	case errors.Is(err, errUnlockPassphraseRequired):
		return &rpcError{Code: rpcErrInvalidParams, Message: "passphrase is required"}
	case errors.Is(err, errUnlockPassphraseInvalid):
		return &rpcError{Code: rpcErrUnlockFailed, Message: "unlock_failed"}
	case errors.Is(err, errCollectionAccessDenied):
		return &rpcError{Code: rpcErrPolicyDenied, Message: "collection_policy_denied"}
	case errors.Is(err, errCollectionNotFound):
		return &rpcError{Code: rpcErrInvalidParams, Message: "collection_not_found"}
	case errors.Is(err, errInvalidCollectionName), errors.Is(err, errInvalidCollectionTier), errors.Is(err, errCollectionAlreadyExists):
		return &rpcError{Code: rpcErrInvalidParams, Message: redact.String(err.Error())}
	case errors.Is(err, errInvalidConnectorProvider), errors.Is(err, errConnectorTokenRequired), errors.Is(err, errInvalidApprovalAction):
		return &rpcError{Code: rpcErrInvalidParams, Message: redact.String(err.Error())}
	case errors.Is(err, errInvalidBase64Content), errors.Is(err, errUnsupportedContentType), errors.Is(err, errExtractedContentEmpty):
		return &rpcError{Code: rpcErrInvalidParams, Message: redact.String(err.Error())}
	case errors.Is(err, errEgressCoverageExceeded), errors.Is(err, errEgressOverlapDetected):
		return &rpcError{Code: rpcErrPolicyDenied, Message: redact.String(err.Error())}
	case errors.Is(err, errObjectNotFound), errors.Is(err, errApprovalNotFound):
		return &rpcError{Code: rpcErrNotFound, Message: "object_not_found"}
	default:
		return &rpcError{Code: rpcErrInternal, Message: "internal_error", Data: map[string]any{"error": redact.String(err.Error())}}
	}
}

func decodeArgs(raw json.RawMessage, out any) error {
	if len(raw) == 0 || string(raw) == "null" {
		raw = []byte("{}")
	}
	return json.Unmarshal(raw, out)
}

func invalidParamsErr(err error) *rpcError {
	return &rpcError{
		Code:    rpcErrInvalidParams,
		Message: "invalid params",
		Data:    map[string]any{"error": redact.String(err.Error())},
	}
}

func budgetErr(msg, budget string, max int) *rpcError {
	return &rpcError{
		Code:    rpcErrBudgetExceeded,
		Message: "budget_exceeded",
		Data: map[string]any{
			"reason": msg,
			"budget": budget,
			"max":    max,
		},
	}
}

func parseBearerToken(header string) (string, bool) {
	header = strings.TrimSpace(header)
	if header == "" {
		return "", false
	}
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	if strings.TrimSpace(parts[1]) == "" {
		return "", false
	}
	return parts[1], true
}

func requestID(r *http.Request) string {
	if r == nil {
		return randomID()
	}
	for _, key := range []string{"X-Request-ID", "x-request-id"} {
		if v := strings.TrimSpace(r.Header.Get(key)); v != "" {
			return v
		}
	}
	return randomID()
}

func randomID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "req_fallback"
	}
	return "req_" + hex.EncodeToString(b[:])
}

func isLoopbackRemoteAddr(addr string) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return false
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	return ip != nil && ip.IsLoopback()
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

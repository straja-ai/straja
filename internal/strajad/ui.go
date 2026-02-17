package strajad

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/straja-ai/straja/internal/redact"
)

const (
	vaultUIRobotsTag = "noindex, nofollow, noarchive"
)

//go:embed static/vault-ui.html
var vaultUIHTML []byte

type vaultUIQueryTraceStep struct {
	Stage      string `json:"stage"`
	Name       string `json:"name,omitempty"`
	Arguments  any    `json:"arguments,omitempty"`
	Result     any    `json:"result,omitempty"`
	Message    string `json:"message,omitempty"`
	Error      string `json:"error,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty"`
}

type vaultUIQueryResponse struct {
	Task        string                  `json:"task"`
	Collection  string                  `json:"collection,omitempty"`
	Plan        deterministicPlan       `json:"plan"`
	SearchHits  []searchHit             `json:"search_results,omitempty"`
	Snippets    []snippetHit            `json:"snippets,omitempty"`
	FinalAnswer string                  `json:"final_response"`
	LLMUsed     bool                    `json:"llm_used"`
	Trace       []vaultUIQueryTraceStep `json:"trace"`
}

func (d *Daemon) handleVaultUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path != "/vault" && r.URL.Path != "/vault/" {
		http.NotFound(w, r)
		return
	}
	if !isLoopbackRemoteAddr(strings.TrimSpace(r.RemoteAddr)) {
		http.Error(w, "forbidden: local-only endpoint", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Robots-Tag", vaultUIRobotsTag)
	_, _ = w.Write(vaultUIHTML)
}

func (d *Daemon) handleVaultUIState(w http.ResponseWriter, r *http.Request) {
	requestID, remote, ok := d.authorizeVaultUIAPI(w, r, "vault.ui.state")
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		d.auditDeny(r.Context(), requestID, remote, "ui/state", "vault.ui.state", "method_not_allowed", nil)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	payload := d.vaultUIStatePayload()
	d.auditAllow(r.Context(), requestID, remote, "ui/state", "vault.ui.state", "ok_vault_ui_state", map[string]any{
		"unlocked": payload["unlocked"],
	})
	writeJSON(w, http.StatusOK, payload)
}

func (d *Daemon) handleVaultUIUnlock(w http.ResponseWriter, r *http.Request) {
	requestID, remote, ok := d.authorizeVaultUIAPI(w, r, "vault.ui.unlock")
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		d.auditDeny(r.Context(), requestID, remote, "ui/unlock", "vault.ui.unlock", "method_not_allowed", nil)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	var req struct {
		Passphrase    string `json:"passphrase"`
		PresenceToken string `json:"presence_token"`
	}
	if err := decodeVaultUIBody(r.Body, d.cfg.MaxRequestBodyBytes, &req); err != nil {
		d.auditDeny(r.Context(), requestID, remote, "ui/unlock", "vault.ui.unlock", "invalid_request_body", map[string]any{"error": redact.String(err.Error())})
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "invalid_request_body",
		})
		return
	}

	created, err := d.store.Unlock(req.Passphrase, req.PresenceToken)
	if err != nil {
		status, code := uiErrorForStore(err)
		d.auditDeny(r.Context(), requestID, remote, "ui/unlock", "vault.ui.unlock", code, map[string]any{"error": redact.String(err.Error())})
		writeJSON(w, status, map[string]any{
			"error": code,
		})
		return
	}

	payload := d.vaultUIStatePayload()
	payload["created"] = created
	d.auditAllow(r.Context(), requestID, remote, "ui/unlock", "vault.ui.unlock", "ok_vault_ui_unlock", map[string]any{
		"created": created,
	})
	writeJSON(w, http.StatusOK, payload)
}

func (d *Daemon) handleVaultUILock(w http.ResponseWriter, r *http.Request) {
	requestID, remote, ok := d.authorizeVaultUIAPI(w, r, "vault.ui.lock")
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		d.auditDeny(r.Context(), requestID, remote, "ui/lock", "vault.ui.lock", "method_not_allowed", nil)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := d.store.Lock(); err != nil {
		status, code := uiErrorForStore(err)
		d.auditDeny(r.Context(), requestID, remote, "ui/lock", "vault.ui.lock", code, map[string]any{"error": redact.String(err.Error())})
		writeJSON(w, status, map[string]any{
			"error": code,
		})
		return
	}
	payload := d.vaultUIStatePayload()
	d.auditAllow(r.Context(), requestID, remote, "ui/lock", "vault.ui.lock", "ok_vault_ui_lock", nil)
	writeJSON(w, http.StatusOK, payload)
}

func (d *Daemon) handleVaultUICollections(w http.ResponseWriter, r *http.Request) {
	requestID, remote, ok := d.authorizeVaultUIAPI(w, r, "vault.ui.collections")
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		d.auditDeny(r.Context(), requestID, remote, "ui/collections", "vault.ui.collections", "method_not_allowed", nil)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !d.store.IsUnlocked() {
		d.auditAllow(r.Context(), requestID, remote, "ui/collections", "vault.ui.collections", "ok_vault_ui_collections_locked", nil)
		writeJSON(w, http.StatusOK, map[string]any{
			"locked":      true,
			"collections": []collectionHit{},
		})
		return
	}
	collections, err := d.store.ListCollections()
	if err != nil {
		status, code := uiErrorForStore(err)
		d.auditDeny(r.Context(), requestID, remote, "ui/collections", "vault.ui.collections", code, map[string]any{"error": redact.String(err.Error())})
		writeJSON(w, status, map[string]any{
			"error": code,
		})
		return
	}
	d.auditAllow(r.Context(), requestID, remote, "ui/collections", "vault.ui.collections", "ok_vault_ui_collections", map[string]any{
		"count": len(collections),
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"locked":      false,
		"collections": collections,
	})
}

func (d *Daemon) handleVaultUICollectionUpdate(w http.ResponseWriter, r *http.Request) {
	requestID, remote, ok := d.authorizeVaultUIAPI(w, r, "vault.ui.collections.update")
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		d.auditDeny(r.Context(), requestID, remote, "ui/collections/update", "vault.ui.collections.update", "method_not_allowed", nil)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	var req struct {
		Name        string `json:"name"`
		Tier        string `json:"tier"`
		Description string `json:"description"`
	}
	if err := decodeVaultUIBody(r.Body, d.cfg.MaxRequestBodyBytes, &req); err != nil {
		d.auditDeny(r.Context(), requestID, remote, "ui/collections/update", "vault.ui.collections.update", "invalid_request_body", map[string]any{"error": redact.String(err.Error())})
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "invalid_request_body",
		})
		return
	}
	updated, err := d.store.UpdateCollection(req.Name, req.Tier, req.Description)
	if err != nil {
		status, code := uiErrorForStore(err)
		d.auditDeny(r.Context(), requestID, remote, "ui/collections/update", "vault.ui.collections.update", code, map[string]any{"error": redact.String(err.Error())})
		writeJSON(w, status, map[string]any{
			"error": code,
		})
		return
	}
	d.auditAllow(r.Context(), requestID, remote, "ui/collections/update", "vault.ui.collections.update", "ok_vault_ui_collections_update", map[string]any{
		"name": updated.Name,
		"tier": updated.Tier,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"collection": updated,
	})
}

func (d *Daemon) handleVaultUIItems(w http.ResponseWriter, r *http.Request) {
	requestID, remote, ok := d.authorizeVaultUIAPI(w, r, "vault.ui.items")
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !d.store.IsUnlocked() {
			d.auditAllow(r.Context(), requestID, remote, "ui/items", "vault.ui.items", "ok_vault_ui_items_locked", nil)
			writeJSON(w, http.StatusOK, map[string]any{
				"locked": true,
				"items":  []itemHit{},
			})
			return
		}
		collection := strings.TrimSpace(r.URL.Query().Get("collection"))
		limit := clampInt(parseUIInt(r.URL.Query().Get("limit"), 50), 1, 200)
		items, err := d.store.ListItems(collection, limit)
		if err != nil {
			status, code := uiErrorForStore(err)
			d.auditDeny(r.Context(), requestID, remote, "ui/items", "vault.ui.items", code, map[string]any{"error": redact.String(err.Error())})
			writeJSON(w, status, map[string]any{
				"error": code,
			})
			return
		}
		d.auditAllow(r.Context(), requestID, remote, "ui/items", "vault.ui.items", "ok_vault_ui_items", map[string]any{
			"count": len(items),
		})
		writeJSON(w, http.StatusOK, map[string]any{
			"locked": false,
			"items":  items,
		})
	case http.MethodPost:
		defer r.Body.Close()
		var req struct {
			Action     string   `json:"action"`
			ID         string   `json:"id"`
			IDs        []string `json:"ids"`
			Collection string   `json:"collection"`
		}
		if err := decodeVaultUIBody(r.Body, d.cfg.MaxRequestBodyBytes, &req); err != nil {
			d.auditDeny(r.Context(), requestID, remote, "ui/items", "vault.ui.items", "invalid_request_body", map[string]any{"error": redact.String(err.Error())})
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": "invalid_request_body",
			})
			return
		}
		action := strings.TrimSpace(strings.ToLower(req.Action))
		if action == "" {
			action = "delete"
		}
		switch action {
		case "delete":
			id := strings.TrimSpace(req.ID)
			if id == "" {
				d.auditDeny(r.Context(), requestID, remote, "ui/items", "vault.ui.items", "item_id_required", nil)
				writeJSON(w, http.StatusBadRequest, map[string]any{
					"error": "item_id_required",
				})
				return
			}
			if err := d.store.Delete(id); err != nil {
				status, code := uiErrorForStore(err)
				d.auditDeny(r.Context(), requestID, remote, "ui/items", "vault.ui.items", code, map[string]any{"error": redact.String(err.Error())})
				writeJSON(w, status, map[string]any{
					"error": code,
				})
				return
			}
			d.auditAllow(r.Context(), requestID, remote, "ui/items", "vault.ui.items", "ok_vault_ui_item_delete", map[string]any{"id": id})
			writeJSON(w, http.StatusOK, map[string]any{
				"deleted": 1,
			})
		case "delete_batch":
			deleted, missing, err := d.store.DeleteMany(req.IDs)
			if err != nil {
				status, code := uiErrorForStore(err)
				d.auditDeny(r.Context(), requestID, remote, "ui/items", "vault.ui.items", code, map[string]any{"error": redact.String(err.Error())})
				writeJSON(w, status, map[string]any{
					"error": code,
				})
				return
			}
			d.auditAllow(r.Context(), requestID, remote, "ui/items", "vault.ui.items", "ok_vault_ui_items_delete_batch", map[string]any{
				"deleted": deleted,
				"missing": len(missing),
			})
			writeJSON(w, http.StatusOK, map[string]any{
				"deleted": deleted,
				"missing": missing,
			})
		case "delete_all":
			deleted, err := d.store.DeleteAll(req.Collection)
			if err != nil {
				status, code := uiErrorForStore(err)
				d.auditDeny(r.Context(), requestID, remote, "ui/items", "vault.ui.items", code, map[string]any{"error": redact.String(err.Error())})
				writeJSON(w, status, map[string]any{
					"error": code,
				})
				return
			}
			d.auditAllow(r.Context(), requestID, remote, "ui/items", "vault.ui.items", "ok_vault_ui_items_delete_all", map[string]any{
				"deleted":    deleted,
				"collection": normalizeCollectionName(req.Collection),
			})
			writeJSON(w, http.StatusOK, map[string]any{
				"deleted":    deleted,
				"collection": normalizeCollectionName(req.Collection),
			})
		default:
			d.auditDeny(r.Context(), requestID, remote, "ui/items", "vault.ui.items", "invalid_action", nil)
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": "invalid_action",
			})
		}
	default:
		d.auditDeny(r.Context(), requestID, remote, "ui/items", "vault.ui.items", "method_not_allowed", nil)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (d *Daemon) handleVaultUIReindex(w http.ResponseWriter, r *http.Request) {
	requestID, remote, ok := d.authorizeVaultUIAPI(w, r, "vault.ui.reindex")
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		d.auditDeny(r.Context(), requestID, remote, "ui/reindex", "vault.ui.reindex", "method_not_allowed", nil)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()

	var req struct {
		Reason string `json:"reason"`
	}
	if err := decodeVaultUIBody(r.Body, d.cfg.MaxRequestBodyBytes, &req); err != nil {
		d.auditDeny(r.Context(), requestID, remote, "ui/reindex", "vault.ui.reindex", "invalid_request_body", map[string]any{"error": redact.String(err.Error())})
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "invalid_request_body",
		})
		return
	}
	reindexed, err := d.store.ReindexAll(req.Reason)
	if err != nil {
		status, code := uiErrorForStore(err)
		d.auditDeny(r.Context(), requestID, remote, "ui/reindex", "vault.ui.reindex", code, map[string]any{"error": redact.String(err.Error())})
		writeJSON(w, status, map[string]any{
			"error": code,
		})
		return
	}

	d.auditAllow(r.Context(), requestID, remote, "ui/reindex", "vault.ui.reindex", "ok_vault_ui_reindex", map[string]any{
		"reindexed_objects": reindexed,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"reindexed_objects": reindexed,
		"state":             d.vaultUIStatePayload(),
	})
}

func (d *Daemon) handleVaultUIConnectors(w http.ResponseWriter, r *http.Request) {
	requestID, remote, ok := d.authorizeVaultUIAPI(w, r, "vault.ui.connectors")
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !d.store.IsUnlocked() {
			d.auditAllow(r.Context(), requestID, remote, "ui/connectors", "vault.ui.connectors", "ok_vault_ui_connectors_locked", nil)
			writeJSON(w, http.StatusOK, map[string]any{
				"locked":     true,
				"connectors": []connectorStatus{},
			})
			return
		}
		connectors, err := d.store.ListConnectorStatuses()
		if err != nil {
			status, code := uiErrorForStore(err)
			d.auditDeny(r.Context(), requestID, remote, "ui/connectors", "vault.ui.connectors", code, map[string]any{"error": redact.String(err.Error())})
			writeJSON(w, status, map[string]any{
				"error": code,
			})
			return
		}
		d.auditAllow(r.Context(), requestID, remote, "ui/connectors", "vault.ui.connectors", "ok_vault_ui_connectors", map[string]any{
			"count": len(connectors),
		})
		writeJSON(w, http.StatusOK, map[string]any{
			"locked":     false,
			"connectors": connectors,
		})
	case http.MethodPost:
		defer r.Body.Close()
		var req struct {
			Action   string `json:"action"`
			Provider string `json:"provider"`
			Token    string `json:"token"`
		}
		if err := decodeVaultUIBody(r.Body, d.cfg.MaxRequestBodyBytes, &req); err != nil {
			d.auditDeny(r.Context(), requestID, remote, "ui/connectors", "vault.ui.connectors", "invalid_request_body", map[string]any{"error": redact.String(err.Error())})
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": "invalid_request_body",
			})
			return
		}
		action := strings.TrimSpace(strings.ToLower(req.Action))
		if action == "" {
			action = "set_token"
		}
		switch action {
		case "set_token":
			updated, err := d.store.SetConnectorToken(req.Provider, req.Token)
			if err != nil {
				status, code := uiErrorForStore(err)
				d.auditDeny(r.Context(), requestID, remote, "ui/connectors", "vault.ui.connectors", code, map[string]any{"error": redact.String(err.Error())})
				writeJSON(w, status, map[string]any{
					"error": code,
				})
				return
			}
			d.auditAllow(r.Context(), requestID, remote, "ui/connectors", "vault.ui.connectors", "ok_vault_ui_connectors_set_token", map[string]any{
				"provider": updated.Provider,
			})
			writeJSON(w, http.StatusOK, map[string]any{
				"connector": updated,
			})
		case "clear_token":
			updated, err := d.store.RemoveConnectorToken(req.Provider)
			if err != nil {
				status, code := uiErrorForStore(err)
				d.auditDeny(r.Context(), requestID, remote, "ui/connectors", "vault.ui.connectors", code, map[string]any{"error": redact.String(err.Error())})
				writeJSON(w, status, map[string]any{
					"error": code,
				})
				return
			}
			d.auditAllow(r.Context(), requestID, remote, "ui/connectors", "vault.ui.connectors", "ok_vault_ui_connectors_clear_token", map[string]any{
				"provider": updated.Provider,
			})
			writeJSON(w, http.StatusOK, map[string]any{
				"connector": updated,
			})
		default:
			d.auditDeny(r.Context(), requestID, remote, "ui/connectors", "vault.ui.connectors", "invalid_action", nil)
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": "invalid_action",
			})
		}
	default:
		d.auditDeny(r.Context(), requestID, remote, "ui/connectors", "vault.ui.connectors", "method_not_allowed", nil)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (d *Daemon) handleVaultUIApprovals(w http.ResponseWriter, r *http.Request) {
	requestID, remote, ok := d.authorizeVaultUIAPI(w, r, "vault.ui.approvals")
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		if !d.store.IsUnlocked() {
			d.auditAllow(r.Context(), requestID, remote, "ui/approvals", "vault.ui.approvals", "ok_vault_ui_approvals_locked", nil)
			writeJSON(w, http.StatusOK, map[string]any{
				"locked":    true,
				"approvals": []approvalRequest{},
			})
			return
		}
		limit := clampInt(parseUIInt(r.URL.Query().Get("limit"), 50), 1, d.cfg.MaxAuditRecords)
		statusFilter := strings.TrimSpace(r.URL.Query().Get("status"))
		approvals, err := d.store.ListApprovals(statusFilter, limit)
		if err != nil {
			status, code := uiErrorForStore(err)
			d.auditDeny(r.Context(), requestID, remote, "ui/approvals", "vault.ui.approvals", code, map[string]any{"error": redact.String(err.Error())})
			writeJSON(w, status, map[string]any{
				"error": code,
			})
			return
		}
		d.auditAllow(r.Context(), requestID, remote, "ui/approvals", "vault.ui.approvals", "ok_vault_ui_approvals", map[string]any{
			"count": len(approvals),
		})
		writeJSON(w, http.StatusOK, map[string]any{
			"locked":    false,
			"approvals": approvals,
		})
	case http.MethodPost:
		defer r.Body.Close()
		var req struct {
			Action string `json:"action"`
			ID     string `json:"id"`
			Reason string `json:"reason"`
		}
		if err := decodeVaultUIBody(r.Body, d.cfg.MaxRequestBodyBytes, &req); err != nil {
			d.auditDeny(r.Context(), requestID, remote, "ui/approvals", "vault.ui.approvals", "invalid_request_body", map[string]any{"error": redact.String(err.Error())})
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": "invalid_request_body",
			})
			return
		}
		action := strings.TrimSpace(strings.ToLower(req.Action))
		if action != "approve" && action != "reject" {
			d.auditDeny(r.Context(), requestID, remote, "ui/approvals", "vault.ui.approvals", "invalid_action", nil)
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": "invalid_action",
			})
			return
		}
		id := strings.TrimSpace(req.ID)
		if id == "" {
			d.auditDeny(r.Context(), requestID, remote, "ui/approvals", "vault.ui.approvals", "approval_id_required", nil)
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": "approval_id_required",
			})
			return
		}
		decision := "approved"
		if action == "reject" {
			decision = "rejected"
		}
		updated, err := d.store.ResolveApproval(id, decision, req.Reason)
		if err != nil {
			status, code := uiErrorForStore(err)
			d.auditDeny(r.Context(), requestID, remote, "ui/approvals", "vault.ui.approvals", code, map[string]any{"error": redact.String(err.Error())})
			writeJSON(w, status, map[string]any{
				"error": code,
			})
			return
		}
		if updated.Action == "mail.send" && strings.TrimSpace(updated.ResourceID) != "" {
			_, _ = d.mail.MarkDraftApprovalDecision(updated.ResourceID, updated.Status, updated.Reason)
		}
		d.auditAllow(r.Context(), requestID, remote, "ui/approvals", "vault.ui.approvals", "ok_vault_ui_approvals_resolve", map[string]any{
			"id":     updated.ID,
			"status": updated.Status,
		})
		writeJSON(w, http.StatusOK, map[string]any{
			"approval": updated,
		})
	default:
		d.auditDeny(r.Context(), requestID, remote, "ui/approvals", "vault.ui.approvals", "method_not_allowed", nil)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (d *Daemon) handleVaultUIDriveOAuthStart(w http.ResponseWriter, r *http.Request) {
	requestID, remote, ok := d.authorizeVaultUIAPI(w, r, "vault.ui.drive.oauth.start")
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		d.auditDeny(r.Context(), requestID, remote, "ui/drive/oauth/start", "vault.ui.drive.oauth.start", "method_not_allowed", nil)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	state, err := d.newOAuthState()
	if err != nil {
		d.auditDeny(r.Context(), requestID, remote, "ui/drive/oauth/start", "vault.ui.drive.oauth.start", "state_generation_failed", map[string]any{"error": redact.String(err.Error())})
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"error": "state_generation_failed",
		})
		return
	}
	authURL, err := d.buildDriveOAuthURL(state)
	if err != nil {
		status, code := uiErrorForDrive(err)
		d.auditDeny(r.Context(), requestID, remote, "ui/drive/oauth/start", "vault.ui.drive.oauth.start", code, map[string]any{"error": redact.String(err.Error())})
		writeJSON(w, status, map[string]any{
			"error": code,
		})
		return
	}
	d.auditAllow(r.Context(), requestID, remote, "ui/drive/oauth/start", "vault.ui.drive.oauth.start", "ok_vault_ui_drive_oauth_start", nil)
	writeJSON(w, http.StatusOK, map[string]any{
		"provider": "drive",
		"auth_url": authURL,
	})
}

func (d *Daemon) handleVaultUIDriveOAuthCallback(w http.ResponseWriter, r *http.Request) {
	requestID := requestID(r)
	remote := strings.TrimSpace(r.RemoteAddr)
	if r.Method != http.MethodGet {
		d.auditDeny(r.Context(), requestID, remote, "ui/drive/oauth/callback", "vault.ui.drive.oauth.callback", "method_not_allowed", nil)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isLoopbackRemoteAddr(remote) {
		d.auditDeny(r.Context(), requestID, remote, "ui/drive/oauth/callback", "vault.ui.drive.oauth.callback", "non_loopback_remote", nil)
		http.Error(w, "forbidden: local-only endpoint", http.StatusForbidden)
		return
	}

	if oauthErr := strings.TrimSpace(r.URL.Query().Get("error")); oauthErr != "" {
		d.auditDeny(r.Context(), requestID, remote, "ui/drive/oauth/callback", "vault.ui.drive.oauth.callback", "oauth_denied", map[string]any{"error": oauthErr})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(driveCallbackResultHTML(false, "Google authorization failed: "+oauthErr)))
		return
	}
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if code == "" || state == "" || !d.consumeOAuthState(state) {
		d.auditDeny(r.Context(), requestID, remote, "ui/drive/oauth/callback", "vault.ui.drive.oauth.callback", "oauth_state_invalid", nil)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(driveCallbackResultHTML(false, "OAuth callback validation failed.")))
		return
	}
	token, err := d.exchangeDriveOAuthCode(r.Context(), code)
	if err != nil {
		status, code := uiErrorForDrive(err)
		d.auditDeny(r.Context(), requestID, remote, "ui/drive/oauth/callback", "vault.ui.drive.oauth.callback", code, map[string]any{"error": redact.String(err.Error())})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(driveCallbackResultHTML(false, "Token exchange failed.")))
		return
	}
	serialized, err := serializeDriveOAuthToken(token)
	if err != nil {
		d.auditDeny(r.Context(), requestID, remote, "ui/drive/oauth/callback", "vault.ui.drive.oauth.callback", "serialize_failed", map[string]any{"error": redact.String(err.Error())})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(driveCallbackResultHTML(false, "Token serialization failed.")))
		return
	}
	if _, err := d.store.SetConnectorToken("drive", serialized); err != nil {
		status, code := uiErrorForStore(err)
		d.auditDeny(r.Context(), requestID, remote, "ui/drive/oauth/callback", "vault.ui.drive.oauth.callback", code, map[string]any{"error": redact.String(err.Error())})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(driveCallbackResultHTML(false, "Vault unlock is required before storing Drive token.")))
		return
	}
	d.auditAllow(r.Context(), requestID, remote, "ui/drive/oauth/callback", "vault.ui.drive.oauth.callback", "ok_vault_ui_drive_oauth_callback", nil)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(driveCallbackResultHTML(true, "Google Drive connected.")))
}

func (d *Daemon) handleVaultUIDriveFiles(w http.ResponseWriter, r *http.Request) {
	requestID, remote, ok := d.authorizeVaultUIAPI(w, r, "vault.ui.drive.files")
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		d.auditDeny(r.Context(), requestID, remote, "ui/drive/files", "vault.ui.drive.files", "method_not_allowed", nil)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !d.store.IsUnlocked() {
		d.auditAllow(r.Context(), requestID, remote, "ui/drive/files", "vault.ui.drive.files", "ok_vault_ui_drive_files_locked", nil)
		writeJSON(w, http.StatusOK, map[string]any{
			"locked":          true,
			"items":           []driveRemoteItem{},
			"next_page_token": "",
		})
		return
	}
	folderID := strings.TrimSpace(r.URL.Query().Get("folder_id"))
	pageToken := strings.TrimSpace(r.URL.Query().Get("page_token"))
	pageSize := clampInt(parseUIInt(r.URL.Query().Get("page_size"), drivePageSizeDefault), 1, drivePageSizeHardCeil)
	items, nextPageToken, err := d.driveListFolder(r.Context(), folderID, pageToken, pageSize)
	if err != nil {
		status, code := uiErrorForDrive(err)
		d.auditDeny(r.Context(), requestID, remote, "ui/drive/files", "vault.ui.drive.files", code, map[string]any{"error": redact.String(err.Error())})
		writeJSON(w, status, map[string]any{
			"error": code,
		})
		return
	}
	d.auditAllow(r.Context(), requestID, remote, "ui/drive/files", "vault.ui.drive.files", "ok_vault_ui_drive_files", map[string]any{
		"count": len(items),
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"locked":          false,
		"folder_id":       strings.TrimSpace(folderID),
		"items":           items,
		"next_page_token": nextPageToken,
	})
}

func (d *Daemon) handleVaultUIDriveImport(w http.ResponseWriter, r *http.Request) {
	requestID, remote, ok := d.authorizeVaultUIAPI(w, r, "vault.ui.drive.import")
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		d.auditDeny(r.Context(), requestID, remote, "ui/drive/import", "vault.ui.drive.import", "method_not_allowed", nil)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	var req struct {
		Collection string   `json:"collection"`
		FileIDs    []string `json:"file_ids"`
		FolderIDs  []string `json:"folder_ids"`
	}
	if err := decodeVaultUIBody(r.Body, d.cfg.MaxRequestBodyBytes, &req); err != nil {
		d.auditDeny(r.Context(), requestID, remote, "ui/drive/import", "vault.ui.drive.import", "invalid_request_body", map[string]any{"error": redact.String(err.Error())})
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "invalid_request_body",
		})
		return
	}
	if len(req.FileIDs) == 0 && len(req.FolderIDs) == 0 {
		d.auditDeny(r.Context(), requestID, remote, "ui/drive/import", "vault.ui.drive.import", "selection_required", nil)
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "selection_required",
		})
		return
	}
	imported, failed, err := d.driveImportSelection(r.Context(), req.Collection, req.FileIDs, req.FolderIDs)
	if err != nil {
		status, code := uiErrorForDrive(err)
		d.auditDeny(r.Context(), requestID, remote, "ui/drive/import", "vault.ui.drive.import", code, map[string]any{"error": redact.String(err.Error())})
		writeJSON(w, status, map[string]any{
			"error": code,
		})
		return
	}
	d.auditAllow(r.Context(), requestID, remote, "ui/drive/import", "vault.ui.drive.import", "ok_vault_ui_drive_import", map[string]any{
		"imported": len(imported),
		"failed":   len(failed),
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"imported": imported,
		"failed":   failed,
		"counts": map[string]any{
			"imported": len(imported),
			"failed":   len(failed),
		},
	})
}

func (d *Daemon) handleVaultUIBrokerModel(w http.ResponseWriter, r *http.Request) {
	requestID, remote, ok := d.authorizeVaultUIAPI(w, r, "vault.ui.broker.model")
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		d.auditDeny(r.Context(), requestID, remote, "ui/broker/model", "vault.ui.broker.model", "method_not_allowed", nil)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	payload, err := d.brokerModelStatusPayload(r.Context(), d.cfg)
	if err != nil {
		status, code := uiErrorForBroker(err)
		d.auditDeny(r.Context(), requestID, remote, "ui/broker/model", "vault.ui.broker.model", code, map[string]any{"error": redact.String(err.Error())})
		payload["error"] = code
		payload["error_detail"] = sanitizeOneLine(err.Error(), "", 512)
		payload["hint"] = brokerErrorHint(err, d.cfg)
		writeJSON(w, status, payload)
		return
	}
	d.auditAllow(r.Context(), requestID, remote, "ui/broker/model", "vault.ui.broker.model", "ok_vault_ui_broker_model", map[string]any{
		"model":   payload["broker_model"],
		"present": payload["model_present"],
	})
	writeJSON(w, http.StatusOK, payload)
}

func (d *Daemon) handleVaultUIBrokerModelInstall(w http.ResponseWriter, r *http.Request) {
	requestID, remote, ok := d.authorizeVaultUIAPI(w, r, "vault.ui.broker.model.install")
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		d.auditDeny(r.Context(), requestID, remote, "ui/broker/model/install", "vault.ui.broker.model.install", "method_not_allowed", nil)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cfg := d.cfg
	installTimeout := 20 * time.Minute
	ctx, cancel := context.WithTimeout(r.Context(), installTimeout)
	defer cancel()

	if err := InstallBrokerModel(ctx, cfg); err != nil {
		status, code := uiErrorForBroker(err)
		d.auditDeny(r.Context(), requestID, remote, "ui/broker/model/install", "vault.ui.broker.model.install", code, map[string]any{"error": redact.String(err.Error())})
		writeJSON(w, status, map[string]any{
			"error":           code,
			"error_detail":    sanitizeOneLine(err.Error(), "", 512),
			"hint":            brokerErrorHint(err, cfg),
			"broker_model":    cfg.BrokerModel,
			"broker_enabled":  cfg.BrokerEnabled,
			"broker_endpoint": cfg.BrokerEndpoint,
		})
		return
	}

	payload, statusErr := d.brokerModelStatusPayload(ctx, cfg)
	if statusErr != nil {
		d.auditAllow(r.Context(), requestID, remote, "ui/broker/model/install", "vault.ui.broker.model.install", "ok_vault_ui_broker_model_install_partial", map[string]any{
			"model": cfg.BrokerModel,
		})
		writeJSON(w, http.StatusOK, map[string]any{
			"installed":      true,
			"broker_model":   cfg.BrokerModel,
			"broker_enabled": cfg.BrokerEnabled,
			"check_error":    sanitizeOneLine(statusErr.Error(), "broker_check_failed", 256),
		})
		return
	}
	payload["installed"] = true
	d.auditAllow(r.Context(), requestID, remote, "ui/broker/model/install", "vault.ui.broker.model.install", "ok_vault_ui_broker_model_install", map[string]any{
		"model":   payload["broker_model"],
		"present": payload["model_present"],
	})
	writeJSON(w, http.StatusOK, payload)
}

func (d *Daemon) handleVaultUIAudit(w http.ResponseWriter, r *http.Request) {
	requestID, remote, ok := d.authorizeVaultUIAPI(w, r, "vault.ui.audit")
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		d.auditDeny(r.Context(), requestID, remote, "ui/audit", "vault.ui.audit", "method_not_allowed", nil)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	limit := clampInt(parseUIInt(r.URL.Query().Get("limit"), 50), 1, d.cfg.MaxAuditRecords)
	d.auditAllow(r.Context(), requestID, remote, "ui/audit", "vault.ui.audit", "ok_vault_ui_audit", nil)
	records := d.auditor.List(limit)
	writeJSON(w, http.StatusOK, map[string]any{
		"records": records,
		"budget": map[string]any{
			"max_audit_records": d.cfg.MaxAuditRecords,
			"requested_limit":   limit,
			"returned":          len(records),
		},
	})
}

func (d *Daemon) brokerModelStatusPayload(ctx context.Context, cfg Config) (map[string]any, error) {
	payload := map[string]any{
		"broker_enabled":  cfg.BrokerEnabled,
		"broker_provider": cfg.BrokerProvider,
		"broker_endpoint": cfg.BrokerEndpoint,
		"broker_model":    cfg.BrokerModel,
		"checked_at":      time.Now().UTC().Format(time.RFC3339),
	}
	present, err := BrokerModelAvailable(ctx, cfg)
	payload["model_present"] = present
	return payload, err
}

func (d *Daemon) handleVaultUIQuery(w http.ResponseWriter, r *http.Request) {
	requestID, remote, ok := d.authorizeVaultUIAPI(w, r, "vault.ui.query")
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		d.auditDeny(r.Context(), requestID, remote, "ui/query", "vault.ui.query", "method_not_allowed", nil)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()

	var req struct {
		Task       string `json:"task"`
		Collection string `json:"collection"`
	}
	if err := decodeVaultUIBody(r.Body, d.cfg.MaxRequestBodyBytes, &req); err != nil {
		d.auditDeny(r.Context(), requestID, remote, "ui/query", "vault.ui.query", "invalid_request_body", map[string]any{"error": redact.String(err.Error())})
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "invalid_request_body",
		})
		return
	}

	task := sanitizeOneLine(req.Task, "", d.cfg.MaxTaskChars)
	if task == "" {
		d.auditDeny(r.Context(), requestID, remote, "ui/query", "vault.ui.query", "task_required", nil)
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "task_required",
		})
		return
	}
	if len([]byte(strings.TrimSpace(req.Task))) > d.cfg.MaxTaskChars {
		d.auditDeny(r.Context(), requestID, remote, "ui/query", "vault.ui.query", "task_too_large", map[string]any{
			"budget": "max_task_chars",
			"max":    d.cfg.MaxTaskChars,
		})
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{
			"error": "task_too_large",
		})
		return
	}

	response, status, code := d.executeVaultUIQuery(r.Context(), task, req.Collection)
	if status != http.StatusOK {
		d.auditDeny(r.Context(), requestID, remote, "ui/query", "vault.ui.query", code, map[string]any{
			"trace_steps": len(response.Trace),
		})
		payload := map[string]any{
			"error": code,
			"trace": response.Trace,
		}
		if strings.TrimSpace(response.FinalAnswer) != "" {
			payload["final_response"] = response.FinalAnswer
		}
		if strings.TrimSpace(response.Plan.PlanID) != "" {
			payload["plan"] = response.Plan
		}
		writeJSON(w, status, payload)
		return
	}
	d.auditAllow(r.Context(), requestID, remote, "ui/query", "vault.ui.query", "ok_vault_ui_query", map[string]any{
		"trace_steps":    len(response.Trace),
		"llm_used":       response.LLMUsed,
		"search_results": len(response.SearchHits),
		"snippet_count":  len(response.Snippets),
	})
	writeJSON(w, http.StatusOK, response)
}

func (d *Daemon) executeVaultUIQuery(ctx context.Context, task, collection string) (vaultUIQueryResponse, int, string) {
	normalizedCollection := normalizeCollectionName(collection)
	in := plannerInput{
		Task:              task,
		Collection:        normalizedCollection,
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
	fallbackPlan := buildDeterministicPlan(in)
	response := vaultUIQueryResponse{
		Task:       task,
		Collection: normalizedCollection,
		Plan:       fallbackPlan,
		Trace:      make([]vaultUIQueryTraceStep, 0, 8),
	}

	runTool := func(name string, args map[string]any) (any, *rpcError) {
		started := time.Now()
		rawArgs, err := json.Marshal(args)
		if err != nil {
			response.Trace = append(response.Trace, vaultUIQueryTraceStep{
				Stage:   "mcp_tool_call",
				Name:    name,
				Message: "argument_encode_failed",
				Error:   redact.String(err.Error()),
			})
			return nil, &rpcError{Code: rpcErrInternal, Message: "internal_error"}
		}
		res, rpcErr, reason, meta := d.callTool(name, rawArgs)
		step := vaultUIQueryTraceStep{
			Stage:      "mcp_tool_call",
			Name:       name,
			Arguments:  sanitizeTraceAny(args),
			DurationMS: time.Since(started).Milliseconds(),
			Message:    sanitizeOneLine(reason, "", 256),
		}
		if rpcErr != nil {
			step.Error = fmt.Sprintf("%s (%d)", sanitizeOneLine(rpcErr.Message, "tool_failed", 256), rpcErr.Code)
			if meta != nil {
				step.Result = sanitizeTraceAny(meta)
			}
			response.Trace = append(response.Trace, step)
			return nil, rpcErr
		}
		step.Result = sanitizeTraceAny(res)
		if meta != nil {
			metaMsg := fmt.Sprintf("meta=%v", sanitizeTraceAny(meta))
			if strings.TrimSpace(step.Message) == "" {
				step.Message = metaMsg
			} else {
				step.Message = step.Message + " | " + metaMsg
			}
		}
		response.Trace = append(response.Trace, step)
		return res, nil
	}

	planRaw, rpcErr := runTool("vault.request", map[string]any{
		"task":       task,
		"collection": normalizedCollection,
	})
	if rpcErr != nil {
		status, code := uiErrorForRPC(rpcErr)
		response.FinalAnswer = "Planning failed."
		return response, status, code
	}
	if err := decodeAny(planRaw, &response.Plan); err != nil {
		response.Plan = fallbackPlan
	}

	searchArgs := querySearchArgsFromPlan(response.Plan, task, normalizedCollection, d.cfg.MaxSearchResults, d.cfg.MaxTaskChars)
	searchRaw, rpcErr := runTool("vault.search", searchArgs)
	if rpcErr != nil {
		status, code := uiErrorForRPC(rpcErr)
		if code == "vault_locked" {
			response.FinalAnswer = "Vault is locked. Unlock the session to query data."
		}
		return response, status, code
	}

	var searchPayload struct {
		Results []searchHit `json:"results"`
	}
	if err := decodeAny(searchRaw, &searchPayload); err == nil {
		response.SearchHits = searchPayload.Results
	}

	ids := queryReadTargetsFromHits(response.SearchHits, d.cfg.MaxSnippetObjects)
	if len(ids) == 0 {
		response.FinalAnswer = "No matching Vault records found for this prompt."
		response.Trace = append(response.Trace, vaultUIQueryTraceStep{
			Stage:   "final_response",
			Message: "no_matches",
			Result:  map[string]any{"final_response": response.FinalAnswer},
		})
		return response, http.StatusOK, ""
	}

	readArgs := queryReadArgsFromPlan(response.Plan, task, ids, d.cfg.MaxSnippetBytes, d.cfg.MaxSnippetChars)
	readArgs["task_window_id"] = nonEmpty(response.Plan.PlanID, "ui_query")
	readRaw, rpcErr := runTool("vault.read_snippets", readArgs)
	if rpcErr != nil {
		status, code := uiErrorForRPC(rpcErr)
		return response, status, code
	}

	var readPayload struct {
		Snippets []snippetHit `json:"snippets"`
	}
	if err := decodeAny(readRaw, &readPayload); err == nil {
		response.Snippets = readPayload.Snippets
	}
	if !hasReadableSnippets(response.Snippets) && len(response.SearchHits) > len(ids) {
		maxRetries := 2
		cursor := len(ids)
		for retry := 0; retry < maxRetries && cursor < len(response.SearchHits); retry++ {
			nextIDs := queryReadTargetsFromHits(response.SearchHits[cursor:], d.cfg.MaxSnippetObjects)
			if len(nextIDs) == 0 {
				break
			}
			cursor += len(nextIDs)

			retryArgs := queryReadArgsFromPlan(response.Plan, task, nextIDs, d.cfg.MaxSnippetBytes, d.cfg.MaxSnippetChars)
			retryArgs["task_window_id"] = nonEmpty(response.Plan.PlanID, "ui_query")
			retryRaw, retryErr := runTool("vault.read_snippets", retryArgs)
			if retryErr != nil {
				continue
			}
			var retryPayload struct {
				Snippets []snippetHit `json:"snippets"`
			}
			if err := decodeAny(retryRaw, &retryPayload); err != nil {
				continue
			}
			if hasReadableSnippets(retryPayload.Snippets) {
				response.Snippets = retryPayload.Snippets
				break
			}
		}
	}
	response.Snippets = prioritizeSnippetsForTask(response.Task, response.Snippets, 3)

	answer, llmUsed := d.composeVaultQueryAnswer(ctx, &response)
	response.FinalAnswer = answer
	response.LLMUsed = llmUsed
	response.Trace = append(response.Trace, vaultUIQueryTraceStep{
		Stage:   "final_response",
		Message: "response_ready",
		Result:  map[string]any{"final_response": truncateUTF8ByBytes(response.FinalAnswer, 12000)},
	})
	return response, http.StatusOK, ""
}

func (d *Daemon) composeVaultQueryAnswer(ctx context.Context, response *vaultUIQueryResponse) (answer string, llmUsed bool) {
	if response == nil {
		return "No response context available.", false
	}
	if d.broker != nil {
		if b, ok := d.broker.(traceableAnswerBroker); ok {
			answerTimeout := 20 * time.Second
			if d.cfg.BrokerTimeout > 0 && d.cfg.BrokerTimeout < answerTimeout {
				answerTimeout = d.cfg.BrokerTimeout
			}
			if d.cfg.WriteTimeout > 0 {
				ceiling := d.cfg.WriteTimeout - (5 * time.Second)
				if ceiling > 0 && ceiling < answerTimeout {
					answerTimeout = ceiling
				}
			}
			if answerTimeout <= 0 {
				answerTimeout = 10 * time.Second
			}
			answerCtx, cancel := context.WithTimeout(ctx, answerTimeout)
			defer cancel()
			out, err := b.AnswerWithTrace(answerCtx, brokerAnswerInput{
				Task:          response.Task,
				Collection:    response.Collection,
				Plan:          response.Plan,
				SearchResults: response.SearchHits,
				Snippets:      response.Snippets,
			})
			response.Trace = append(response.Trace, vaultUIQueryTraceStep{
				Stage:   "llm_call",
				Name:    "broker.answer",
				Message: "local_llm_request",
				Result:  sanitizeTraceAny(out.Trace),
			})
			if err == nil && strings.TrimSpace(out.Response) != "" {
				response.Trace = append(response.Trace, vaultUIQueryTraceStep{
					Stage:   "llm_response",
					Name:    "broker.answer",
					Message: "local_llm_response",
					Result: map[string]any{
						"response": truncateUTF8ByBytes(out.Response, 12000),
					},
				})
				return strings.TrimSpace(out.Response), true
			}
			response.Trace = append(response.Trace, vaultUIQueryTraceStep{
				Stage:   "llm_response",
				Name:    "broker.answer",
				Message: "local_llm_failed",
				Error:   sanitizeOneLine(fmt.Sprintf("%v", err), "local_llm_failed", 512),
			})
		}
	}
	return deterministicQueryAnswer(response.Task, response.SearchHits, response.Snippets), false
}

func deterministicQueryAnswer(task string, hits []searchHit, snippets []snippetHit) string {
	if len(snippets) == 0 {
		if len(hits) == 0 {
			return "No matching Vault records found for this prompt."
		}
		return "Matching items were found, but no readable snippets were returned within current budgets."
	}
	parts := make([]string, 0, minInt(len(snippets), 3)+1)
	parts = append(parts, "Evidence from Vault snippets:")
	maxSnippets := minInt(len(snippets), 3)
	readableCount := 0
	for i := 0; i < maxSnippets; i++ {
		snippet := sanitizeOneLine(snippets[i].Snippet, "", 360)
		if snippet == "" {
			continue
		}
		if snippet == snippetNonTextPlaceholder {
			continue
		}
		parts = append(parts, fmt.Sprintf("%d) [%s] %s", i+1, snippets[i].Collection, snippet))
		readableCount++
	}
	if readableCount == 0 {
		if len(hits) == 0 {
			return "No matching Vault records found for this prompt."
		}
		return "Matching items were found, but retrieved snippets were non-text or unreadable within current budgets."
	}
	parts = append(parts, fmt.Sprintf("Prompt: %s", sanitizeOneLine(task, "", 220)))
	return strings.Join(parts, "\n")
}

func querySearchArgsFromPlan(plan deterministicPlan, task, requestedCollection string, maxResults, maxTaskChars int) map[string]any {
	limit := minInt(8, maxResults)
	args := map[string]any{
		"query": sanitizeOneLine(task, "", maxTaskChars),
		"limit": limit,
	}
	if strings.TrimSpace(requestedCollection) != "" {
		args["collection"] = normalizeCollectionName(requestedCollection)
	}
	for _, call := range plan.RecommendedToolCalls {
		if strings.TrimSpace(call.Name) != "vault.search" {
			continue
		}
		query := sanitizeOneLine(getStringArg(call.Args, "query"), task, maxTaskChars)
		if query != "" {
			args["query"] = query
		}
		collection := normalizeCollectionName(getStringArg(call.Args, "collection"))
		if collection != "" {
			args["collection"] = collection
		}
		limit = clampInt(getIntArg(call.Args, "limit", limit), 1, maxResults)
		minUIQueryLimit := minInt(8, maxResults)
		if limit < minUIQueryLimit {
			limit = minUIQueryLimit
		}
		args["limit"] = limit
		break
	}
	if strings.TrimSpace(requestedCollection) != "" {
		args["collection"] = normalizeCollectionName(requestedCollection)
	}
	return args
}

func queryReadArgsFromPlan(plan deterministicPlan, task string, ids []string, maxBytes, maxChars int) map[string]any {
	minBytes := minInt(maxBytes, 2048)
	minChars := minInt(maxChars, 420)
	args := map[string]any{
		"ids":                   ids,
		"query":                 sanitizeOneLine(task, "", maxBytes),
		"max_bytes":             maxBytes,
		"max_chars_per_snippet": maxChars,
	}
	for _, call := range plan.RecommendedToolCalls {
		if strings.TrimSpace(call.Name) != "vault.read_snippets" {
			continue
		}
		query := sanitizeOneLine(getStringArg(call.Args, "query"), task, maxBytes)
		if query != "" {
			args["query"] = query
		}
		args["max_bytes"] = clampInt(getIntArg(call.Args, "max_bytes", maxBytes), minBytes, maxBytes)
		args["max_chars_per_snippet"] = clampInt(getIntArg(call.Args, "max_chars_per_snippet", maxChars), minChars, maxChars)
		break
	}
	return args
}

func queryReadTargetsFromHits(hits []searchHit, max int) []string {
	if max <= 0 {
		return nil
	}
	out := make([]string, 0, minInt(len(hits), max))
	seen := make(map[string]struct{}, len(hits)*3)
	for _, h := range hits {
		for _, chunkID := range h.EvidenceChunkIDs {
			chunkID = strings.TrimSpace(chunkID)
			if chunkID == "" {
				continue
			}
			if _, exists := seen[chunkID]; exists {
				continue
			}
			seen[chunkID] = struct{}{}
			out = append(out, chunkID)
			if len(out) >= max {
				return out
			}
		}
	}
	for _, h := range hits {
		id := strings.TrimSpace(h.ID)
		if id == "" {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
		if len(out) >= max {
			break
		}
	}
	return out
}

func hasReadableSnippets(snippets []snippetHit) bool {
	for _, snippet := range snippets {
		if strings.TrimSpace(snippet.Snippet) == "" {
			continue
		}
		if strings.TrimSpace(snippet.Snippet) == snippetNonTextPlaceholder {
			continue
		}
		return true
	}
	return false
}

func prioritizeSnippetsForTask(task string, snippets []snippetHit, max int) []snippetHit {
	if len(snippets) == 0 || max <= 0 {
		return snippets
	}
	hasReadableNonNoise := false
	for _, hit := range snippets {
		snippet := strings.TrimSpace(hit.Snippet)
		if snippet == "" || snippet == snippetNonTextPlaceholder {
			continue
		}
		if looksLikePDFOperatorNoise(snippet) {
			continue
		}
		hasReadableNonNoise = true
		break
	}
	type ranked struct {
		hit   snippetHit
		score float64
	}
	rows := make([]ranked, 0, len(snippets))
	for _, hit := range snippets {
		score := scoreSnippetForQuery(hit.Snippet, task)
		if strings.TrimSpace(hit.Snippet) == snippetNonTextPlaceholder {
			score -= 100
		}
		rows = append(rows, ranked{hit: hit, score: score})
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].score != rows[j].score {
			return rows[i].score > rows[j].score
		}
		return rows[i].hit.ID < rows[j].hit.ID
	})
	bestScore := rows[0].score
	minScore := 0.15
	if bestScore > 0.5 {
		minScore = bestScore * 0.35
	}
	out := make([]snippetHit, 0, minInt(max, len(rows)))
	for _, row := range rows {
		if len(out) >= max {
			break
		}
		if hasReadableNonNoise && looksLikePDFOperatorNoise(row.hit.Snippet) {
			continue
		}
		if row.score < minScore && len(out) > 0 {
			continue
		}
		if len(out) > 0 && scoreOverlap(out[len(out)-1].Snippet, row.hit.Snippet) >= 0.95 {
			continue
		}
		out = append(out, row.hit)
	}
	if len(out) == 0 {
		return snippets
	}
	return out
}

func sanitizeTraceAny(v any) any {
	normalized, err := normalizeAny(v)
	if err != nil {
		return map[string]any{"error": "trace_normalization_failed"}
	}
	return sanitizeTraceAnyNormalized(normalized)
}

func sanitizeTraceAnyNormalized(v any) any {
	switch val := v.(type) {
	case string:
		return truncateUTF8ByBytes(val, 6000)
	case []any:
		out := make([]any, 0, len(val))
		for _, item := range val {
			out = append(out, sanitizeTraceAnyNormalized(item))
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(val))
		for key, item := range val {
			out[key] = sanitizeTraceAnyNormalized(item)
		}
		return out
	default:
		return val
	}
}

func normalizeAny(v any) (any, error) {
	if v == nil {
		return nil, nil
	}
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func decodeAny(raw any, out any) error {
	data, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

func (d *Daemon) authorizeVaultUIAPI(w http.ResponseWriter, r *http.Request, tool string) (reqID, remote string, ok bool) {
	reqID = requestID(r)
	remote = strings.TrimSpace(r.RemoteAddr)

	if !isLoopbackRemoteAddr(remote) {
		d.auditDeny(r.Context(), reqID, remote, "ui", tool, "non_loopback_remote", nil)
		http.Error(w, "forbidden: local-only endpoint", http.StatusForbidden)
		return reqID, remote, false
	}
	if !d.authorized(r) {
		d.auditDeny(r.Context(), reqID, remote, "ui", tool, "auth_failed", nil)
		w.Header().Set("WWW-Authenticate", `Bearer realm="strajad"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return reqID, remote, false
	}
	return reqID, remote, true
}

func (d *Daemon) vaultUIStatePayload() map[string]any {
	unlocked := d.store.IsUnlocked()
	presence := d.store.HasPresenceAccess()
	annInit := d.store.ANNInitStatus()

	collectionCount := 0
	accessibleCollections := 0
	pendingObjects := 0
	failedObjects := 0
	if unlocked {
		collections, err := d.store.ListCollections()
		if err == nil {
			collectionCount = len(collections)
			for _, col := range collections {
				if col.Accessible {
					accessibleCollections++
				}
				pendingObjects += col.Pending
				failedObjects += col.Failed
			}
		}
	}

	return map[string]any{
		"unlocked":                 unlocked,
		"presence_access":          presence,
		"zero_access_by_default":   !unlocked,
		"collection_count":         collectionCount,
		"accessible_collections":   accessibleCollections,
		"indexing_pending_objects": pendingObjects,
		"indexing_failed_objects":  failedObjects,
		"broker_enabled":           d.cfg.BrokerEnabled,
		"broker_provider":          d.cfg.BrokerProvider,
		"broker_model":             d.cfg.BrokerModel,
		"embedding_enabled":        d.cfg.EmbeddingEnabled,
		"embedding_provider":       d.cfg.EmbeddingProvider,
		"embedding_model":          d.cfg.EmbeddingModel,
		"reranker_enabled":         d.cfg.RerankerEnabled,
		"reranker_provider":        d.cfg.RerankerProvider,
		"reranker_model":           d.cfg.RerankerModel,
		"ann_provider":             d.cfg.ANNProvider,
		"ann_version":              d.store.retrieval.indexMeta.ANNVersion,
		"ann_init_mode":            annInit.Mode,
		"ann_init_chunks":          annInit.ChunkCount,
		"ann_init_at":              annInit.At,
		"budgets": map[string]any{
			"max_task_chars":        d.cfg.MaxTaskChars,
			"max_search_results":    d.cfg.MaxSearchResults,
			"max_snippet_objects":   d.cfg.MaxSnippetObjects,
			"max_snippet_bytes":     d.cfg.MaxSnippetBytes,
			"max_task_window_bytes": d.cfg.MaxTaskWindowBytes,
			"max_read_rpm":          d.cfg.MaxReadRPM,
			"max_snippet_chars":     d.cfg.MaxSnippetChars,
			"max_write_chars":       d.cfg.MaxWriteChars,
			"max_ingest_bytes":      d.cfg.MaxIngestBytes,
			"max_audit_records":     d.cfg.MaxAuditRecords,
		},
	}
}

func decodeVaultUIBody(r io.Reader, maxBytes int64, out any) error {
	if r == nil {
		return errors.New("empty request body")
	}
	if maxBytes <= 0 {
		maxBytes = 1 * 1024 * 1024
	}
	dec := json.NewDecoder(io.LimitReader(r, maxBytes))
	if err := dec.Decode(out); err != nil {
		return err
	}
	return nil
}

func parseUIInt(raw string, fallback int) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return n
}

func uiErrorForRPC(err *rpcError) (status int, code string) {
	if err == nil {
		return http.StatusInternalServerError, "internal_error"
	}
	message := sanitizeOneLine(err.Message, "internal_error", 128)
	switch err.Code {
	case rpcErrInvalidParams:
		if message == "" {
			message = "invalid_request"
		}
		return http.StatusBadRequest, message
	case rpcErrBudgetExceeded:
		if message == "" {
			message = "budget_exceeded"
		}
		return http.StatusRequestEntityTooLarge, message
	case rpcErrVaultLocked:
		return http.StatusLocked, "vault_locked"
	case rpcErrUnlockFailed:
		return http.StatusUnauthorized, "unlock_failed"
	case rpcErrPolicyDenied:
		if message == "" {
			message = "policy_denied"
		}
		return http.StatusForbidden, message
	case rpcErrNotFound:
		return http.StatusNotFound, "not_found"
	default:
		return http.StatusInternalServerError, "internal_error"
	}
}

func uiErrorForStore(err error) (status int, code string) {
	switch {
	case errors.Is(err, errVaultLocked):
		return http.StatusLocked, "vault_locked"
	case errors.Is(err, errUnlockPassphraseRequired):
		return http.StatusBadRequest, "passphrase_required"
	case errors.Is(err, errUnlockPassphraseInvalid):
		return http.StatusUnauthorized, "unlock_failed"
	case errors.Is(err, errCollectionNotFound), errors.Is(err, errObjectNotFound), errors.Is(err, errApprovalNotFound):
		return http.StatusNotFound, "not_found"
	case errors.Is(err, errCollectionAccessDenied):
		return http.StatusForbidden, "collection_policy_denied"
	case errors.Is(err, errInvalidCollectionName), errors.Is(err, errInvalidCollectionTier), errors.Is(err, errCollectionAlreadyExists), errors.Is(err, errInvalidBase64Content), errors.Is(err, errUnsupportedContentType), errors.Is(err, errExtractedContentEmpty), errors.Is(err, errInvalidConnectorProvider), errors.Is(err, errConnectorTokenRequired), errors.Is(err, errInvalidApprovalAction):
		return http.StatusBadRequest, "invalid_request"
	case errors.Is(err, errEgressCoverageExceeded), errors.Is(err, errEgressOverlapDetected):
		return http.StatusForbidden, "egress_policy_denied"
	default:
		return http.StatusInternalServerError, "internal_error"
	}
}

func uiErrorForDrive(err error) (status int, code string) {
	if err == nil {
		return http.StatusInternalServerError, "internal_error"
	}
	if status, code := uiErrorForStore(err); code != "internal_error" {
		return status, code
	}
	switch {
	case errors.Is(err, errGoogleOAuthNotConfigured):
		return http.StatusBadRequest, "google_oauth_not_configured"
	case errors.Is(err, errOAuthStateInvalid):
		return http.StatusBadRequest, "oauth_state_invalid"
	case errors.Is(err, errDriveTokenUnavailable), errors.Is(err, errDriveTokenMalformed):
		return http.StatusBadRequest, "drive_not_connected"
	case errors.Is(err, errDriveImportItemLimitExceeded):
		return http.StatusRequestEntityTooLarge, "drive_import_item_limit_exceeded"
	case errors.Is(err, errDriveFileTooLarge):
		return http.StatusRequestEntityTooLarge, "drive_file_too_large"
	case errors.Is(err, errDriveFolderNotImportable):
		return http.StatusBadRequest, "drive_folder_not_importable"
	case errors.Is(err, errDriveAPIRequestFailed):
		return http.StatusBadGateway, "drive_api_request_failed"
	default:
		return http.StatusInternalServerError, "internal_error"
	}
}

func uiErrorForBroker(err error) (status int, code string) {
	if err == nil {
		return http.StatusInternalServerError, "internal_error"
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	switch {
	case errors.Is(err, errUnsupportedBrokerProvider), strings.Contains(msg, "unsupported broker provider"):
		return http.StatusBadRequest, "unsupported_broker_provider"
	case strings.Contains(msg, "required"):
		return http.StatusBadRequest, "invalid_broker_config"
	case strings.Contains(msg, "failed"), strings.Contains(msg, "status="), strings.Contains(msg, "connection"), strings.Contains(msg, "refused"), strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline"):
		return http.StatusBadGateway, "broker_unavailable"
	default:
		return http.StatusInternalServerError, "internal_error"
	}
}

func brokerErrorHint(err error, cfg Config) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(strings.TrimSpace(err.Error()))
	if strings.Contains(msg, "connection refused") || strings.Contains(msg, "couldn't connect") || strings.Contains(msg, "no such host") || strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline") {
		endpoint := strings.TrimSpace(cfg.BrokerEndpoint)
		if endpoint == "" {
			endpoint = "http://127.0.0.1:11434"
		}
		return "Start Ollama and ensure it is reachable at " + endpoint + ". If Ollama is not installed, install it first."
	}
	if strings.Contains(msg, "unsupported broker provider") {
		return "Set STRAJAD_BROKER_PROVIDER=ollama (or a supported provider) and restart strajad."
	}
	if strings.Contains(msg, "broker model is required") {
		return "Set STRAJAD_BROKER_MODEL (for example phi4-mini:3.8b) and restart strajad."
	}
	if strings.Contains(msg, "broker endpoint is required") {
		return "Set STRAJAD_BROKER_ENDPOINT (for example http://127.0.0.1:11434) and restart strajad."
	}
	return ""
}

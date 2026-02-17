package strajad

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/straja-ai/straja/internal/redact"
)

const (
	driveOAuthScope       = "https://www.googleapis.com/auth/drive.readonly"
	driveOAuthStateTTL    = 10 * time.Minute
	driveImportItemLimit  = 50
	drivePageSizeDefault  = 50
	drivePageSizeHardCeil = 100
)

var (
	errGoogleOAuthNotConfigured     = errors.New("google oauth is not configured")
	errOAuthStateInvalid            = errors.New("oauth state is invalid")
	errDriveTokenUnavailable        = errors.New("drive token is unavailable")
	errDriveTokenMalformed          = errors.New("drive token is malformed")
	errDriveAPIRequestFailed        = errors.New("drive api request failed")
	errDriveImportItemLimitExceeded = errors.New("drive import item limit exceeded")
	errDriveFileTooLarge            = errors.New("drive file exceeds max ingest bytes")
	errDriveFolderNotImportable     = errors.New("drive folder cannot be downloaded directly")
)

type driveOAuthToken struct {
	AccessToken  string    `json:"access_token,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	Scope        string    `json:"scope,omitempty"`
	Expiry       time.Time `json:"expiry,omitempty"`
}

type driveRemoteItem struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	MIMEType     string `json:"mime_type"`
	Size         int64  `json:"size,omitempty"`
	ModifiedTime string `json:"modified_time,omitempty"`
	IsFolder     bool   `json:"is_folder"`
}

type driveImportRecord struct {
	ID                 string `json:"id,omitempty"`
	Name               string `json:"name"`
	Collection         string `json:"collection,omitempty"`
	SourceID           string `json:"source_id,omitempty"`
	SourceMIMEType     string `json:"source_mime_type,omitempty"`
	ExtractedChars     int    `json:"extracted_chars,omitempty"`
	ExtractedTruncated bool   `json:"extracted_truncated,omitempty"`
	Error              string `json:"error,omitempty"`
}

func (d *Daemon) driveOAuthConfigured() bool {
	if d == nil {
		return false
	}
	return strings.TrimSpace(d.cfg.GoogleOAuthClientID) != "" &&
		strings.TrimSpace(d.cfg.GoogleOAuthClientSecret) != "" &&
		strings.TrimSpace(d.cfg.GoogleOAuthRedirectURL) != ""
}

func (d *Daemon) newOAuthState() (string, error) {
	raw := strings.TrimPrefix(randomID(), "req_")
	d.oauthMu.Lock()
	defer d.oauthMu.Unlock()
	now := time.Now().UTC()
	for state, createdAt := range d.oauthState {
		if now.Sub(createdAt) > driveOAuthStateTTL {
			delete(d.oauthState, state)
		}
	}
	d.oauthState[raw] = now
	return raw, nil
}

func (d *Daemon) consumeOAuthState(state string) bool {
	state = strings.TrimSpace(state)
	if state == "" {
		return false
	}
	d.oauthMu.Lock()
	defer d.oauthMu.Unlock()
	createdAt, ok := d.oauthState[state]
	if !ok {
		return false
	}
	delete(d.oauthState, state)
	return time.Since(createdAt) <= driveOAuthStateTTL
}

func (d *Daemon) buildDriveOAuthURL(state string) (string, error) {
	if !d.driveOAuthConfigured() {
		return "", errGoogleOAuthNotConfigured
	}
	base := strings.TrimSpace(d.cfg.GoogleOAuthAuthURL)
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("client_id", d.cfg.GoogleOAuthClientID)
	q.Set("redirect_uri", d.cfg.GoogleOAuthRedirectURL)
	q.Set("response_type", "code")
	q.Set("scope", driveOAuthScope)
	q.Set("access_type", "offline")
	q.Set("prompt", "consent")
	q.Set("include_granted_scopes", "true")
	q.Set("state", strings.TrimSpace(state))
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (d *Daemon) exchangeDriveOAuthCode(ctx context.Context, code string) (driveOAuthToken, error) {
	if !d.driveOAuthConfigured() {
		return driveOAuthToken{}, errGoogleOAuthNotConfigured
	}
	form := url.Values{}
	form.Set("code", strings.TrimSpace(code))
	form.Set("client_id", d.cfg.GoogleOAuthClientID)
	form.Set("client_secret", d.cfg.GoogleOAuthClientSecret)
	form.Set("redirect_uri", d.cfg.GoogleOAuthRedirectURL)
	form.Set("grant_type", "authorization_code")

	out, err := d.oauthTokenRequest(ctx, form)
	if err != nil {
		return driveOAuthToken{}, err
	}
	if strings.TrimSpace(out.AccessToken) == "" {
		return driveOAuthToken{}, fmt.Errorf("%w: missing access token", errDriveAPIRequestFailed)
	}
	return out, nil
}

func (d *Daemon) refreshDriveOAuthToken(ctx context.Context, refreshToken string) (driveOAuthToken, error) {
	if !d.driveOAuthConfigured() {
		return driveOAuthToken{}, errGoogleOAuthNotConfigured
	}
	refreshToken = strings.TrimSpace(refreshToken)
	if refreshToken == "" {
		return driveOAuthToken{}, errDriveTokenUnavailable
	}
	form := url.Values{}
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", d.cfg.GoogleOAuthClientID)
	form.Set("client_secret", d.cfg.GoogleOAuthClientSecret)
	form.Set("grant_type", "refresh_token")

	out, err := d.oauthTokenRequest(ctx, form)
	if err != nil {
		return driveOAuthToken{}, err
	}
	if strings.TrimSpace(out.RefreshToken) == "" {
		out.RefreshToken = refreshToken
	}
	if strings.TrimSpace(out.AccessToken) == "" {
		return driveOAuthToken{}, fmt.Errorf("%w: missing access token", errDriveAPIRequestFailed)
	}
	return out, nil
}

func (d *Daemon) oauthTokenRequest(ctx context.Context, form url.Values) (driveOAuthToken, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSpace(d.cfg.GoogleOAuthTokenURL), strings.NewReader(form.Encode()))
	if err != nil {
		return driveOAuthToken{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return driveOAuthToken{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1*1024*1024))
	if err != nil {
		return driveOAuthToken{}, err
	}
	var payload struct {
		AccessToken      string `json:"access_token"`
		RefreshToken     string `json:"refresh_token"`
		TokenType        string `json:"token_type"`
		Scope            string `json:"scope"`
		ExpiresIn        int    `json:"expires_in"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return driveOAuthToken{}, fmt.Errorf("%w: invalid token response", errDriveAPIRequestFailed)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		reason := strings.TrimSpace(payload.ErrorDescription)
		if reason == "" {
			reason = strings.TrimSpace(payload.Error)
		}
		if reason == "" {
			reason = resp.Status
		}
		return driveOAuthToken{}, fmt.Errorf("%w: %s", errDriveAPIRequestFailed, reason)
	}
	expiry := time.Time{}
	if payload.ExpiresIn > 0 {
		expiry = time.Now().UTC().Add(time.Duration(payload.ExpiresIn) * time.Second)
	}
	return driveOAuthToken{
		AccessToken:  strings.TrimSpace(payload.AccessToken),
		RefreshToken: strings.TrimSpace(payload.RefreshToken),
		TokenType:    strings.TrimSpace(payload.TokenType),
		Scope:        strings.TrimSpace(payload.Scope),
		Expiry:       expiry,
	}, nil
}

func serializeDriveOAuthToken(token driveOAuthToken) (string, error) {
	b, err := json.Marshal(token)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func parseDriveOAuthToken(raw string) (driveOAuthToken, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return driveOAuthToken{}, errDriveTokenUnavailable
	}
	if strings.HasPrefix(raw, "{") {
		var tok driveOAuthToken
		if err := json.Unmarshal([]byte(raw), &tok); err != nil {
			return driveOAuthToken{}, errDriveTokenMalformed
		}
		if strings.TrimSpace(tok.AccessToken) == "" && strings.TrimSpace(tok.RefreshToken) == "" {
			return driveOAuthToken{}, errDriveTokenMalformed
		}
		return tok, nil
	}
	return driveOAuthToken{AccessToken: raw}, nil
}

func (d *Daemon) driveToken(ctx context.Context) (driveOAuthToken, error) {
	raw, err := d.store.GetConnectorToken("drive")
	if err != nil {
		return driveOAuthToken{}, err
	}
	token, err := parseDriveOAuthToken(raw)
	if err != nil {
		return driveOAuthToken{}, err
	}

	if strings.TrimSpace(token.AccessToken) != "" {
		if token.Expiry.IsZero() || token.Expiry.After(time.Now().UTC().Add(45*time.Second)) {
			return token, nil
		}
	}
	if strings.TrimSpace(token.RefreshToken) == "" {
		if strings.TrimSpace(token.AccessToken) != "" {
			return token, nil
		}
		return driveOAuthToken{}, errDriveTokenUnavailable
	}

	refreshed, err := d.refreshDriveOAuthToken(ctx, token.RefreshToken)
	if err != nil {
		return driveOAuthToken{}, err
	}
	if strings.TrimSpace(refreshed.RefreshToken) == "" {
		refreshed.RefreshToken = token.RefreshToken
	}
	serialized, err := serializeDriveOAuthToken(refreshed)
	if err != nil {
		return driveOAuthToken{}, err
	}
	if _, err := d.store.SetConnectorToken("drive", serialized); err != nil {
		return driveOAuthToken{}, err
	}
	return refreshed, nil
}

func (d *Daemon) driveListFolder(ctx context.Context, folderID, pageToken string, pageSize int) ([]driveRemoteItem, string, error) {
	if pageSize <= 0 {
		pageSize = drivePageSizeDefault
	}
	if pageSize > drivePageSizeHardCeil {
		pageSize = drivePageSizeHardCeil
	}
	folderID = strings.TrimSpace(folderID)
	if folderID == "" {
		folderID = "root"
	}
	token, err := d.driveToken(ctx)
	if err != nil {
		return nil, "", err
	}
	endpoint := strings.TrimRight(strings.TrimSpace(d.cfg.GoogleDriveAPIBaseURL), "/") + "/files"
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, "", err
	}
	q := u.Query()
	q.Set("fields", "nextPageToken,files(id,name,mimeType,size,modifiedTime)")
	q.Set("pageSize", strconv.Itoa(pageSize))
	q.Set("q", fmt.Sprintf("trashed=false and '%s' in parents", escapeDriveQueryLiteral(folderID)))
	q.Set("orderBy", "folder,name,modifiedTime desc")
	if strings.TrimSpace(pageToken) != "" {
		q.Set("pageToken", strings.TrimSpace(pageToken))
	}
	u.RawQuery = q.Encode()

	body, status, err := d.driveRequest(ctx, token, http.MethodGet, u.String(), nil, "")
	if err != nil {
		return nil, "", err
	}
	if status < 200 || status >= 300 {
		return nil, "", fmt.Errorf("%w: %d", errDriveAPIRequestFailed, status)
	}

	var payload struct {
		NextPageToken string `json:"nextPageToken"`
		Files         []struct {
			ID           string `json:"id"`
			Name         string `json:"name"`
			MIMEType     string `json:"mimeType"`
			Size         string `json:"size"`
			ModifiedTime string `json:"modifiedTime"`
		} `json:"files"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, "", err
	}
	items := make([]driveRemoteItem, 0, len(payload.Files))
	for _, file := range payload.Files {
		size := int64(0)
		if n, err := strconv.ParseInt(strings.TrimSpace(file.Size), 10, 64); err == nil {
			size = n
		}
		mime := strings.TrimSpace(file.MIMEType)
		items = append(items, driveRemoteItem{
			ID:           strings.TrimSpace(file.ID),
			Name:         strings.TrimSpace(file.Name),
			MIMEType:     mime,
			Size:         size,
			ModifiedTime: strings.TrimSpace(file.ModifiedTime),
			IsFolder:     mime == "application/vnd.google-apps.folder",
		})
	}
	return items, strings.TrimSpace(payload.NextPageToken), nil
}

func (d *Daemon) driveGetFile(ctx context.Context, id string) (driveRemoteItem, error) {
	token, err := d.driveToken(ctx)
	if err != nil {
		return driveRemoteItem{}, err
	}
	base := strings.TrimRight(strings.TrimSpace(d.cfg.GoogleDriveAPIBaseURL), "/")
	u, err := url.Parse(base + "/files/" + url.PathEscape(strings.TrimSpace(id)))
	if err != nil {
		return driveRemoteItem{}, err
	}
	q := u.Query()
	q.Set("fields", "id,name,mimeType,size,modifiedTime")
	u.RawQuery = q.Encode()
	body, status, err := d.driveRequest(ctx, token, http.MethodGet, u.String(), nil, "")
	if err != nil {
		return driveRemoteItem{}, err
	}
	if status < 200 || status >= 300 {
		return driveRemoteItem{}, fmt.Errorf("%w: %d", errDriveAPIRequestFailed, status)
	}
	var payload struct {
		ID           string `json:"id"`
		Name         string `json:"name"`
		MIMEType     string `json:"mimeType"`
		Size         string `json:"size"`
		ModifiedTime string `json:"modifiedTime"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return driveRemoteItem{}, err
	}
	size := int64(0)
	if n, err := strconv.ParseInt(strings.TrimSpace(payload.Size), 10, 64); err == nil {
		size = n
	}
	mime := strings.TrimSpace(payload.MIMEType)
	return driveRemoteItem{
		ID:           strings.TrimSpace(payload.ID),
		Name:         strings.TrimSpace(payload.Name),
		MIMEType:     mime,
		Size:         size,
		ModifiedTime: strings.TrimSpace(payload.ModifiedTime),
		IsFolder:     mime == "application/vnd.google-apps.folder",
	}, nil
}

func (d *Daemon) driveRequest(ctx context.Context, token driveOAuthToken, method, rawURL string, body []byte, contentType string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	if strings.TrimSpace(contentType) != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token.AccessToken))

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, int64(d.cfg.MaxIngestBytes)+1024))
	if err != nil {
		return nil, 0, err
	}
	return data, resp.StatusCode, nil
}

func (d *Daemon) driveDownloadFile(ctx context.Context, item driveRemoteItem) ([]byte, string, error) {
	token, err := d.driveToken(ctx)
	if err != nil {
		return nil, "", err
	}
	base := strings.TrimRight(strings.TrimSpace(d.cfg.GoogleDriveAPIBaseURL), "/")
	var rawURL string
	contentType := strings.TrimSpace(item.MIMEType)
	switch {
	case item.IsFolder:
		return nil, "", errDriveFolderNotImportable
	case strings.HasPrefix(item.MIMEType, "application/vnd.google-apps."):
		u, err := url.Parse(base + "/files/" + url.PathEscape(item.ID) + "/export")
		if err != nil {
			return nil, "", err
		}
		q := u.Query()
		q.Set("mimeType", "text/plain")
		u.RawQuery = q.Encode()
		rawURL = u.String()
		contentType = "text/plain"
	default:
		u, err := url.Parse(base + "/files/" + url.PathEscape(item.ID))
		if err != nil {
			return nil, "", err
		}
		q := u.Query()
		q.Set("alt", "media")
		u.RawQuery = q.Encode()
		rawURL = u.String()
	}

	body, status, err := d.driveRequest(ctx, token, http.MethodGet, rawURL, nil, "")
	if err != nil {
		return nil, "", err
	}
	if status < 200 || status >= 300 {
		return nil, "", fmt.Errorf("%w: %d", errDriveAPIRequestFailed, status)
	}
	if len(body) > d.cfg.MaxIngestBytes {
		return nil, "", errDriveFileTooLarge
	}
	return body, contentType, nil
}

func (d *Daemon) driveCollectFilesFromFolder(ctx context.Context, folderID string, limit int) ([]driveRemoteItem, error) {
	if limit <= 0 {
		limit = driveImportItemLimit
	}
	folderID = strings.TrimSpace(folderID)
	if folderID == "" {
		return nil, nil
	}
	visited := map[string]bool{}
	pending := []string{folderID}
	out := make([]driveRemoteItem, 0, minInt(limit, 10))
	for len(pending) > 0 {
		current := pending[0]
		pending = pending[1:]
		if visited[current] {
			continue
		}
		visited[current] = true

		pageToken := ""
		for {
			items, nextPage, err := d.driveListFolder(ctx, current, pageToken, drivePageSizeDefault)
			if err != nil {
				return nil, err
			}
			for _, item := range items {
				if item.IsFolder {
					pending = append(pending, item.ID)
					continue
				}
				out = append(out, item)
				if len(out) > limit {
					return nil, errDriveImportItemLimitExceeded
				}
			}
			if strings.TrimSpace(nextPage) == "" {
				break
			}
			pageToken = nextPage
		}
	}
	return out, nil
}

func (d *Daemon) driveImportSelection(ctx context.Context, collection string, fileIDs, folderIDs []string) ([]driveImportRecord, []driveImportRecord, error) {
	collection = normalizeCollectionName(collection)
	if collection == "" {
		collection = "work"
	}
	if err := d.store.EnsureCollectionAccess(collection); err != nil {
		return nil, nil, err
	}

	dedup := map[string]driveRemoteItem{}
	for _, raw := range fileIDs {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}
		meta, err := d.driveGetFile(ctx, id)
		if err != nil {
			return nil, nil, err
		}
		if meta.IsFolder {
			folderIDs = append(folderIDs, meta.ID)
			continue
		}
		dedup[meta.ID] = meta
	}
	for _, raw := range folderIDs {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}
		files, err := d.driveCollectFilesFromFolder(ctx, id, driveImportItemLimit)
		if err != nil {
			return nil, nil, err
		}
		for _, file := range files {
			dedup[file.ID] = file
			if len(dedup) > driveImportItemLimit {
				return nil, nil, errDriveImportItemLimitExceeded
			}
		}
	}

	targets := make([]driveRemoteItem, 0, len(dedup))
	for _, item := range dedup {
		targets = append(targets, item)
	}
	if len(targets) == 0 {
		return []driveImportRecord{}, []driveImportRecord{}, nil
	}

	imported := make([]driveImportRecord, 0, len(targets))
	failed := make([]driveImportRecord, 0)
	for _, item := range targets {
		content, contentType, err := d.driveDownloadFile(ctx, item)
		if err != nil {
			failed = append(failed, driveImportRecord{
				Name:           item.Name,
				SourceID:       item.ID,
				SourceMIMEType: item.MIMEType,
				Error:          redact.String(err.Error()),
			})
			continue
		}
		obj, extractedChars, extractedTruncated, err := d.store.Ingest(collection, item.Name, contentType, content, d.cfg.MaxExtractedChars)
		if err != nil {
			failed = append(failed, driveImportRecord{
				Name:           item.Name,
				SourceID:       item.ID,
				SourceMIMEType: item.MIMEType,
				Error:          redact.String(err.Error()),
			})
			continue
		}
		imported = append(imported, driveImportRecord{
			ID:                 obj.ID,
			Name:               obj.Title,
			Collection:         obj.Collection,
			SourceID:           item.ID,
			SourceMIMEType:     item.MIMEType,
			ExtractedChars:     extractedChars,
			ExtractedTruncated: extractedTruncated,
		})
	}
	return imported, failed, nil
}

func escapeDriveQueryLiteral(id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return id
	}
	return strings.ReplaceAll(id, "'", "\\'")
}

func driveCallbackResultHTML(success bool, message string) string {
	status := "failed"
	if success {
		status = "ok"
	}
	safe := strings.TrimSpace(message)
	if safe == "" {
		safe = status
	}
	return fmt.Sprintf(`<!doctype html><html><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>Drive OAuth %s</title></head><body><main><h1>Drive OAuth %s</h1><p>%s</p><p><a href="/vault?oauth=drive_%s">Return to Vault</a></p></main></body></html>`, status, status, safe, status)
}

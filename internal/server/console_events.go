package server

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/straja-ai/straja/internal/activation"
	"github.com/straja-ai/straja/internal/consoleauth"
)

const (
	consoleEventsDefaultLimit = 10
	consoleEventsMaxLimit     = 50
	consoleEventsChunkSize    = 256 * 1024
)

type consoleEventDecision struct {
	Action string                   `json:"action"`
	Hits   []activation.ActionEntry `json:"hits,omitempty"`
	Score  *float32                 `json:"score,omitempty"`
}

type consoleEventListItem struct {
	ID            string                `json:"id"`
	TS            string                `json:"ts"`
	RequestID     string                `json:"request_id"`
	ProjectID     string                `json:"project_id"`
	Provider      string                `json:"provider"`
	Route         string                `json:"route"`
	RequestFinal  *consoleEventDecision `json:"request_final,omitempty"`
	ResponseFinal *consoleEventDecision `json:"response_final,omitempty"`
	Summary       string                `json:"summary"`
	Activation    *activation.Event     `json:"activation,omitempty"`
}

type consoleEventsResponse struct {
	Items      []consoleEventListItem `json:"items"`
	NextCursor string                 `json:"next_cursor"`
	Totals     *consoleEventsTotals   `json:"totals,omitempty"`
}

type consoleEventsTotals struct {
	Total   int `json:"total"`
	Allow   int `json:"allow"`
	Redact  int `json:"redact"`
	Block   int `json:"block"`
	Warn    int `json:"warn"`
	Unknown int `json:"unknown"`
}

func (s *Server) handleConsoleEvents(w http.ResponseWriter, r *http.Request) {
	setConsoleRobotsHeader(w)

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	projectID, ok := s.verifyConsoleSession(r)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}

	path, ok := s.consoleActivationPath()
	if !ok {
		http.NotFound(w, r)
		return
	}

	limit := parseConsoleEventsLimit(r)
	rawCursor := strings.TrimSpace(r.URL.Query().Get("cursor"))
	items, nextCursor, err := readConsoleEvents(path, rawCursor, limit, projectID)
	if err != nil {
		if errors.Is(err, errInvalidCursor) {
			http.Error(w, "invalid cursor", http.StatusBadRequest)
			return
		}
		http.Error(w, "failed to read events", http.StatusInternalServerError)
		return
	}

	resp := consoleEventsResponse{
		Items:      items,
		NextCursor: nextCursor,
	}
	if shouldIncludeTotals(r) {
		totals, err := countConsoleEvents(path, projectID)
		if err != nil {
			http.Error(w, "failed to read events", http.StatusInternalServerError)
			return
		}
		resp.Totals = &totals
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) verifyConsoleSession(r *http.Request) (string, bool) {
	if !s.cfg.Console.Enabled {
		return "", false
	}
	cookieName := strings.TrimSpace(s.cfg.Console.SessionCookieName)
	if cookieName == "" {
		return "", false
	}
	cookie, err := r.Cookie(cookieName)
	if err != nil || cookie == nil || cookie.Value == "" {
		return "", false
	}
	projectID, _, err := consoleauth.VerifyConsoleSession(cookie.Value, s.cfg.Console.SessionSecret)
	if err != nil || strings.TrimSpace(projectID) == "" {
		return "", false
	}
	return projectID, true
}

func (s *Server) consoleActivationPath() (string, bool) {
	for _, sink := range s.cfg.Activation.Sinks {
		if !strings.EqualFold(strings.TrimSpace(sink.Type), "file_jsonl") {
			continue
		}
		if strings.TrimSpace(sink.Path) == "" {
			continue
		}
		return sink.Path, true
	}
	return "", false
}

func parseConsoleEventsLimit(r *http.Request) int {
	limit := consoleEventsDefaultLimit
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			limit = n
		}
	}
	if limit <= 0 {
		limit = consoleEventsDefaultLimit
	}
	if limit > consoleEventsMaxLimit {
		limit = consoleEventsMaxLimit
	}
	return limit
}

func shouldIncludeTotals(r *http.Request) bool {
	raw := strings.TrimSpace(r.URL.Query().Get("include_totals"))
	if raw == "" {
		return false
	}
	raw = strings.ToLower(raw)
	return raw == "1" || raw == "true" || raw == "yes"
}

var errInvalidCursor = errors.New("invalid cursor")

type consoleCursor struct {
	Snapshot int64
	Offset   int64
}

func readConsoleEvents(path string, rawCursor string, limit int, projectID string) ([]consoleEventListItem, string, error) {
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []consoleEventListItem{}, "", nil
		}
		return nil, "", err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, "", err
	}
	fileSize := info.Size()

	cursor, err := parseConsoleCursor(rawCursor, fileSize)
	if err != nil {
		return nil, "", err
	}

	end := cursor.Offset
	if end <= 0 {
		return []consoleEventListItem{}, "", nil
	}

	items, nextOffset, err := scanConsoleEvents(file, end, limit, projectID)
	if err != nil {
		return nil, "", err
	}
	nextCursor := ""
	if nextOffset > 0 {
		nextCursor = formatConsoleCursor(cursor.Snapshot, nextOffset)
	}
	return items, nextCursor, nil
}

func parseConsoleCursor(raw string, fileSize int64) (consoleCursor, error) {
	if strings.TrimSpace(raw) == "" {
		return consoleCursor{Snapshot: fileSize, Offset: fileSize}, nil
	}
	parts := strings.Split(raw, ":")
	if len(parts) != 2 {
		return consoleCursor{}, errInvalidCursor
	}
	snapshot, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return consoleCursor{}, errInvalidCursor
	}
	offset, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return consoleCursor{}, errInvalidCursor
	}
	if snapshot < 0 || offset < 0 || offset > snapshot {
		return consoleCursor{}, errInvalidCursor
	}
	if snapshot > fileSize {
		snapshot = fileSize
	}
	if offset > snapshot {
		return consoleCursor{}, errInvalidCursor
	}
	return consoleCursor{Snapshot: snapshot, Offset: offset}, nil
}

func formatConsoleCursor(snapshot int64, offset int64) string {
	return fmt.Sprintf("%d:%d", snapshot, offset)
}

func scanConsoleEvents(file *os.File, end int64, limit int, projectID string) ([]consoleEventListItem, int64, error) {
	if end <= 0 {
		return []consoleEventListItem{}, 0, nil
	}
	items := make([]consoleEventListItem, 0, limit)
	var nextOffset int64
	var partial []byte
	offset := end

	for offset > 0 && len(items) < limit {
		readSize := int64(consoleEventsChunkSize)
		if readSize > offset {
			readSize = offset
		}
		offset -= readSize
		chunk := make([]byte, readSize)
		n, err := file.ReadAt(chunk, offset)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, 0, err
		}
		chunk = chunk[:n]
		data := append(chunk, partial...)

		lineItems, lineNextOffset, leftover, done := parseConsoleLines(data, offset, limit-len(items), projectID)
		items = append(items, lineItems...)
		if lineNextOffset > 0 {
			nextOffset = lineNextOffset
		}
		if done {
			break
		}
		partial = leftover
	}

	return items, nextOffset, nil
}

func parseConsoleLines(data []byte, dataOffset int64, remaining int, projectID string) ([]consoleEventListItem, int64, []byte, bool) {
	if remaining <= 0 {
		return nil, 0, nil, true
	}
	var items []consoleEventListItem
	var nextOffset int64
	i := len(data) - 1
	for i >= 0 {
		j := bytes.LastIndexByte(data[:i+1], '\n')
		if j == -1 {
			if i >= 0 {
				return items, nextOffset, data[:i+1], false
			}
			break
		}
		line := bytes.TrimSpace(data[j+1 : i+1])
		lineStart := dataOffset + int64(j+1)
		i = j - 1
		if len(line) == 0 {
			continue
		}
		item, ok := consoleItemFromLine(line, projectID)
		if !ok {
			continue
		}
		items = append(items, item)
		nextOffset = lineStart
		if len(items) >= remaining {
			return items, nextOffset, nil, true
		}
	}
	return items, nextOffset, nil, false
}

func consoleItemFromLine(line []byte, projectID string) (consoleEventListItem, bool) {
	var ev activation.Event
	if err := json.Unmarshal(line, &ev); err != nil {
		return consoleEventListItem{}, false
	}
	if projectID != "" && strings.TrimSpace(ev.Meta.ProjectID) != strings.TrimSpace(projectID) {
		return consoleEventListItem{}, false
	}
	return buildConsoleItem(ev, line), true
}

func buildConsoleItem(ev activation.Event, raw []byte) consoleEventListItem {
	requestID := strings.TrimSpace(ev.RequestID)
	id := requestID
	if id == "" {
		id = hashConsoleID(raw)
	}
	id = "req_" + id
	ts := ev.Timestamp.UTC()
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	reqAction := normalizeDecision(ev.Summary.RequestFinal)
	if reqAction == "" {
		reqAction = normalizeDecision(ev.Request.Decision.Final)
	}
	respAction := normalizeDecision(ev.Summary.ResponseFinal)
	if respAction == "" {
		respAction = normalizeDecision(ev.Response.Decision.Final)
	}

	item := consoleEventListItem{
		ID:         id,
		TS:         ts.Format(time.RFC3339Nano),
		RequestID:  requestID,
		ProjectID:  strings.TrimSpace(ev.Meta.ProjectID),
		Provider:   firstNonEmpty(ev.Meta.Provider, ev.Meta.ProviderID),
		Route:      consoleRouteFromMode(ev.Meta.Mode),
		Summary:    buildConsoleSummary(ev, reqAction, respAction),
		Activation: &ev,
	}

	if reqAction != "" {
		item.RequestFinal = &consoleEventDecision{
			Action: reqAction,
			Hits:   ev.Request.Hits,
			Score:  maxScore(ev.Request.Scores),
		}
	}
	if respAction != "" {
		item.ResponseFinal = &consoleEventDecision{
			Action: respAction,
			Hits:   ev.Response.Hits,
			Score:  maxScore(ev.Response.Scores),
		}
	}

	return item
}

func normalizeDecision(action string) string {
	return strings.ToLower(strings.TrimSpace(action))
}

func consoleRouteFromMode(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "toolgate_check" {
		return "toolgate"
	}
	return "responses"
}

func buildConsoleSummary(ev activation.Event, reqAction string, respAction string) string {
	action := reqAction
	if action == "" {
		action = respAction
	}
	if action == "" {
		action = "unknown"
	}
	label := action
	switch {
	case strings.Contains(action, "block"):
		label = "blocked"
	case strings.Contains(action, "redact"):
		label = "redacted"
	case strings.Contains(action, "warn"):
		label = "warn"
	case action == "allow":
		label = "ok"
	}
	cats := ev.Summary.Categories
	if len(cats) == 0 {
		return label
	}
	return fmt.Sprintf("%s: %s", label, strings.Join(cats, ", "))
}

func maxScore(scores map[string]float32) *float32 {
	if len(scores) == 0 {
		return nil
	}
	var max float32
	var set bool
	for _, v := range scores {
		if !set || v > max {
			max = v
			set = true
		}
	}
	if !set {
		return nil
	}
	return &max
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func hashConsoleID(data []byte) string {
	sum := sha256Sum(data)
	return sum[:12]
}

func sha256Sum(data []byte) string {
	h := sha256.New()
	_, _ = h.Write(data)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func countConsoleEvents(path string, projectID string) (consoleEventsTotals, error) {
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return consoleEventsTotals{}, nil
		}
		return consoleEventsTotals{}, err
	}
	defer file.Close()

	var totals consoleEventsTotals
	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			line = bytes.TrimSpace(line)
			if len(line) > 0 {
				var ev activation.Event
				if jsonErr := json.Unmarshal(line, &ev); jsonErr == nil {
					if projectID == "" || strings.TrimSpace(ev.Meta.ProjectID) == strings.TrimSpace(projectID) {
						totals.Total++
						decision := consoleDecisionFromEvent(ev)
						switch decision {
						case "allow":
							totals.Allow++
						case "redact", "redacted":
							totals.Redact++
						case "block", "blocked":
							totals.Block++
						case "warn":
							totals.Warn++
						default:
							totals.Unknown++
						}
					}
				}
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return consoleEventsTotals{}, err
		}
	}

	return totals, nil
}

func consoleDecisionFromEvent(ev activation.Event) string {
	reqAction := normalizeDecision(ev.Summary.RequestFinal)
	if reqAction == "" {
		reqAction = normalizeDecision(ev.Request.Decision.Final)
	}
	respAction := normalizeDecision(ev.Summary.ResponseFinal)
	if respAction == "" {
		respAction = normalizeDecision(ev.Response.Decision.Final)
	}
	if reqAction != "" {
		return reqAction
	}
	if respAction != "" {
		return respAction
	}
	return ""
}

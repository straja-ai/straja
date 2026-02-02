package activation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/straja-ai/straja/internal/config"
)

const (
	telegramDefaultAPIBaseURL      = "https://api.telegram.org"
	telegramDefaultTimeout         = 2 * time.Second
	telegramDefaultRateLimitPerSec = 1
	telegramDefaultMinLevel        = "warn"
	telegramDefaultMaxMessageLen   = 3500
	telegramMaxMessageLen          = 4096
)

// TelegramSink sends redacted activation summaries to Telegram chat via Bot API.
type TelegramSink struct {
	name                  string
	token                 string
	chatID                string
	apiBaseURL            string
	disableWebPagePreview bool
	parseMode             string
	timeout               time.Duration
	minLevel              string
	onlyCategories        map[string]struct{}
	sendOnActions         map[string]struct{}
	maxMessageLen         int
	client                *http.Client
	rateLimiter           *rateLimiter
}

type rateLimiter struct {
	ch   chan struct{}
	stop chan struct{}
	wg   sync.WaitGroup
}

func newRateLimiter(perSec int) *rateLimiter {
	if perSec <= 0 {
		return nil
	}
	interval := time.Second / time.Duration(perSec)
	if interval <= 0 {
		interval = time.Nanosecond
	}
	rl := &rateLimiter{
		ch:   make(chan struct{}, 1),
		stop: make(chan struct{}),
	}
	rl.ch <- struct{}{}
	rl.wg.Add(1)
	go func() {
		defer rl.wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				select {
				case rl.ch <- struct{}{}:
				default:
				}
			case <-rl.stop:
				return
			}
		}
	}()
	return rl
}

func (r *rateLimiter) wait(ctx context.Context) error {
	if r == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-r.ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *rateLimiter) close() {
	if r == nil {
		return
	}
	close(r.stop)
	r.wg.Wait()
}

func NewTelegramSink(cfg config.ActivationSinkConfig) (*TelegramSink, error) {
	tokenEnv := strings.TrimSpace(cfg.TokenEnv)
	chatEnv := strings.TrimSpace(cfg.ChatIDEnv)
	if tokenEnv == "" || chatEnv == "" {
		return nil, fmt.Errorf("telegram sink requires token_env and chat_id_env")
	}
	token := strings.TrimSpace(os.Getenv(tokenEnv))
	chatID := strings.TrimSpace(os.Getenv(chatEnv))
	if token == "" || chatID == "" {
		return nil, fmt.Errorf("telegram sink requires token_env/chat_id_env env vars to be set")
	}

	apiBaseURL := strings.TrimSpace(cfg.APIBaseURL)
	if apiBaseURL == "" {
		apiBaseURL = telegramDefaultAPIBaseURL
	}
	disableWebPagePreview := true
	if cfg.DisableWebPagePreview != nil {
		disableWebPagePreview = *cfg.DisableWebPagePreview
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = telegramDefaultTimeout
	}
	rateLimit := cfg.RateLimitPerSec
	if rateLimit <= 0 {
		rateLimit = telegramDefaultRateLimitPerSec
	}
	minLevel := strings.ToLower(strings.TrimSpace(cfg.MinLevel))
	if minLevel == "" {
		minLevel = telegramDefaultMinLevel
	}
	if minLevel != "warn" && minLevel != "block" {
		return nil, fmt.Errorf("telegram sink min_level must be warn or block")
	}

	sendOnActions := normalizeActions(cfg.SendOnActions)
	if len(sendOnActions) == 0 {
		sendOnActions = map[string]struct{}{"block": {}, "warn": {}}
	}

	maxMessageLen := cfg.MaxMessageLen
	if maxMessageLen <= 0 {
		maxMessageLen = telegramDefaultMaxMessageLen
	}
	if maxMessageLen > telegramMaxMessageLen {
		maxMessageLen = telegramMaxMessageLen
	}

	onlyCategories := normalizeCategories(cfg.OnlyCategories)
	parseMode := strings.TrimSpace(cfg.ParseMode)
	if parseMode != "" && parseMode != "MarkdownV2" {
		return nil, fmt.Errorf("telegram sink parse_mode must be empty or MarkdownV2")
	}

	return &TelegramSink{
		name:                  "telegram:chat:" + chatID,
		token:                 token,
		chatID:                chatID,
		apiBaseURL:            apiBaseURL,
		disableWebPagePreview: disableWebPagePreview,
		parseMode:             parseMode,
		timeout:               timeout,
		minLevel:              minLevel,
		onlyCategories:        onlyCategories,
		sendOnActions:         sendOnActions,
		maxMessageLen:         maxMessageLen,
		client: &http.Client{
			Timeout: timeout,
		},
		rateLimiter: newRateLimiter(rateLimit),
	}, nil
}

func (s *TelegramSink) Name() string { return s.name }

func (s *TelegramSink) Deliver(ctx context.Context, ev *Event) error {
	if ev == nil {
		return nil
	}
	action := actionFromEvent(ev)
	if !s.shouldSend(ev, action) {
		return nil
	}

	msg := s.formatMessage(ev, action)
	if msg == "" {
		return nil
	}

	reqCtx := ctx
	if reqCtx == nil {
		reqCtx = context.Background()
	}
	if s.timeout > 0 {
		if _, ok := reqCtx.Deadline(); !ok {
			var cancel context.CancelFunc
			reqCtx, cancel = context.WithTimeout(reqCtx, s.timeout)
			defer cancel()
		}
	}

	if err := s.rateLimiter.wait(reqCtx); err != nil {
		return err
	}

	body, err := json.Marshal(telegramMessage{
		ChatID:                s.chatID,
		Text:                  msg,
		DisableWebPagePreview: s.disableWebPagePreview,
		ParseMode:             s.parseMode,
	})
	if err != nil {
		return fmt.Errorf("encode telegram payload: %w", err)
	}

	endpoint := strings.TrimRight(s.apiBaseURL, "/") + "/bot" + s.token + "/sendMessage"
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("post telegram: %w", err)
	}
	defer resp.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("telegram status %d body=%q", resp.StatusCode, truncateBody(payload))
	}

	var result telegramResponse
	if err := json.Unmarshal(payload, &result); err == nil && !result.OK {
		if result.Description != "" {
			return fmt.Errorf("telegram ok=false: %s", result.Description)
		}
		return fmt.Errorf("telegram ok=false")
	}

	return nil
}

func (s *TelegramSink) Close(context.Context) error {
	if s.rateLimiter != nil {
		s.rateLimiter.close()
	}
	return nil
}

type telegramMessage struct {
	ChatID                string `json:"chat_id"`
	Text                  string `json:"text"`
	DisableWebPagePreview bool   `json:"disable_web_page_preview"`
	ParseMode             string `json:"parse_mode,omitempty"`
}

type telegramResponse struct {
	OK          bool   `json:"ok"`
	Description string `json:"description"`
}

func (s *TelegramSink) shouldSend(ev *Event, action string) bool {
	if action == "" {
		return false
	}
	if _, ok := s.sendOnActions[action]; !ok {
		return false
	}
	if s.minLevel == "block" && action != "block" {
		return false
	}
	if len(s.onlyCategories) > 0 && !eventHasCategory(ev, s.onlyCategories) {
		return false
	}
	return true
}

func (s *TelegramSink) formatMessage(ev *Event, action string) string {
	required := make([]string, 0, 2)
	required = append(required, "Straja alert: "+strings.ToUpper(action))
	if ev.RequestID != "" {
		required = append(required, "request_id="+ev.RequestID)
	}

	optional := make([]string, 0, 6)
	if ev.Meta.ProjectID != "" {
		optional = append(optional, "project="+ev.Meta.ProjectID)
	}
	optional = append(optional, "route="+routeFromEvent(ev))
	if isToolgateEvent(ev) {
		if toolLine := buildToolgateLine(ev, action); toolLine != "" {
			optional = append(optional, toolLine)
		}
	}
	if reason := buildReasonLine(ev); reason != "" {
		optional = append(optional, reason)
	}
	if hits := buildHitsLine(ev); hits != "" {
		optional = append(optional, hits)
	}
	if !ev.Timestamp.IsZero() {
		optional = append(optional, "time="+ev.Timestamp.UTC().Format(time.RFC3339))
	}

	msg, truncated := buildMessageWithLimit(required, optional, s.maxMessageLen)
	if s.parseMode == "MarkdownV2" {
		msg = escapeMarkdownV2(msg)
		if truncated {
			msg = appendTruncationSuffix(msg, s.maxMessageLen, escapeMarkdownV2("\n...(truncated)"))
		}
		return msg
	}
	if truncated {
		msg = appendTruncationSuffix(msg, s.maxMessageLen, "\n...(truncated)")
	}
	return msg
}

func actionFromEvent(ev *Event) string {
	if ev == nil {
		return ""
	}
	reqFinal := strings.ToLower(strings.TrimSpace(ev.Summary.RequestFinal))
	respFinal := strings.ToLower(strings.TrimSpace(ev.Summary.ResponseFinal))
	if reqFinal == "block" || respFinal == "block" {
		return "block"
	}
	if respFinal == "warn" {
		return "warn"
	}
	if hasHitAction(ev.Request.Hits, "warn") || hasHitAction(ev.Response.Hits, "warn") {
		return "warn"
	}
	return ""
}

func hasHitAction(hits []ActionEntry, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	for _, h := range hits {
		if strings.Contains(strings.ToLower(h.Action), needle) {
			return true
		}
	}
	return false
}

func eventHasCategory(ev *Event, allow map[string]struct{}) bool {
	if ev == nil {
		return false
	}
	for _, cat := range ev.Summary.Categories {
		if _, ok := allow[strings.ToLower(strings.TrimSpace(cat))]; ok {
			return true
		}
	}
	for _, hit := range ev.Request.Hits {
		if _, ok := allow[strings.ToLower(strings.TrimSpace(hit.Category))]; ok {
			return true
		}
	}
	for _, hit := range ev.Response.Hits {
		if _, ok := allow[strings.ToLower(strings.TrimSpace(hit.Category))]; ok {
			return true
		}
	}
	return false
}

func routeFromEvent(ev *Event) string {
	if ev == nil {
		return "responses"
	}
	if isToolgateEvent(ev) {
		return "toolgate"
	}
	return "/v1/responses"
}

func isToolgateEvent(ev *Event) bool {
	if ev == nil {
		return false
	}
	return strings.ToLower(strings.TrimSpace(ev.Meta.Mode)) == "toolgate_check" ||
		strings.ToLower(strings.TrimSpace(ev.Meta.Provider)) == "toolgate"
}

func buildToolgateLine(ev *Event, action string) string {
	if ev == nil {
		return ""
	}
	toolName := ""
	if ev.Request.Preview.Tool != nil {
		toolName = strings.TrimSpace(ev.Request.Preview.Tool.ToolName)
	}
	ruleID := firstRuleID(ev.Request.Hits)
	if toolName == "" && ruleID == "" {
		return ""
	}
	parts := make([]string, 0, 3)
	if toolName != "" {
		parts = append(parts, "tool="+toolName)
	}
	if ruleID != "" {
		parts = append(parts, "rule="+ruleID)
	}
	parts = append(parts, "action="+action)
	return strings.Join(parts, " ")
}

func firstRuleID(hits []ActionEntry) string {
	for _, hit := range hits {
		for _, src := range hit.Sources {
			src = strings.TrimSpace(src)
			if strings.HasPrefix(src, "rule:") {
				return strings.TrimPrefix(src, "rule:")
			}
		}
	}
	return ""
}

func buildReasonLine(ev *Event) string {
	hit := topHit(append(append([]ActionEntry{}, ev.Request.Hits...), ev.Response.Hits...))
	if hit != nil {
		action := normalizeActionLabel(hit.Action)
		if action != "" {
			return fmt.Sprintf("reason=%s (%s)", hit.Category, action)
		}
		return fmt.Sprintf("reason=%s", hit.Category)
	}
	if len(ev.Summary.Categories) > 0 {
		return fmt.Sprintf("reason=%s", ev.Summary.Categories[0])
	}
	return ""
}

func buildHitsLine(ev *Event) string {
	counts := make(map[string]int)
	for _, hit := range ev.Request.Hits {
		cat := strings.TrimSpace(hit.Category)
		if cat == "" {
			continue
		}
		counts[cat]++
	}
	for _, hit := range ev.Response.Hits {
		cat := strings.TrimSpace(hit.Category)
		if cat == "" {
			continue
		}
		counts[cat]++
	}
	if len(counts) == 0 {
		return ""
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s:%d", k, counts[k]))
	}
	return "hits=" + strings.Join(parts, " ")
}

func topHit(hits []ActionEntry) *ActionEntry {
	if len(hits) == 0 {
		return nil
	}
	best := hits[0]
	bestScore := actionScore(best.Action)
	for _, h := range hits[1:] {
		score := actionScore(h.Action)
		if score > bestScore {
			best = h
			bestScore = score
		}
	}
	return &best
}

func actionScore(action string) int {
	action = strings.ToLower(strings.TrimSpace(action))
	switch {
	case strings.Contains(action, "block"):
		return 3
	case strings.Contains(action, "warn"):
		return 2
	case strings.Contains(action, "redact"):
		return 1
	default:
		return 0
	}
}

func normalizeActionLabel(action string) string {
	action = strings.ToLower(strings.TrimSpace(action))
	switch {
	case strings.Contains(action, "block"):
		return "block"
	case strings.Contains(action, "warn"):
		return "warn"
	case strings.Contains(action, "redact"):
		return "redact"
	default:
		return ""
	}
}

func normalizeActions(actions []string) map[string]struct{} {
	out := make(map[string]struct{}, len(actions))
	for _, action := range actions {
		val := strings.ToLower(strings.TrimSpace(action))
		if val == "" {
			continue
		}
		out[val] = struct{}{}
	}
	return out
}

func normalizeCategories(categories []string) map[string]struct{} {
	out := make(map[string]struct{}, len(categories))
	for _, cat := range categories {
		val := strings.ToLower(strings.TrimSpace(cat))
		if val == "" {
			continue
		}
		out[val] = struct{}{}
	}
	return out
}

func truncateWithSuffix(text string, maxLen int, suffix string) string {
	if maxLen <= 0 || len(text) <= maxLen {
		return text
	}
	if len(suffix) >= maxLen {
		return text[:maxLen]
	}
	cut := maxLen - len(suffix)
	if cut < 0 {
		cut = 0
	}
	return text[:cut] + suffix
}

func buildMessageWithLimit(required, optional []string, maxLen int) (string, bool) {
	if maxLen <= 0 {
		return strings.Join(append(required, optional...), "\n"), false
	}
	lines := make([]string, 0, len(required)+len(optional))
	lines = append(lines, required...)
	truncated := false
	current := 0
	for i, line := range lines {
		if i > 0 {
			current++ // newline
		}
		current += len(line)
	}
	if current > maxLen {
		return strings.Join(lines, "\n"), true
	}
	for _, line := range optional {
		addLen := len(line)
		if current > 0 {
			addLen++ // newline
		}
		if current+addLen > maxLen {
			truncated = true
			continue
		}
		lines = append(lines, line)
		current += addLen
	}
	return strings.Join(lines, "\n"), truncated
}

func appendTruncationSuffix(text string, maxLen int, suffix string) string {
	if maxLen <= 0 {
		return text
	}
	if len(suffix) >= maxLen {
		if len(text) <= maxLen {
			return text
		}
		return text[:maxLen]
	}
	cut := maxLen - len(suffix)
	if cut < 0 {
		cut = 0
	}
	if len(text) > cut {
		return text[:cut] + suffix
	}
	return text + suffix
}

func escapeMarkdownV2(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

package strajad

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type plannerInput struct {
	Task           string
	Collection     string
	VaultLocked    bool
	PresenceAccess bool

	MaxTaskChars      int
	MaxSearchResults  int
	MaxSnippetObjects int
	MaxSnippetBytes   int
	MaxSnippetChars   int
	MaxWriteChars     int
	MaxIngestBytes    int
}

type deterministicPlan struct {
	ExecutionMode        string            `json:"execution_mode"`
	PlannerMode          string            `json:"planner_mode"`
	Deterministic        bool              `json:"deterministic"`
	PlanID               string            `json:"plan_id"`
	Collection           string            `json:"collection,omitempty"`
	VaultLocked          bool              `json:"vault_locked"`
	Plan                 []string          `json:"plan"`
	RecommendedToolCalls []recommendedCall `json:"recommended_tool_calls"`
	ExpectedBudgets      map[string]any    `json:"expected_budgets"`
	ApprovalsNeeded      []string          `json:"approvals_needed"`
	SafetyNotes          []string          `json:"safety_notes"`
}

type recommendedCall struct {
	Name string         `json:"name"`
	Args map[string]any `json:"args"`
}

func buildDeterministicPlan(in plannerInput) deterministicPlan {
	task := normalizePlannerText(in.Task)
	collection := normalizeCollectionName(in.Collection)

	searchLimit := clampInt(3, 1, in.MaxSearchResults)
	readBytes := clampInt(1024, 1, in.MaxSnippetBytes)
	readChars := clampInt(256, 1, in.MaxSnippetChars)

	intentIngest := containsPlannerKeyword(task, []string{"ingest", "import", "upload", "index", "pdf", "document", "parse"})
	intentWrite := containsPlannerKeyword(task, []string{"save", "store", "remember", "persist", "write", "draft", "note"})
	intentSummarize := containsPlannerKeyword(task, []string{"summarize", "summary", "compare", "review", "analyze"})
	if !intentSummarize && !intentWrite && !intentIngest {
		intentSummarize = true
	}

	steps := []string{
		"Search for candidate objects using vault.search.",
		"Read bounded snippets from selected IDs using vault.read_snippets.",
	}
	if intentIngest {
		steps = append(steps, "Ingest source content through vault.ingest for indexing.")
	}
	if intentWrite {
		steps = append(steps, "Persist output as a bounded note via vault.write.")
	}

	calls := []recommendedCall{
		{
			Name: "vault.search",
			Args: map[string]any{
				"query":      strings.TrimSpace(in.Task),
				"collection": collection,
				"limit":      searchLimit,
			},
		},
		{
			Name: "vault.read_snippets",
			Args: map[string]any{
				"ids":                   []string{"<id_from_search>"},
				"query":                 strings.TrimSpace(in.Task),
				"max_bytes":             readBytes,
				"max_chars_per_snippet": readChars,
			},
		},
	}

	if intentIngest {
		calls = append(calls, recommendedCall{
			Name: "vault.ingest",
			Args: map[string]any{
				"collection":   nonEmpty(collection, "agent_memory"),
				"title":        "Ingested source for task",
				"content_type": "text/plain",
				"text":         "<source_text>",
			},
		})
	}
	if intentWrite {
		calls = append(calls, recommendedCall{
			Name: "vault.write",
			Args: map[string]any{
				"collection": nonEmpty(collection, "agent_memory"),
				"title":      "Planned note",
				"content":    "<final_note>",
			},
		})
	}

	approvals := make([]string, 0, 2)
	if in.VaultLocked {
		approvals = append(approvals, "vault_unlock_required_before_execution")
	}
	if (collection == "tax" || collection == "health") && !in.PresenceAccess {
		approvals = append(approvals, "presence_token_required_for_sensitive_collection")
	}

	safetyNotes := []string{
		"vault.request is plan-only and does not execute side effects.",
		"All downstream tool calls are still enforced by deterministic budgets and policies.",
	}
	if intentIngest {
		safetyNotes = append(safetyNotes, "Ingestion is bounded by max_ingest_bytes and max_extracted_chars.")
	}
	if intentSummarize {
		safetyNotes = append(safetyNotes, "Summaries should use snippets, not full-document dumps.")
	}

	planSeed := strings.Join([]string{
		task,
		collection,
		strconv.FormatBool(in.VaultLocked),
		strconv.FormatBool(in.PresenceAccess),
		strconv.Itoa(in.MaxTaskChars),
		strconv.Itoa(in.MaxSearchResults),
		strconv.Itoa(in.MaxSnippetObjects),
		strconv.Itoa(in.MaxSnippetBytes),
		strconv.Itoa(in.MaxSnippetChars),
		strconv.Itoa(in.MaxWriteChars),
		strconv.Itoa(in.MaxIngestBytes),
		strconv.FormatBool(intentIngest),
		strconv.FormatBool(intentWrite),
		strconv.FormatBool(intentSummarize),
	}, "|")
	planID := derivePlanID("plan", planSeed)

	return deterministicPlan{
		ExecutionMode:        "plan_only",
		PlannerMode:          "deterministic_scaffold_v1",
		Deterministic:        true,
		PlanID:               planID,
		Collection:           collection,
		VaultLocked:          in.VaultLocked,
		Plan:                 steps,
		RecommendedToolCalls: calls,
		ExpectedBudgets: map[string]any{
			"max_task_chars":      in.MaxTaskChars,
			"max_search_results":  in.MaxSearchResults,
			"max_snippet_objects": in.MaxSnippetObjects,
			"max_snippet_bytes":   in.MaxSnippetBytes,
			"max_snippet_chars":   in.MaxSnippetChars,
			"max_write_chars":     in.MaxWriteChars,
			"max_ingest_bytes":    in.MaxIngestBytes,
		},
		ApprovalsNeeded: approvals,
		SafetyNotes:     safetyNotes,
	}
}

func buildPlanWithBroker(in plannerInput, fallback deterministicPlan, broker plannerBroker) (deterministicPlan, bool) {
	if broker == nil {
		return fallback, false
	}
	brokerCtx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	draft, err := broker.Plan(brokerCtx, in, fallback)
	if err != nil {
		out := fallback
		out.SafetyNotes = appendUniqueStrings(out.SafetyNotes,
			"Broker unavailable; deterministic planner fallback is active.",
		)
		return out, false
	}
	return mergeBrokerPlan(in, fallback, draft, broker.Mode()), true
}

func mergeBrokerPlan(in plannerInput, fallback deterministicPlan, draft brokerPlanDraft, mode string) deterministicPlan {
	out := fallback
	out.PlannerMode = strings.TrimSpace(mode)
	if out.PlannerMode == "" {
		out.PlannerMode = brokerModeOllamaV1
	}
	out.Deterministic = false

	if plan := sanitizeTextList(draft.Plan, 8, 180); len(plan) > 0 {
		out.Plan = plan
	}
	if calls := sanitizeRecommendedCalls(in, draft.RecommendedToolCalls); len(calls) > 0 {
		out.RecommendedToolCalls = calls
	}

	approvals := sanitizeTextList(draft.ApprovalsNeeded, 8, 120)
	out.ApprovalsNeeded = appendUniqueStrings(approvals, fallback.ApprovalsNeeded...)

	safety := sanitizeTextList(draft.SafetyNotes, 10, 180)
	out.SafetyNotes = appendUniqueStrings(safety, fallback.SafetyNotes...)

	seed, err := json.Marshal(struct {
		Task                 string            `json:"task"`
		Collection           string            `json:"collection"`
		ExecutionMode        string            `json:"execution_mode"`
		PlannerMode          string            `json:"planner_mode"`
		Plan                 []string          `json:"plan"`
		RecommendedToolCalls []recommendedCall `json:"recommended_tool_calls"`
		ApprovalsNeeded      []string          `json:"approvals_needed"`
		SafetyNotes          []string          `json:"safety_notes"`
	}{
		Task:                 normalizePlannerText(in.Task),
		Collection:           normalizeCollectionName(in.Collection),
		ExecutionMode:        out.ExecutionMode,
		PlannerMode:          out.PlannerMode,
		Plan:                 out.Plan,
		RecommendedToolCalls: out.RecommendedToolCalls,
		ApprovalsNeeded:      out.ApprovalsNeeded,
		SafetyNotes:          out.SafetyNotes,
	})
	if err == nil {
		out.PlanID = derivePlanID("plan", string(seed))
	}
	return out
}

func sanitizeRecommendedCalls(in plannerInput, calls []recommendedCall) []recommendedCall {
	out := make([]recommendedCall, 0, len(calls))
	for _, call := range calls {
		name := strings.TrimSpace(call.Name)
		var sanitized recommendedCall
		switch name {
		case "vault.search":
			sanitized = sanitizeSearchCall(in, call.Args)
		case "vault.read_snippets":
			sanitized = sanitizeReadSnippetsCall(in, call.Args)
		case "vault.ingest":
			sanitized = sanitizeIngestCall(in, call.Args)
		case "vault.write":
			sanitized = sanitizeWriteCall(in, call.Args)
		default:
			continue
		}
		out = append(out, sanitized)
		if len(out) >= 6 {
			break
		}
	}
	return out
}

func sanitizeSearchCall(in plannerInput, args map[string]any) recommendedCall {
	query := sanitizeOneLine(getStringArg(args, "query"), strings.TrimSpace(in.Task), in.MaxTaskChars)
	collection := normalizeCollectionName(getStringArg(args, "collection"))
	if collection == "" {
		collection = normalizeCollectionName(in.Collection)
	}
	defaultLimit := 3
	if defaultLimit > in.MaxSearchResults {
		defaultLimit = in.MaxSearchResults
	}
	limit := clampInt(getIntArg(args, "limit", defaultLimit), 1, in.MaxSearchResults)

	out := map[string]any{
		"query": query,
		"limit": limit,
	}
	if collection != "" {
		out["collection"] = collection
	}
	return recommendedCall{Name: "vault.search", Args: out}
}

func sanitizeReadSnippetsCall(in plannerInput, args map[string]any) recommendedCall {
	ids := getStringSliceArg(args, "ids")
	if len(ids) == 0 {
		ids = []string{"<id_from_search>"}
	}
	if len(ids) > in.MaxSnippetObjects {
		ids = ids[:in.MaxSnippetObjects]
	}
	query := sanitizeOneLine(getStringArg(args, "query"), strings.TrimSpace(in.Task), in.MaxTaskChars)

	defaultBytes := 1024
	if defaultBytes > in.MaxSnippetBytes {
		defaultBytes = in.MaxSnippetBytes
	}
	maxBytes := clampInt(getIntArg(args, "max_bytes", defaultBytes), 1, in.MaxSnippetBytes)

	defaultChars := 256
	if defaultChars > in.MaxSnippetChars {
		defaultChars = in.MaxSnippetChars
	}
	maxChars := clampInt(getIntArg(args, "max_chars_per_snippet", defaultChars), 1, in.MaxSnippetChars)

	return recommendedCall{
		Name: "vault.read_snippets",
		Args: map[string]any{
			"ids":                   ids,
			"query":                 query,
			"max_bytes":             maxBytes,
			"max_chars_per_snippet": maxChars,
		},
	}
}

func sanitizeIngestCall(in plannerInput, args map[string]any) recommendedCall {
	collection := normalizeCollectionName(getStringArg(args, "collection"))
	if collection == "" {
		collection = nonEmpty(normalizeCollectionName(in.Collection), "agent_memory")
	}
	title := sanitizeOneLine(getStringArg(args, "title"), "Ingested source for task", 160)
	contentType := strings.TrimSpace(strings.ToLower(getStringArg(args, "content_type")))
	if contentType != "application/pdf" {
		contentType = "text/plain"
	}
	text := sanitizeOneLine(getStringArg(args, "text"), "<source_text>", in.MaxIngestBytes)
	maxPreviewBytes := in.MaxIngestBytes
	if maxPreviewBytes > 256 {
		maxPreviewBytes = 256
	}
	text = truncateUTF8ByBytes(text, maxPreviewBytes)
	if text == "" {
		text = "<source_text>"
	}

	return recommendedCall{
		Name: "vault.ingest",
		Args: map[string]any{
			"collection":   collection,
			"title":        title,
			"content_type": contentType,
			"text":         text,
		},
	}
}

func sanitizeWriteCall(in plannerInput, args map[string]any) recommendedCall {
	collection := normalizeCollectionName(getStringArg(args, "collection"))
	if collection == "" {
		collection = nonEmpty(normalizeCollectionName(in.Collection), "agent_memory")
	}
	title := sanitizeOneLine(getStringArg(args, "title"), "Planned note", 160)
	content := sanitizeOneLine(getStringArg(args, "content"), "<final_note>", in.MaxWriteChars)
	content = truncateUTF8ByBytes(content, in.MaxWriteChars)
	if content == "" {
		content = "<final_note>"
	}
	return recommendedCall{
		Name: "vault.write",
		Args: map[string]any{
			"collection": collection,
			"title":      title,
			"content":    content,
		},
	}
}

func sanitizeTextList(items []string, maxItems, maxChars int) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		s := sanitizeOneLine(item, "", maxChars)
		if s == "" {
			continue
		}
		out = append(out, s)
		if len(out) >= maxItems {
			break
		}
	}
	return out
}

func sanitizeOneLine(s, fallback string, maxBytes int) string {
	s = strings.TrimSpace(s)
	if s == "" {
		s = strings.TrimSpace(fallback)
	}
	if s == "" {
		return ""
	}
	s = strings.Join(strings.Fields(s), " ")
	if maxBytes > 0 {
		s = truncateUTF8ByBytes(s, maxBytes)
	}
	return strings.TrimSpace(s)
}

func truncateUTF8ByBytes(s string, maxBytes int) string {
	if maxBytes <= 0 || len([]byte(s)) <= maxBytes {
		return s
	}
	var b strings.Builder
	b.Grow(maxBytes)
	used := 0
	for _, r := range s {
		size := utf8.RuneLen(r)
		if size < 0 {
			continue
		}
		if used+size > maxBytes {
			break
		}
		b.WriteRune(r)
		used += size
	}
	return strings.TrimSpace(b.String())
}

func getStringArg(args map[string]any, key string) string {
	if args == nil {
		return ""
	}
	raw, ok := args[key]
	if !ok || raw == nil {
		return ""
	}
	s, ok := raw.(string)
	if !ok {
		return ""
	}
	return s
}

func getIntArg(args map[string]any, key string, fallback int) int {
	if args == nil {
		return fallback
	}
	raw, ok := args[key]
	if !ok || raw == nil {
		return fallback
	}
	switch v := raw.(type) {
	case int:
		return v
	case int8:
		return int(v)
	case int16:
		return int(v)
	case int32:
		return int(v)
	case int64:
		return int(v)
	case uint:
		return int(v)
	case uint8:
		return int(v)
	case uint16:
		return int(v)
	case uint32:
		return int(v)
	case uint64:
		return int(v)
	case float32:
		return int(v)
	case float64:
		return int(v)
	case json.Number:
		n, err := v.Int64()
		if err == nil {
			return int(n)
		}
	}
	return fallback
}

func getStringSliceArg(args map[string]any, key string) []string {
	if args == nil {
		return nil
	}
	raw, ok := args[key]
	if !ok || raw == nil {
		return nil
	}
	switch v := raw.(type) {
	case []string:
		out := make([]string, 0, len(v))
		for _, item := range v {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			out = append(out, item)
		}
		return out
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				continue
			}
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			out = append(out, s)
		}
		return out
	default:
		return nil
	}
}

func appendUniqueStrings(head []string, tail ...string) []string {
	out := make([]string, 0, len(head)+len(tail))
	seen := make(map[string]struct{}, len(head)+len(tail))
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		if _, exists := seen[s]; exists {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, s := range head {
		add(s)
	}
	for _, s := range tail {
		add(s)
	}
	return out
}

func derivePlanID(prefix, seed string) string {
	hash := sha256.Sum256([]byte(seed))
	id := hex.EncodeToString(hash[:8])
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		prefix = "plan"
	}
	return prefix + "_" + id
}

func containsPlannerKeyword(task string, keywords []string) bool {
	task = normalizePlannerText(task)
	if task == "" {
		return false
	}
	for _, kw := range keywords {
		kw = strings.TrimSpace(strings.ToLower(kw))
		if kw == "" {
			continue
		}
		if strings.Contains(task, kw) {
			return true
		}
	}
	return false
}

func normalizePlannerText(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return ""
	}
	return strings.Join(strings.Fields(s), " ")
}

func clampInt(v, minVal, maxVal int) int {
	if v < minVal {
		return minVal
	}
	if maxVal > 0 && v > maxVal {
		return maxVal
	}
	return v
}

func nonEmpty(v, fallback string) string {
	if strings.TrimSpace(v) != "" {
		return v
	}
	return fallback
}

package strajad

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	vaultTierAlwaysOn         = "always_on"
	vaultTierPresenceRequired = "presence_required"
)

const (
	defaultStorePath = "./tmp/strajad/vault.enc"
	kdfRounds        = 120000
)

var (
	errVaultLocked               = errors.New("vault is locked")
	errUnlockPassphraseRequired  = errors.New("unlock passphrase is required")
	errUnlockPassphraseInvalid   = errors.New("unlock passphrase is invalid")
	errCollectionNotFound        = errors.New("collection not found")
	errCollectionAccessDenied    = errors.New("collection access denied")
	errCollectionAlreadyExists   = errors.New("collection already exists")
	errObjectNotFound            = errors.New("object not found")
	errInvalidCollectionName     = errors.New("invalid collection name")
	errInvalidCollectionTier     = errors.New("invalid collection tier")
	errInvalidConnectorProvider  = errors.New("invalid connector provider")
	errConnectorTokenRequired    = errors.New("connector token is required")
	errApprovalNotFound          = errors.New("approval not found")
	errInvalidApprovalAction     = errors.New("invalid approval action")
	errEncryptedStoreCorrupt     = errors.New("encrypted store is corrupt")
	errEncryptedStorePersistFail = errors.New("encrypted store persist failed")
)

type vaultObject struct {
	ID         string    `json:"id"`
	Collection string    `json:"collection"`
	Title      string    `json:"title"`
	Content    string    `json:"content"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type vaultCollection struct {
	Name        string `json:"name"`
	Tier        string `json:"tier"`
	Description string `json:"description,omitempty"`
}

type connectorCredential struct {
	Token     string    `json:"token"`
	UpdatedAt time.Time `json:"updated_at"`
}

type connectorStatus struct {
	Provider   string    `json:"provider"`
	Configured bool      `json:"configured"`
	UpdatedAt  time.Time `json:"updated_at,omitempty"`
}

type approvalRequest struct {
	ID         string            `json:"id"`
	Action     string            `json:"action"`
	Collection string            `json:"collection,omitempty"`
	ResourceID string            `json:"resource_id,omitempty"`
	Summary    string            `json:"summary,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	Status     string            `json:"status"`
	Reason     string            `json:"reason,omitempty"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
}

type indexJob struct {
	ID         string    `json:"id"`
	ObjectID   string    `json:"object_id"`
	Collection string    `json:"collection"`
	Reason     string    `json:"reason,omitempty"`
	EnqueuedAt time.Time `json:"enqueued_at"`
}

type objectIndexStatus struct {
	ObjectID    string    `json:"object_id"`
	Collection  string    `json:"collection"`
	State       string    `json:"state"`
	Reason      string    `json:"reason,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
	Attempts    int       `json:"attempts"`
	UpdatedAt   time.Time `json:"updated_at"`
	LastIndexed time.Time `json:"last_indexed,omitempty"`
}

type vaultData struct {
	Version         int                            `json:"version"`
	Collections     map[string]vaultCollection     `json:"collections"`
	Order           []string                       `json:"order"`
	Objects         map[string]vaultObject         `json:"objects"`
	SemanticChunks  map[string]semanticChunk       `json:"semantic_chunks,omitempty"`
	ObjectChunkIDs  map[string][]string            `json:"object_chunk_ids,omitempty"`
	IndexMeta       retrievalIndexMeta             `json:"index_meta,omitempty"`
	IndexStatuses   map[string]objectIndexStatus   `json:"index_statuses,omitempty"`
	IndexQueue      []indexJob                     `json:"index_queue,omitempty"`
	NextIndexJobID  int                            `json:"next_index_job_id,omitempty"`
	NextNoteID      int                            `json:"next_note_id"`
	ConnectorTokens map[string]connectorCredential `json:"connector_tokens,omitempty"`
	Approvals       map[string]approvalRequest     `json:"approvals,omitempty"`
	ApprovalOrder   []string                       `json:"approval_order,omitempty"`
	NextApprovalID  int                            `json:"next_approval_id,omitempty"`
}

type encryptedVaultFile struct {
	Version    int    `json:"version"`
	KDF        string `json:"kdf"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type searchHit struct {
	ID               string   `json:"id"`
	Collection       string   `json:"collection"`
	Type             string   `json:"type,omitempty"`
	Summary          string   `json:"summary"`
	Score            int      `json:"score,omitempty"`
	Confidence       string   `json:"confidence,omitempty"`
	WhyMatched       []string `json:"why_matched,omitempty"`
	TopSectionIDs    []string `json:"top_section_ids,omitempty"`
	EvidenceChunkIDs []string `json:"evidence_chunk_ids,omitempty"`
}

type snippetHit struct {
	ID         string `json:"id"`
	Collection string `json:"collection"`
	Snippet    string `json:"snippet"`
	Bytes      int    `json:"bytes"`
	StartChar  int    `json:"start_char"`
	EndChar    int    `json:"end_char"`
	Redacted   bool   `json:"redacted,omitempty"`
}

type collectionHit struct {
	Name        string `json:"name"`
	Tier        string `json:"tier"`
	Description string `json:"description,omitempty"`
	Accessible  bool   `json:"accessible"`
	Indexed     int    `json:"indexed_objects,omitempty"`
	Pending     int    `json:"pending_objects,omitempty"`
	Failed      int    `json:"failed_objects,omitempty"`
}

type itemHit struct {
	ID         string    `json:"id"`
	Collection string    `json:"collection"`
	Title      string    `json:"title"`
	Preview    string    `json:"preview"`
	Bytes      int       `json:"bytes"`
	IndexState string    `json:"index_state,omitempty"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type vaultStore struct {
	mu               sync.RWMutex
	path             string
	presenceToken    string
	salt             []byte
	key              []byte
	state            *vaultData
	index            map[string]map[string]int
	objectTokens     map[string]map[string]int
	chunkLexIndex    map[string]map[string]int
	chunkLexTokens   map[string]map[string]int
	chunkLexDocLen   map[string]int
	semanticChunks   map[string]semanticChunk
	objectChunkIDs   map[string][]string
	annBuckets       map[uint64][]string
	chunkANNKeys     map[string][]uint64
	annEngine        annEngine
	retrieval        retrievalConfig
	embeddingCache   map[string][]float32
	embeddingCacheAt map[string]time.Time
	queryNormCache   map[string]string
	candidateCache   map[string]cachedCandidateSet
	rerankCache      map[string]cachedCandidateSet
	cacheClock       func() time.Time
	lastANNInitMode  string
	lastANNChunks    int
	lastANNInitAt    time.Time
	unlocked         bool
	presenceGranted  bool
}

func newVaultStore(path, presenceToken string, retrieval retrievalConfig) *vaultStore {
	path = strings.TrimSpace(path)
	if path == "" {
		path = defaultStorePath
	}
	if retrieval.maxSnippetChars <= 0 {
		retrieval.maxSnippetChars = 512
	}
	if retrieval.maxReadCoverage <= 0 {
		retrieval.maxReadCoverage = 0.75
	}
	if retrieval.cacheTTL <= 0 {
		retrieval.cacheTTL = 45 * time.Second
	}
	if strings.TrimSpace(retrieval.annProvider) == "" {
		retrieval.annProvider = "hnswlib"
	}
	retrieval.profile = normalizeRetrievalProfile(retrieval.profile)
	if retrieval.profile == "" {
		retrieval.profile = "high_accuracy"
	}
	if retrieval.hnswM <= 0 {
		retrieval.hnswM = 32
	}
	if retrieval.hnswEfConstruction <= 0 {
		retrieval.hnswEfConstruction = 200
	}
	if retrieval.hnswEfSearch <= 0 {
		retrieval.hnswEfSearch = 128
	}
	if retrieval.hnswMaxElements <= 0 {
		retrieval.hnswMaxElements = 200000
	}
	ann := newANNEngine(retrieval)
	if strings.TrimSpace(retrieval.indexMeta.Version) == "" {
		retrieval.indexMeta = defaultRetrievalIndexMeta(retrieval.embedder, retrieval.reranker, resolveANNVersion(retrieval.annProvider, ann))
	}
	retrieval.indexMeta.ANNVersion = resolveANNVersion(retrieval.annProvider, ann)
	retrieval.indexMeta.EmbeddingDim = semanticEmbeddingDims
	retrieval.indexMeta.LexicalIndexVersion = nonEmpty(retrieval.indexMeta.LexicalIndexVersion, "bm25.chunk.v1")
	retrieval.indexMeta.HNSWM = retrieval.hnswM
	retrieval.indexMeta.HNSWEfConstruction = retrieval.hnswEfConstruction
	if retrieval.maxLexicalTopN <= 0 {
		retrieval.maxLexicalTopN = retrievalDefaultLexicalTopN
	}
	if retrieval.maxDenseTopN <= 0 {
		retrieval.maxDenseTopN = retrievalDefaultDenseTopN
	}
	if retrieval.maxCandidateN <= 0 {
		retrieval.maxCandidateN = retrievalDefaultCandidateN
	}
	if retrieval.maxRerankInN <= 0 {
		retrieval.maxRerankInN = retrievalDefaultRerankInN
	}
	if retrieval.maxRerankOutN <= 0 {
		retrieval.maxRerankOutN = retrievalDefaultRerankOutN
	}
	if retrieval.iterativePasses <= 0 {
		retrieval.iterativePasses = 2
	}
	if retrieval.secondPassAddN <= 0 {
		retrieval.secondPassAddN = 15
	}
	if retrieval.maxCacheEntries <= 0 {
		retrieval.maxCacheEntries = 1024
	}
	return &vaultStore{
		path:             path,
		presenceToken:    strings.TrimSpace(presenceToken),
		retrieval:        retrieval,
		annEngine:        ann,
		embeddingCache:   map[string][]float32{},
		embeddingCacheAt: map[string]time.Time{},
		queryNormCache:   map[string]string{},
		candidateCache:   map[string]cachedCandidateSet{},
		rerankCache:      map[string]cachedCandidateSet{},
		chunkLexDocLen:   map[string]int{},
		cacheClock:       time.Now,
	}
}

func (s *vaultStore) IsUnlocked() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.unlocked
}

func (s *vaultStore) HasPresenceAccess() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.presenceGranted
}

type annInitStatus struct {
	Mode       string
	ChunkCount int
	At         time.Time
}

func (s *vaultStore) ANNInitStatus() annInitStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return annInitStatus{
		Mode:       strings.TrimSpace(s.lastANNInitMode),
		ChunkCount: s.lastANNChunks,
		At:         s.lastANNInitAt,
	}
}

func (s *vaultStore) EnsureCollectionAccess(collection string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if err := s.ensureUnlockedLocked(); err != nil {
		return err
	}
	_, err := s.requireCollectionAccessLocked(collection)
	return err
}

func (s *vaultStore) Unlock(passphrase, presenceToken string) (created bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	passphrase = strings.TrimSpace(passphrase)
	if passphrase == "" {
		return false, errUnlockPassphraseRequired
	}

	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return false, err
	}

	if _, statErr := os.Stat(s.path); os.IsNotExist(statErr) {
		data := defaultVaultData()
		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return false, err
		}
		key := deriveEncryptionKey(passphrase, salt)
		if err := saveEncryptedStore(s.path, salt, key, data); err != nil {
			return false, err
		}
		s.salt = salt
		s.key = key
		s.state = &data
		s.rebuildIndexLocked()
		s.unlocked = true
		s.presenceGranted = s.checkPresenceTokenLocked(presenceToken)
		return true, nil
	} else if statErr != nil {
		return false, statErr
	}

	salt, key, data, err := loadEncryptedStore(s.path, passphrase)
	if err != nil {
		if errors.Is(err, errUnlockPassphraseInvalid) {
			return false, errUnlockPassphraseInvalid
		}
		return false, err
	}
	s.salt = salt
	s.key = key
	s.state = &data
	s.rebuildIndexLocked()
	s.unlocked = true
	s.presenceGranted = s.checkPresenceTokenLocked(presenceToken)
	return false, nil
}

func (s *vaultStore) Lock() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.unlocked {
		return nil
	}
	if err := s.persistLocked(); err != nil {
		return err
	}
	for i := range s.key {
		s.key[i] = 0
	}
	s.key = nil
	s.salt = nil
	s.state = nil
	s.index = nil
	s.objectTokens = nil
	s.chunkLexIndex = nil
	s.chunkLexTokens = nil
	s.chunkLexDocLen = nil
	s.semanticChunks = nil
	s.objectChunkIDs = nil
	s.annBuckets = nil
	s.chunkANNKeys = nil
	if s.annEngine != nil {
		s.annEngine.Close()
	}
	s.embeddingCache = map[string][]float32{}
	s.embeddingCacheAt = map[string]time.Time{}
	s.queryNormCache = map[string]string{}
	s.candidateCache = map[string]cachedCandidateSet{}
	s.rerankCache = map[string]cachedCandidateSet{}
	s.unlocked = false
	s.presenceGranted = false
	return nil
}

func (s *vaultStore) ListCollections() ([]collectionHit, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if err := s.ensureUnlockedLocked(); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(s.state.Collections))
	for name := range s.state.Collections {
		names = append(names, name)
	}
	sort.Strings(names)

	collectionStatus := map[string]struct {
		indexed int
		pending int
		failed  int
	}{}
	for id, obj := range s.state.Objects {
		col := normalizeCollectionName(obj.Collection)
		state := s.objectIndexStateLocked(id)
		stats := collectionStatus[col]
		switch state {
		case "pending", "indexing":
			stats.pending++
		case "failed":
			stats.failed++
		default:
			stats.indexed++
		}
		collectionStatus[col] = stats
	}

	out := make([]collectionHit, 0, len(names))
	for _, name := range names {
		col := s.state.Collections[name]
		stats := collectionStatus[normalizeCollectionName(name)]
		out = append(out, collectionHit{
			Name:        col.Name,
			Tier:        col.Tier,
			Description: col.Description,
			Accessible:  s.collectionAccessibleLocked(col),
			Indexed:     stats.indexed,
			Pending:     stats.pending,
			Failed:      stats.failed,
		})
	}
	return out, nil
}

func (s *vaultStore) CreateCollection(name, tier, description string) (collectionHit, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureUnlockedLocked(); err != nil {
		return collectionHit{}, err
	}
	name = normalizeCollectionName(name)
	if name == "" {
		return collectionHit{}, errInvalidCollectionName
	}
	if _, ok := s.state.Collections[name]; ok {
		return collectionHit{}, fmt.Errorf("%w: %s", errCollectionAlreadyExists, name)
	}
	tier = normalizeTier(tier)
	if tier == "" {
		tier = vaultTierAlwaysOn
	}
	if tier != vaultTierAlwaysOn && tier != vaultTierPresenceRequired {
		return collectionHit{}, fmt.Errorf("%w: %s", errInvalidCollectionTier, tier)
	}
	col := vaultCollection{
		Name:        name,
		Tier:        tier,
		Description: strings.TrimSpace(description),
	}
	s.state.Collections[name] = col
	if err := s.persistLocked(); err != nil {
		return collectionHit{}, err
	}
	return collectionHit{
		Name:        col.Name,
		Tier:        col.Tier,
		Description: col.Description,
		Accessible:  s.collectionAccessibleLocked(col),
	}, nil
}

func (s *vaultStore) UpdateCollection(name, tier, description string) (collectionHit, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureUnlockedLocked(); err != nil {
		return collectionHit{}, err
	}
	name = normalizeCollectionName(name)
	if name == "" {
		return collectionHit{}, errInvalidCollectionName
	}

	col, ok := s.state.Collections[name]
	if !ok {
		return collectionHit{}, fmt.Errorf("%w: %s", errCollectionNotFound, name)
	}

	if strings.TrimSpace(tier) != "" {
		normalizedTier := normalizeTier(tier)
		if normalizedTier != vaultTierAlwaysOn && normalizedTier != vaultTierPresenceRequired {
			return collectionHit{}, fmt.Errorf("%w: %s", errInvalidCollectionTier, tier)
		}
		col.Tier = normalizedTier
	}
	col.Description = strings.TrimSpace(description)
	s.state.Collections[name] = col

	if err := s.persistLocked(); err != nil {
		return collectionHit{}, err
	}
	return collectionHit{
		Name:        col.Name,
		Tier:        col.Tier,
		Description: col.Description,
		Accessible:  s.collectionAccessibleLocked(col),
	}, nil
}

func (s *vaultStore) ListItems(collection string, limit int) ([]itemHit, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if err := s.ensureUnlockedLocked(); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 50
	}

	collection = normalizeCollectionName(collection)
	if collection != "" {
		if _, err := s.requireCollectionAccessLocked(collection); err != nil {
			return nil, err
		}
	}

	out := make([]itemHit, 0, minInt(limit, len(s.state.Order)))
	for _, id := range s.state.Order {
		obj, ok := s.state.Objects[id]
		if !ok {
			continue
		}
		if collection != "" && normalizeCollectionName(obj.Collection) != collection {
			continue
		}
		if _, err := s.requireCollectionAccessLocked(obj.Collection); err != nil {
			continue
		}
		preview := strings.TrimSpace(obj.Content)
		if len([]rune(preview)) > 140 {
			runes := []rune(preview)
			preview = string(runes[:140]) + "..."
		}
		out = append(out, itemHit{
			ID:         obj.ID,
			Collection: obj.Collection,
			Title:      obj.Title,
			Preview:    preview,
			Bytes:      len([]byte(obj.Content)),
			IndexState: s.objectIndexStateLocked(obj.ID),
			UpdatedAt:  obj.UpdatedAt,
		})
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (s *vaultStore) ListConnectorStatuses() ([]connectorStatus, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if err := s.ensureUnlockedLocked(); err != nil {
		return nil, err
	}

	providers := connectorProviders()
	out := make([]connectorStatus, 0, len(providers))
	for _, provider := range providers {
		credential, ok := s.state.ConnectorTokens[provider]
		out = append(out, connectorStatus{
			Provider:   provider,
			Configured: ok && strings.TrimSpace(credential.Token) != "",
			UpdatedAt:  credential.UpdatedAt,
		})
	}
	return out, nil
}

func (s *vaultStore) SetConnectorToken(provider, token string) (connectorStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureUnlockedLocked(); err != nil {
		return connectorStatus{}, err
	}
	provider = normalizeConnectorProvider(provider)
	if provider == "" {
		return connectorStatus{}, errInvalidConnectorProvider
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return connectorStatus{}, errConnectorTokenRequired
	}
	now := time.Now().UTC()
	s.state.ConnectorTokens[provider] = connectorCredential{
		Token:     token,
		UpdatedAt: now,
	}
	if err := s.persistLocked(); err != nil {
		return connectorStatus{}, err
	}
	return connectorStatus{
		Provider:   provider,
		Configured: true,
		UpdatedAt:  now,
	}, nil
}

func (s *vaultStore) RemoveConnectorToken(provider string) (connectorStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureUnlockedLocked(); err != nil {
		return connectorStatus{}, err
	}
	provider = normalizeConnectorProvider(provider)
	if provider == "" {
		return connectorStatus{}, errInvalidConnectorProvider
	}
	delete(s.state.ConnectorTokens, provider)
	if err := s.persistLocked(); err != nil {
		return connectorStatus{}, err
	}
	return connectorStatus{
		Provider:   provider,
		Configured: false,
	}, nil
}

func (s *vaultStore) GetConnectorToken(provider string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if err := s.ensureUnlockedLocked(); err != nil {
		return "", err
	}
	provider = normalizeConnectorProvider(provider)
	if provider == "" {
		return "", errInvalidConnectorProvider
	}
	credential, ok := s.state.ConnectorTokens[provider]
	if !ok {
		return "", fmt.Errorf("%w: %s", errObjectNotFound, provider)
	}
	token := strings.TrimSpace(credential.Token)
	if token == "" {
		return "", fmt.Errorf("%w: %s", errObjectNotFound, provider)
	}
	return token, nil
}

func (s *vaultStore) QueueApproval(action, collection, resourceID, summary string, metadata map[string]string) (approvalRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureUnlockedLocked(); err != nil {
		return approvalRequest{}, err
	}
	action = strings.TrimSpace(strings.ToLower(action))
	if action == "" {
		return approvalRequest{}, errInvalidApprovalAction
	}
	collection = normalizeCollectionName(collection)
	if collection != "" {
		if _, err := s.requireCollectionAccessLocked(collection); err != nil {
			return approvalRequest{}, err
		}
	}
	if s.state.NextApprovalID <= 0 {
		s.state.NextApprovalID = 1
	}
	now := time.Now().UTC()
	id := fmt.Sprintf("approval_%04d", s.state.NextApprovalID)
	s.state.NextApprovalID++

	req := approvalRequest{
		ID:         id,
		Action:     action,
		Collection: collection,
		ResourceID: strings.TrimSpace(resourceID),
		Summary:    strings.TrimSpace(summary),
		Metadata:   copyStringMap(metadata),
		Status:     "pending",
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	s.state.Approvals[id] = req
	s.state.ApprovalOrder = append([]string{id}, s.state.ApprovalOrder...)
	if err := s.persistLocked(); err != nil {
		return approvalRequest{}, err
	}
	return req, nil
}

func (s *vaultStore) ListApprovals(status string, limit int) ([]approvalRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if err := s.ensureUnlockedLocked(); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 20
	}
	status = normalizeApprovalStatus(status)
	if strings.TrimSpace(status) != "" && status == "invalid" {
		return nil, errInvalidApprovalAction
	}

	out := make([]approvalRequest, 0, minInt(limit, len(s.state.ApprovalOrder)))
	for _, id := range s.state.ApprovalOrder {
		req, ok := s.state.Approvals[id]
		if !ok {
			continue
		}
		if status != "" && req.Status != status {
			continue
		}
		if req.Collection != "" {
			if _, err := s.requireCollectionAccessLocked(req.Collection); err != nil {
				continue
			}
		}
		out = append(out, req)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (s *vaultStore) ResolveApproval(id, decision, reason string) (approvalRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureUnlockedLocked(); err != nil {
		return approvalRequest{}, err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return approvalRequest{}, errApprovalNotFound
	}
	req, ok := s.state.Approvals[id]
	if !ok {
		return approvalRequest{}, fmt.Errorf("%w: %s", errApprovalNotFound, id)
	}
	if req.Collection != "" {
		if _, err := s.requireCollectionAccessLocked(req.Collection); err != nil {
			return approvalRequest{}, err
		}
	}
	decision = normalizeApprovalStatus(decision)
	if decision != "approved" && decision != "rejected" {
		return approvalRequest{}, errInvalidApprovalAction
	}
	if req.Status != "pending" {
		return approvalRequest{}, fmt.Errorf("%w: approval already resolved", errInvalidApprovalAction)
	}

	req.Status = decision
	req.Reason = strings.TrimSpace(reason)
	req.UpdatedAt = time.Now().UTC()
	s.state.Approvals[id] = req
	if err := s.persistLocked(); err != nil {
		return approvalRequest{}, err
	}
	return req, nil
}

func (s *vaultStore) Search(query string, limit int, collection string) ([]searchHit, error) {
	return s.SearchExpanded(query, limit, collection, defaultQueryExpansion(query, collection))
}

func (s *vaultStore) ReadSnippets(ids []string, query string, maxBytes, maxCharsPerSnippet int) (hits []snippetHit, truncated bool, missing []string, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if err := s.ensureUnlockedLocked(); err != nil {
		return nil, false, nil, err
	}
	if hasDuplicateIDs(ids) {
		return nil, false, nil, errEgressOverlapDetected
	}

	remaining := maxBytes
	out := make([]snippetHit, 0, len(ids))
	var notFound []string
	wasTruncated := false
	lastSnippet := ""
	var placeholderFallback *snippetHit
	expansion := defaultQueryExpansion(query, "")

	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if remaining <= 0 {
			wasTruncated = true
			break
		}

		// Allow direct chunk handles in addition to object IDs.
		if chunk, ok := s.semanticChunks[id]; ok {
			obj, ok := s.state.Objects[chunk.ObjectID]
			if !ok {
				notFound = append(notFound, id)
				continue
			}
			if _, err := s.requireCollectionAccessLocked(obj.Collection); err != nil {
				return nil, false, nil, err
			}
			selection := selectSnippet(chunk.Text, query, maxCharsPerSnippet, s.retrieval)
			selection.startChar += chunk.StartChar
			selection.endChar += chunk.StartChar
			selectionScore := scoreSnippetForQuery(selection.snippet, query)
			if strings.TrimSpace(query) != "" {
				objectSelection := selectSnippet(obj.Content, query, maxCharsPerSnippet, s.retrieval)
				objectScore := scoreSnippetForQuery(objectSelection.snippet, query)
				if objectScore > selectionScore+0.05 {
					selection = objectSelection
					selectionScore = objectScore
				}
				for _, altChunk := range s.topChunksForObjectExpandedLocked(obj.ID, query, expansion, 10) {
					altSelection := selectSnippet(altChunk.Text, query, maxCharsPerSnippet, s.retrieval)
					altSelection.startChar += altChunk.StartChar
					altSelection.endChar += altChunk.StartChar
					altScore := scoreSnippetForQuery(altSelection.snippet, query)
					if altScore > selectionScore+0.02 {
						selection = altSelection
						selectionScore = altScore
					}
				}
			}
			if selection.snippet == "" && len(chunk.Text) > 0 {
				return nil, false, nil, errEgressCoverageExceeded
			}
			if !isReadableSnippet(selection.snippet) {
				wasTruncated = true
				if placeholderFallback == nil {
					placeholder := snippetHit{
						ID:         id,
						Collection: obj.Collection,
						Snippet:    selection.snippet,
						Bytes:      len([]byte(selection.snippet)),
						StartChar:  selection.startChar,
						EndChar:    selection.endChar,
						Redacted:   selection.redacted,
					}
					placeholderFallback = &placeholder
				}
				continue
			}
			if lastSnippet != "" && scoreOverlap(lastSnippet, selection.snippet) >= 0.95 {
				wasTruncated = true
				continue
			}
			snippet, wasCut := bytePrefix(selection.snippet, remaining)
			size := len([]byte(snippet))
			if size == 0 {
				wasTruncated = true
				break
			}
			out = append(out, snippetHit{
				ID:         id,
				Collection: obj.Collection,
				Snippet:    snippet,
				Bytes:      size,
				StartChar:  selection.startChar,
				EndChar:    selection.endChar,
				Redacted:   selection.redacted,
			})
			remaining -= size
			wasTruncated = wasTruncated || wasCut || selection.truncated
			lastSnippet = snippet
			continue
		}

		obj, ok := s.state.Objects[id]
		if !ok {
			notFound = append(notFound, id)
			continue
		}
		if _, err := s.requireCollectionAccessLocked(obj.Collection); err != nil {
			return nil, false, nil, err
		}
		selection := s.selectSnippetForObjectLocked(obj, query, maxCharsPerSnippet)
		selectionScore := scoreSnippetForQuery(selection.snippet, query)
		if strings.TrimSpace(query) != "" {
			if bestChunk, ok := s.bestChunkForObjectExpandedLocked(obj.ID, query, expansion); ok {
				chunkSelection := selectSnippet(bestChunk.Text, query, maxCharsPerSnippet, s.retrieval)
				chunkSelection.startChar += bestChunk.StartChar
				chunkSelection.endChar += bestChunk.StartChar
				chunkScore := scoreSnippetForQuery(chunkSelection.snippet, query)
				// Prefer chunk-level selection only when it is clearly more relevant.
				if chunkScore > selectionScore+0.05 || (!isReadableSnippet(selection.snippet) && isReadableSnippet(chunkSelection.snippet)) {
					selection = chunkSelection
					selectionScore = chunkScore
				}
			}
			// Last-pass object-wide anchor search to avoid sending irrelevant chunk text.
			objectSelection := selectSnippet(obj.Content, query, maxCharsPerSnippet, s.retrieval)
			objectScore := scoreSnippetForQuery(objectSelection.snippet, query)
			if objectScore > selectionScore+0.05 {
				selection = objectSelection
				selectionScore = objectScore
			}
			// If selection is still unreadable, try additional top reranked chunks for the same object.
			if !isReadableSnippet(selection.snippet) {
				for _, altChunk := range s.topChunksForObjectExpandedLocked(obj.ID, query, expansion, 8) {
					altSelection := selectSnippet(altChunk.Text, query, maxCharsPerSnippet, s.retrieval)
					altSelection.startChar += altChunk.StartChar
					altSelection.endChar += altChunk.StartChar
					if !isReadableSnippet(altSelection.snippet) {
						continue
					}
					altScore := scoreSnippetForQuery(altSelection.snippet, query)
					if altScore > selectionScore {
						selection = altSelection
						selectionScore = altScore
					}
				}
			}
		}
		if selection.snippet == "" && len(obj.Content) > 0 {
			return nil, false, nil, errEgressCoverageExceeded
		}
		if !isReadableSnippet(selection.snippet) {
			// Keep one placeholder as fallback, but continue scanning for readable snippets.
			wasTruncated = true
			if placeholderFallback == nil {
				placeholder := snippetHit{
					ID:         obj.ID,
					Collection: obj.Collection,
					Snippet:    selection.snippet,
					Bytes:      len([]byte(selection.snippet)),
					StartChar:  selection.startChar,
					EndChar:    selection.endChar,
					Redacted:   selection.redacted,
				}
				placeholderFallback = &placeholder
			}
			continue
		}
		if lastSnippet != "" && scoreOverlap(lastSnippet, selection.snippet) >= 0.95 {
			// Skip near-duplicate snippet payloads instead of failing the whole call.
			wasTruncated = true
			continue
		}
		snippet, wasCut := bytePrefix(selection.snippet, remaining)
		size := len([]byte(snippet))
		if size == 0 {
			wasTruncated = true
			break
		}
		out = append(out, snippetHit{
			ID:         obj.ID,
			Collection: obj.Collection,
			Snippet:    snippet,
			Bytes:      size,
			StartChar:  selection.startChar,
			EndChar:    selection.endChar,
			Redacted:   selection.redacted,
		})
		remaining -= size
		wasTruncated = wasTruncated || wasCut || selection.truncated
		lastSnippet = snippet
	}
	if len(out) == 0 && placeholderFallback != nil && maxBytes > 0 {
		snippet := placeholderFallback.Snippet
		if len([]byte(snippet)) > maxBytes {
			var cut bool
			snippet, cut = bytePrefix(snippet, maxBytes)
			if cut {
				wasTruncated = true
			}
		}
		size := len([]byte(snippet))
		if size > 0 {
			out = append(out, snippetHit{
				ID:         placeholderFallback.ID,
				Collection: placeholderFallback.Collection,
				Snippet:    snippet,
				Bytes:      size,
				StartChar:  placeholderFallback.StartChar,
				EndChar:    placeholderFallback.EndChar,
				Redacted:   placeholderFallback.Redacted,
			})
		}
	}

	return out, wasTruncated, notFound, nil
}

func isReadableSnippet(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	return s != snippetNonTextPlaceholder
}

func (s *vaultStore) Write(id, collection, title, content string) (obj vaultObject, created bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureUnlockedLocked(); err != nil {
		return vaultObject{}, false, err
	}

	collection = normalizeCollectionName(collection)
	if collection == "" {
		collection = "agent_memory"
	}
	if _, err := s.requireCollectionAccessLocked(collection); err != nil {
		return vaultObject{}, false, err
	}
	title = strings.TrimSpace(title)
	if title == "" {
		title = "Memory note"
	}
	content = strings.TrimSpace(content)

	id = strings.TrimSpace(id)
	now := time.Now().UTC()
	if id == "" {
		id = fmt.Sprintf("note_%04d", s.state.NextNoteID)
		s.state.NextNoteID++
		obj = vaultObject{
			ID:         id,
			Collection: collection,
			Title:      title,
			Content:    content,
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		s.state.Order = append([]string{id}, s.state.Order...)
		s.state.Objects[id] = obj
		s.enqueueIndexJobLocked(obj.ID, obj.Collection, "create")
		s.processIndexQueueLocked(1)
		if err := s.persistLocked(); err != nil {
			return vaultObject{}, false, err
		}
		return obj, true, nil
	}

	existing, ok := s.state.Objects[id]
	if !ok {
		return vaultObject{}, false, fmt.Errorf("%w: %s", errObjectNotFound, id)
	}
	if _, err := s.requireCollectionAccessLocked(existing.Collection); err != nil {
		return vaultObject{}, false, err
	}
	s.unindexObjectLocked(existing.ID)
	existing.Collection = collection
	existing.Title = title
	existing.Content = content
	existing.UpdatedAt = now
	s.state.Objects[id] = existing
	s.enqueueIndexJobLocked(existing.ID, existing.Collection, "update")
	s.processIndexQueueLocked(1)
	if err := s.persistLocked(); err != nil {
		return vaultObject{}, false, err
	}
	return existing, false, nil
}

func (s *vaultStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureUnlockedLocked(); err != nil {
		return err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("%w: empty id", errObjectNotFound)
	}

	obj, ok := s.state.Objects[id]
	if !ok {
		return fmt.Errorf("%w: %s", errObjectNotFound, id)
	}
	if _, err := s.requireCollectionAccessLocked(obj.Collection); err != nil {
		return err
	}
	s.unindexObjectLocked(id)
	delete(s.state.Objects, id)
	delete(s.state.IndexStatuses, id)
	s.removeQueuedIndexJobsLocked(id)

	newOrder := make([]string, 0, len(s.state.Order))
	for _, currentID := range s.state.Order {
		if currentID == id {
			continue
		}
		newOrder = append(newOrder, currentID)
	}
	s.state.Order = newOrder
	if err := s.persistLocked(); err != nil {
		return err
	}
	return nil
}

func (s *vaultStore) DeleteMany(ids []string) (deleted int, missing []string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureUnlockedLocked(); err != nil {
		return 0, nil, err
	}
	if len(ids) == 0 {
		return 0, nil, nil
	}

	dedup := make([]string, 0, len(ids))
	seen := make(map[string]struct{}, len(ids))
	for _, raw := range ids {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		dedup = append(dedup, id)
	}
	if len(dedup) == 0 {
		return 0, nil, nil
	}

	toDelete := make(map[string]struct{}, len(dedup))
	for _, id := range dedup {
		obj, ok := s.state.Objects[id]
		if !ok {
			missing = append(missing, id)
			continue
		}
		if _, err := s.requireCollectionAccessLocked(obj.Collection); err != nil {
			return 0, nil, err
		}
		toDelete[id] = struct{}{}
	}
	if len(toDelete) == 0 {
		return 0, missing, nil
	}

	for id := range toDelete {
		s.unindexObjectLocked(id)
		delete(s.state.Objects, id)
		delete(s.state.IndexStatuses, id)
		s.removeQueuedIndexJobsLocked(id)
	}
	newOrder := make([]string, 0, len(s.state.Order))
	for _, currentID := range s.state.Order {
		if _, ok := toDelete[currentID]; ok {
			continue
		}
		newOrder = append(newOrder, currentID)
	}
	s.state.Order = newOrder
	if err := s.persistLocked(); err != nil {
		return 0, nil, err
	}
	return len(toDelete), missing, nil
}

func (s *vaultStore) DeleteAll(collection string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureUnlockedLocked(); err != nil {
		return 0, err
	}
	filter := normalizeCollectionName(collection)
	if filter != "" {
		if _, err := s.requireCollectionAccessLocked(filter); err != nil {
			return 0, err
		}
	}

	toDelete := make(map[string]struct{}, len(s.state.Objects))
	for id, obj := range s.state.Objects {
		if filter != "" && normalizeCollectionName(obj.Collection) != filter {
			continue
		}
		if _, err := s.requireCollectionAccessLocked(obj.Collection); err != nil {
			return 0, err
		}
		toDelete[id] = struct{}{}
	}
	if len(toDelete) == 0 {
		return 0, nil
	}

	for id := range toDelete {
		s.unindexObjectLocked(id)
		delete(s.state.Objects, id)
		delete(s.state.IndexStatuses, id)
		s.removeQueuedIndexJobsLocked(id)
	}
	newOrder := make([]string, 0, len(s.state.Order))
	for _, currentID := range s.state.Order {
		if _, ok := toDelete[currentID]; ok {
			continue
		}
		newOrder = append(newOrder, currentID)
	}
	s.state.Order = newOrder
	if err := s.persistLocked(); err != nil {
		return 0, err
	}
	return len(toDelete), nil
}

func (s *vaultStore) Ingest(collection, title, contentType string, raw []byte, maxExtractedChars int) (obj vaultObject, extractedChars int, extractedTruncated bool, err error) {
	extracted, truncated, err := extractContentByType(contentType, raw, maxExtractedChars)
	if err != nil {
		return vaultObject{}, 0, false, err
	}
	extracted = normalizeSpacing(extracted)
	if extracted == "" {
		return vaultObject{}, 0, false, errExtractedContentEmpty
	}
	obj, _, err = s.Write("", collection, title, extracted)
	if err != nil {
		return vaultObject{}, 0, false, err
	}
	return obj, len([]rune(extracted)), truncated, nil
}

func (s *vaultStore) rebuildIndexLocked() {
	s.index = map[string]map[string]int{}
	s.objectTokens = map[string]map[string]int{}
	s.chunkLexIndex = map[string]map[string]int{}
	s.chunkLexTokens = map[string]map[string]int{}
	s.chunkLexDocLen = map[string]int{}
	s.semanticChunks = map[string]semanticChunk{}
	s.objectChunkIDs = map[string][]string{}
	s.annBuckets = map[uint64][]string{}
	s.chunkANNKeys = map[string][]uint64{}
	s.resetANNEngineLocked(semanticANNCandidateLimit)
	s.embeddingCache = map[string][]float32{}
	s.embeddingCacheAt = map[string]time.Time{}
	s.queryNormCache = map[string]string{}
	s.candidateCache = map[string]cachedCandidateSet{}
	s.rerankCache = map[string]cachedCandidateSet{}
	if s.state == nil {
		s.setANNInitStatusLocked("no_state", 0)
		return
	}
	if s.state.IndexStatuses == nil {
		s.state.IndexStatuses = map[string]objectIndexStatus{}
	}
	for _, obj := range s.state.Objects {
		s.indexObjectLexicalLocked(obj)
	}
	if s.loadSemanticIndexFromStateLocked() {
		s.state.IndexQueue = nil
		now := time.Now().UTC()
		for id, obj := range s.state.Objects {
			state := s.state.IndexStatuses[id]
			state.ObjectID = id
			state.Collection = normalizeCollectionName(obj.Collection)
			if strings.TrimSpace(state.State) == "" || state.State == "pending" || state.State == "indexing" {
				state.State = "ready"
			}
			if state.LastIndexed.IsZero() {
				state.LastIndexed = now
			}
			state.UpdatedAt = now
			s.state.IndexStatuses[id] = state
		}
		s.state.IndexMeta = s.retrieval.indexMeta
		s.rebuildChunkLexicalIndexLocked()
		return
	}
	s.rebuildIndexFromObjectsLocked("rebuild_from_objects")
}

func (s *vaultStore) rebuildIndexFromObjectsLocked(reason string) {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "rebuild_from_objects"
	}
	s.index = map[string]map[string]int{}
	s.objectTokens = map[string]map[string]int{}
	s.chunkLexIndex = map[string]map[string]int{}
	s.chunkLexTokens = map[string]map[string]int{}
	s.chunkLexDocLen = map[string]int{}
	s.semanticChunks = map[string]semanticChunk{}
	s.objectChunkIDs = map[string][]string{}
	s.annBuckets = map[uint64][]string{}
	s.chunkANNKeys = map[string][]uint64{}
	s.resetANNEngineLocked(semanticANNCandidateLimit)
	s.invalidateRetrievalCachesLocked()
	if s.state == nil {
		s.setANNInitStatusLocked("no_state", 0)
		return
	}
	if s.state.IndexStatuses == nil {
		s.state.IndexStatuses = map[string]objectIndexStatus{}
	}
	now := time.Now().UTC()
	for _, obj := range s.state.Objects {
		s.indexObjectLexicalLocked(obj)
		s.indexObjectChunksLocked(obj)
		s.state.IndexStatuses[obj.ID] = objectIndexStatus{
			ObjectID:    obj.ID,
			Collection:  normalizeCollectionName(obj.Collection),
			State:       "ready",
			Reason:      reason,
			Attempts:    1,
			UpdatedAt:   now,
			LastIndexed: now,
		}
	}
	s.state.IndexQueue = nil
	s.state.IndexMeta = s.retrieval.indexMeta
	s.rebuildChunkLexicalIndexLocked()
	if s.annEngine == nil {
		s.setANNInitStatusLocked("lsh_rebuilt_from_vectors", len(s.semanticChunks))
		return
	}
	s.setANNInitStatusLocked("hnsw_rebuilt_from_vectors", len(s.semanticChunks))
}

func (s *vaultStore) ReindexAll(reason string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureUnlockedLocked(); err != nil {
		return 0, err
	}
	total := len(s.state.Objects)
	s.rebuildIndexFromObjectsLocked(reason)
	if err := s.persistLocked(); err != nil {
		return 0, err
	}
	return total, nil
}

func (s *vaultStore) indexObjectLocked(obj vaultObject) {
	s.invalidateRetrievalCachesLocked()
	s.indexObjectLexicalLocked(obj)
	s.indexObjectChunksLocked(obj)
}

func (s *vaultStore) indexObjectLexicalLocked(obj vaultObject) {
	if s.index == nil {
		s.index = map[string]map[string]int{}
	}
	if s.objectTokens == nil {
		s.objectTokens = map[string]map[string]int{}
	}
	tokens := buildTokenCounts(joinForIndex(obj.Title, obj.Content))
	s.objectTokens[obj.ID] = tokens
	for token, freq := range tokens {
		postings, ok := s.index[token]
		if !ok {
			postings = map[string]int{}
			s.index[token] = postings
		}
		postings[obj.ID] = freq
	}
}

func (s *vaultStore) unindexObjectLocked(id string) {
	s.invalidateRetrievalCachesLocked()
	s.unindexObjectLexicalLocked(id)
	s.unindexObjectChunksLocked(id)
}

func (s *vaultStore) invalidateRetrievalCachesLocked() {
	s.embeddingCache = map[string][]float32{}
	s.embeddingCacheAt = map[string]time.Time{}
	s.queryNormCache = map[string]string{}
	s.candidateCache = map[string]cachedCandidateSet{}
	s.rerankCache = map[string]cachedCandidateSet{}
}

func (s *vaultStore) resetANNEngineLocked(capacity int) {
	if s == nil || s.annEngine == nil {
		return
	}
	if capacity <= 0 {
		capacity = semanticANNCandidateLimit
	}
	if err := s.annEngine.Reset(semanticEmbeddingDims, capacity); err != nil {
		// Disable broken ANN engine and continue with deterministic fallback.
		s.annEngine.Close()
		s.annEngine = nil
		s.retrieval.indexMeta.ANNVersion = "lsh.ann.v1"
		s.setANNInitStatusLocked("lsh_fallback", 0)
		return
	}
	s.retrieval.indexMeta.ANNVersion = resolveANNVersion(s.retrieval.annProvider, s.annEngine)
}

func (s *vaultStore) setANNInitStatusLocked(mode string, chunks int) {
	s.lastANNInitMode = strings.TrimSpace(mode)
	if chunks < 0 {
		chunks = 0
	}
	s.lastANNChunks = chunks
	s.lastANNInitAt = time.Now().UTC()
}

func (s *vaultStore) enqueueIndexJobLocked(objectID, collection, reason string) {
	objectID = strings.TrimSpace(objectID)
	if objectID == "" || s.state == nil {
		return
	}
	if s.state.IndexStatuses == nil {
		s.state.IndexStatuses = map[string]objectIndexStatus{}
	}
	if s.state.NextIndexJobID <= 0 {
		s.state.NextIndexJobID = 1
	}
	now := time.Now().UTC()
	status := s.state.IndexStatuses[objectID]
	status.ObjectID = objectID
	status.Collection = normalizeCollectionName(collection)
	status.State = "pending"
	status.Reason = strings.TrimSpace(reason)
	status.UpdatedAt = now
	s.state.IndexStatuses[objectID] = status

	for _, job := range s.state.IndexQueue {
		if strings.TrimSpace(job.ObjectID) == objectID {
			return
		}
	}
	jobID := fmt.Sprintf("idx_%05d", s.state.NextIndexJobID)
	s.state.NextIndexJobID++
	s.state.IndexQueue = append(s.state.IndexQueue, indexJob{
		ID:         jobID,
		ObjectID:   objectID,
		Collection: status.Collection,
		Reason:     status.Reason,
		EnqueuedAt: now,
	})
}

func (s *vaultStore) processIndexQueueLocked(maxJobs int) int {
	if s.state == nil || len(s.state.IndexQueue) == 0 {
		return 0
	}
	if maxJobs <= 0 {
		maxJobs = 1
	}
	processed := 0
	for processed < maxJobs && len(s.state.IndexQueue) > 0 {
		job := s.state.IndexQueue[0]
		s.state.IndexQueue = s.state.IndexQueue[1:]

		obj, ok := s.state.Objects[job.ObjectID]
		if !ok {
			delete(s.state.IndexStatuses, job.ObjectID)
			continue
		}
		now := time.Now().UTC()
		status := s.state.IndexStatuses[job.ObjectID]
		status.ObjectID = job.ObjectID
		status.Collection = normalizeCollectionName(obj.Collection)
		status.State = "indexing"
		status.Reason = job.Reason
		status.Attempts++
		status.UpdatedAt = now
		s.state.IndexStatuses[job.ObjectID] = status

		s.invalidateRetrievalCachesLocked()
		s.unindexObjectLexicalLocked(job.ObjectID)
		s.unindexObjectChunksLocked(job.ObjectID)
		s.indexObjectLexicalLocked(obj)
		s.indexObjectChunksLocked(obj)

		status = s.state.IndexStatuses[job.ObjectID]
		status.State = "ready"
		status.LastError = ""
		status.Collection = normalizeCollectionName(obj.Collection)
		status.LastIndexed = time.Now().UTC()
		status.UpdatedAt = status.LastIndexed
		s.state.IndexStatuses[job.ObjectID] = status
		processed++
	}
	return processed
}

func (s *vaultStore) removeQueuedIndexJobsLocked(objectID string) {
	if s.state == nil || len(s.state.IndexQueue) == 0 {
		return
	}
	objectID = strings.TrimSpace(objectID)
	if objectID == "" {
		return
	}
	filtered := s.state.IndexQueue[:0]
	for _, job := range s.state.IndexQueue {
		if strings.TrimSpace(job.ObjectID) == objectID {
			continue
		}
		filtered = append(filtered, job)
	}
	s.state.IndexQueue = append([]indexJob(nil), filtered...)
}

func (s *vaultStore) objectIndexStateLocked(objectID string) string {
	if s.state == nil {
		return "unknown"
	}
	status, ok := s.state.IndexStatuses[objectID]
	if ok && strings.TrimSpace(status.State) != "" {
		return strings.TrimSpace(status.State)
	}
	if _, exists := s.state.Objects[objectID]; exists {
		return "ready"
	}
	return "unknown"
}

func (s *vaultStore) unindexObjectLexicalLocked(id string) {
	if s.index == nil || s.objectTokens == nil {
		return
	}
	tokens, ok := s.objectTokens[id]
	if !ok {
		return
	}
	for token := range tokens {
		postings := s.index[token]
		delete(postings, id)
		if len(postings) == 0 {
			delete(s.index, token)
		}
	}
	delete(s.objectTokens, id)
}

func (s *vaultStore) ensureUnlockedLocked() error {
	if !s.unlocked || s.state == nil {
		return errVaultLocked
	}
	return nil
}

func (s *vaultStore) requireCollectionAccessLocked(collection string) (vaultCollection, error) {
	collection = normalizeCollectionName(collection)
	col, ok := s.state.Collections[collection]
	if !ok {
		return vaultCollection{}, fmt.Errorf("%w: %s", errCollectionNotFound, collection)
	}
	if !s.collectionAccessibleLocked(col) {
		return vaultCollection{}, fmt.Errorf("%w: %s", errCollectionAccessDenied, collection)
	}
	return col, nil
}

func (s *vaultStore) collectionAccessibleLocked(col vaultCollection) bool {
	tier := normalizeTier(col.Tier)
	if tier != vaultTierPresenceRequired {
		return true
	}
	if strings.TrimSpace(s.presenceToken) == "" {
		return true
	}
	return s.presenceGranted
}

func (s *vaultStore) checkPresenceTokenLocked(provided string) bool {
	expected := strings.TrimSpace(s.presenceToken)
	if expected == "" {
		return true
	}
	got := strings.TrimSpace(provided)
	if got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(got)) == 1
}

func (s *vaultStore) persistLocked() error {
	if !s.unlocked || s.state == nil {
		return errVaultLocked
	}
	if len(s.salt) == 0 {
		return errEncryptedStorePersistFail
	}
	if len(s.key) != 32 {
		return errEncryptedStorePersistFail
	}
	s.syncSemanticStateLocked()
	s.state.IndexMeta = s.retrieval.indexMeta
	if err := saveEncryptedStore(s.path, s.salt, s.key, *s.state); err != nil {
		return err
	}
	if err := s.persistANNSnapshotLocked(); err != nil {
		return err
	}
	return nil
}

func saveEncryptedStore(path string, salt, key []byte, state vaultData) error {
	plaintext, err := json.Marshal(state)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	env := encryptedVaultFile{
		Version:    1,
		KDF:        "sha256_iter_" + strconv.Itoa(kdfRounds),
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	blob, err := json.Marshal(env)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		return err
	}
	return nil
}

func loadEncryptedStore(path, passphrase string) (salt, key []byte, data vaultData, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, vaultData{}, err
	}
	var env encryptedVaultFile
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, nil, vaultData{}, fmt.Errorf("%w: %v", errEncryptedStoreCorrupt, err)
	}

	salt, err = base64.StdEncoding.DecodeString(env.Salt)
	if err != nil {
		return nil, nil, vaultData{}, fmt.Errorf("%w: invalid salt", errEncryptedStoreCorrupt)
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, nil, vaultData{}, fmt.Errorf("%w: invalid nonce", errEncryptedStoreCorrupt)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, nil, vaultData{}, fmt.Errorf("%w: invalid ciphertext", errEncryptedStoreCorrupt)
	}

	key = deriveEncryptionKey(passphrase, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, vaultData{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, vaultData{}, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, nil, vaultData{}, errUnlockPassphraseInvalid
	}
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return nil, nil, vaultData{}, fmt.Errorf("%w: %v", errEncryptedStoreCorrupt, err)
	}
	normalizeVaultData(&data)
	return salt, key, data, nil
}

func deriveEncryptionKey(passphrase string, salt []byte) []byte {
	seed := make([]byte, 0, len(passphrase)+len(salt))
	seed = append(seed, []byte(passphrase)...)
	seed = append(seed, salt...)
	digest := sha256.Sum256(seed)
	for i := 0; i < kdfRounds; i++ {
		digest = sha256.Sum256(digest[:])
	}
	key := make([]byte, 32)
	copy(key, digest[:])
	return key
}

func normalizeCollectionName(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '_' || r == '-':
			b.WriteRune(r)
		case r == ' ':
			b.WriteRune('_')
		}
	}
	return strings.Trim(b.String(), "_-")
}

func connectorProviders() []string {
	return []string{"drive", "github", "mail", "web"}
}

func normalizeConnectorProvider(provider string) string {
	provider = strings.TrimSpace(strings.ToLower(provider))
	for _, allowed := range connectorProviders() {
		if provider == allowed {
			return allowed
		}
	}
	return ""
}

func normalizeApprovalStatus(status string) string {
	status = strings.TrimSpace(strings.ToLower(status))
	switch status {
	case "":
		return ""
	case "pending", "approved", "rejected":
		return status
	default:
		return "invalid"
	}
}

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		key := strings.TrimSpace(k)
		if key == "" {
			continue
		}
		out[key] = strings.TrimSpace(v)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeTier(tier string) string {
	tier = strings.TrimSpace(strings.ToLower(tier))
	if tier == "" {
		return ""
	}
	switch tier {
	case "always", "always_on", "always-on":
		return vaultTierAlwaysOn
	case "presence", "presence_required", "presence-required":
		return vaultTierPresenceRequired
	default:
		return tier
	}
}

func defaultVaultData() vaultData {
	now := time.Now().UTC()
	out := vaultData{
		Version: 4,
		Collections: map[string]vaultCollection{
			"work": {
				Name:        "work",
				Tier:        vaultTierAlwaysOn,
				Description: "Default work collection",
			},
			"personal": {
				Name:        "personal",
				Tier:        vaultTierAlwaysOn,
				Description: "Default personal collection",
			},
			"tax": {
				Name:        "tax",
				Tier:        vaultTierPresenceRequired,
				Description: "Sensitive tax records collection",
			},
			"health": {
				Name:        "health",
				Tier:        vaultTierPresenceRequired,
				Description: "Sensitive health records collection",
			},
			"agent_memory": {
				Name:        "agent_memory",
				Tier:        vaultTierAlwaysOn,
				Description: "Agent memory collection",
			},
		},
		Objects: map[string]vaultObject{
			"obj_work_roadmap": {
				ID:         "obj_work_roadmap",
				Collection: "work",
				Title:      "Q2 launch workstream",
				Content:    "Finalize launch checklist, release notes, and rollout communication plan.",
				CreatedAt:  now,
				UpdatedAt:  now,
			},
			"obj_personal_budget": {
				ID:         "obj_personal_budget",
				Collection: "personal",
				Title:      "Monthly household budget note",
				Content:    "Track rent, groceries, transport, and emergency buffer in one monthly table.",
				CreatedAt:  now,
				UpdatedAt:  now,
			},
			"obj_agent_memory": {
				ID:         "obj_agent_memory",
				Collection: "agent_memory",
				Title:      "Agent preference memory",
				Content:    "User prefers concise outputs, explicit budgets, and deterministic policy checks.",
				CreatedAt:  now,
				UpdatedAt:  now,
			},
			"obj_tax_stub": {
				ID:         "obj_tax_stub",
				Collection: "tax",
				Title:      "2025 estimated tax reminders",
				Content:    "Quarterly estimated tax payment reminders and filing notes.",
				CreatedAt:  now,
				UpdatedAt:  now,
			},
		},
		Order:           []string{"obj_work_roadmap", "obj_personal_budget", "obj_agent_memory", "obj_tax_stub"},
		SemanticChunks:  map[string]semanticChunk{},
		ObjectChunkIDs:  map[string][]string{},
		IndexMeta:       defaultRetrievalIndexMeta(nil, nil, "lsh.ann.v1"),
		IndexStatuses:   map[string]objectIndexStatus{},
		IndexQueue:      []indexJob{},
		NextIndexJobID:  1,
		NextNoteID:      1,
		ConnectorTokens: map[string]connectorCredential{},
		Approvals:       map[string]approvalRequest{},
		ApprovalOrder:   []string{},
		NextApprovalID:  1,
	}
	return out
}

func normalizeVaultData(data *vaultData) {
	if data == nil {
		return
	}
	if data.Collections == nil {
		data.Collections = map[string]vaultCollection{}
	}
	if data.Objects == nil {
		data.Objects = map[string]vaultObject{}
	}
	if data.SemanticChunks == nil {
		data.SemanticChunks = map[string]semanticChunk{}
	}
	if data.ObjectChunkIDs == nil {
		data.ObjectChunkIDs = map[string][]string{}
	}
	if data.ConnectorTokens == nil {
		data.ConnectorTokens = map[string]connectorCredential{}
	}
	if data.Approvals == nil {
		data.Approvals = map[string]approvalRequest{}
	}
	if data.NextNoteID <= 0 {
		data.NextNoteID = 1
	}
	if data.NextApprovalID <= 0 {
		data.NextApprovalID = 1
	}
	if data.IndexStatuses == nil {
		data.IndexStatuses = map[string]objectIndexStatus{}
	}
	if data.NextIndexJobID <= 0 {
		data.NextIndexJobID = 1
	}
	if strings.TrimSpace(data.IndexMeta.Version) == "" {
		data.IndexMeta = defaultRetrievalIndexMeta(nil, nil, "lsh.ann.v1")
	}
	defaults := defaultVaultData()
	for name, col := range defaults.Collections {
		if _, ok := data.Collections[name]; !ok {
			data.Collections[name] = col
		}
	}
	if len(data.Order) == 0 {
		for id := range data.Objects {
			data.Order = append(data.Order, id)
		}
	} else {
		seen := make(map[string]struct{}, len(data.Order))
		for _, id := range data.Order {
			seen[id] = struct{}{}
		}
		for id := range data.Objects {
			if _, ok := seen[id]; ok {
				continue
			}
			data.Order = append(data.Order, id)
		}
	}

	if len(data.ApprovalOrder) == 0 {
		for id := range data.Approvals {
			data.ApprovalOrder = append(data.ApprovalOrder, id)
		}
		sort.SliceStable(data.ApprovalOrder, func(i, j int) bool {
			a := data.Approvals[data.ApprovalOrder[i]]
			b := data.Approvals[data.ApprovalOrder[j]]
			if !a.UpdatedAt.Equal(b.UpdatedAt) {
				return a.UpdatedAt.After(b.UpdatedAt)
			}
			return data.ApprovalOrder[i] < data.ApprovalOrder[j]
		})
	} else {
		seenApprovals := make(map[string]struct{}, len(data.ApprovalOrder))
		for _, id := range data.ApprovalOrder {
			seenApprovals[id] = struct{}{}
		}
		for id := range data.Approvals {
			if _, ok := seenApprovals[id]; ok {
				continue
			}
			data.ApprovalOrder = append(data.ApprovalOrder, id)
		}
	}

	filteredQueue := make([]indexJob, 0, len(data.IndexQueue))
	seenQueued := map[string]struct{}{}
	for _, job := range data.IndexQueue {
		objectID := strings.TrimSpace(job.ObjectID)
		if objectID == "" {
			continue
		}
		if _, ok := data.Objects[objectID]; !ok {
			continue
		}
		if _, exists := seenQueued[objectID]; exists {
			continue
		}
		seenQueued[objectID] = struct{}{}
		if strings.TrimSpace(job.ID) == "" {
			job.ID = fmt.Sprintf("idx_%05d", data.NextIndexJobID)
			data.NextIndexJobID++
		}
		filteredQueue = append(filteredQueue, job)
	}
	data.IndexQueue = filteredQueue
	for objectID, status := range data.IndexStatuses {
		if _, ok := data.Objects[objectID]; !ok {
			delete(data.IndexStatuses, objectID)
			continue
		}
		if strings.TrimSpace(status.State) == "" {
			status.State = "ready"
		}
		if strings.TrimSpace(status.Collection) == "" {
			status.Collection = normalizeCollectionName(data.Objects[objectID].Collection)
		}
		status.ObjectID = objectID
		data.IndexStatuses[objectID] = status
	}
}

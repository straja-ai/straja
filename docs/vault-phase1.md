# Straja Vault Phases 1-5 (strajad) - Execution and Confidence Gates

This document tracks the implemented Phase 1, Phase 2, Phase 3, Phase 4a, Phase 4b, and Phase 5 Vault daemon baseline and the test gates required for each phase.

## Phase 1 scope implemented

- New local daemon binary: `cmd/strajad/main.go`
- New daemon module: `internal/strajad/*`
- Local MCP endpoint: `POST /mcp`
- Health/readiness endpoints: `GET /healthz`, `GET /readyz`
- Local-only request enforcement (loopback-only remote checks)
- Bearer token auth enforcement for MCP calls
- Audit pipeline with in-memory records + optional JSONL sink
- Stub capability tools (schema-versioned):
  - `vault.request` (plan-only)
  - `vault.search`
  - `vault.read_snippets`
  - `vault.write`
  - `vault.audit`
- Deterministic budget enforcement from day one:
  - max task size
  - max search results
  - max snippet object count
  - max snippet bytes
  - max write bytes
  - max audit records

## Running strajad (local)

```bash
export STRAJAD_AUTH_TOKEN="replace-with-local-token"
make strajad-run
```

Optional overrides:

- `STRAJAD_ADDR` (default `127.0.0.1:8787`)
- `STRAJAD_AUDIT_LOG` (default `./tmp/strajad/audit.jsonl`)
- `STRAJAD_STORE_PATH` (default `./tmp/strajad/vault.enc`)
- `STRAJAD_PRESENCE_TOKEN` (optional token for presence-gated collections)
- `STRAJAD_GOOGLE_OAUTH_CLIENT_ID` (required for Google Drive login)
- `STRAJAD_GOOGLE_OAUTH_CLIENT_SECRET` (required for Google Drive login)
- `STRAJAD_GOOGLE_OAUTH_REDIRECT_URL` (default `http://127.0.0.1:8787/vault/api/drive/oauth/callback`)
- `STRAJAD_MAX_INGEST_BYTES` (default `8388608`; increase for larger file/PDF imports)
- `STRAJAD_MAX_REQUEST_BODY_BYTES` (default `12582912`; keep above base64 upload payload size)

## Phase confidence gates (required tests)

The goal is high confidence that each phase behaves safely and deterministically, not just functionally.

### Phase 1 gates (implemented)

- `TestConfigValidate_RequiresLoopbackAndToken`
- `TestMCPEnforcesLocalOnlyAndAuth`
- `TestToolsList_StableSchemaAndToolSet`
- `TestVaultRequest_IsPlanOnly`
- `TestBudgetEnforcement_BlocksOversizedSearchAndSnippetRead`
- `TestVaultAudit_ReturnsAllowAndDenyRecords`

Run:

```bash
go test ./internal/strajad
```

### Phase 2 gates (zero-knowledge core, implemented)

- `TestVaultLockUnlockLifecycleAndAccessControl`
- `TestVaultEncryptedAtRestAndReload`
- `TestUnlockRejectsWrongPassphrase`
- `TestCollectionPresencePolicyEnforced`
- `TestCRUDAndAuditIntegrity`

### Phase 2 scope implemented

- Encrypted object store persisted to disk (`vault.enc`) with authenticated encryption.
- Explicit `vault.unlock` / `vault.lock` lifecycle.
- Decrypted state held only while unlocked; lock clears in-memory key/state.
- Collection model with policy tiers:
  - `always_on`
  - `presence_required`
- Presence-gated access support via optional `STRAJAD_PRESENCE_TOKEN`.
- CRUD-complete tool surface:
  - `vault.write` (create/update)
  - `vault.read_snippets` / `vault.search` (read)
  - `vault.delete` (delete)
- Collection management tool: `vault.collections` (list/create).
- Audit logging preserved for allow/deny decisions across all tool calls.

### Phase 3 gates (retrieval fundamentals)

- `TestIngestExtraction_TextAndPDF`
- `TestSearchFTSRanking`
- `TestSearchHybridSemanticRecall_ApproximateTerms`
- `TestReadSnippets_BoundariesAndByteCaps`
- `TestReadSnippets_OverlapAndRedaction`
- `TestWriteBuildsSemanticChunksForLongContent`
- `TestSemanticChunksPersistAcrossLockUnlock`
- `TestBudgetEnforcement_BlocksOversizedSearchAndSnippetRead`

### Phase 3 scope implemented

- Ingestion + extraction tool: `vault.ingest`
  - `text/plain` extraction
  - baseline `application/pdf` text extraction
- Hybrid retrieval index for `vault.search` ranking:
  - deterministic lexical token index
  - chunked semantic embedding index persisted inside encrypted vault state
  - ANN candidate routing over semantic chunks for bounded approximate nearest-neighbor lookup
  - weighted lexical + semantic ranking with semantic-anchor gating
- Chunked retrieval substrate:
  - per-object chunking with overlap
  - chunk-level vector embedding for approximate term recall
  - semantic chunk vectors survive lock/restart and are rehydrated on unlock
- Snippet window controls in `vault.read_snippets`:
  - query-centered snippets
  - query-aligned chunk selection before snippet extraction
  - explicit byte and char caps
  - start/end character boundaries in response
- Deterministic no-bulk/overlap controls:
  - duplicate-ID overlap denial
  - coverage-based egress denial for large documents
- Sensitive entity redaction on snippet egress:
  - email
  - SSN format
  - payment-card-like sequences

### Phase 4a gates (deterministic planner, plan-only, implemented)

- `TestVaultRequest_PlanContract`
- `TestVaultRequest_NoExecutionInvariant`
- `TestVaultRequest_RecommendedCallsRespectBudgets`
- `TestVaultRequest_DeterministicForSameInput`

### Phase 4a scope implemented

- Deterministic planner scaffolding module for `vault.request`.
- Structured, stable plan contract:
  - `execution_mode=plan_only`
  - `planner_mode=deterministic_scaffold_v1`
  - deterministic `plan_id`
  - step list + recommended tool calls + expected budgets + approvals + safety notes
- Recommended calls constrained to configured max budgets.
- Planner remains strictly non-executing (no internal tool execution side effects).

### Phase 4b gates (broker LLM integration, implemented)

- `TestVaultRequest_BrokerPlanContractCompatible`
- `TestVaultRequest_BrokerUnavailableFallsBack`
- `TestVaultRequest_BrokerPromptInjectionResilience`
- `TestVaultRequest_BrokerRecommendationsStillEnforceDownstreamBudgets`
- `TestInstallBrokerModel_PullsConfiguredModel`
- `TestOllamaBrokerPlan_ParsesStructuredJSON`
- `TestDecodeBrokerPlanDraft_StripsCodeFence`

### Phase 4b scope implemented

- Optional internal broker LLM integration for `vault.request` (still strict `plan_only`).
- Broker provider path starts with Ollama (`phi4-mini:3.8b` default model name).
- Contract remains stable with Phase 4a fields:
  - `execution_mode`
  - `planner_mode`
  - `deterministic`
  - `plan_id`
  - `plan`
  - `recommended_tool_calls`
  - `expected_budgets`
  - `approvals_needed`
  - `safety_notes`
- Deterministic fallback preserved:
  - broker unavailable/invalid output => deterministic scaffold plan remains active.
- Broker output sanitization + clamping:
  - only allowed tool names survive (`vault.search`, `vault.read_snippets`, `vault.ingest`, `vault.write`)
  - all recommended args clamped to configured budgets
  - required approvals from deterministic policy path are preserved.
- Installer-friendly model pull flow (no bundled model artifacts):
  - one-shot model install command:
    - `./bin/strajad --broker-install-model --broker-model phi4-mini:3.8b`
  - intended for install scripts/setup flow so model downloads at install time.

### Phase 5 gates (desktop trust surface)

- `TestVaultUIStateReflectsUnlockLockRaces`
- `TestVaultUIPolicyEditAndEnforcement`
- `TestVaultUIAuditTimelineConsistency`
- `TestVaultUI_RenderingAndLocalOnly`
- `TestVaultUIConnectorsAndApprovalsFlow`
- `TestVaultUIConnectorsAndApprovalsAuthAndLocalOnly`

### Phase 5 scope implemented

- Local trust/control UI exposed by daemon:
  - `GET /vault` (single-page control surface)
  - `GET /vault/api/state`
  - `POST /vault/api/unlock`
  - `POST /vault/api/lock`
  - `GET /vault/api/collections`
  - `POST /vault/api/collections/update`
  - `GET /vault/api/items`
  - `GET/POST /vault/api/connectors`
  - `GET/POST /vault/api/approvals`
  - `GET /vault/api/drive/oauth/start`
  - `GET /vault/api/drive/oauth/callback`
  - `GET /vault/api/drive/files`
  - `POST /vault/api/drive/import`
  - `GET /vault/api/audit`
- UI shows:
  - lock/unlock session state
  - budget visibility
  - collections + tier policy edits
  - connector token status/update controls (without token egress)
  - Google OAuth login for Drive + folder/file browser + import selection
  - approval queue review + resolve controls
  - drag-and-drop/file-picker local upload surface that calls MCP `vault.ingest`
  - item listing by collection
  - audit timeline
  - OpenClaw integration quickstart snippet
- Local-only and auth enforcement on UI APIs, with audit events for UI decisions.
- Responsive render baseline with desktop/mobile layout and basic accessibility landmarks.

Open locally after starting daemon:

```bash
http://127.0.0.1:8787/vault?token=<STRAJAD_AUTH_TOKEN>
```

### Post-MVP gates (connectors and enterprise controls)

- Connector token protection tests (encrypted storage + no token leakage in logs/audit payloads).
- Connector bounded-read tests (snippet/draft-first defaults enforced).
- Side-effect governance tests (draft-first and approval-required paths for sends/posts/deletes).
- Multi-tenant/org policy tests (org overrides and user policy interaction correctness).
- High-volume audit durability tests (ordering, retention, and query correctness at scale).

### Post-MVP step 1-4 scope implemented (connector + governance skeleton)

- Added initial bounded mail connector MCP tools:
  - `mail.search`
  - `mail.read_snippets`
  - `mail.draft`
- Added approval-gated send queue path (`mail.send` -> `queued_for_approval`).
- Mail connector enforces existing deterministic budgets for result counts, snippet bytes/chars/object counts, and draft body size.
- Mail connector operations are still collection-policy gated (including presence-required collections).
- Added bounded drive connector MCP tools:
  - `drive.search`
  - `drive.read_snippets`
- Drive connector enforces the same deterministic budgets and collection-policy gates (including presence-required collections).
- Added bounded GitHub connector MCP tools:
  - `github.search`
  - `github.read_snippets`
- GitHub connector enforces the same deterministic budgets and collection-policy gates (including presence-required collections).
- Added bounded web connector MCP tools:
  - `web.search`
  - `web.open_reader_snippet`
- Web connector enforces deterministic result/snippet budgets and collection-policy gates (including presence-required collections).
- Added encrypted connector credential control tool:
  - `vault.connectors` (`list`, `set_token`, `clear_token`)
- Connector tokens are persisted inside encrypted Vault state and never returned in tool responses.
- Added Google Drive OAuth/browser/import UI flow:
  - login via Google OAuth (`/vault/api/drive/oauth/start`, `/vault/api/drive/oauth/callback`)
  - browse Drive folders/files (`/vault/api/drive/files`)
  - import selected files/folders into Vault via `vault.ingest`-equivalent ingestion path (`/vault/api/drive/import`)
- Added explicit approval queue control tool:
  - `vault.approvals` (`list`, `approve`, `reject`)
- Updated side-effect flow:
  - `mail.send` now queues approval requests (`queued_for_approval`) instead of directly sending.
  - Approval decisions are recorded without directly executing side effects in Vault.

Implemented confidence tests:

- `TestMailConnector_BoundedSearchAndSnippetRead`
- `TestMailConnector_BudgetEnforcement`
- `TestMailConnector_DraftFirstPolicyAndApprovalQueue`
- `TestMailConnector_CollectionPolicyEnforced`
- `TestDriveConnector_BoundedSearchAndSnippetRead`
- `TestDriveConnector_BudgetEnforcement`
- `TestDriveConnector_CollectionPolicyEnforced`
- `TestGitHubConnector_BoundedSearchAndSnippetRead`
- `TestGitHubConnector_BudgetEnforcement`
- `TestGitHubConnector_CollectionPolicyEnforced`
- `TestWebConnector_BoundedSearchAndReaderSnippet`
- `TestWebConnector_BudgetEnforcement`
- `TestWebConnector_CollectionPolicyEnforced`
- `TestConnectorTokens_EncryptedAtRestAndNotLeaked`
- `TestConnectorTokens_ProviderValidation`
- `TestMailConnector_DraftFirstPolicyAndApprovalQueue`
- `TestVaultApprovals_RejectFlowAndValidation`
- `TestVaultUIDriveOAuthStartRequiresGoogleConfig`
- `TestVaultUIDriveOAuthAndImportFlow`
- `TestVaultUIDriveImport_FileTooLargeReported`

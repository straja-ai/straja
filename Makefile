# Straja Makefile

# Binary name
BIN_NAME := straja

# Main package (CLI entrypoint)
CMD_PKG := ./cmd/straja

# Output dir
BIN_DIR := bin

# Go options
GO_FILES := $(shell find . -name '*.go' -not -path "./vendor/*")
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X 'github.com/straja-ai/straja/internal/server.version=$(VERSION)'
K6_SCRIPT := tools/loadtest/chat_completion.js
STRAJA_BASE_URL ?= http://localhost:8080
MOCK_GATEWAY_LOG := /tmp/straja_mock_gateway.log
MOCK_GATEWAY_PID := /tmp/straja_mock_gateway.pid
STRAJAGUARD_ONNX ?= intel/strajaguard_v1/strajaguard_v1.onnx
BENCH_CONFIG ?= examples/straja.mock.yaml
DOCKER_IMAGE ?= straja:local
EVAL_BUNDLE ?= ../straja-intel-guard/artifacts/strajaguard_v1_specialists
EVAL_CONFIG ?= configs/strajaguard_specialists.yaml
EVAL_PI_INPUT ?= data/subset60_pi.jsonl
EVAL_JB_INPUT ?= data/subset60_jb.jsonl
EVAL_SUBSET_PI ?= data/subset60_pi.jsonl
EVAL_SUBSET_JB ?= data/subset60_jb.jsonl
EVAL_THRESHOLD ?= 0.8
EVAL_SEQ_LEN ?= 256
EVAL_MAX_SESSIONS ?= 1
EVAL_INTRA ?= 4
EVAL_INTER ?= 1
EVAL_SHOW_TEXT ?= false
EVAL_PROGRESS_EVERY ?= 25
EVAL_OUTPUT ?= /tmp/straja_eval_detectors.jsonl
EVAL_METRICS ?= /tmp/straja_eval_detectors.metrics.log

.PHONY: all build run test lint fmt tidy clean loadtest loadtest-ml loadtest-regex loadtest-mock loadtest-mock-delay bench-strajaguard docker-build docker-run activation-receiver eval eval_detectors

all: build

## Build the Straja binary
build:
	@echo ">> Building $(BIN_NAME)..."
	@mkdir -p $(BIN_DIR)
	@go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BIN_NAME) $(CMD_PKG)

## Run Straja with local config + .env variables (if .env exists)
run:
	@echo ">> Running $(BIN_NAME)..."
	@if [ -f .env ]; then \
		echo "   -> Loading .env"; \
		set -a; \
		. ./.env; \
		set +a; \
	else \
		echo "   -> No .env file found, running with current environment"; \
	fi; \
	go run -ldflags "$(LDFLAGS)" $(CMD_PKG) --config=straja.yaml

## Dev helper: local activation webhook receiver
activation-receiver:
	@echo ">> Starting activation receiver on :8099 (POST /activation)..."
	@go run ./cmd/activation-receiver --addr=:8099

## Run tests
test:
	@echo ">> Running tests..."
	@go test ./...

## Lint (basic) using go vet
lint:
	@echo ">> Running go vet..."
	@go vet ./...

## Format Go files
fmt:
	@echo ">> Formatting Go files..."
	@gofmt -w $(GO_FILES)

## Tidy Go modules
tidy:
	@echo ">> Tidying Go modules..."
	@go mod tidy

## Clean build artifacts
clean:
	@echo ">> Cleaning..."
	@rm -rf $(BIN_DIR)

## Run k6 load test with default settings
loadtest:
	@echo ">> Running k6 load test (STRAJA_BASE_URL=$(STRAJA_BASE_URL))..."
	@STRAJA_BASE_URL=$(STRAJA_BASE_URL) k6 run $(K6_SCRIPT)

## Run load test expecting ML to be enabled
loadtest-ml:
	@echo ">> Ensure StrajaGuard ML is enabled and a bundle is present before running this."
	@$(MAKE) loadtest

## Run load test expecting regex-only mode
loadtest-regex:
	@echo ">> Running in regex-only mode; disable ML or set STRAJA_ALLOW_REGEX_ONLY=true with no bundle."
	@$(MAKE) loadtest

## Run load test against mock upstream to isolate Straja overhead
loadtest-mock: build
	@echo ">> Starting Straja gateway with mock provider (config=examples/straja.mock.yaml)..."
	@MOCK_DELAY_MS=0 STRAJA_GUARD_MAX_SESSIONS=2 STRAJA_GUARD_INTRA_THREADS=4 STRAJA_GUARD_INTER_THREADS=1 ./bin/straja --config=examples/straja.mock.yaml > $(MOCK_GATEWAY_LOG) 2>&1 & echo $$! > $(MOCK_GATEWAY_PID)
	@echo ">> Waiting for gateway readiness (logs: $(MOCK_GATEWAY_LOG))..."
	@attempts=0; \
	while [ $$attempts -lt 10 ]; do \
		if curl -fsS http://localhost:8080/readyz >/dev/null 2>&1; then \
			echo ">> Gateway ready"; \
			break; \
		fi; \
		attempts=$$((attempts+1)); \
		sleep 1; \
	done; \
	if [ $$attempts -ge 10 ]; then \
		echo "Gateway not ready after 10s; see $(MOCK_GATEWAY_LOG)"; \
		kill $$(cat $(MOCK_GATEWAY_PID)) >/dev/null 2>&1 || true; \
		exit 1; \
	fi; \
	STRAJA_BASE_URL=$(STRAJA_BASE_URL) STRAJA_API_KEY=mock-api-key k6 run $(K6_SCRIPT); \
	status=$$?; \
	kill $$(cat $(MOCK_GATEWAY_PID)) >/dev/null 2>&1 || true; \
	exit $$status

## Run load test against mock upstream with 50ms artificial delay
loadtest-mock-delay: build
	@echo ">> Starting Straja gateway with mock provider (delay=50ms, config=examples/straja.mock.yaml)..."
	@MOCK_DELAY_MS=50 STRAJA_GUARD_MAX_SESSIONS=2 STRAJA_GUARD_INTRA_THREADS=4 STRAJA_GUARD_INTER_THREADS=1 ./bin/straja --config=examples/straja.mock.yaml > $(MOCK_GATEWAY_LOG) 2>&1 & echo $$! > $(MOCK_GATEWAY_PID)
	@echo ">> Waiting for gateway readiness (logs: $(MOCK_GATEWAY_LOG))..."
	@attempts=0; \
	while [ $$attempts -lt 10 ]; do \
		if curl -fsS http://localhost:8080/readyz >/dev/null 2>&1; then \
			echo ">> Gateway ready"; \
			break; \
		fi; \
		attempts=$$((attempts+1)); \
		sleep 1; \
	done; \
	if [ $$attempts -ge 10 ]; then \
		echo "Gateway not ready after 10s; see $(MOCK_GATEWAY_LOG)"; \
		kill $$(cat $(MOCK_GATEWAY_PID)) >/dev/null 2>&1 || true; \
		exit 1; \
	fi; \
	STRAJA_BASE_URL=$(STRAJA_BASE_URL) STRAJA_API_KEY=mock-api-key k6 run $(K6_SCRIPT); \
	status=$$?; \
	kill $$(cat $(MOCK_GATEWAY_PID)) >/dev/null 2>&1 || true; \
	exit $$status

## Build and run StrajaGuard microbenchmark
bench-strajaguard: build
	@echo ">> Building StrajaGuard benchmark..."
	@go build -ldflags "$(LDFLAGS)" -o bin/straja-bench ./cmd/straja-bench
	@echo ">> Running StrajaGuard benchmark ($(BENCH_CONFIG))..."
	@MOCK_DELAY_MS=0 STRAJA_GUARD_MAX_SESSIONS=2 STRAJA_GUARD_INTRA_THREADS=4 STRAJA_GUARD_INTER_THREADS=1 ./bin/straja-bench --config=$(BENCH_CONFIG) --n=200

## Evaluate specialist detectors on prompt injection + jailbreak JSONL datasets
## Example:
##   make eval_detectors EVAL_CONFIG=tmp/strajaguard_specialists_jb2xl_only.yaml
## make eval is intentionally fixed to subset60 inputs.
eval:
	@$(MAKE) eval_detectors EVAL_PI_INPUT="$(EVAL_SUBSET_PI)" EVAL_JB_INPUT="$(EVAL_SUBSET_JB)"

eval_detectors:
	@echo ">> Running detector eval..."
	@test -d "$(EVAL_BUNDLE)" || (echo "missing bundle dir: $(EVAL_BUNDLE)" && exit 1)
	@test -f "$(EVAL_PI_INPUT)" || (echo "missing prompt_injection input: $(EVAL_PI_INPUT)" && exit 1)
	@test -f "$(EVAL_JB_INPUT)" || (echo "missing jailbreak input: $(EVAL_JB_INPUT)" && exit 1)
	@if [ -n "$(EVAL_CONFIG)" ] && [ ! -f "$(EVAL_CONFIG)" ]; then \
		echo "missing specialists config: $(EVAL_CONFIG)"; \
		exit 1; \
	fi
	@errpipe=/tmp/straja_eval_detectors_err.$$; \
	rm -f "$$errpipe"; \
	mkfifo "$$errpipe"; \
	tee "$(EVAL_METRICS)" < "$$errpipe" | awk '/^PROGRESS / { print > "/dev/stderr"; fflush("/dev/stderr") }' & \
	teepid=$$!; \
	go run ./cmd/straja-eval \
		-bundle "$(EVAL_BUNDLE)" \
		-specialists-config "$(EVAL_CONFIG)" \
		-seq-len $(EVAL_SEQ_LEN) \
		-threshold $(EVAL_THRESHOLD) \
		-max-sessions $(EVAL_MAX_SESSIONS) \
		-intra $(EVAL_INTRA) \
		-inter $(EVAL_INTER) \
		-progress-every $(EVAL_PROGRESS_EVERY) \
		-show-text=$(EVAL_SHOW_TEXT) \
		"$(EVAL_PI_INPUT)" "$(EVAL_JB_INPUT)" \
		> "$(EVAL_OUTPUT)" 2> "$$errpipe"; \
	status=$$?; \
	wait $$teepid; \
	rm -f "$$errpipe"; \
	if [ $$status -ne 0 ]; then \
		echo ">> Eval failed. Last log lines:" >&2; \
		tail -n 60 "$(EVAL_METRICS)" >&2 || true; \
		exit $$status; \
	fi; \
	exit $$status
	@echo ">> Eval JSONL: $(EVAL_OUTPUT)"
	@echo ">> Eval metrics: $(EVAL_METRICS)"
	@echo ">> Metrics summary:"
	@bash ./scripts/format_eval_metrics.sh "$(EVAL_METRICS)"

## Build Docker image (multi-stage, distroless runtime)
docker-build:
	@echo ">> Building Docker image ($(DOCKER_IMAGE))..."
	@docker build -t $(DOCKER_IMAGE) .

## Run Docker image with mounted config + intel/bundle dirs and print readiness JSON
docker-run: docker-build
	@echo ">> Running $(DOCKER_IMAGE)..."
	@mkdir -p bundles intel
	@docker run --rm -d --name straja-local \
		-p 8080:8080 \
		-v $(PWD)/straja.yaml:/etc/straja/straja.yaml:ro \
		-v $(PWD)/intel:/var/lib/straja/intel \
		-v $(PWD)/bundles:/var/lib/straja/bundles \
		$(DOCKER_IMAGE) >/dev/null
	@echo ">> Waiting for readiness..."
	@attempts=0; \
	while [ $$attempts -lt 20 ]; do \
		if docker exec straja-local /busybox wget -qO- http://127.0.0.1:8080/readyz >/tmp/straja_ready.json 2>/dev/null; then \
			break; \
		fi; \
		attempts=$$((attempts+1)); \
		sleep 1; \
	done; \
	if [ $$attempts -ge 20 ]; then \
		echo "Gateway not ready after 20s"; \
		docker logs straja-local || true; \
		docker rm -f straja-local >/dev/null 2>&1 || true; \
		exit 1; \
	fi; \
	echo ">> Readiness response:"; \
	cat /tmp/straja_ready.json; echo; \
	docker rm -f straja-local >/dev/null 2>&1 || true

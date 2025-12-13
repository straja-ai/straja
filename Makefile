# Straja Makefile

# Binary name
BIN_NAME := straja

# Main package (CLI entrypoint)
CMD_PKG := ./cmd/straja

# Output dir
BIN_DIR := bin

# Go options
GO_FILES := $(shell find . -name '*.go' -not -path "./vendor/*")
K6_SCRIPT := tools/loadtest/chat_completion.js
STRAJA_BASE_URL ?= http://localhost:8080
MOCK_GATEWAY_LOG := /tmp/straja_mock_gateway.log
MOCK_GATEWAY_PID := /tmp/straja_mock_gateway.pid

.PHONY: all build run test lint fmt tidy clean loadtest loadtest-ml loadtest-regex loadtest-mock loadtest-mock-delay

all: build

## Build the Straja binary
build:
	@echo ">> Building $(BIN_NAME)..."
	@mkdir -p $(BIN_DIR)
	@go build -o $(BIN_DIR)/$(BIN_NAME) $(CMD_PKG)

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
	go run $(CMD_PKG) --config=straja.yaml

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
	@MOCK_DELAY_MS=0 ./bin/straja --config=examples/straja.mock.yaml > $(MOCK_GATEWAY_LOG) 2>&1 & echo $$! > $(MOCK_GATEWAY_PID)
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
	@MOCK_DELAY_MS=50 ./bin/straja --config=examples/straja.mock.yaml > $(MOCK_GATEWAY_LOG) 2>&1 & echo $$! > $(MOCK_GATEWAY_PID)
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

# Straja Makefile

# Binary name
BIN_NAME := straja

# Main package (CLI entrypoint)
CMD_PKG := ./cmd/straja

# Output dir
BIN_DIR := bin

# Go options
GO_FILES := $(shell find . -name '*.go' -not -path "./vendor/*")

.PHONY: all build run test lint fmt tidy clean

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
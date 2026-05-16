# xodbox developer workflow.
#
#   make help           print every target
#   make test           run the full test suite
#   make race           run the test suite with the race detector
#   make cover          run tests with a coverage profile and print the summary
#   make lint           run golangci-lint
#   make fmt            run gofmt -s -w over the repo
#   make build          build the xodbox binary into ./bin/
#   make run            build then start the server with the embedded config
#   make tidy           run go mod tidy and verify no go.mod / go.sum changes
#   make release-dry    run goreleaser in snapshot mode (requires syft + cosign)
#   make clean          remove the local build / coverage artifacts

GO              ?= go
GOLANGCI_LINT   ?= golangci-lint
GORELEASER      ?= goreleaser

BIN_DIR         := bin
COVERAGE_FILE   := coverage.out
PKG             := ./...

VERSION         := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT          := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS         := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)

.DEFAULT_GOAL := help

.PHONY: help test race cover lint fmt build run tidy release-dry clean

help: ## print every target
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

test: ## run the full test suite
	$(GO) test -timeout 120s $(PKG)

race: ## run the test suite with the race detector
	$(GO) test -race -timeout 180s $(PKG)

cover: ## run tests with a coverage profile and print the summary
	$(GO) test -race -timeout 180s -coverprofile=$(COVERAGE_FILE) $(PKG)
	$(GO) tool cover -func=$(COVERAGE_FILE) | tail -1

lint: ## run golangci-lint
	$(GOLANGCI_LINT) run $(PKG)

fmt: ## run gofmt -s -w over the repo
	gofmt -s -w .

build: ## build the xodbox binary into ./bin/
	mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/xodbox ./

run: build ## build then start the server with the embedded config
	$(BIN_DIR)/xodbox serve

tidy: ## run go mod tidy and verify no go.mod / go.sum changes
	$(GO) mod tidy
	@if ! git diff --quiet -- go.mod go.sum; then \
		echo "go.mod / go.sum changed after 'go mod tidy'; commit the diff."; \
		git --no-pager diff -- go.mod go.sum; \
		exit 1; \
	fi

release-dry: ## run goreleaser in snapshot mode (requires syft + cosign)
	$(GORELEASER) release --snapshot --clean --skip=publish,sign,sbom

clean: ## remove the local build / coverage artifacts
	rm -rf $(BIN_DIR) $(COVERAGE_FILE) dist

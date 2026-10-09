BINARY     := portpeek
CMD_PATH   := ./cmd/portpeek
BIN_DIR    := bin
VERSION    := $(shell grep -m1 '^const Version' internal/config/config.go | sed -E 's/.*"([^"]+)".*/\1/')
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS    := -X github.com/rithinkrishnakv/portpeek/internal/version.GitCommit=$(GIT_COMMIT)

.PHONY: build test lint fmt install clean

build:
	mkdir -p $(BIN_DIR)
	go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) $(CMD_PATH)

test:
	go test ./...

lint:
	go vet ./...
	@fmtfiles=$$(gofmt -l .); \
	if [ -n "$$fmtfiles" ]; then \
		echo "The following files are not gofmt-formatted:"; \
		echo "$$fmtfiles"; \
		exit 1; \
	fi
	@if command -v staticcheck >/dev/null 2>&1; then \
		staticcheck ./...; \
	else \
		echo "staticcheck not installed, skipping (see CONTRIBUTING.md)"; \
	fi

fmt:
	gofmt -w .

install:
	go install -ldflags "$(LDFLAGS)" $(CMD_PATH)

clean:
	rm -rf $(BIN_DIR)

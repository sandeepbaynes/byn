SHELL := /bin/bash

# Version: a v-prefixed git tag (v0.0.1) with the leading v stripped, else 0.0.1.
VERSION ?= $(patsubst v%,%,$(shell git describe --tags --dirty --always 2>/dev/null || echo 0.0.1))
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%d)
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildDate=$(DATE)

GO          ?= go
GOFLAGS     ?=
PKG         := ./...
BIN_DIR     := bin
BIN         := $(BIN_DIR)/byn

# Cross-compile targets for release artifacts (pure-Go, CGO disabled).
DIST_DIR  := dist
PLATFORMS := darwin/amd64 darwin/arm64 linux/amd64 linux/arm64

PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin
MANDIR  ?= $(PREFIX)/share/man/man1
MANFILE := man/byn.1

.PHONY: all build test test-integration lint cover clean clean-dist tidy fmt vet man install-man uninstall-man install uninstall dist

all: build

build:
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) -ldflags='$(LDFLAGS)' -o $(BIN) ./cmd/byn

man: $(MANFILE)
	@echo "Preview: man $(MANFILE)"

install-man: $(MANFILE)
	install -d $(DESTDIR)$(MANDIR)
	install -m 0644 $(MANFILE) $(DESTDIR)$(MANDIR)/byn.1
	@echo "Installed $(MANDIR)/byn.1"

uninstall-man:
	rm -f $(DESTDIR)$(MANDIR)/byn.1

# Build then install the binary (and man page) to $(PREFIX). Override the
# location with PREFIX=... or BINDIR=... (e.g. `make install BINDIR=$HOME/bin`).
install: build install-man
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(BIN) $(DESTDIR)$(BINDIR)/byn
	@echo "Installed $(BINDIR)/byn ($(VERSION))"

uninstall: uninstall-man
	rm -f $(DESTDIR)$(BINDIR)/byn

test:
	$(GO) test $(GOFLAGS) -race -timeout 15m $(PKG)

test-integration:
	$(GO) test $(GOFLAGS) -tags=integration -race -timeout 15m ./tests/integration/...

lint:
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "golangci-lint not installed. Install: https://golangci-lint.run/usage/install/"; \
		exit 1; \
	fi
	golangci-lint run

cover:
	$(GO) test $(GOFLAGS) -race -coverprofile=coverage.out -covermode=atomic $(PKG)
	$(GO) tool cover -func=coverage.out | tail -1
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

tidy:
	$(GO) mod tidy

fmt:
	$(GO) fmt $(PKG)

vet:
	$(GO) vet $(PKG)

# Cross-compile release binaries (one per platform) + a SHA-256 manifest into
# dist/. These are the artifacts the npm package, Homebrew formula, and the
# curl|sh installer download. Upload them to a public release for v$(VERSION).
dist: clean-dist
	@mkdir -p $(DIST_DIR)
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; out=$(DIST_DIR)/byn-$$os-$$arch; \
		echo "  building $$out"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 $(GO) build -trimpath -ldflags='$(LDFLAGS)' -o $$out ./cmd/byn || exit 1; \
	done
	@cd $(DIST_DIR) && shasum -a 256 byn-* > byn-$(VERSION).sha256
	@echo "dist artifacts (v$(VERSION)) in $(DIST_DIR)/:"
	@ls -1 $(DIST_DIR)

clean-dist:
	rm -rf $(DIST_DIR)

clean: clean-dist
	rm -rf $(BIN_DIR) coverage.out coverage.html

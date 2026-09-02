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
# Privileged spawn helper for NU-5 exec-child privsep. Installed root-owned
# with file caps by `byn setup`, which resolves it BESIDE the byn binary —
# so it ships next to byn and is built alongside it here.
HELPER      := $(BIN_DIR)/byn-exec-helper

# The modal editor, shipped as its own binary so that `byn` does not link
# bubbletea — whose package init queries the terminal and waits up to five
# seconds for a reply, on every command, in any program that links it. Resolved
# BESIDE byn at runtime, like the helper, so a `go install`-ed byn and a packaged
# one each find their own.
TUI         := $(BIN_DIR)/byn-tui

# Cross-compile targets for release artifacts (pure-Go, CGO disabled).
DIST_DIR  := dist
PLATFORMS := darwin/amd64 darwin/arm64 linux/amd64 linux/arm64

PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin
MANDIR  ?= $(PREFIX)/share/man/man1
MANFILE := man/byn.1

.PHONY: all build test test-integration lint cover clean clean-dist tidy fmt vet man install-man uninstall-man install uninstall dist site site-check

all: build

build:
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) -ldflags='$(LDFLAGS)' -o $(BIN) ./cmd/byn
	$(GO) build $(GOFLAGS) -ldflags='$(LDFLAGS)' -o $(HELPER) ./cmd/byn-exec-helper
	$(GO) build $(GOFLAGS) -ldflags='$(LDFLAGS)' -o $(TUI) ./cmd/byn-tui

# Render the docs site: docs/*.md (the single source of truth) -> themed
# docs/<name>/index.html via the committed generator. The generated HTML is a
# build artifact (gitignored) and is published to gh-pages separately.
site:
	$(GO) run ./tools/gensite

# CI guard: fail if the committed markdown would produce different HTML than
# what is on disk (i.e. someone edited a doc but didn't re-run `make site`).
# Local convenience: reports which generated pages your working tree would
# change. CI cannot use this — the generated HTML is not committed, so a fresh
# checkout has none of it and everything reads as stale. CI generates and then
# checks that no TRACKED file moved.
site-check:
	$(GO) run ./tools/gensite -check

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
#
# macOS only: set CODESIGN_IDENTITY to sign the installed binaries with a stable
# identity so a Full Disk Access grant SURVIVES reinstalls (the default ad-hoc
# signature changes every build, forcing a re-grant). A FREE Apple ID is enough:
#   make install CODESIGN_IDENTITY="Apple Development: you@example.com (TEAMID)"
# Find the identity with: security find-identity -v -p codesigning
# See docs/troubleshooting.md "macOS Full Disk Access (TCC)".
install: build
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(BIN) $(DESTDIR)$(BINDIR)/byn
	install -m 0755 $(HELPER) $(DESTDIR)$(BINDIR)/byn-exec-helper
	install -m 0755 $(TUI) $(DESTDIR)$(BINDIR)/byn-tui
	@# The helper that actually RUNS lives in libexec with file capabilities,
	@# put there by `byn setup`. Installing only to bindir left it untouched:
	@# it drifted six weeks behind the CLI it shares an exec-token protocol
	@# with, and the mismatch surfaced as a helper that did not understand a
	@# flag byn had just started sending. Refresh it in place when it exists —
	@# never create it here, since an unprovisioned machine has no service user
	@# for it to drop to.
	@# How the helper holds its privilege differs per OS, and `byn setup` already
	@# knows: Linux gives it file capabilities and mode 0755; macOS has no file
	@# capabilities, so it is setuid-root at 4755, owned root:wheel. Refreshing it
	@# with the Linux form on a Mac fails outright ("install: unknown group root",
	@# since the group is wheel) — and had that succeeded, mode 0755 would have
	@# dropped the setuid bit and left a helper that can no longer drop to
	@# _byn-exec, which is a silent break rather than a loud one.
	@if [ -x /usr/local/libexec/byn-exec-helper ]; then \
		if [ "$$(uname -s)" = "Darwin" ]; then \
			install -o root -g wheel -m 4755 $(HELPER) /usr/local/libexec/byn-exec-helper && \
			echo "Refreshed /usr/local/libexec/byn-exec-helper (setuid-root privsep helper)"; \
		else \
			install -o root -g root -m 0755 $(HELPER) /usr/local/libexec/byn-exec-helper && \
			setcap cap_setuid,cap_setgid+ep /usr/local/libexec/byn-exec-helper && \
			echo "Refreshed /usr/local/libexec/byn-exec-helper (privsep helper)"; \
		fi; \
	fi
	@if [ -n "$(CODESIGN_IDENTITY)" ]; then \
		echo "Signing installed binaries with: $(CODESIGN_IDENTITY)"; \
		codesign --force --identifier com.sandeepbaynes.byn \
			--sign "$(CODESIGN_IDENTITY)" $(DESTDIR)$(BINDIR)/byn; \
		codesign --force --identifier com.sandeepbaynes.byn-exec-helper \
			--sign "$(CODESIGN_IDENTITY)" $(DESTDIR)$(BINDIR)/byn-exec-helper; \
		echo "Signed. Re-add /usr/local/bin/byn to Full Disk Access once; the grant then persists across reinstalls signed with this identity."; \
	fi
	@echo "Installed $(BINDIR)/byn (+ byn-exec-helper) ($(VERSION))"
	@# Same asymmetry, quieter: the system data dir is /var/lib/byn on Linux and
	@# "/Library/Application Support/byn" on macOS, so testing only the Linux path
	@# made this a no-op on a Mac rather than a failure. Mode matters as much as
	@# owner here — macOS keeps the daemon socket INSIDE this directory, so it is
	@# 0711 (traverse, no listing) and a 0700 leaves the owner unable to reach a
	@# running daemon.
	@_dir=""; \
	 if [ "$$(uname -s)" = "Darwin" ]; then _dir="/Library/Application Support/byn"; \
	 else _dir="/var/lib/byn"; fi; \
	 if id _byn >/dev/null 2>&1 && [ -d "$$_dir" ]; then \
		chown _byn:_byn "$$_dir" && chmod 0711 "$$_dir" && \
		echo "  fixed $$_dir ownership → _byn:_byn (mode 0711)"; \
	 fi
	@$(MAKE) install-man 2>/dev/null || echo "  (man page skipped — $(MANDIR) not writable)"

# Remove byn binaries, man page, and (if provisioned) the system service +
# privsep accounts. The vault and its secrets are LEFT INTACT.
# Run as: sudo make uninstall
uninstall: uninstall-man
	@# Stop the daemon as the original (pre-sudo) user. Root's home is /root, not
	@# the user's, so running `byn stop` as root can't find the pidfile under
	@# ~/.byn. SUDO_USER is set by sudo and gives us the right identity.
	@_u=$${SUDO_USER:-}; \
	 if [ -n "$$_u" ]; then \
	   su -c "$(DESTDIR)$(BINDIR)/byn stop" "$$_u" 2>/dev/null || true; \
	 else \
	   $(DESTDIR)$(BINDIR)/byn stop 2>/dev/null || true; \
	 fi
	@# Reverse privsep setup if provisioned (removes service, spawn helper, owner
	@# record). Idempotent and silent when setup was never run.
	@$(DESTDIR)$(BINDIR)/byn setup --uninstall 2>/dev/null || true
	rm -f $(DESTDIR)$(BINDIR)/byn $(DESTDIR)$(BINDIR)/byn-exec-helper
	@echo "Uninstalled $(BINDIR)/byn — vault preserved"

# The byntest tag compiles the data-root test seam (internal/paths) so tests can
# isolate a tempdir via BYN_TEST_DIR. It is NEVER in a production build — see
# internal/paths/paths_testdir.go.
#
# The second line runs internal/paths WITHOUT the byntest tag so the production
# resolver tests (paths_test.go, //go:build !byntest) actually execute — these
# assert the core §6.5 property that NO env var can repoint the production data
# root. They are excluded from the byntest run above, so without this they would
# never run in CI. The paths package is read-only (no real-state writes), so it
# is safe to run untagged.
test:
	$(GO) test $(GOFLAGS) -tags=byntest -race -timeout 15m $(PKG)
	$(GO) test $(GOFLAGS) -race ./internal/paths/...

test-integration:
	$(GO) test $(GOFLAGS) -tags='integration byntest' -race -timeout 15m ./tests/integration/...

lint:
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "golangci-lint not installed. Install: https://golangci-lint.run/usage/install/"; \
		exit 1; \
	fi
	golangci-lint run

cover:
	$(GO) test $(GOFLAGS) -tags=byntest -race -coverprofile=coverage.out -covermode=atomic $(PKG)
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
# byn-exec-helper is built alongside byn for each platform so release tarballs
# contain both binaries and `byn setup` can find the helper next to byn.
dist: clean-dist
	@mkdir -p $(DIST_DIR)
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; out=$(DIST_DIR)/byn-$$os-$$arch; \
		echo "  building $$out"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 $(GO) build -trimpath -ldflags='$(LDFLAGS)' -o $$out ./cmd/byn || exit 1; \
		helper=$(DIST_DIR)/byn-exec-helper-$$os-$$arch; \
		echo "  building $$helper"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 $(GO) build -trimpath -ldflags='-s -w' -o $$helper ./cmd/byn-exec-helper || exit 1; \
		tui=$(DIST_DIR)/byn-tui-$$os-$$arch; \
		echo "  building $$tui"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 $(GO) build -trimpath -ldflags='$(LDFLAGS)' -o $$tui ./cmd/byn-tui || exit 1; \
	done
	@# sha256sum on Linux, shasum on macOS — `make dist` built every artifact and
	@# then died on the checksum line for want of a command that only ships with
	@# one of them.
	@# Binaries only. The shell creates the redirect target before the glob
	@# expands, so `byn-*` swept the checksum file into its own list and the
	@# first line was the digest of an empty file.
	@cd $(DIST_DIR) && files=$$(ls byn-* | grep -v '\.sha256$$') && 		{ command -v sha256sum >/dev/null && sha256sum $$files || shasum -a 256 $$files; } > byn-$(VERSION).sha256
	@echo "dist artifacts (v$(VERSION)) in $(DIST_DIR)/:"
	@ls -1 $(DIST_DIR)

clean-dist:
	rm -rf $(DIST_DIR)

clean: clean-dist
	rm -rf $(BIN_DIR) coverage.out coverage.html

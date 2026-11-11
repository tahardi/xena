# https://clarkgrubb.com/makefile-style-guide
MAKEFLAGS += --warn-undefined-variables
SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := pre-pr
.DELETE_ON_ERROR:
.SUFFIXES:

lint_modfile=modfiles/golangci-lint/go.mod
vuln_modfile=modfiles/govulncheck/go.mod
gitleaks_modfile=modfiles/gitleaks/go.mod

VERSION ?=

.PHONY: pre-pr
pre-pr: \
	tidy \
	fix \
	fmt \
	lint \
	test-unit \
	test-cloud \
	vuln \
	secrets \
	shellcheck \
	test-shell \
	test-scripts

.PHONY: agent
agent:
	@mkdir -p vm/agent
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
		-trimpath \
		-o vm/agent/xena-agent \
		./cmd/xena-agent

.PHONY: tidy
tidy:
	@go mod tidy

.PHONY: fix
fix: agent
	@go fix ./...

.PHONY: fmt
fmt:
	@go tool -modfile=$(lint_modfile) golangci-lint fmt --config .golangci.yaml

.PHONY: lint
lint: tidy agent
	@go tool -modfile=$(lint_modfile) golangci-lint run --config .golangci.yaml

.PHONY: lint-version
lint-version:
	@go tool -modfile=$(lint_modfile) golangci-lint --version

.PHONY: test-unit
test-unit: tidy agent
	@go test -v -count=1 -race ./...

.PHONY: test-cloud
test-cloud:
	@python3 -B -m unittest discover \
		-s deploy/cloud/gcp-billing-cap \
		-p 'test_*.py'

.PHONY: vuln
vuln: tidy agent
	@go tool -modfile=$(vuln_modfile) govulncheck ./...

.PHONY: secrets
secrets:
	@go tool -modfile=$(gitleaks_modfile) gitleaks git \
		--redact \
		--no-banner \
		.

.PHONY: shellcheck
shellcheck:
	@git ls-files -z \
		'*.sh' \
		vm/cloud-init/files/gh \
		vm/cloud-init/files/motd-rebuild \
		| xargs -0 -r shellcheck

.PHONY: test-shell
test-shell:
	@deploy/desktop/harden_test.sh

.PHONY: test-scripts
test-scripts:
	@./scripts/install_test.sh

.PHONY: install
install:
	./scripts/install.sh install $(VERSION)

.PHONY: release-major
release-major:
	./scripts/release.sh major

.PHONY: release-minor
release-minor:
	./scripts/release.sh minor

.PHONY: release-patch
release-patch:
	./scripts/release.sh patch

.PHONY: rollback
rollback:
	$(if $(filter command line,$(origin VERSION)),,$(error rollback needs VERSION=vX.Y.Z))
	./scripts/install.sh install $(VERSION)

.PHONY: uninstall
uninstall:
	./scripts/uninstall.sh

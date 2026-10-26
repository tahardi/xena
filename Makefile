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

.PHONY: pre-pr
pre-pr: \
	tidy \
	fix \
	lint \
	test-unit \
	vuln \
	secrets \
	shellcheck \
	test-agent

.PHONY: tidy
tidy:
	@go mod tidy

.PHONY: fix
fix:
	@go fix ./...

.PHONY: lint
lint: tidy
	@go tool -modfile=$(lint_modfile) golangci-lint run --config .golangci.yaml

.PHONY: lint-version
lint-version:
	@go tool -modfile=$(lint_modfile) golangci-lint --version

.PHONY: test-unit
test-unit: tidy
	@go test -v -count=1 -race ./...

.PHONY: test-agent
test-agent:
	@bash vm/agent/xena-agent_test.sh

.PHONY: vuln
vuln: tidy
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
		vm/agent/xena-agent \
		| xargs -0 -r shellcheck

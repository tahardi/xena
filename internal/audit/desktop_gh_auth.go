package audit

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/tahardi/xena/internal/logs"
)

var (
	ghScopesLine = regexp.MustCompile(`Token scopes:(.*)`)
	ghScope      = regexp.MustCompile(`'([^']+)'`)
	ghPlainToken = regexp.MustCompile(`(?m)^\s*oauth_token:`)
)

type GHAuth struct {
	cmd    Commander
	home   string
	scopes []string
}

func NewGHAuth(cmd Commander, home string, scopes []string) *GHAuth {
	return &GHAuth{cmd: cmd, home: home, scopes: scopes}
}

func (*GHAuth) Name() string {
	return "desktop-gh-auth"
}

func (g *GHAuth) Run(ctx context.Context) ([]Finding, error) {
	var findings []Finding
	hosts, err := os.ReadFile(filepath.Join(g.home, ".config", "gh", "hosts.yml"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("reading gh hosts.yml: %w", err)
	}
	if ghPlainToken.Match(hosts) {
		findings = append(findings, Finding{
			Severity: logs.SeverityHigh,
			Message:  "gh token stored in plain text",
			Fix:      "Run gh auth logout, then gh auth login so the token goes into the keyring.",
		})
	}

	out, err := g.cmd.Output(ctx, "gh", "auth", "status", "--hostname", "github.com")
	if err != nil {
		return nil, fmt.Errorf("reading gh auth status: %w", err)
	}

	status := string(out)
	if !strings.Contains(status, "(keyring)") {
		findings = append(findings, Finding{
			Severity: logs.SeverityHigh,
			Message:  "gh is not logged in with a token from the keyring",
			Fix:      "Unset GH_TOKEN and GITHUB_TOKEN, then run gh auth login.",
		})
	}

	match := ghScopesLine.FindStringSubmatch(status)
	if match == nil {
		return findings, nil
	}
	for _, scope := range ghScope.FindAllStringSubmatch(match[1], -1) {
		if slices.Contains(g.scopes, scope[1]) {
			continue
		}
		findings = append(findings, Finding{
			Severity: logs.SeverityMedium,
			Message:  fmt.Sprintf("gh token has scope %s, which audit.yaml does not allow", scope[1]),
			Fix:      "Run gh auth refresh --remove-scopes " + scope[1] + ", or add it to gh_scopes in audit.yaml.",
		})
	}
	return findings, nil
}

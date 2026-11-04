package inventory

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	atlassianSecurityPage = "https://id.atlassian.com/manage-profile/security/api-tokens"
	jiraTokenKey          = "JIRA_TOKEN"
)

var (
	ErrNewRejected  = errors.New("new token rejected")
	ErrInsecureSite = errors.New("jira site is not https")
)

type JiraToken struct {
	In   *bufio.Reader
	Out  io.Writer
	HTTP *http.Client
}

func (j JiraToken) Create(ctx context.Context, old []byte) ([]byte, error) {
	_, err := fmt.Fprintf(
		j.Out,
		"Open %s as the bot user, create a token named xena-vm-%s with a 90-day expiry, and paste it here: ",
		atlassianSecurityPage,
		time.Now().Format(time.DateOnly),
	)
	if err != nil {
		return nil, fmt.Errorf("prompting for new jira token: %w", err)
	}

	line, err := j.In.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("reading new jira token: %w", err)
	}

	token := strings.TrimSpace(line)
	if token == "" {
		return nil, fmt.Errorf("reading new jira token: %w", ErrNewRejected)
	}

	current := withJiraToken(string(old), token)
	status, err := j.myself(ctx, []byte(current))
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("checking new jira token: %w", ErrNewRejected)
	}

	return []byte(current), nil
}

func (j JiraToken) Revoke(_ context.Context, _, _ []byte) error {
	if _, err := fmt.Fprintln(j.Out, "Revoke the old token on the same page, then press Enter."); err != nil {
		return fmt.Errorf("prompting to revoke old jira token: %w", err)
	}

	if _, err := j.In.ReadString('\n'); err != nil {
		return fmt.Errorf("waiting for old jira token revoke: %w", err)
	}

	return nil
}

func (j JiraToken) Rejected(ctx context.Context, old []byte) (bool, error) {
	status, err := j.myself(ctx, old)
	if err != nil {
		return false, err
	}

	return status == http.StatusUnauthorized, nil
}

func (j JiraToken) myself(ctx context.Context, secret []byte) (int, error) {
	env := parseEnv(string(secret))
	if !strings.HasPrefix(env["JIRA_SITE"], "https://") {
		return 0, fmt.Errorf("checking jira site: %w", ErrInsecureSite)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, env["JIRA_SITE"]+"/rest/api/3/myself", nil)
	if err != nil {
		return 0, fmt.Errorf("building jira request: %w", err)
	}
	req.SetBasicAuth(env["JIRA_EMAIL"], env[jiraTokenKey])

	resp, err := j.HTTP.Do(req)
	if err != nil {
		return 0, fmt.Errorf("checking jira token: %w", err)
	}
	_ = resp.Body.Close()

	return resp.StatusCode, nil
}

func parseEnv(text string) map[string]string {
	env := map[string]string{}
	for line := range strings.Lines(text) {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			env[k] = v
		}
	}

	return env
}

func withJiraToken(text, token string) string {
	var b strings.Builder
	for line := range strings.Lines(text) {
		if strings.HasPrefix(line, jiraTokenKey+"=") {
			line = jiraTokenKey + "=" + token + "\n"
		}
		b.WriteString(line)
	}

	return b.String()
}

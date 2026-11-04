package inventory

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const cardLabel = "needs-taylor"

type Jira interface {
	Summaries(ctx context.Context) ([]string, error)
	Create(ctx context.Context, summary, description string) error
}

type JiraScript struct {
	Python  string
	Script  string
	Project string
}

func (j JiraScript) Summaries(ctx context.Context) ([]string, error) {
	out, err := j.run(ctx, "", "list", j.Project, "--label", cardLabel)
	if err != nil {
		return nil, err
	}

	var summaries []string
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		for i, f := range fields {
			if strings.HasPrefix(f, "epic=") {
				summaries = append(summaries, strings.Join(fields[i+1:], " "))
				break
			}
		}
	}

	return summaries, scanner.Err()
}

func (j JiraScript) Create(ctx context.Context, summary, description string) error {
	_, err := j.run(ctx, description, "create", j.Project, summary, "--labels", cardLabel)
	return err
}

func (j JiraScript) run(ctx context.Context, stdin string, args ...string) ([]byte, error) {
	// #nosec G204 -- Python and Script are fixed by the caller and args are a card summary and fixed flags.
	cmd := exec.CommandContext(ctx, j.Python, append([]string{j.Script}, args...)...)
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Stderr = os.Stderr

	return cmd.Output()
}

func FileCards(ctx context.Context, j Jira, inv Inventory, findings []Finding) ([]string, error) {
	open, err := j.Summaries(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing jira cards: %w", err)
	}

	filed := []string{}
	seen := map[string]bool{}

	for _, s := range open {
		seen[s] = true
	}

	for _, f := range findings {
		if f.Kind != KindNearExpiry && f.Kind != KindOverdue {
			continue
		}

		summary := "Rotate " + f.Token
		if seen[summary] {
			continue
		}

		seen[summary] = true

		tok, err := inv.Find(f.Token)
		if err != nil {
			return filed, err
		}

		if err := j.Create(ctx, summary, cardDescription(f, tok)); err != nil {
			return filed, fmt.Errorf("creating jira card %s: %w", summary, err)
		}

		filed = append(filed, summary)
	}

	return filed, nil
}

func cardDescription(f Finding, tok Token) string {
	return fmt.Sprintf(
		"Finding: %s (%s)\n\nService: %s\nStored: %s\n\nRotation steps:\n%s\n",
		f.Kind,
		f.Detail,
		tok.Service,
		tok.Stored,
		tok.Rotate,
	)
}

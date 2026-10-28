package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tahardi/xena/internal/logs"
)

const wantedUbuntu = "26.04"

type Wayland struct {
	cmd  Commander
	root string
	user string
}

func NewWayland(cmd Commander, root, user string) *Wayland {
	return &Wayland{cmd: cmd, root: root, user: user}
}

type loginSession struct {
	Session string `json:"session"`
	User    string `json:"user"`
}

func (*Wayland) Name() string {
	return "desktop-wayland"
}

func (w *Wayland) Run(ctx context.Context) ([]Finding, error) {
	release, err := os.ReadFile(filepath.Join(w.root, "etc", "os-release"))
	if err != nil {
		return nil, fmt.Errorf("reading os-release: %w", err)
	}

	var findings []Finding
	if version := keyValues(string(release))["VERSION_ID"]; version != wantedUbuntu {
		findings = append(findings, Finding{
			Severity: logs.SeverityMedium,
			Message:  fmt.Sprintf("Ubuntu version is %q, but the spec expects %s", version, wantedUbuntu),
			Fix:      "Move the desktop to Ubuntu " + wantedUbuntu + ", or update the spec and this check by PR.",
		})
	}

	out, err := w.cmd.Output(ctx, "loginctl", "list-sessions", "--json=short")
	if err != nil {
		return nil, fmt.Errorf("reading loginctl sessions: %w", err)
	}

	var sessions []loginSession
	if err := json.Unmarshal(out, &sessions); err != nil {
		return nil, fmt.Errorf("parsing loginctl sessions: %w", err)
	}

	for _, session := range sessions {
		if session.User != w.user {
			continue
		}

		out, err := w.cmd.Output(ctx, "loginctl", "show-session", session.Session, "-p", "Type", "--value")
		if err != nil {
			return nil, fmt.Errorf("reading session %s type: %w", session.Session, err)
		}
		if strings.TrimSpace(string(out)) == "x11" {
			findings = append(findings, Finding{
				Severity: logs.SeverityHigh,
				Message:  fmt.Sprintf("session %s for %s runs X11", session.Session, w.user),
				Fix:      "Log out and pick the Ubuntu (Wayland) session at the login screen.",
			})
		}
	}
	return findings, nil
}

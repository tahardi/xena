package audit

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/tahardi/xena/internal/logs"
)

const ufwFix = "Run the desktop hardening script again (XENA-16), or sudo ufw default deny incoming && sudo ufw enable."

type UFW struct {
	root string
}

func NewUFW(root string) *UFW {
	return &UFW{root: root}
}

func (*UFW) Name() string {
	return "desktop-inbound-firewall"
}

func (u *UFW) Run(context.Context) ([]Finding, error) {
	conf, err := os.ReadFile(filepath.Join(u.root, "etc", "ufw", "ufw.conf"))
	if errors.Is(err, fs.ErrNotExist) {
		return []Finding{ufwFinding("ufw not configured")}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading ufw.conf: %w", err)
	}

	defaults, err := os.ReadFile(filepath.Join(u.root, "etc", "default", "ufw"))
	if errors.Is(err, fs.ErrNotExist) {
		return []Finding{ufwFinding("ufw not configured")}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading /etc/default/ufw: %w", err)
	}

	var findings []Finding
	if enabled := keyValues(string(conf))["ENABLED"]; enabled != "yes" {
		findings = append(findings, ufwFinding("ufw is not enabled"))
	}

	policy := keyValues(string(defaults))["DEFAULT_INPUT_POLICY"]
	if policy != "DROP" && policy != "REJECT" {
		findings = append(findings, ufwFinding(fmt.Sprintf("ufw default input policy is %q, not DROP or REJECT", policy)))
	}
	return findings, nil
}

func ufwFinding(message string) Finding {
	return Finding{Severity: logs.SeverityHigh, Message: message, Fix: ufwFix}
}

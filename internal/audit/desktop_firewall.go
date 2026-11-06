package audit

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/tahardi/xena/internal/logs"
)

const firewallFix = "Run sudo deploy/desktop/harden.sh (XENA-16) when switching over to the VM."

type Firewall struct {
	cmd  Commander
	root string
}

func NewFirewall(cmd Commander, root string) *Firewall {
	return &Firewall{cmd: cmd, root: root}
}

func (*Firewall) Name() string {
	return "desktop-inbound-firewall"
}

func (f *Firewall) Run(ctx context.Context) ([]Finding, error) {
	var findings []Finding

	ruleset, err := os.ReadFile(filepath.Join(f.root, "etc", "nftables.conf"))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		findings = append(findings, firewallFinding("nftables not configured"))
	case err != nil:
		return nil, fmt.Errorf("reading nftables.conf: %w", err)
	case !dropsInput(string(ruleset)):
		findings = append(findings, firewallFinding("nftables input chain does not drop by default"))
	}

	out, _ := f.cmd.Output(ctx, "systemctl", "is-enabled", "nftables")
	state := strings.TrimSpace(string(out))
	if state == "" {
		state = "unknown"
	}

	if state != "enabled" {
		findings = append(findings, firewallFinding(fmt.Sprintf("nftables service is %q, not enabled", state)))
	}
	return findings, nil
}

func dropsInput(ruleset string) bool {
	for line := range strings.Lines(ruleset) {
		if strings.Contains(line, "hook input") && strings.Contains(line, "policy drop") {
			return true
		}
	}
	return false
}

func firewallFinding(message string) Finding {
	return Finding{Severity: logs.SeverityHigh, Message: message, Fix: firewallFix}
}

package audit

import (
	"context"
	"fmt"
	"regexp"

	"github.com/tahardi/xena/internal/logs"
)

var aptPeriodicLine = regexp.MustCompile(`(?m)^\s*APT::Periodic::([A-Za-z-]+)\s+"([^"]*)"\s*;`)

var requiredAptPeriodic = []string{"Update-Package-Lists", "Unattended-Upgrade"}

type AutoUpdates struct {
	cmd Commander
}

func NewAutoUpdates(cmd Commander) *AutoUpdates {
	return &AutoUpdates{cmd: cmd}
}

func (*AutoUpdates) Name() string {
	return "desktop-auto-updates"
}

func (a *AutoUpdates) Run(ctx context.Context) ([]Finding, error) {
	out, err := a.cmd.Output(ctx, "apt-config", "dump", "APT::Periodic")
	if err != nil {
		return nil, fmt.Errorf("reading apt periodic settings: %w", err)
	}

	values := map[string]string{}
	for _, match := range aptPeriodicLine.FindAllStringSubmatch(string(out), -1) {
		values[match[1]] = match[2]
	}

	var findings []Finding
	for _, key := range requiredAptPeriodic {
		if values[key] != "1" {
			findings = append(findings, Finding{
				Severity: logs.SeverityMedium,
				Message:  fmt.Sprintf("APT::Periodic::%s is %q, not \"1\"", key, values[key]),
				Fix:      "Run sudo dpkg-reconfigure -plow unattended-upgrades and answer Yes.",
			})
		}
	}
	return findings, nil
}

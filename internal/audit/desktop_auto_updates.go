package audit

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	"github.com/tahardi/xena/internal/logs"
)

var aptPeriodicLine = regexp.MustCompile(`(?m)^\s*APT::Periodic::([A-Za-z-]+)\s+"([^"]*)"\s*;`)

var requiredAptPeriodic = []string{"Update-Package-Lists", "Unattended-Upgrade"}

type AutoUpdates struct {
	root string
}

func NewAutoUpdates(root string) *AutoUpdates {
	return &AutoUpdates{root: root}
}

func (*AutoUpdates) Name() string {
	return "desktop-auto-updates"
}

func (a *AutoUpdates) Run(context.Context) ([]Finding, error) {
	data, err := os.ReadFile(filepath.Join(a.root, "etc", "apt", "apt.conf.d", "20auto-upgrades"))
	if errors.Is(err, fs.ErrNotExist) {
		return []Finding{autoUpdatesFinding("unattended upgrades are not configured")}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading 20auto-upgrades: %w", err)
	}

	values := map[string]string{}
	for _, match := range aptPeriodicLine.FindAllStringSubmatch(string(data), -1) {
		values[match[1]] = match[2]
	}

	var findings []Finding
	for _, key := range requiredAptPeriodic {
		if values[key] != "1" {
			findings = append(findings, autoUpdatesFinding(fmt.Sprintf("APT::Periodic::%s is not \"1\"", key)))
		}
	}
	return findings, nil
}

func autoUpdatesFinding(message string) Finding {
	return Finding{
		Severity: logs.SeverityMedium,
		Message:  message,
		Fix:      "Run sudo dpkg-reconfigure -plow unattended-upgrades and answer Yes.",
	}
}

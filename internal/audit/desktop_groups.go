package audit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/tahardi/xena/internal/logs"
)

const groupFields = 4

var riskyGroups = []string{"docker", "libvirt"}

type Groups struct {
	root string
	user string
}

func NewGroups(root, user string) *Groups {
	return &Groups{root: root, user: user}
}

func (*Groups) Name() string {
	return "desktop-groups"
}

func (g *Groups) Run(context.Context) ([]Finding, error) {
	data, err := os.ReadFile(filepath.Join(g.root, "etc", "group"))
	if err != nil {
		return nil, fmt.Errorf("reading /etc/group: %w", err)
	}

	var findings []Finding
	for line := range strings.Lines(string(data)) {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) != groupFields || !slices.Contains(riskyGroups, fields[0]) {
			continue
		}
		if !slices.Contains(strings.Split(fields[3], ","), g.user) {
			continue
		}

		findings = append(findings, Finding{
			Severity: logs.SeverityHigh,
			Message:  fmt.Sprintf("%s is in the %s group, which grants root", g.user, fields[0]),
			Fix:      fmt.Sprintf("Run sudo gpasswd -d %s %s, then log out and back in.", g.user, fields[0]),
		})
	}
	return findings, nil
}

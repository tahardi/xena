package audit

import (
	"context"
	"errors"
	"fmt"
	"io/fs"

	"github.com/tahardi/xena/internal/allowlist"
	"github.com/tahardi/xena/internal/config"
	"github.com/tahardi/xena/internal/logs"
)

const defaultOverlayPort = 443

type Overlay struct {
	path string
}

func NewOverlay(path string) *Overlay {
	return &Overlay{path: path}
}

func (*Overlay) Name() string {
	return "desktop-overlay"
}

func (o *Overlay) Run(context.Context) ([]Finding, error) {
	overlay, err := config.Load[allowlist.Allowlist](o.path, allowlist.CurrentVersion, nil)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading overlay allowlist: %w", err)
	}

	findings := make([]Finding, 0, len(overlay.Hosts))
	for _, rule := range overlay.Hosts {
		ports := rule.Ports
		if len(ports) == 0 {
			ports = []int{defaultOverlayPort}
		}
		findings = append(findings, Finding{
			Severity: logs.SeverityLow,
			Message:  fmt.Sprintf("overlay allowlist entry %s ports %v", rule.Host, ports),
			Fix:      "move it into config/allowlist.yaml by PR, or remove it",
		})
	}
	return findings, nil
}

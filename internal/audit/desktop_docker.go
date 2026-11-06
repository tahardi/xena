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

var dockerBinaries = []string{
	"/usr/bin/docker",
	"/usr/bin/dockerd",
	"/usr/local/bin/docker",
	"/usr/local/bin/dockerd",
	"/usr/sbin/dockerd",
	"/snap/bin/docker",
}

type Docker struct {
	root string
}

func NewDocker(root string) *Docker {
	return &Docker{root: root}
}

func (*Docker) Name() string {
	return "desktop-docker"
}

func (d *Docker) Run(context.Context) ([]Finding, error) {
	var findings []Finding
	for _, binary := range dockerBinaries {
		_, err := os.Lstat(filepath.Join(d.root, binary))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", binary, err)
		}

		findings = append(findings, Finding{
			Severity: logs.SeverityHigh,
			Message:  "docker binary found at " + binary,
			Fix:      "Uninstall Docker from the desktop; containers run inside the VM.",
		})
	}
	return findings, nil
}

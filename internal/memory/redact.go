package memory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

var errOutsideDir = errors.New("finding outside scanned dir")

// Finding uses the exact field names of a gitleaks report.
//
//nolint:tagliatelle
type Finding struct {
	RuleID string `json:"RuleID"`
	File   string `json:"File"`
	Secret string `json:"Secret"`
	Match  string `json:"Match"`
}

func Scan(ctx context.Context, gitleaks, dir string) ([]Finding, error) {
	reportDir, err := os.MkdirTemp("", "xena-gitleaks-")
	if err != nil {
		return nil, fmt.Errorf("scanning memory: %w", err)
	}
	defer os.RemoveAll(reportDir)

	report := filepath.Join(reportDir, "report.json")

	// #nosec G204 -- gitleaks is a fixed binary name from the caller and every argument is a path we chose.
	cmd := exec.CommandContext(
		ctx,
		gitleaks,
		"dir",
		"--no-banner",
		"--report-format", "json",
		"--report-path", report,
		"--exit-code", "0",
		dir,
	)
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("scanning memory: %w", err)
	}

	data, err := os.ReadFile(report)
	if err != nil {
		return nil, fmt.Errorf("scanning memory: %w", err)
	}

	var findings []Finding
	if err := json.Unmarshal(data, &findings); err != nil {
		return nil, fmt.Errorf("scanning memory: decoding report: %w", err)
	}

	return findings, nil
}

func Redact(dir string, findings []Finding) (int, error) {
	byFile := map[string][]Finding{}
	var order []string

	for _, f := range findings {
		rel, err := filepath.Rel(dir, f.File)
		if err != nil || !filepath.IsLocal(rel) {
			return 0, fmt.Errorf("redacting: %w", errOutsideDir)
		}

		if _, ok := byFile[rel]; !ok {
			order = append(order, rel)
		}

		byFile[rel] = append(byFile[rel], f)
	}

	total := 0
	for _, rel := range order {
		n, err := redactFile(filepath.Join(dir, rel), byFile[rel])
		if err != nil {
			return 0, fmt.Errorf("redacting %s: %w", rel, err)
		}

		total += n
	}

	return total, nil
}

func redactFile(path string, findings []Finding) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}

	n := 0
	for _, f := range findings {
		target := f.Secret
		if target == "" {
			target = f.Match
		}

		if target == "" {
			continue
		}

		n += bytes.Count(data, []byte(target))
		data = bytes.ReplaceAll(data, []byte(target), []byte("[REDACTED:"+f.RuleID+"]"))
	}

	if n == 0 {
		return 0, nil
	}

	return n, writeAtomic(path, data)
}

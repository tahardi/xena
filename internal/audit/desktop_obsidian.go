package audit

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/tahardi/xena/internal/logs"
)

const frontmatterFence = "---"

var (
	codePlugins  = []string{"templater-obsidian", "execute-code", "obsidian-shellcommands", "customjs"}
	remoteEmbed  = regexp.MustCompile(`(?i)!\[[^\]]*\]\(\s*https?://|<iframe|<img[^>]+src\s*=\s*["']?https?://`)
	vmSourceLine = regexp.MustCompile(`(?m)^source:\s*["']?xena-vm["']?\s*$`)
)

type Obsidian struct {
	vault string
}

func NewObsidian(vault string) *Obsidian {
	return &Obsidian{vault: vault}
}

type dataviewSettings struct {
	// Dataview's settings file uses camelCase keys.
	EnableDataviewJS bool `json:"enableDataviewJs"` //nolint:tagliatelle
}

func (*Obsidian) Name() string {
	return "desktop-obsidian"
}

func (o *Obsidian) Run(context.Context) ([]Finding, error) {
	findings, err := o.pluginFindings()
	if err != nil {
		return nil, err
	}

	notes, err := o.noteFindings()
	if err != nil {
		return nil, err
	}
	return append(findings, notes...), nil
}

func (o *Obsidian) pluginFindings() ([]Finding, error) {
	var plugins []string
	err := readJSON(filepath.Join(o.vault, ".obsidian", "community-plugins.json"), &plugins)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var findings []Finding
	for _, plugin := range plugins {
		if slices.Contains(codePlugins, plugin) {
			findings = append(findings, pluginFinding(plugin, "Disable the "+plugin+" plugin."))
		}
	}

	if !slices.Contains(plugins, "dataview") {
		return findings, nil
	}

	var dataview dataviewSettings
	err = readJSON(filepath.Join(o.vault, ".obsidian", "plugins", "dataview", "data.json"), &dataview)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if dataview.EnableDataviewJS {
		findings = append(findings, pluginFinding("dataview", "Turn off JavaScript queries in Dataview's settings."))
	}
	return findings, nil
}

func (o *Obsidian) noteFindings() ([]Finding, error) {
	root, err := os.OpenRoot(o.vault)
	if err != nil {
		return nil, fmt.Errorf("reading vault notes: %w", err)
	}
	defer root.Close()

	var findings []Finding
	vault := root.FS()
	err = fs.WalkDir(vault, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && path != "." && strings.HasPrefix(d.Name(), ".") {
			return fs.SkipDir
		}
		if d.IsDir() || filepath.Ext(path) != ".md" {
			return nil
		}

		data, err := fs.ReadFile(vault, path)
		if err != nil {
			return err
		}
		if !fromVM(string(data)) || !remoteEmbed.Match(data) {
			return nil
		}

		findings = append(findings, Finding{
			Severity: logs.SeverityMedium,
			Message:  fmt.Sprintf("gateway-written note %q embeds remote content", path),
			Fix:      "Remove the remote image or iframe from the note; it loads a URL the VM chose when you open it.",
		})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("reading vault notes: %w", err)
	}
	return findings, nil
}

func fromVM(note string) bool {
	rest, ok := strings.CutPrefix(note, frontmatterFence+"\n")
	if !ok {
		return false
	}

	frontmatter, _, ok := strings.Cut(rest, "\n"+frontmatterFence)
	return ok && vmSourceLine.MatchString(frontmatter)
}

func pluginFinding(plugin, fix string) Finding {
	return Finding{
		Severity: logs.SeverityHigh,
		Message:  "Obsidian plugin " + plugin + " can run code from notes",
		Fix:      fix,
	}
}

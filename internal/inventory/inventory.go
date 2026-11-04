package inventory

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/tahardi/xena/internal/config"
)

var (
	ErrDuplicateName = errors.New("duplicate token name")
	ErrMissingField  = errors.New("missing token field")
	ErrInvalidName   = errors.New("invalid token name")
	ErrNotListed     = errors.New("token not listed in inventory")

	validName = regexp.MustCompile(`^[a-z0-9-]+$`)
)

const (
	DefaultRotationDays = 90
	currentVersion      = 1
	fileMode            = 0o600
	yamlIndent          = 2
)

type Inventory struct {
	Version int     `yaml:"version"`
	Entries []Token `yaml:"entries"`
}

type Token struct {
	Name         string    `yaml:"name"`
	Service      string    `yaml:"service"`
	Owner        string    `yaml:"owner"`
	Scope        string    `yaml:"scope"`
	Stored       string    `yaml:"stored"`
	Rotated      time.Time `yaml:"rotated"`
	Expires      time.Time `yaml:"expires,omitempty"`
	RotationDays *int      `yaml:"rotation_days,omitempty"`
	CanSpend     bool      `yaml:"can_spend"`
	SpendCap     string    `yaml:"spend_cap,omitempty"`
	Rotate       string    `yaml:"rotate"`
}

func Load(path string) (Inventory, error) {
	inv, err := config.Load[Inventory](path, currentVersion, nil)
	if err != nil {
		return Inventory{}, err
	}

	seen := map[string]bool{}
	for i := range inv.Entries {
		tok := &inv.Entries[i]
		if err := tok.validate(); err != nil {
			return Inventory{}, err
		}

		if seen[tok.Name] {
			return Inventory{}, fmt.Errorf("checking token %s: %w", tok.Name, ErrDuplicateName)
		}
		seen[tok.Name] = true

		if tok.RotationDays == nil {
			days := DefaultRotationDays
			tok.RotationDays = &days
		}
	}

	return inv, nil
}

func (inv Inventory) Find(name string) (Token, error) {
	for _, tok := range inv.Entries {
		if tok.Name == name {
			return tok, nil
		}
	}

	return Token{}, fmt.Errorf("finding token %s: %w", name, ErrNotListed)
}

func (t Token) Due() (time.Time, bool) {
	var due time.Time
	if t.RotationDays != nil && *t.RotationDays > 0 {
		due = t.Rotated.AddDate(0, 0, *t.RotationDays)
	}

	if !t.Expires.IsZero() && (due.IsZero() || t.Expires.Before(due)) {
		due = t.Expires
	}

	return due, !due.IsZero()
}

func SetRotated(path, name string, day time.Time) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}

	entry := findEntry(&doc, name)
	if entry == nil {
		return fmt.Errorf("setting rotated for %s: %w", name, ErrNotListed)
	}
	setScalar(entry, "rotated", day.Format(time.DateOnly))
	removeKey(entry, "expires")

	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(yamlIndent)
	if err := enc.Encode(&doc); err != nil {
		return fmt.Errorf("encoding %s: %w", path, err)
	}

	if err := enc.Close(); err != nil {
		return fmt.Errorf("encoding %s: %w", path, err)
	}

	return writeAtomic(path, out.Bytes())
}

func (t Token) validate() error {
	fields := []struct {
		name  string
		empty bool
	}{
		{"name", t.Name == ""},
		{"service", t.Service == ""},
		{"stored", t.Stored == ""},
		{"rotated", t.Rotated.IsZero()},
		{"rotate", t.Rotate == ""},
	}
	for _, f := range fields {
		if f.empty {
			return fmt.Errorf("checking token %s: %w: %s", t.Name, ErrMissingField, f.name)
		}
	}

	if !validName.MatchString(t.Name) {
		return fmt.Errorf("checking token %q: %w", t.Name, ErrInvalidName)
	}

	return nil
}

func findEntry(doc *yaml.Node, name string) *yaml.Node {
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil
	}

	entries := mapValue(doc.Content[0], "entries")
	if entries == nil || entries.Kind != yaml.SequenceNode {
		return nil
	}

	for _, entry := range entries.Content {
		if v := mapValue(entry, "name"); v != nil && v.Value == name {
			return entry
		}
	}

	return nil
}

func mapValue(m *yaml.Node, key string) *yaml.Node {
	if m.Kind != yaml.MappingNode {
		return nil
	}

	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}

	return nil
}

func setScalar(m *yaml.Node, key, value string) {
	if v := mapValue(m, key); v != nil {
		v.Kind = yaml.ScalarNode
		v.Tag = ""
		v.Style = 0
		v.Value = value
		return
	}

	m.Content = append(
		m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Value: key},
		&yaml.Node{Kind: yaml.ScalarNode, Value: value},
	)
}

func removeKey(m *yaml.Node, key string) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return
		}
	}
}

func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("creating temp file for %s: %w", path, err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()

	if err := tmp.Chmod(fileMode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("setting mode of %s: %w", tmp.Name(), err)
	}

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing %s: %w", tmp.Name(), err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing %s: %w", tmp.Name(), err)
	}

	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("renaming %s: %w", tmp.Name(), err)
	}

	return nil
}

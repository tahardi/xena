package vault

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxPathBytes  = 1024
	ideasNote     = "Ideas.md"
	projectsDir   = "Projects/"
	reportsPrefix = "projects/xena/reports/"
)

var (
	ErrScope     = errors.New("path out of scope")
	ErrTraversal = errors.New("path traversal")
	ErrSymlink   = errors.New("symlink in path")
	ErrAbsolute  = errors.New("absolute path")
)

var lookAlikes = map[rune]bool{
	'\\':     true,
	'\u2215': true,
	'\u2044': true,
	'\uFF0F': true,
	'\u29F8': true,
	'\uFF3C': true,
	'\uFF0E': true,
	'\u2024': true,
	'\uFE52': true,
}

type Policy struct {
	root string
}

func NewPolicy(root string) *Policy {
	return &Policy{root: filepath.Clean(root)}
}

func (p *Policy) Root() string {
	return p.root
}

func (p *Policy) CheckRead(rel string) error {
	if rel == "" || len(rel) > maxPathBytes {
		return ErrScope
	}

	if isAbsolute(rel) {
		return ErrAbsolute
	}

	if hasRefusedRune(rel) {
		return ErrTraversal
	}

	segments := strings.Split(rel, "/")
	if slices.Contains(segments, "..") {
		return ErrTraversal
	}

	if rel != path.Clean(rel) {
		return ErrTraversal
	}

	for _, segment := range segments {
		if strings.HasPrefix(segment, ".") {
			return ErrScope
		}
	}

	inProjects := strings.HasPrefix(rel, projectsDir) && strings.HasSuffix(rel, ".md")
	if rel != ideasNote && !inProjects {
		return ErrScope
	}

	return p.walk(segments)
}

func (p *Policy) CheckWrite(rel string) error {
	if err := p.CheckRead(rel); err != nil {
		return err
	}

	if strings.HasPrefix(strings.ToLower(rel), reportsPrefix) {
		return ErrScope
	}
	return nil
}

func FilterResults[T any](p *Policy, items []T, pathOf func(T) string) []T {
	kept := make([]T, 0, len(items))
	for _, item := range items {
		if p.CheckRead(pathOf(item)) == nil {
			kept = append(kept, item)
		}
	}
	return kept
}

func (p *Policy) walk(segments []string) error {
	for i := range segments {
		prefix := strings.Join(segments[:i+1], "/")

		info, err := os.Lstat(filepath.Join(p.root, filepath.FromSlash(prefix)))
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("checking path: %w", err)
		}

		if info.Mode()&fs.ModeSymlink != 0 {
			return ErrSymlink
		}

		if i == len(segments)-1 && !info.Mode().IsRegular() {
			return ErrScope
		}
	}
	return nil
}

func isAbsolute(rel string) bool {
	if strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, "~") {
		return true
	}

	if len(rel) < 2 || rel[1] != ':' {
		return false
	}

	drive := rel[0]
	return ('A' <= drive && drive <= 'Z') || ('a' <= drive && drive <= 'z')
}

func hasRefusedRune(rel string) bool {
	if !utf8.ValidString(rel) {
		return true
	}

	for _, r := range rel {
		if r < 0x20 || r == 0x7f || unicode.Is(unicode.Cf, r) || lookAlikes[r] {
			return true
		}
	}
	return false
}

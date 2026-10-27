package agent

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

const (
	dirMode  = 0o700
	fileMode = 0o600
)

func isSecretName(name string) bool {
	switch name {
	case "jira-token", "aws-credentials", "gcp-token":
		return true
	default:
		return false
	}
}

func (a *Agent) xenaDir() string {
	return filepath.Join(a.home, ".config", "xena")
}

func (a *Agent) writeSecret(name string) error {
	dir := a.xenaDir()
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("creating %s: %w", dir, err)
	}

	if err := os.Chmod(dir, dirMode); err != nil {
		return fmt.Errorf("setting mode on %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, "."+name+".*")
	if err != nil {
		return fmt.Errorf("creating temp file for %s: %w", name, err)
	}
	defer os.Remove(tmp.Name())

	n, err := io.Copy(tmp, a.stdin)
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}

	if err != nil {
		return fmt.Errorf("writing %s: %w", name, err)
	}

	if n == 0 {
		return ErrEmptyValue
	}

	if err := os.Chmod(tmp.Name(), fileMode); err != nil {
		return fmt.Errorf("setting mode on %s: %w", name, err)
	}

	if err := os.Rename(tmp.Name(), filepath.Join(dir, name)); err != nil {
		return fmt.Errorf("replacing %s: %w", name, err)
	}

	return nil
}

func (a *Agent) clearSecret(name string) error {
	err := os.Remove(filepath.Join(a.xenaDir(), name))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("removing %s: %w", name, err)
	}

	return nil
}

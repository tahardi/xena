package secrets

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/tahardi/xena/internal/config"
)

const (
	suffix   = ".age"
	dirMode  = 0o700
	fileMode = 0o600
)

var (
	ErrNotFound    = errors.New("secret not found")
	ErrInvalidName = errors.New("invalid secret name")

	validName = regexp.MustCompile(`^[a-z0-9-]+$`)
)

type Store struct {
	Dir            string
	RecipientsFile string
	IdentityFile   string
	Age            string
}

func NewDefaultStore() (Store, error) {
	age, err := exec.LookPath("age")
	if err != nil {
		return Store{}, fmt.Errorf("finding age: %w", err)
	}

	return Store{
		Dir:            config.SecretsDir(),
		RecipientsFile: filepath.Join(config.ConfigDir(), "age-recipients.txt"),
		IdentityFile:   filepath.Join(config.ConfigDir(), "age-identities.txt"),
		Age:            age,
	}, nil
}

func (s Store) Put(name string, value io.Reader) error {
	if err := checkName(name); err != nil {
		return err
	}

	if err := s.encrypt(name, value); err != nil {
		return fmt.Errorf("encrypting secret %s: %w", name, err)
	}

	return nil
}

func (s Store) Get(ctx context.Context, name string) ([]byte, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}

	path := s.path(name)
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("reading secret %s: %w", name, ErrNotFound)
	}

	var out bytes.Buffer
	// #nosec G204 -- s.Age is the age binary from NewDefaultStore and every argument is a path, never secret data.
	cmd := exec.CommandContext(ctx, s.Age, "-d", "-i", s.IdentityFile, path)
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("decrypting secret %s: %w", name, err)
	}

	return out.Bytes(), nil
}

func (s Store) List() ([]string, error) {
	paths, err := filepath.Glob(filepath.Join(s.Dir, "*"+suffix))
	if err != nil {
		return nil, fmt.Errorf("listing secrets: %w", err)
	}

	names := make([]string, 0, len(paths))
	for _, p := range paths {
		name := strings.TrimSuffix(filepath.Base(p), suffix)
		if validName.MatchString(name) {
			names = append(names, name)
		}
	}

	slices.Sort(names)

	return names, nil
}

func (s Store) Delete(name string) error {
	if err := checkName(name); err != nil {
		return err
	}

	err := os.Remove(s.path(name))
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("deleting secret %s: %w", name, ErrNotFound)
	}
	if err != nil {
		return fmt.Errorf("deleting secret %s: %w", name, err)
	}

	return nil
}

func (s Store) encrypt(name string, value io.Reader) error {
	if err := os.MkdirAll(s.Dir, dirMode); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(s.Dir, "."+name+suffix+".tmp-*")
	if err != nil {
		return err
	}

	defer func() { _ = os.Remove(tmp.Name()) }()

	if err := s.writeTemp(tmp, value); err != nil {
		_ = tmp.Close()
		return err
	}

	return os.Rename(tmp.Name(), s.path(name))
}

func (s Store) writeTemp(tmp *os.File, value io.Reader) error {
	if err := tmp.Chmod(fileMode); err != nil {
		return err
	}

	// #nosec G204 -- s.Age is the age binary from NewDefaultStore and every argument is a path, never secret data.
	cmd := exec.CommandContext(context.Background(), s.Age, "-e", "-R", s.RecipientsFile)
	cmd.Stdin = value
	cmd.Stdout = tmp
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}

	if err := tmp.Sync(); err != nil {
		return err
	}

	return tmp.Close()
}

func (s Store) path(name string) string {
	return filepath.Join(s.Dir, name+suffix)
}

func checkName(name string) error {
	if !validName.MatchString(name) {
		return fmt.Errorf("checking secret name %q: %w", name, ErrInvalidName)
	}

	return nil
}

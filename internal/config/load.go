package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"
)

var (
	ErrUnknownVersion   = errors.New("unknown version")
	ErrMissingVersion   = errors.New("missing version")
	ErrMissingMigration = errors.New("missing migration")
)

func Load[T any](
	path string,
	current int,
	migrate map[int]func(map[string]any) (map[string]any, error),
) (T, error) {
	var zero T
	original, err := os.ReadFile(path)
	if err != nil {
		return zero, fmt.Errorf("reading %s: %w", path, err)
	}
	var raw map[string]any
	if err := yaml.Unmarshal(original, &raw); err != nil {
		return zero, fmt.Errorf("parsing %s: %w", path, err)
	}
	version, ok := raw["version"].(int)
	if !ok || version < 1 {
		return zero, fmt.Errorf("reading version of %s: %w", path, ErrMissingVersion)
	}
	if version > current {
		return zero, fmt.Errorf("loading %s version %d: %w", path, version, ErrUnknownVersion)
	}
	data := original
	if version < current {
		data, err = migrateFile(path, original, raw, version, current, migrate)
		if err != nil {
			return zero, err
		}
	}
	var out T
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&out); err != nil {
		return zero, fmt.Errorf("decoding %s: %w", path, err)
	}
	return out, nil
}

func migrateFile(
	path string,
	original []byte,
	raw map[string]any,
	from int,
	current int,
	migrate map[int]func(map[string]any) (map[string]any, error),
) ([]byte, error) {
	var err error
	for v := from; v < current; v++ {
		step, ok := migrate[v]
		if !ok {
			return nil, fmt.Errorf("migrating %s from version %d: %w", path, v, ErrMissingMigration)
		}
		if raw, err = step(raw); err != nil {
			return nil, fmt.Errorf("migrating %s from version %d: %w", path, v, err)
		}
	}
	raw["version"] = current
	data, err := yaml.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("encoding %s: %w", path, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("reading mode of %s: %w", path, err)
	}
	backup := fmt.Sprintf("%s.v%d.bak", path, from)
	if err := writeAtomic(backup, original, info.Mode().Perm()); err != nil {
		return nil, err
	}
	if err := writeAtomic(path, data, info.Mode().Perm()); err != nil {
		return nil, err
	}
	return data, nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("creating temp file for %s: %w", path, err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("writing %s: %w", tmp.Name(), err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing %s: %w", tmp.Name(), err)
	}
	if err := os.Chmod(tmp.Name(), mode); err != nil {
		return fmt.Errorf("setting mode of %s: %w", tmp.Name(), err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("renaming %s: %w", tmp.Name(), err)
	}
	return nil
}

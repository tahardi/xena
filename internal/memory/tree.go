package memory

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"time"
)

func listFiles(dir string) ([]string, error) {
	var files []string

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if errors.Is(err, fs.ErrNotExist) && path == dir {
			return filepath.SkipDir
		}

		if err != nil {
			return err
		}

		if !d.Type().IsRegular() {
			return nil
		}

		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}

		files = append(files, filepath.ToSlash(rel))

		return nil
	})
	if err != nil {
		return nil, err
	}

	slices.Sort(files)

	return files, nil
}

func copyTree(src, dst string) error {
	files, err := listFiles(src)
	if err != nil {
		return err
	}

	for _, rel := range files {
		data, err := os.ReadFile(filepath.Join(src, rel))
		if err != nil {
			return err
		}

		target := filepath.Join(dst, rel)
		if err := os.MkdirAll(filepath.Dir(target), dirMode); err != nil {
			return err
		}

		// The target is a relative path listed from our own staging copy under dst.
		if err := os.WriteFile(target, data, fileMode); err != nil { //nolint:gosec
			return err
		}
	}

	return nil
}

func swapIn(dir, name, staging string, now time.Time) error {
	target := filepath.Join(dir, name)
	old := filepath.Join(dir, ".old-"+strconv.FormatInt(now.Unix(), 10))

	err := os.Rename(target, old)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	hadOld := err == nil

	if err := os.Rename(staging, target); err != nil {
		if hadOld {
			_ = os.Rename(old, target)
		}

		return err
	}

	return os.RemoveAll(old)
}

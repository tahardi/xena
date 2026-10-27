package agent

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

func (a *Agent) exportMemory() error {
	roots, err := filepath.Glob(filepath.Join(a.home, ".claude", "projects", "*", "memory"))
	if err != nil {
		return fmt.Errorf("finding memory dirs: %w", err)
	}

	roots = append(roots, filepath.Join(a.home, ".claude-mem"))
	tw := tar.NewWriter(a.stdout)

	for _, root := range roots {
		if err := a.addTree(tw, root); err != nil {
			return err
		}
	}

	if err := tw.Close(); err != nil {
		return fmt.Errorf("closing archive: %w", err)
	}

	return nil
}

func (a *Agent) addTree(tw *tar.Writer, root string) error {
	if !isRealDir(root) || !isRealDir(filepath.Dir(root)) {
		return nil
	}

	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walking %s: %w", path, err)
		}

		if !d.IsDir() && !d.Type().IsRegular() {
			return nil
		}

		return a.addMember(tw, path, d)
	})
}

func (a *Agent) addMember(tw *tar.Writer, path string, d fs.DirEntry) error {
	info, err := d.Info()
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}

	rel, err := filepath.Rel(a.home, path)
	if err != nil {
		return fmt.Errorf("naming %s: %w", path, err)
	}

	h, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return fmt.Errorf("building header for %s: %w", rel, err)
	}

	h.Name = filepath.ToSlash(rel)
	h.Uname, h.Gname = "", ""

	if d.IsDir() {
		h.Name += "/"
	}

	if err := tw.WriteHeader(h); err != nil {
		return fmt.Errorf("writing header for %s: %w", rel, err)
	}

	if d.IsDir() {
		return nil
	}

	return copyFile(tw, path)
}

func copyFile(w io.Writer, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()

	if _, err := io.Copy(w, f); err != nil {
		return fmt.Errorf("copying %s: %w", path, err)
	}

	return nil
}

func isRealDir(path string) bool {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) || err != nil {
		return false
	}

	return info.IsDir()
}

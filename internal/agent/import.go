package agent

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
)

const cleanPath = "PATH=/usr/sbin:/usr/bin:/sbin:/bin"

func (a *Agent) importMemory(ctx context.Context) error {
	exists, err := a.memoryExists()
	if err != nil {
		return err
	}

	if exists {
		return ErrMemoryExists
	}

	tmp, err := os.MkdirTemp(a.home, ".xena-import-")
	if err != nil {
		return fmt.Errorf("creating import dir: %w", err)
	}
	defer os.RemoveAll(tmp)

	if err := extract(a.stdin, tmp); err != nil {
		return err
	}

	if err := a.moveMemory(tmp); err != nil {
		return err
	}

	return a.loadDatabase(ctx, filepath.Join(tmp, "claude-mem", "claude-mem.sql"))
}

func (a *Agent) memoryExists() (bool, error) {
	_, err := os.Lstat(filepath.Join(a.home, ".claude-mem", "claude-mem.db"))
	if err == nil {
		return true, nil
	}

	if !errors.Is(err, fs.ErrNotExist) {
		return false, fmt.Errorf("checking claude-mem database: %w", err)
	}

	files, err := filepath.Glob(filepath.Join(a.home, ".claude", "projects", "*", "memory", "*"))
	if err != nil {
		return false, fmt.Errorf("checking memory files: %w", err)
	}

	return len(files) > 0, nil
}

func extract(r io.Reader, dir string) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("opening import dir: %w", err)
	}
	defer root.Close()

	tr := tar.NewReader(r)

	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}

		if err != nil {
			return fmt.Errorf("reading archive: %w", err)
		}

		if err := extractMember(root, tr, h); err != nil {
			return err
		}
	}
}

func extractMember(root *os.Root, r io.Reader, h *tar.Header) error {
	name := path.Clean(h.Name)
	if !filepath.IsLocal(name) {
		return fmt.Errorf("checking member %q: %w", h.Name, ErrUnsafeArchive)
	}

	switch h.Typeflag {
	case tar.TypeDir:
		if err := root.MkdirAll(name, dirMode); err != nil {
			return fmt.Errorf("creating %s: %w", name, err)
		}

		return nil
	case tar.TypeReg:
		return writeMember(root, r, name)
	default:
		return fmt.Errorf("checking member %q: %w", h.Name, ErrUnsafeArchive)
	}
}

func writeMember(root *os.Root, r io.Reader, name string) error {
	if err := root.MkdirAll(path.Dir(name), dirMode); err != nil {
		return fmt.Errorf("creating dir for %s: %w", name, err)
	}

	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
	if err != nil {
		return fmt.Errorf("creating %s: %w", name, err)
	}

	_, err = io.Copy(f, r)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}

	if err != nil {
		return fmt.Errorf("writing %s: %w", name, err)
	}

	return nil
}

func (a *Agent) moveMemory(tmp string) error {
	dirs, err := filepath.Glob(filepath.Join(tmp, "projects", "*", "memory"))
	if err != nil {
		return fmt.Errorf("finding imported memory: %w", err)
	}

	for _, dir := range dirs {
		if !isRealDir(dir) {
			continue
		}

		project := filepath.Join(a.home, ".claude", "projects", filepath.Base(filepath.Dir(dir)))
		if err := os.MkdirAll(project, dirMode); err != nil {
			return fmt.Errorf("creating %s: %w", project, err)
		}

		dest := filepath.Join(project, "memory")
		if err := os.Remove(dest); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("removing empty %s: %w", dest, err)
		}

		if err := os.Rename(dir, dest); err != nil {
			return fmt.Errorf("moving memory into %s: %w", project, err)
		}
	}

	return nil
}

func (a *Agent) loadDatabase(ctx context.Context, sqlPath string) error {
	info, err := os.Lstat(sqlPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("checking claude-mem export: %w", err)
	}

	if !info.Mode().IsRegular() {
		return nil
	}

	dbDir := filepath.Join(a.home, ".claude-mem")
	if err := os.MkdirAll(dbDir, dirMode); err != nil {
		return fmt.Errorf("creating %s: %w", dbDir, err)
	}

	sql, err := os.Open(sqlPath)
	if err != nil {
		return fmt.Errorf("opening claude-mem export: %w", err)
	}
	defer sql.Close()

	// #nosec G204 -- a.sqlite is fixed in main and the only argument is the database path under home.
	cmd := exec.CommandContext(ctx, a.sqlite, "-safe", filepath.Join(dbDir, "claude-mem.db"))
	cmd.Dir = a.home
	cmd.Env = []string{"HOME=" + a.home, cleanPath}
	cmd.Stdin = sql
	cmd.Stderr = a.stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("importing claude-mem database: %w", err)
	}

	return nil
}

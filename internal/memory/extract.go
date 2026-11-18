package memory

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"strings"
)

const (
	dirMode  = 0o700
	fileMode = 0o600
)

var (
	ErrUnsafeEntry = errors.New("unsafe archive entry")
	ErrTooLarge    = errors.New("memory export too large")
)

type Limits struct {
	MaxFile  int64
	MaxTotal int64
	MaxFiles int
}

const (
	maxFileBytes  = 256 << 20
	maxTotalBytes = 1 << 30
	maxFiles      = 10000
)

var DefaultLimits = Limits{MaxFile: maxFileBytes, MaxTotal: maxTotalBytes, MaxFiles: maxFiles}

var dbFiles = []string{"claude-mem.db", "claude-mem.db-wal", "claude-mem.db-shm"}

func Extract(r io.Reader, dst string, lim Limits) (int, error) {
	root, err := os.OpenRoot(dst)
	if err != nil {
		return 0, fmt.Errorf("writing %s: %w", ".", err)
	}
	defer root.Close()

	tr := tar.NewReader(r)
	files := 0
	var total int64

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return files, nil
		}

		if err != nil {
			return 0, fmt.Errorf("reading export: %w", err)
		}

		if strings.HasPrefix(hdr.Name, "/") || slices.Contains(strings.Split(hdr.Name, "/"), "..") {
			return 0, fmt.Errorf("reading export: %w", ErrUnsafeEntry)
		}

		name, kept := keptName(path.Clean(hdr.Name))
		if !kept || hdr.Typeflag == tar.TypeDir {
			continue
		}

		if hdr.Typeflag != tar.TypeReg {
			return 0, fmt.Errorf("reading export: %w", ErrUnsafeEntry)
		}

		files++
		if files > lim.MaxFiles || hdr.Size > lim.MaxFile || total+hdr.Size > lim.MaxTotal {
			return 0, fmt.Errorf("reading export: %w", ErrTooLarge)
		}

		n, err := writeEntry(root, tr, name, hdr.Size)
		if err != nil {
			return 0, err
		}

		total += n
	}
}

func keptName(name string) (string, bool) {
	parts := strings.Split(name, "/")

	if len(parts) >= 5 && parts[0] == ".claude" && parts[1] == "projects" && parts[3] == "memory" {
		return path.Join(parts[1:]...), true
	}

	if len(parts) == 2 && parts[0] == ".claude-mem" && slices.Contains(dbFiles, parts[1]) {
		return path.Join("db", parts[1]), true
	}

	return "", false
}

func writeEntry(root *os.Root, r io.Reader, name string, size int64) (int64, error) {
	if err := root.MkdirAll(path.Dir(name), dirMode); err != nil {
		return 0, fmt.Errorf("writing %s: %w", name, err)
	}

	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
	if err != nil {
		return 0, fmt.Errorf("writing %s: %w", name, err)
	}

	n, err := io.CopyN(f, r, size)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}

	if err != nil {
		return 0, fmt.Errorf("writing %s: %w", name, err)
	}

	return n, nil
}

package memory

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/tahardi/xena/internal/vmexec"
)

var (
	ErrEmptyExport   = errors.New("empty memory export")
	ErrSecretsRemain = errors.New("secrets remain after redaction")
)

type Result struct {
	Time       time.Time `json:"time"`
	Files      int       `json:"files"`
	Redactions int       `json:"redactions"`
}

type Sync struct {
	runner   vmexec.Runner
	dir      string
	gitleaks string
	sqlite   string
	now      func() time.Time
	logger   *slog.Logger
}

func NewSync(
	runner vmexec.Runner,
	dir string,
	gitleaks string,
	sqlite string,
	now func() time.Time,
	logger *slog.Logger,
) *Sync {
	return &Sync{runner: runner, dir: dir, gitleaks: gitleaks, sqlite: sqlite, now: now, logger: logger}
}

func (s *Sync) Pull(ctx context.Context, force bool) (Result, error) {
	unlock, err := Lock(ctx, s.dir)
	if err != nil {
		return Result{}, err
	}
	defer unlock()

	export, err := s.runner.Run(ctx, "memory-export", nil, nil)
	if err != nil {
		return Result{}, fmt.Errorf("exporting memory: %w", err)
	}

	staging, err := os.MkdirTemp(s.dir, ".staging-")
	if err != nil {
		return Result{}, fmt.Errorf("extracting memory: %w", err)
	}
	defer os.RemoveAll(staging)

	if _, err := Extract(bytes.NewReader(export), staging, DefaultLimits); err != nil {
		return Result{}, fmt.Errorf("extracting memory: %w", err)
	}

	if err := s.dumpDB(ctx, staging); err != nil {
		return Result{}, fmt.Errorf("dumping claude-mem: %w", err)
	}

	files, err := listFiles(staging)
	if err != nil {
		return Result{}, fmt.Errorf("extracting memory: %w", err)
	}

	if err := s.checkNotEmpty(len(files), force); err != nil {
		return Result{}, err
	}

	redactions, err := s.redact(ctx, staging)
	if err != nil {
		return Result{}, err
	}

	result := Result{Time: s.now(), Files: len(files), Redactions: redactions}
	if err := swapIn(s.dir, "current", staging, result.Time); err != nil {
		return Result{}, fmt.Errorf("swapping memory copy: %w", err)
	}

	data, err := json.Marshal(result)
	if err != nil {
		return Result{}, fmt.Errorf("writing last sync: %w", err)
	}

	if err := writeAtomic(filepath.Join(s.dir, "last-sync.json"), data); err != nil {
		return Result{}, fmt.Errorf("writing last sync: %w", err)
	}

	s.logger.Info("pulled memory", "files", result.Files, "redactions", result.Redactions)

	return result, nil
}

func (s *Sync) Restore(ctx context.Context, reviewed bool) error {
	unlock, err := Lock(ctx, s.dir)
	if err != nil {
		return err
	}
	defer unlock()

	src := filepath.Join(s.dir, "current")
	if reviewed {
		src = filepath.Join(s.dir, "reviewed")
	}

	archive, err := tarTree(src)
	if err != nil {
		return fmt.Errorf("importing memory: %w", err)
	}

	if _, err := s.runner.Run(ctx, "memory-import", nil, archive); err != nil {
		return fmt.Errorf("importing memory: %w", err)
	}

	return nil
}

func (s *Sync) dumpDB(ctx context.Context, staging string) error {
	dbDir := filepath.Join(staging, "db")
	defer os.RemoveAll(dbDir)

	db := filepath.Join(dbDir, "claude-mem.db")
	if _, err := os.Lstat(db); errors.Is(err, fs.ErrNotExist) {
		return nil
	}

	outDir := filepath.Join(staging, "claude-mem")
	if err := os.MkdirAll(outDir, dirMode); err != nil {
		return err
	}

	out, err := os.OpenFile(filepath.Join(outDir, "claude-mem.sql"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
	if err != nil {
		return err
	}
	defer out.Close()

	// #nosec G204 -- sqlite is a fixed binary name from the caller and the only argument is our staging path.
	cmd := exec.CommandContext(ctx, s.sqlite, "-readonly", "-safe", db, ".dump")
	cmd.Stdout = out

	if err := cmd.Run(); err != nil {
		return err
	}

	return out.Close()
}

func (s *Sync) checkNotEmpty(files int, force bool) error {
	if files > 0 || force {
		return nil
	}

	existing, err := listFiles(filepath.Join(s.dir, "current"))
	if err != nil {
		return fmt.Errorf("checking memory copy: %w", err)
	}

	if len(existing) > 0 {
		return fmt.Errorf(
			"checking memory export: %w; run xena memory restore, or xena memory sync --force to accept it",
			ErrEmptyExport,
		)
	}

	return nil
}

func (s *Sync) redact(ctx context.Context, staging string) (int, error) {
	findings, err := Scan(ctx, s.gitleaks, staging)
	if err != nil {
		return 0, err
	}

	redactions, err := Redact(staging, findings)
	if err != nil {
		return 0, fmt.Errorf("redacting memory: %w", err)
	}

	remaining, err := Scan(ctx, s.gitleaks, staging)
	if err != nil {
		return 0, err
	}

	if len(remaining) > 0 {
		return 0, fmt.Errorf("redacting memory: %w", ErrSecretsRemain)
	}

	return redactions, nil
}

func tarTree(dir string) (*bytes.Buffer, error) {
	files, err := listFiles(dir)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	for _, rel := range files {
		data, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil {
			return nil, err
		}

		hdr := &tar.Header{Name: rel, Typeflag: tar.TypeReg, Mode: fileMode, Size: int64(len(data))}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}

		if _, err := tw.Write(data); err != nil {
			return nil, err
		}
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}

	return &buf, nil
}

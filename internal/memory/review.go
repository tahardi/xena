package memory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const diffChanged = 1

var ErrStaleDigest = errors.New("memory changed since diff")

func TreeDigest(dir string) (string, error) {
	files, err := listFiles(dir)
	if err != nil {
		return "", fmt.Errorf("hashing memory: %w", err)
	}

	tree := sha256.New()
	for _, rel := range files {
		data, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil {
			return "", fmt.Errorf("hashing memory: %w", err)
		}

		sum := sha256.Sum256(data)
		tree.Write([]byte(rel))
		tree.Write([]byte{0})
		tree.Write(sum[:])
	}

	return hex.EncodeToString(tree.Sum(nil)), nil
}

func MarkReviewed(dir, digest string, now time.Time) error {
	unlock, err := Lock(dir)
	if err != nil {
		return err
	}
	defer unlock()

	got, err := TreeDigest(filepath.Join(dir, "current"))
	if err != nil {
		return err
	}

	if got != digest {
		return fmt.Errorf("checking digest: %w", ErrStaleDigest)
	}

	staging, err := os.MkdirTemp(dir, ".staging-")
	if err != nil {
		return fmt.Errorf("copying reviewed memory: %w", err)
	}
	defer os.RemoveAll(staging)

	if err := copyTree(filepath.Join(dir, "current"), staging); err != nil {
		return fmt.Errorf("copying reviewed memory: %w", err)
	}

	if err := swapIn(dir, "reviewed", staging, now); err != nil {
		return fmt.Errorf("copying reviewed memory: %w", err)
	}

	if err := writeAtomic(filepath.Join(dir, "reviewed-at"), []byte(now.Format(time.RFC3339))); err != nil {
		return fmt.Errorf("writing review time: %w", err)
	}

	return nil
}

func Diff(ctx context.Context, diffBin, dir string) ([]byte, bool, error) {
	for _, tree := range []string{"reviewed", "current"} {
		if err := os.MkdirAll(filepath.Join(dir, tree), dirMode); err != nil {
			return nil, false, fmt.Errorf("diffing memory: %w", err)
		}
	}

	// #nosec G204 -- diffBin is a fixed binary name from the caller and the arguments are constant.
	cmd := exec.CommandContext(ctx, diffBin, "-ruNa", "reviewed", "current")
	cmd.Dir = dir

	out, err := cmd.Output()
	if err == nil {
		return out, false, nil
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == diffChanged {
		return out, true, nil
	}

	return nil, false, fmt.Errorf("diffing memory: %w", err)
}

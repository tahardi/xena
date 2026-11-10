package vm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const imageMode = 0o644

var (
	ErrChecksumMismatch = errors.New("checksum mismatch")
	errUnexpectedStatus = errors.New("unexpected status")
)

func FetchImage(ctx context.Context, client *http.Client, url, sha256Hex, dest string) error {
	if fileHasHash(dest, sha256Hex) {
		return nil
	}

	tmp, err := os.CreateTemp(filepath.Dir(dest), ".image-*")
	if err != nil {
		return fmt.Errorf("downloading image: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	defer func() { _ = tmp.Close() }()

	hasher := sha256.New()
	if err = download(ctx, client, url, io.MultiWriter(tmp, hasher)); err != nil {
		return fmt.Errorf("downloading image: %w", err)
	}

	if hexSum(hasher) != sha256Hex {
		return fmt.Errorf("verifying image: %w", ErrChecksumMismatch)
	}

	if err = tmp.Close(); err != nil {
		return fmt.Errorf("downloading image: %w", err)
	}

	if err = os.Chmod(tmp.Name(), imageMode); err != nil {
		return fmt.Errorf("downloading image: %w", err)
	}

	if err = os.Rename(tmp.Name(), dest); err != nil {
		return fmt.Errorf("downloading image: %w", err)
	}

	return nil
}

func download(ctx context.Context, client *http.Client, url string, w io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w %d", errUnexpectedStatus, resp.StatusCode)
	}

	_, err = io.Copy(w, resp.Body)
	return err
}

func fileHasHash(path, sha256Hex string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()

	hasher := sha256.New()
	if _, err = io.Copy(hasher, f); err != nil {
		return false
	}

	return hexSum(hasher) == sha256Hex
}

func hexSum(h hash.Hash) string {
	return hex.EncodeToString(h.Sum(nil))
}

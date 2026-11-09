package vm_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/vm"
)

func TestFetchImage(t *testing.T) {
	body := []byte("fake image bytes")
	sum := sha256.Sum256(body)
	goodSHA := hex.EncodeToString(sum[:])
	wrongSHA := hex.EncodeToString(make([]byte, sha256.Size))

	tests := []struct {
		name         string
		status       int
		sha          string
		existing     []byte
		wantErr      error
		wantErrText  string
		wantRequests int32
		wantDest     bool
	}{
		{
			name:         "happy path - download",
			status:       http.StatusOK,
			sha:          goodSHA,
			wantRequests: 1,
			wantDest:     true,
		},
		{
			name:         "happy path - cached",
			status:       http.StatusOK,
			sha:          goodSHA,
			existing:     body,
			wantRequests: 0,
			wantDest:     true,
		},
		{
			name:         "happy path - stale file is replaced",
			status:       http.StatusOK,
			sha:          goodSHA,
			existing:     []byte("stale bytes"),
			wantRequests: 1,
			wantDest:     true,
		},
		{
			name:         "error - checksum mismatch",
			status:       http.StatusOK,
			sha:          wrongSHA,
			wantErr:      vm.ErrChecksumMismatch,
			wantRequests: 1,
		},
		{
			name:         "error - server returns 404",
			status:       http.StatusNotFound,
			sha:          goodSHA,
			wantErrText:  "downloading image: unexpected status 404",
			wantRequests: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(tt.status)
				_, _ = w.Write(body)
			}))
			t.Cleanup(server.Close)

			dir := t.TempDir()
			dest := filepath.Join(dir, "base.img")
			if tt.existing != nil {
				require.NoError(t, os.WriteFile(dest, tt.existing, 0o600))
			}

			// when
			err := vm.FetchImage(context.Background(), server.Client(), server.URL, tt.sha, dest)

			// then
			require.Equal(t, tt.wantRequests, requests.Load())

			if !tt.wantDest {
				require.Error(t, err)
				if tt.wantErr != nil {
					require.ErrorIs(t, err, tt.wantErr)
				}
				if tt.wantErrText != "" {
					require.EqualError(t, err, tt.wantErrText)
				}

				entries, readErr := os.ReadDir(dir)
				require.NoError(t, readErr)
				require.Empty(t, entries)
				return
			}

			require.NoError(t, err)

			got, readErr := os.ReadFile(dest)
			require.NoError(t, readErr)
			require.Equal(t, body, got)

			if tt.wantRequests == 1 {
				info, statErr := os.Stat(dest)
				require.NoError(t, statErr)
				require.Equal(t, os.FileMode(0o644), info.Mode().Perm())
			}
		})
	}

	t.Run("error - failed download keeps stale file", func(t *testing.T) {
		// given
		server := httptest.NewServer(http.NotFoundHandler())
		t.Cleanup(server.Close)

		dest := filepath.Join(t.TempDir(), "base.img")
		require.NoError(t, os.WriteFile(dest, []byte("stale bytes"), 0o600))

		// when
		err := vm.FetchImage(context.Background(), server.Client(), server.URL, goodSHA, dest)

		// then
		require.Error(t, err)

		got, readErr := os.ReadFile(dest)
		require.NoError(t, readErr)
		require.Equal(t, "stale bytes", string(got))
	})

	t.Run("error - connection drops mid body", func(t *testing.T) {
		// given
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(len(body)*2))
			_, _ = w.Write(body)
		}))
		t.Cleanup(server.Close)

		dir := t.TempDir()

		// when
		err := vm.FetchImage(context.Background(), server.Client(), server.URL, goodSHA, filepath.Join(dir, "base.img"))

		// then
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)

		entries, readErr := os.ReadDir(dir)
		require.NoError(t, readErr)
		require.Empty(t, entries)
	})

	t.Run("error - cancelled context", func(t *testing.T) {
		// given
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(body)
		}))
		t.Cleanup(server.Close)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		dir := t.TempDir()

		// when
		err := vm.FetchImage(ctx, server.Client(), server.URL, goodSHA, filepath.Join(dir, "base.img"))

		// then
		require.ErrorIs(t, err, context.Canceled)

		entries, readErr := os.ReadDir(dir)
		require.NoError(t, readErr)
		require.Empty(t, entries)
	})

	t.Run("error - destination directory missing", func(t *testing.T) {
		// given
		dest := filepath.Join(t.TempDir(), "missing", "base.img")

		// when
		err := vm.FetchImage(context.Background(), http.DefaultClient, "http://127.0.0.1:1", goodSHA, dest)

		// then
		require.ErrorIs(t, err, fs.ErrNotExist)
		require.ErrorContains(t, err, "downloading image: ")
	})
}

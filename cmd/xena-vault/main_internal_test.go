package main

import (
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func writeScript(t *testing.T, body string) string {
	t.Helper()

	bin := filepath.Join(t.TempDir(), "anchorhold")
	require.NoError(t, os.WriteFile(bin, []byte("#!/bin/sh\n"+body+"\n"), 0o700))
	return bin
}

func TestRun(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{name: "happy path - help", args: []string{"-h"}},
		{name: "error - unknown flag", args: []string{"-bogus"}, wantErr: "parsing flags"},
		{
			name:    "error - anchorhold fails",
			args:    []string{"-anchorhold", writeScript(t, "exit 2")},
			wantErr: "reading vault root",
		},
		{
			name:    "error - vault root missing",
			args:    []string{"-anchorhold", writeScript(t, `echo '{"vault":"/nonexistent/vault"}'`)},
			wantErr: "resolving vault root",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			logger := slog.New(slog.DiscardHandler)

			// when
			err := run(t.Context(), tt.args, logger)

			// then
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestListen(t *testing.T) {
	t.Run("error - non-socket at socket path", func(t *testing.T) {
		// given
		socket := filepath.Join(t.TempDir(), "vault.sock")
		require.NoError(t, os.WriteFile(socket, []byte("keep"), 0o600))

		// when
		_, err := listen(t.Context(), socket)

		// then
		require.ErrorIs(t, err, errNonSocket)
		data, readErr := os.ReadFile(socket)
		require.NoError(t, readErr)
		require.Equal(t, "keep", string(data))
	})

	t.Run("happy path - creates state dir and socket", func(t *testing.T) {
		// given
		socket := filepath.Join(t.TempDir(), "state", "vault.sock")

		// when
		ln, err := listen(t.Context(), socket)

		// then
		require.NoError(t, err)
		defer ln.Close()

		dir, err := os.Stat(filepath.Dir(socket))
		require.NoError(t, err)
		require.Equal(t, fs.FileMode(0o700), dir.Mode().Perm())

		info, err := os.Lstat(socket)
		require.NoError(t, err)
		require.NotZero(t, info.Mode()&fs.ModeSocket)
		require.Equal(t, fs.FileMode(0o600), info.Mode().Perm())
	})

	t.Run("happy path - replaces stale socket", func(t *testing.T) {
		// given
		socket := filepath.Join(t.TempDir(), "vault.sock")
		var lc net.ListenConfig
		stale, err := lc.Listen(t.Context(), "unix", socket)
		require.NoError(t, err)

		unixStale, ok := stale.(*net.UnixListener)
		require.True(t, ok)
		unixStale.SetUnlinkOnClose(false)
		require.NoError(t, stale.Close())

		// when
		ln, err := listen(t.Context(), socket)

		// then
		require.NoError(t, err)
		defer ln.Close()

		var dialer net.Dialer
		conn, err := dialer.DialContext(t.Context(), "unix", socket)
		require.NoError(t, err)
		require.NoError(t, conn.Close())
	})
}

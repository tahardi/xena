package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunVM(t *testing.T) {
	tests := []struct {
		name          string
		args          []string
		wantErr       error
		wantErrPrefix string
	}{
		{name: "error - no subcommand", args: nil, wantErr: errUnknownCommand},
		{name: "error - unknown subcommand", args: []string{"bogus"}, wantErr: errUnknownCommand},
		{name: "error - snapshot without name", args: []string{"snapshot"}, wantErrPrefix: "checking arguments: "},
		{name: "error - restore without name", args: []string{"restore"}, wantErrPrefix: "checking arguments: "},
		{name: "error - start without vm config", args: []string{"start"}, wantErrPrefix: "loading vm config: "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			t.Setenv("XENA_REPO_CONFIG_DIR", t.TempDir())
			logger := slog.New(slog.DiscardHandler)

			// when
			err := runVM(context.Background(), tt.args, logger)

			// then
			require.Error(t, err)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
			}
			if tt.wantErrPrefix != "" {
				require.True(t, strings.HasPrefix(err.Error(), tt.wantErrPrefix), err.Error())
			}
		})
	}
}

func TestNewDiskKeyStore(t *testing.T) {
	t.Run("error - prints only the disk unlock touch line", func(t *testing.T) {
		// given
		binDir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(binDir, "age"), []byte("#!/bin/sh\nexit 1\n"), 0o700))
		t.Setenv("PATH", binDir)

		secretsDir := t.TempDir()
		t.Setenv("XENA_SECRETS_DIR", secretsDir)
		require.NoError(t, os.WriteFile(filepath.Join(secretsDir, "a.age"), nil, 0o600))

		stdout := swapFile(t, &os.Stdout)
		stderr := swapFile(t, &os.Stderr)

		store, err := newDiskKeyStore(slog.New(slog.DiscardHandler))
		require.NoError(t, err)

		// when
		_, err = store.Get(context.Background(), "a")

		// then
		require.ErrorContains(t, err, "decrypting secret")

		gotStdout, err := os.ReadFile(stdout)
		require.NoError(t, err)
		assert.Empty(t, string(gotStdout))

		gotStderr, err := os.ReadFile(stderr)
		require.NoError(t, err)
		assert.Equal(t, "touch your YubiKey to unlock the VM disk\n", string(gotStderr))
	})

	t.Run("error - age missing", func(t *testing.T) {
		// given
		t.Setenv("PATH", t.TempDir())

		// when
		_, err := newDiskKeyStore(slog.New(slog.DiscardHandler))

		// then
		require.ErrorContains(t, err, "building secrets store")
	})
}

func swapFile(t *testing.T, target **os.File) string {
	t.Helper()

	file, err := os.CreateTemp(t.TempDir(), "out")
	require.NoError(t, err)

	original := *target
	*target = file
	t.Cleanup(func() {
		*target = original
		_ = file.Close()
	})

	return file.Name()
}

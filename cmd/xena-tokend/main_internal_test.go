package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/github"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name          string
		args          []string
		appConfig     string
		wantErrPrefix string
	}{
		{name: "error - unknown flag", args: []string{"--bogus"}, wantErrPrefix: "parsing flags"},
		{name: "error - missing app config", args: nil, wantErrPrefix: "loading github app config"},
		{
			name:          "error - missing vm config",
			args:          nil,
			appConfig:     "version: 1\napp_id: 12345\ninstallation_id: 67890\n",
			wantErrPrefix: "loading vm config",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			configDir := t.TempDir()
			t.Setenv("XENA_CONFIG_DIR", configDir)
			t.Setenv("XENA_REPO_CONFIG_DIR", t.TempDir())

			if tt.appConfig != "" {
				path := filepath.Join(configDir, "github-app.yaml")
				require.NoError(t, os.WriteFile(path, []byte(tt.appConfig), 0o600))
			}

			logger := slog.New(slog.DiscardHandler)

			// when
			err := run(context.Background(), tt.args, logger)

			// then
			require.Error(t, err)
			assert.True(t, strings.HasPrefix(err.Error(), tt.wantErrPrefix), err.Error())
		})
	}
}

func TestUnlock(t *testing.T) {
	t.Run("error - prints touch prompt before decrypting", func(t *testing.T) {
		// given
		t.Setenv("PATH", t.TempDir())

		var buf bytes.Buffer

		// when
		_, err := unlock(context.Background(), github.AppConfig{}, &buf, slog.New(slog.DiscardHandler))

		// then
		require.Error(t, err)
		assert.True(t, strings.HasPrefix(err.Error(), "building secrets store"), err.Error())
		assert.Equal(t, "touch your YubiKey to unlock the GitHub token service\n", buf.String())
	})

	t.Run("error - prints touch prompt before notify-send", func(t *testing.T) {
		// given
		binDir := t.TempDir()
		marker := filepath.Join(binDir, "notified")
		script := fmt.Sprintf("#!/bin/sh\n: > %q\n", marker)
		require.NoError(t, os.WriteFile(filepath.Join(binDir, "notify-send"), []byte(script), 0o700))
		t.Setenv("PATH", binDir)

		var statErr error
		out := writerFunc(func(p []byte) (int, error) {
			_, statErr = os.Stat(marker)

			return len(p), nil
		})

		// when
		_, err := unlock(context.Background(), github.AppConfig{}, out, slog.New(slog.DiscardHandler))

		// then
		require.Error(t, err)
		require.ErrorIs(t, statErr, os.ErrNotExist)
		require.FileExists(t, marker)
	})

	t.Run("error - touch notification is critical", func(t *testing.T) {
		// given
		binDir := t.TempDir()
		argsFile := filepath.Join(binDir, "args")
		script := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$@\" > %q\n", argsFile)
		require.NoError(t, os.WriteFile(filepath.Join(binDir, "notify-send"), []byte(script), 0o700))
		t.Setenv("PATH", binDir)

		// when
		_, err := unlock(context.Background(), github.AppConfig{}, io.Discard, slog.New(slog.DiscardHandler))

		// then
		require.Error(t, err)

		args, err := os.ReadFile(argsFile)
		require.NoError(t, err)
		want := "--app-name=Xena\n--urgency=critical\nTouch your YubiKey\nto unlock the GitHub token service\n"
		assert.Equal(t, want, string(args))
	})

	t.Run("error - logs when notify-send fails", func(t *testing.T) {
		// given
		t.Setenv("PATH", t.TempDir())

		var logs bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logs, nil))

		// when
		_, err := unlock(context.Background(), github.AppConfig{}, io.Discard, logger)

		// then
		require.Error(t, err)
		assert.Contains(t, logs.String(), `"level":"WARN"`)
		assert.Contains(t, logs.String(), `"msg":"sending desktop notification"`)
		assert.Contains(t, logs.String(), `"error":`)
	})

	t.Run("error - continues when the prompt write fails", func(t *testing.T) {
		// given
		t.Setenv("PATH", t.TempDir())

		out := writerFunc(func([]byte) (int, error) {
			return 0, os.ErrClosed
		})

		// when
		_, err := unlock(context.Background(), github.AppConfig{}, out, slog.New(slog.DiscardHandler))

		// then
		require.Error(t, err)
		assert.True(t, strings.HasPrefix(err.Error(), "building secrets store"), err.Error())
	})
}

func TestUseTerminal(t *testing.T) {
	tests := []struct {
		name       string
		terminal   func(t *testing.T) string
		wantSwitch bool
	}{
		{
			name: "happy path - sends output to the terminal",
			terminal: func(t *testing.T) string {
				t.Helper()

				path := filepath.Join(t.TempDir(), "tty")
				require.NoError(t, os.WriteFile(path, nil, 0o600))

				return path
			},
			wantSwitch: true,
		},
		{
			name: "happy path - keeps output without a terminal",
			terminal: func(t *testing.T) string {
				t.Helper()

				return filepath.Join(t.TempDir(), "missing")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			stdout, stderr := os.Stdout, os.Stderr
			t.Cleanup(func() {
				os.Stdout, os.Stderr = stdout, stderr
			})

			path := tt.terminal(t)

			// when
			useTerminal(path)

			// then
			if tt.wantSwitch {
				assert.Equal(t, path, os.Stdout.Name())
				assert.Equal(t, path, os.Stderr.Name())

				return
			}

			assert.Same(t, stdout, os.Stdout)
			assert.Same(t, stderr, os.Stderr)
		})
	}
}

type writerFunc func(p []byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) {
	return f(p)
}

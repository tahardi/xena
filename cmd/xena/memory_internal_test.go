package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var errMemoryFakeHealth = errors.New("vm unreachable")

type memoryFakeRunner struct {
	err   map[string]error
	verbs []string
}

func (r *memoryFakeRunner) Run(_ context.Context, verb string, _ []string, _ io.Reader) ([]byte, error) {
	r.verbs = append(r.verbs, verb)
	return nil, r.err[verb]
}

func TestRunMemoryWith(t *testing.T) {
	digestLine := regexp.MustCompile(`digest: [0-9a-f]{64}\n$`)

	tests := []struct {
		name          string
		args          []string
		healthErr     error
		wantOut       *regexp.Regexp
		wantVerbs     []string
		wantErr       error
		wantErrPrefix string
	}{
		{
			name:    "error - no subcommand",
			args:    []string{},
			wantErr: errUnknownCommand,
		},
		{
			name:    "error - unknown subcommand",
			args:    []string{"push"},
			wantErr: errUnknownCommand,
		},
		{
			name:      "happy path - sync skips unreachable vm",
			args:      []string{"sync"},
			healthErr: errMemoryFakeHealth,
			wantOut:   regexp.MustCompile(`^skipping memory sync: vm unreachable\n$`),
			wantVerbs: []string{"health"},
		},
		{
			name:          "error - reviewed without digest",
			args:          []string{"reviewed"},
			wantErrPrefix: "reading digest",
		},
		{
			name:    "happy path - diff ends with digest",
			args:    []string{"diff"},
			wantOut: digestLine,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			binDir := t.TempDir()
			diffBin := filepath.Join(binDir, "diff")
			require.NoError(t, os.WriteFile(diffBin, []byte("#!/bin/sh\necho 'diff output'\nexit 1\n"), 0o700))

			runner := &memoryFakeRunner{err: map[string]error{"health": tt.healthErr}}
			var out bytes.Buffer
			deps := memoryDeps{
				Runner:   runner,
				Dir:      filepath.Join(t.TempDir(), "memory"),
				Gitleaks: filepath.Join(binDir, "gitleaks"),
				Sqlite:   filepath.Join(binDir, "sqlite3"),
				Diff:     diffBin,
				Out:      &out,
				Now:      time.Now,
			}

			// when
			err := runMemoryWith(context.Background(), tt.args, deps)

			// then
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}

			if tt.wantErrPrefix != "" {
				require.Error(t, err)
				require.True(t, strings.HasPrefix(err.Error(), tt.wantErrPrefix), err.Error())
				return
			}

			require.NoError(t, err)
			require.Regexp(t, tt.wantOut, out.String())
			require.Equal(t, tt.wantVerbs, runner.verbs)
		})
	}
}

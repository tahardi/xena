package main

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/memory"
)

var (
	errMemoryFakeHealth = errors.New("vm unreachable")
	errMemoryFakePull   = errors.New("exporting memory: vm gone")
	errMemoryFakeState  = errors.New("reading vm state: no libvirt")
)

type memoryFakeRunner struct {
	out   map[string][]byte
	err   map[string]error
	verbs []string
}

func (r *memoryFakeRunner) Run(_ context.Context, verb string, _ []string, _ io.Reader) ([]byte, error) {
	r.verbs = append(r.verbs, verb)
	return r.out[verb], r.err[verb]
}

type memoryFakePuller struct {
	err    error
	pulled bool
}

func (p *memoryFakePuller) Pull(context.Context, bool) (memory.Result, error) {
	p.pulled = true
	return memory.Result{}, p.err
}

type memoryFakeVM struct {
	state string
	err   error
}

func (v memoryFakeVM) State(context.Context) (string, error) {
	return v.state, v.err
}

func memoryExport(t *testing.T) []byte {
	t.Helper()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	body := []byte("remember this")

	hdr := &tar.Header{
		Name:     ".claude/projects/p/memory/MEMORY.md",
		Typeflag: tar.TypeReg,
		Mode:     0o600,
		Size:     int64(len(body)),
	}
	require.NoError(t, tw.WriteHeader(hdr))

	_, err := tw.Write(body)
	require.NoError(t, err)
	require.NoError(t, tw.Close())

	return buf.Bytes()
}

func seedMemoryTree(t *testing.T, dir, tree string) {
	t.Helper()

	path := filepath.Join(dir, tree, "projects", "p", "memory", "MEMORY.md")
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte(tree), 0o600))
}

func TestRunMemoryWith(t *testing.T) {
	tests := []struct {
		name          string
		args          func(t *testing.T, dir string) []string
		seed          []string
		healthErr     error
		diffOut       string
		wantOut       *regexp.Regexp
		wantVerbs     []string
		wantErr       error
		wantErrPrefix string
	}{
		{
			name:    "error - no subcommand",
			args:    func(*testing.T, string) []string { return []string{} },
			wantErr: errUnknownCommand,
		},
		{
			name:    "error - unknown subcommand",
			args:    func(*testing.T, string) []string { return []string{"push"} },
			wantErr: errUnknownCommand,
		},
		{
			name:      "happy path - sync skips unreachable vm",
			args:      func(*testing.T, string) []string { return []string{"sync"} },
			healthErr: errMemoryFakeHealth,
			wantOut:   regexp.MustCompile(`^skipping memory sync: vm unreachable\n$`),
			wantVerbs: []string{"health"},
		},
		{
			name:      "happy path - sync pulls when vm answers",
			args:      func(*testing.T, string) []string { return []string{"sync"} },
			wantOut:   regexp.MustCompile(`^$`),
			wantVerbs: []string{"health", "memory-export"},
		},
		{
			name:          "error - bad sync flag",
			args:          func(*testing.T, string) []string { return []string{"sync", "--nope"} },
			wantErrPrefix: "parsing memory sync flags",
		},
		{
			name:          "error - reviewed without digest",
			args:          func(*testing.T, string) []string { return []string{"reviewed"} },
			wantErrPrefix: "reading digest",
		},
		{
			name: "happy path - reviewed with matching digest",
			args: func(t *testing.T, dir string) []string {
				t.Helper()

				digest, err := memory.TreeDigest(filepath.Join(dir, "current"))
				require.NoError(t, err)

				return []string{"reviewed", digest}
			},
			seed:    []string{"current"},
			wantOut: regexp.MustCompile(`^marked memory reviewed\n$`),
		},
		{
			name:    "happy path - diff ends with digest",
			args:    func(*testing.T, string) []string { return []string{"diff"} },
			diffOut: "diff output",
			wantOut: regexp.MustCompile(`^diff output\ndigest: [0-9a-f]{64}\n$`),
		},
		{
			name:    "happy path - diff escapes terminal control bytes",
			args:    func(*testing.T, string) []string { return []string{"diff"} },
			diffOut: `\033[2K\rhidden\xc2\x9b`,
			wantOut: regexp.MustCompile(`^\\x1b\[2K\\x0dhidden\\x9b\ndigest: [0-9a-f]{64}\n$`),
		},
		{
			name:      "happy path - restore reviewed copy",
			args:      func(*testing.T, string) []string { return []string{"restore", "--reviewed"} },
			seed:      []string{"reviewed"},
			wantOut:   regexp.MustCompile(`^restored memory into the vm\n$`),
			wantVerbs: []string{"memory-import"},
		},
		{
			name:          "error - bad restore flag",
			args:          func(*testing.T, string) []string { return []string{"restore", "--nope"} },
			wantErrPrefix: "parsing memory restore flags",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			binDir := t.TempDir()
			diffBin := filepath.Join(binDir, "diff")
			diffScript := "#!/usr/bin/env bash\nprintf '" + tt.diffOut + "\\n'\nexit 1\n"
			require.NoError(t, os.WriteFile(diffBin, []byte(diffScript), 0o700))

			gitleaks := filepath.Join(binDir, "gitleaks")
			require.NoError(t, os.WriteFile(gitleaks, []byte("#!/usr/bin/env bash\necho '[]' > \"$6\"\n"), 0o700))

			dir := filepath.Join(t.TempDir(), "memory")
			for _, tree := range tt.seed {
				seedMemoryTree(t, dir, tree)
			}

			runner := &memoryFakeRunner{
				out: map[string][]byte{"memory-export": memoryExport(t)},
				err: map[string]error{"health": tt.healthErr},
			}
			var out bytes.Buffer
			deps := memoryDeps{
				Runner:   runner,
				Dir:      dir,
				Gitleaks: gitleaks,
				Sqlite:   filepath.Join(binDir, "sqlite3"),
				Diff:     diffBin,
				Out:      &out,
				Now:      time.Now,
				Logger:   slog.New(slog.DiscardHandler),
			}
			args := tt.args(t, dir)

			// when
			err := runMemoryWith(context.Background(), args, deps)

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

func TestSyncBeforeStop(t *testing.T) {
	tests := []struct {
		name       string
		vm         memoryFakeVM
		pullErr    error
		builderErr error
		wantPulled bool
		wantWarn   string
	}{
		{
			name:       "happy path - running vm pulls",
			vm:         memoryFakeVM{state: "running"},
			wantPulled: true,
		},
		{
			name:       "error - pull fails warns",
			vm:         memoryFakeVM{state: "running"},
			pullErr:    errMemoryFakePull,
			wantPulled: true,
			wantWarn:   "warning: memory sync failed: exporting memory: vm gone\n",
		},
		{
			name: "happy path - shut off vm skips",
			vm:   memoryFakeVM{state: "shut off"},
		},
		{
			name:       "happy path - unknown state still pulls",
			vm:         memoryFakeVM{err: errMemoryFakeState},
			wantPulled: true,
		},
		{
			name:       "error - building puller fails warns",
			vm:         memoryFakeVM{state: "running"},
			builderErr: errMemoryFakeHealth,
			wantWarn:   "warning: memory sync failed: vm unreachable\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			puller := &memoryFakePuller{err: tt.pullErr}
			newPuller := func() (memoryPuller, error) {
				if tt.builderErr != nil {
					return nil, tt.builderErr
				}

				return puller, nil
			}
			var warn bytes.Buffer

			// when
			syncBeforeStop(context.Background(), tt.vm, newPuller, &warn)

			// then
			require.Equal(t, tt.wantPulled, puller.pulled)
			require.Equal(t, tt.wantWarn, warn.String())
		})
	}
}

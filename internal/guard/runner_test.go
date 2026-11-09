package guard_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/guard"
)

func TestRunner_Run(t *testing.T) {
	now := time.Date(2026, 10, 25, 3, 0, 0, 0, time.UTC)
	pass := guard.Pass("a", "evidence")
	fail := guard.Fail("b", "broken")

	tests := []struct {
		name         string
		results      []guard.Result
		targets      [][]string
		reportIsFile bool
		wantPassed   bool
		wantErrIs    error
		wantErr      string
		wantWindow   []string
	}{
		{
			name:       "happy path - all pass",
			results:    []guard.Result{pass, pass},
			wantPassed: true,
		},
		{
			name:      "error - one case fails",
			results:   []guard.Result{fail, pass},
			wantErrIs: guard.ErrFailed,
		},
		{
			name:       "happy path - window written during run",
			results:    []guard.Result{pass, pass},
			targets:    [][]string{{"198.51.100.7", "10.0.0.10"}, {"10.0.0.10", "192.0.2.1"}},
			wantPassed: true,
			wantWindow: []string{"10.0.0.10", "192.0.2.1", "198.51.100.7"},
		},
		{
			name:       "error - failing case with targets still removes the window",
			results:    []guard.Result{fail, pass},
			targets:    [][]string{{"198.51.100.7"}, {"198.51.100.8"}},
			wantErrIs:  guard.ErrFailed,
			wantWindow: []string{"198.51.100.7", "198.51.100.8"},
		},
		{
			name:       "happy path - no targets",
			results:    []guard.Result{pass},
			wantPassed: true,
		},
		{
			name:         "error - report dir not writable",
			results:      []guard.Result{pass},
			reportIsFile: true,
			wantPassed:   true,
			wantErr:      "writing guard report",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			reportDir := filepath.Join(t.TempDir(), "guard")
			windowDir := t.TempDir()

			if tt.reportIsFile {
				require.NoError(t, os.WriteFile(reportDir, []byte("x"), 0o600))
			}

			seen := make([]bool, len(tt.results))
			fakes := make([]*fakeCase, len(tt.results))
			cases := make([]guard.Case, len(tt.results))
			for i, result := range tt.results {
				fakes[i] = &fakeCase{
					name:      fmt.Sprintf("case-%d", i),
					result:    result,
					windowDir: windowDir,
					sawWindow: &seen[i],
				}
				cases[i] = fakes[i]
				if tt.targets != nil {
					cases[i] = &fakeTargetCase{fakeCase: fakes[i], targets: tt.targets[i]}
				}
			}

			env := guard.Env{VMAddr: "192.168.150.10", Now: func() time.Time { return now }}

			// when
			report, err := guard.NewRunner(cases, env, reportDir, windowDir).Run(context.Background())

			// then
			assert.NoFileExists(t, filepath.Join(windowDir, "window.json"))
			for i := range seen {
				assert.Equal(t, tt.wantWindow != nil, seen[i])
				assert.Equal(t, report.Started, fakes[i].gotEnv.RunStarted)
			}

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			if tt.wantErrIs != nil {
				require.ErrorIs(t, err, tt.wantErrIs)
			} else {
				require.NoError(t, err)
			}

			data, err := os.ReadFile(filepath.Join(reportDir, "last.json"))
			require.NoError(t, err)
			assert.True(t, strings.HasPrefix(string(data), `{"version":1,`))

			var got guard.Report
			require.NoError(t, json.Unmarshal(data, &got))
			assert.Equal(t, 1, got.Version)
			assert.Equal(t, tt.wantPassed, got.Passed)
			assert.Equal(t, tt.results, got.Cases)
			assert.Equal(t, now, got.LastRun)
			assert.Equal(t, now, got.Started)

			info, err := os.Stat(filepath.Join(reportDir, "last.json"))
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

			history, err := os.ReadFile(filepath.Join(reportDir, "guard-2026-10-25.jsonl"))
			require.NoError(t, err)
			assert.Equal(t, 1, strings.Count(string(history), "\n"))
			assert.Contains(t, string(history), `"cases":[{"case":"`+tt.results[0].Case+`"`)
		})
	}

	t.Run("happy path - window contents", func(t *testing.T) {
		// given
		windowDir := t.TempDir()
		var got guard.Window
		env := guard.Env{VMAddr: "192.168.150.10", Now: func() time.Time { return now }}
		reader := &windowReadingCase{fakeCase: &fakeCase{name: "a", result: pass}, dir: windowDir, got: &got}
		runner := guard.NewRunner([]guard.Case{reader}, env, filepath.Join(t.TempDir(), "guard"), windowDir)

		// when
		_, err := runner.Run(context.Background())

		// then
		require.NoError(t, err)
		assert.Equal(t, now, got.Start)
		assert.Equal(t, now.Add(15*time.Minute), got.End)
		assert.Equal(t, "192.168.150.10", got.VMAddr)
		assert.Equal(t, []string{"198.51.100.7"}, got.Targets)
	})

	t.Run("error - window cannot be written saves a failed report and runs no case", func(t *testing.T) {
		// given
		windowDir := filepath.Join(t.TempDir(), "missing")
		reportDir := filepath.Join(t.TempDir(), "guard")
		fake := &fakeCase{name: "a", result: pass}
		target := &fakeTargetCase{fakeCase: fake, targets: []string{"198.51.100.7"}}
		env := guard.Env{Now: func() time.Time { return now }}
		runner := guard.NewRunner([]guard.Case{target}, env, reportDir, windowDir)

		// when
		report, err := runner.Run(context.Background())

		// then
		require.ErrorContains(t, err, "writing guard window")
		assert.False(t, fake.ran)
		assert.False(t, report.Passed)

		data, err := os.ReadFile(filepath.Join(reportDir, "last.json"))
		require.NoError(t, err)

		var got guard.Report
		require.NoError(t, json.Unmarshal(data, &got))
		assert.False(t, got.Passed)
		require.Len(t, got.Cases, 1)
		assert.Equal(t, "guard-window", got.Cases[0].Case)
		assert.Contains(t, got.Cases[0].Error, "writing guard window")
	})

	t.Run("error - window removal failure joins the run result", func(t *testing.T) {
		// given
		windowDir := t.TempDir()
		blocker := &windowBlockingCase{fakeCase: &fakeCase{name: "a", result: fail}, dir: windowDir}
		env := guard.Env{Now: func() time.Time { return now }}
		runner := guard.NewRunner([]guard.Case{blocker}, env, filepath.Join(t.TempDir(), "guard"), windowDir)

		// when
		_, err := runner.Run(context.Background())

		// then
		require.ErrorIs(t, err, guard.ErrFailed)
		require.ErrorContains(t, err, "removing guard window")
	})

	t.Run("error - history cannot be appended", func(t *testing.T) {
		// given
		reportDir := filepath.Join(t.TempDir(), "guard")
		require.NoError(t, os.MkdirAll(filepath.Join(reportDir, "guard-2026-10-25.jsonl"), 0o700))
		env := guard.Env{Now: func() time.Time { return now }}
		runner := guard.NewRunner([]guard.Case{&fakeCase{name: "a", result: pass}}, env, reportDir, t.TempDir())

		// when
		_, err := runner.Run(context.Background())

		// then
		require.ErrorContains(t, err, "appending guard history")
	})

	t.Run("happy path - canceled context still saves the report", func(t *testing.T) {
		// given
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		reportDir := filepath.Join(t.TempDir(), "guard")
		env := guard.Env{Now: func() time.Time { return now }}
		runner := guard.NewRunner([]guard.Case{&fakeCase{name: "a", result: fail}}, env, reportDir, t.TempDir())

		// when
		_, err := runner.Run(ctx)

		// then
		require.ErrorIs(t, err, guard.ErrFailed)
		assert.FileExists(t, filepath.Join(reportDir, "last.json"))
	})

	t.Run("happy path - empty report dir saves nothing", func(t *testing.T) {
		// given
		t.Chdir(t.TempDir())
		env := guard.Env{Now: func() time.Time { return now }}
		runner := guard.NewRunner([]guard.Case{&fakeCase{name: "a", result: pass}}, env, "", t.TempDir())

		// when
		report, err := runner.Run(context.Background())

		// then
		require.NoError(t, err)
		assert.True(t, report.Passed)
		assert.NoFileExists(t, "last.json")
		assert.NoFileExists(t, "guard-2026-10-25.jsonl")
	})
}

func TestSelect(t *testing.T) {
	lan := &fakeCase{name: "net-lan"}
	unlisted := &fakeCase{name: "net-unlisted"}
	router := &fakeCase{name: "net-router"}
	all := []guard.Case{unlisted, router, lan}

	tests := []struct {
		name      string
		names     []string
		want      []guard.Case
		wantErrIs error
		wantErr   string
	}{
		{name: "happy path - no names returns all", want: all},
		{name: "happy path - named order", names: []string{"net-lan", "net-unlisted"}, want: []guard.Case{lan, unlisted}},
		{name: "error - unknown name", names: []string{"nope"}, wantErrIs: guard.ErrUnknownCase, wantErr: "nope"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// when
			got, err := guard.Select(all, tt.names)

			// then
			if tt.wantErrIs != nil {
				require.ErrorIs(t, err, tt.wantErrIs)
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

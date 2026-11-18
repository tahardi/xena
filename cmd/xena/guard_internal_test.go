package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/guard"
	"github.com/tahardi/xena/internal/vmexec"
)

type guardFakeCase struct {
	name   string
	result guard.Result
	ran    bool
}

func (c *guardFakeCase) Name() string {
	return c.name
}

func (c *guardFakeCase) Run(context.Context, guard.Env) guard.Result {
	c.ran = true
	return c.result
}

var errGuardFake = errors.New("fake failure")

type guardFakeCommander struct {
	err   error
	calls []string
}

func (c *guardFakeCommander) Output(_ context.Context, name string, args ...string) ([]byte, error) {
	c.calls = append(c.calls, strings.Join(append([]string{name}, args...), " "))
	return nil, c.err
}

type guardFakeCut struct{}

func (guardFakeCut) IsCut(context.Context, string) (bool, error) {
	return false, nil
}

func TestRunGuardWith(t *testing.T) {
	failure := guard.Fail(
		"net-lan",
		"no firewall drop for 10.0.0.10:22/TCP",
		"vm: blocked 10.0.0.10:22",
		"proxy: 10.0.0.10:443 refuse-ip-literal at 03:00:01",
	)
	failOutput := "FAIL net-lan: no firewall drop for 10.0.0.10:22/TCP\n" +
		"  vm: blocked 10.0.0.10:22\n" +
		"  proxy: 10.0.0.10:443 refuse-ip-literal at 03:00:01\n"

	tests := []struct {
		name       string
		args       []string
		lan        guard.Result
		wantOutput string
		wantErrIs  error
		wantErr    string
		wantLan    bool
		wantOther  bool
		wantReport bool
	}{
		{
			name:       "happy path - all pass",
			lan:        guard.Pass("net-lan"),
			wantOutput: "PASS net-lan\nPASS net-router\n",
			wantLan:    true,
			wantOther:  true,
			wantReport: true,
		},
		{
			name:       "error - a case fails",
			lan:        failure,
			wantOutput: failOutput + "PASS net-router\n",
			wantErrIs:  guard.ErrFailed,
			wantLan:    true,
			wantOther:  true,
			wantReport: true,
		},
		{
			name:       "happy path - --case selects",
			args:       []string{"--case", "net-lan"},
			lan:        guard.Pass("net-lan"),
			wantOutput: "PASS net-lan\n",
			wantLan:    true,
		},
		{
			name:      "error - unknown case",
			args:      []string{"--case", "nope"},
			lan:       guard.Pass("net-lan"),
			wantErrIs: guard.ErrUnknownCase,
		},
		{
			name:    "error - bad flag",
			args:    []string{"--wat"},
			lan:     guard.Pass("net-lan"),
			wantErr: "parsing guard flags",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			lan := &guardFakeCase{name: "net-lan", result: tt.lan}
			router := &guardFakeCase{name: "net-router", result: guard.Pass("net-router")}
			out := &bytes.Buffer{}
			deps := guardDeps{
				Env:       guard.Env{Now: time.Now},
				Cases:     []guard.Case{lan, router},
				ReportDir: filepath.Join(t.TempDir(), "guard"),
				WindowDir: t.TempDir(),
				Out:       out,
			}
			logger := slog.New(slog.DiscardHandler)

			// when
			err := runGuardWith(context.Background(), tt.args, logger, deps)

			// then
			switch {
			case tt.wantErrIs != nil:
				require.ErrorIs(t, err, tt.wantErrIs)
			case tt.wantErr != "":
				require.ErrorContains(t, err, tt.wantErr)
			default:
				require.NoError(t, err)
			}

			assert.Equal(t, tt.wantOutput, out.String())
			assert.Equal(t, tt.wantLan, lan.ran)
			assert.Equal(t, tt.wantOther, router.ran)

			if tt.wantReport {
				assert.FileExists(t, filepath.Join(deps.ReportDir, "last.json"))
			} else {
				assert.NoFileExists(t, filepath.Join(deps.ReportDir, "last.json"))
			}
		})
	}
}

func TestDefaultGuardDeps(t *testing.T) {
	complete := "version: 1\nnetwork:\n  bridge: xena9\n  bridge_address: 192.168.150.1\n" +
		"  vm_address: 192.168.150.10\nproxy_port: 3128\n"

	tests := []struct {
		name        string
		vmYAML      string
		noFile      bool
		wantCases   []string
		wantTargets []string
		wantErrIs   error
		wantErr     string
	}{
		{name: "happy path - builds the ten network cases and two tokend cases", vmYAML: complete},
		{
			name:        "happy path - tokend cases are registered",
			vmYAML:      complete,
			wantCases:   []string{"tokend-unlisted", "tokend-proxy-unlisted"},
			wantTargets: []string{"198.51.100.7", "xena-guard-unlisted.invalid"},
		},
		{name: "error - missing vm config", noFile: true, wantErr: "loading vm config"},
		{name: "error - missing vm address", vmYAML: "version: 1\n", wantErrIs: vmexec.ErrMissingVMAddress},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			dir := t.TempDir()
			stateDir := t.TempDir()
			runDir := t.TempDir()
			t.Setenv("XENA_REPO_CONFIG_DIR", dir)
			t.Setenv("XENA_STATE_DIR", stateDir)
			t.Setenv("XENA_GUARD_RUN_DIR", runDir)

			if !tt.noFile {
				require.NoError(t, os.WriteFile(filepath.Join(dir, "vm.yaml"), []byte(tt.vmYAML), 0o600))
			}

			cmd := &guardFakeCommander{err: errGuardFake}

			// when
			deps, err := defaultGuardDeps(context.Background(), cmd)

			// then
			switch {
			case tt.wantErrIs != nil:
				require.ErrorIs(t, err, tt.wantErrIs)
			case tt.wantErr != "":
				require.ErrorContains(t, err, tt.wantErr)
			default:
				require.NoError(t, err)
				assert.Len(t, deps.Cases, 12)
				assert.Subset(t, guardCaseNames(deps.Cases), tt.wantCases)
				assert.Subset(t, guardTargets(deps.Cases), tt.wantTargets)
				assert.Equal(t, "192.168.150.10", deps.Env.VMAddr)
				assert.Equal(t, filepath.Join(stateDir, "guard"), deps.ReportDir)
				assert.Equal(t, runDir, deps.WindowDir)

				deps.Env.Firewall = guardFakeCut{}
				ipv6, err := guard.Select(deps.Cases, []string{"net-ipv6"})
				require.NoError(t, err)

				got := ipv6[0].Run(context.Background(), deps.Env)
				assert.Contains(t, got.Error, errGuardFake.Error())
				assert.Equal(t, []string{"/usr/bin/ip -6 -j neigh show dev xena9"}, cmd.calls)
			}
		})
	}
}

func guardCaseNames(cases []guard.Case) []string {
	names := make([]string, 0, len(cases))
	for _, c := range cases {
		names = append(names, c.Name())
	}

	return names
}

func guardTargets(cases []guard.Case) []string {
	var targets []string
	for _, c := range cases {
		if t, ok := c.(guard.Targeter); ok {
			targets = append(targets, t.Targets()...)
		}
	}

	return targets
}

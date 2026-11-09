package main

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
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
	complete := "version: 1\nnetwork:\n  bridge_address: 192.168.150.1\n  vm_address: 192.168.150.10\nproxy_port: 3128\n"

	tests := []struct {
		name      string
		vmYAML    string
		noFile    bool
		wantErrIs error
		wantErr   string
	}{
		{name: "happy path - builds the ten network cases", vmYAML: complete},
		{name: "error - missing vm config", noFile: true, wantErr: "loading vm config"},
		{name: "error - missing vm address", vmYAML: "version: 1\n", wantErrIs: vmexec.ErrMissingVMAddress},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			dir := t.TempDir()
			t.Setenv("XENA_REPO_CONFIG_DIR", dir)

			if !tt.noFile {
				require.NoError(t, os.WriteFile(filepath.Join(dir, "vm.yaml"), []byte(tt.vmYAML), 0o600))
			}

			// when
			deps, err := defaultGuardDeps(context.Background())

			// then
			switch {
			case tt.wantErrIs != nil:
				require.ErrorIs(t, err, tt.wantErrIs)
			case tt.wantErr != "":
				require.ErrorContains(t, err, tt.wantErr)
			default:
				require.NoError(t, err)
				assert.Len(t, deps.Cases, 10)
				assert.Equal(t, "192.168.150.10", deps.Env.VMAddr)
			}
		})
	}
}

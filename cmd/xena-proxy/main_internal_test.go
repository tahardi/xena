package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/allowlist"
)

const (
	validVM = `version: 1
network:
  bridge_address: 192.168.150.1
  vm_address: 192.168.150.10
proxy_port: 3128
prompt_timeout_seconds: 60
`
	validAllowlist = `version: 1
hosts:
  - host: example.com
`
)

func TestRun(t *testing.T) {
	tests := []struct {
		name       string
		vm         string
		allowlist  string
		overlay    string
		wantErr    error
		wantErrMsg string
	}{
		{
			name:       "missing vm config",
			allowlist:  validAllowlist,
			wantErrMsg: "loading vm config",
		},
		{
			name: "bad vm address",
			vm: `version: 1
network:
  bridge_address: 192.168.150.1
  vm_address: not-an-ip
proxy_port: 3128
prompt_timeout_seconds: 60
`,
			allowlist:  validAllowlist,
			wantErrMsg: "parsing vm address",
		},
		{
			name: "bad bridge address",
			vm: `version: 1
network:
  bridge_address: not-an-ip
  vm_address: 192.168.150.10
proxy_port: 3128
prompt_timeout_seconds: 60
`,
			allowlist:  validAllowlist,
			wantErrMsg: "parsing bridge address",
		},
		{
			name: "invalid proxy port",
			vm: `version: 1
network:
  bridge_address: 192.168.150.1
  vm_address: 192.168.150.10
proxy_port: 70000
prompt_timeout_seconds: 60
`,
			allowlist:  validAllowlist,
			wantErrMsg: "validating proxy port",
		},
		{
			name:       "missing allowlist",
			vm:         validVM,
			wantErrMsg: "loading allowlist",
		},
		{
			name: "shared hosting wildcard",
			vm:   validVM,
			allowlist: `version: 1
hosts:
  - host: "*.vercel.app"
`,
			wantErr: allowlist.ErrSharedHostingWildcard,
		},
		{
			name:       "bad overlay",
			vm:         validVM,
			allowlist:  validAllowlist,
			overlay:    "version: 1\nhosts: [",
			wantErrMsg: "loading overlay",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			configDir := t.TempDir()
			stateDir := t.TempDir()
			t.Setenv("XENA_REPO_CONFIG_DIR", configDir)
			t.Setenv("XENA_PROXY_STATE_DIR", stateDir)
			t.Setenv("XENA_PROMPT_SOCKET", filepath.Join(t.TempDir(), "prompt.sock"))

			files := map[string]string{
				filepath.Join(configDir, "vm.yaml"):        tt.vm,
				filepath.Join(configDir, "allowlist.yaml"): tt.allowlist,
				filepath.Join(stateDir, "overlay.yaml"):    tt.overlay,
			}
			for path, content := range files {
				if content != "" {
					require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
				}
			}

			// when
			err := run(t.Context(), slog.New(slog.DiscardHandler))

			// then
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			require.ErrorContains(t, err, tt.wantErrMsg)
		})
	}
}

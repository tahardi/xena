package vmexec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDefault(t *testing.T) {
	tests := []struct {
		name          string
		file          string
		want          func(configDir string) *SSH
		wantErrPrefix string
		wantErr       error
	}{
		{
			name: "happy path - vm address from vm.yaml",
			file: "version: 1\nnetwork:\n  vm_address: 192.168.150.10\n",
			want: func(configDir string) *SSH {
				return NewSSH(
					filepath.Join(configDir, "automation_ed25519"),
					filepath.Join(configDir, "known_hosts"),
					"dev",
					"192.168.150.10",
				)
			},
		},
		{
			name:    "error - no vm address",
			file:    "version: 1\nnetwork:\n  bridge: xena0\n",
			wantErr: ErrMissingVMAddress,
		},
		{
			name:          "error - missing vm.yaml",
			wantErrPrefix: "loading vm config: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			configDir := t.TempDir()
			repoConfigDir := t.TempDir()
			t.Setenv("XENA_CONFIG_DIR", configDir)
			t.Setenv("XENA_REPO_CONFIG_DIR", repoConfigDir)

			if tt.file != "" {
				path := filepath.Join(repoConfigDir, "vm.yaml")
				require.NoError(t, os.WriteFile(path, []byte(tt.file), 0o640))
			}

			// when
			got, err := Default()

			// then
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				require.Nil(t, got)
				return
			}

			if tt.wantErrPrefix != "" {
				require.Error(t, err)
				require.True(t, strings.HasPrefix(err.Error(), tt.wantErrPrefix), err.Error())
				require.NotContains(t, err.Error(), tt.wantErrPrefix+tt.wantErrPrefix)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, got.run)

			want := tt.want(configDir)
			want.run, got.run = nil, nil
			require.Equal(t, want, got)
		})
	}
}

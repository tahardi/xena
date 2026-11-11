package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

const fullVM = `version: 1
name: xena-dev
image:
  url: https://cloud-images.ubuntu.com/releases/26.04/ubuntu-26.04-server-cloudimg-amd64.img
  sha256: "0000000000000000000000000000000000000000000000000000000000000000"
cpus: 8
memory_mib: 16384
disk_gib: 120
network:
  bridge: xena0
  bridge_address: 192.168.150.1
  vm_address: 192.168.150.10
  prefix: 24
  mac: "52:54:00:78:65:6e"
proxy_port: 3128
grant:
  default_hours: 4
  max_hours: 8
expose:
  iphone_address: "192.0.2.50"
  default_hours: 4
  max_hours: 8
prompt_timeout_seconds: 60
claude_code_version: "2.1.310"
dotclaude_ref: "0123456789abcdef0123456789abcdef01234567"
repos:
  - tahardi/xena
  - tahardi/dotclaude
git:
  name: xena-bot
  email: bot@example.com
`

func TestLoadVM(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		want    VM
		wantErr error
	}{
		{
			name: "happy path - full file",
			file: fullVM,
			want: VM{
				Version: 1,
				Name:    "xena-dev",
				Image: VMImage{
					URL:    "https://cloud-images.ubuntu.com/releases/26.04/ubuntu-26.04-server-cloudimg-amd64.img",
					SHA256: "0000000000000000000000000000000000000000000000000000000000000000",
				},
				CPUs:      8,
				MemoryMiB: 16384,
				DiskGiB:   120,
				Network: VMNetwork{
					Bridge:        "xena0",
					BridgeAddress: "192.168.150.1",
					VMAddress:     "192.168.150.10",
					Prefix:        24,
					MAC:           "52:54:00:78:65:6e",
				},
				ProxyPort:            3128,
				Grant:                VMGrant{DefaultHours: 4, MaxHours: 8},
				Expose:               VMExpose{IPhoneAddress: "192.0.2.50", DefaultHours: 4, MaxHours: 8},
				PromptTimeoutSeconds: 60,
				ClaudeCodeVersion:    "2.1.310",
				DotclaudeRef:         "0123456789abcdef0123456789abcdef01234567",
				Repos:                []string{"tahardi/xena", "tahardi/dotclaude"},
				Git:                  VMGit{Name: "xena-bot", Email: "bot@example.com"},
			},
		},
		{
			name:    "error - version above current",
			file:    "version: 2\n",
			wantErr: ErrUnknownVersion,
		},
		{
			name:    "error - missing version",
			file:    "name: xena-dev\n",
			wantErr: ErrMissingVersion,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			path := filepath.Join(t.TempDir(), "vm.yaml")
			require.NoError(t, os.WriteFile(path, []byte(tt.file), 0o640))

			// when
			got, err := LoadVM(path)

			// then
			require.ErrorIs(t, err, tt.wantErr)
			require.Equal(t, tt.want, got)
		})
	}
	t.Run("happy path - repo file", func(t *testing.T) {
		// given
		path := filepath.Join("..", "..", "config", "vm.yaml")

		// when
		got, err := LoadVM(path)

		// then
		require.NoError(t, err)
		require.Equal(t, "xena-dev", got.Name)
		require.Equal(t, 8, got.Expose.MaxHours)
		require.Regexp(t, `^[0-9a-f]{64}$`, got.Image.SHA256)
		require.Regexp(
			t,
			`^https://cloud-images\.ubuntu\.com/releases/26\.04/release-[0-9]{8}/ubuntu-26\.04-server-cloudimg-amd64\.img$`,
			got.Image.URL,
		)
		require.Regexp(t, `^52:54:00(:[0-9a-f]{2}){3}$`, got.Network.MAC)
		require.Regexp(t, `^[0-9]+\.[0-9]+\.[0-9]+$`, got.ClaudeCodeVersion)
		require.Regexp(t, `^[0-9a-f]{40}$`, got.DotclaudeRef)
		require.NotEmpty(t, got.Repos)
		for _, repo := range got.Repos {
			require.Regexp(t, `^tahardi/[A-Za-z0-9._-]+$`, repo)
		}
	})
	t.Run("happy path - deploy files agree", func(t *testing.T) {
		// given
		got, err := LoadVM(filepath.Join("..", "..", "config", "vm.yaml"))
		require.NoError(t, err)

		// when
		network, networkErr := os.ReadFile(filepath.Join("..", "..", "deploy", "libvirt", "xena-net.xml"))
		firewall, firewallErr := os.ReadFile(filepath.Join("..", "..", "deploy", "nftables", "xena.nft"))

		// then
		require.NoError(t, networkErr)
		require.NoError(t, firewallErr)
		require.Contains(
			t,
			string(network),
			"address='"+got.Network.BridgeAddress+"' prefix='"+strconv.Itoa(got.Network.Prefix)+"'",
		)
		require.Contains(t, string(network), "name='"+got.Network.Bridge+"'")
		require.Contains(
			t,
			string(firewall),
			"ip saddr "+got.Network.VMAddress+" tcp dport "+strconv.Itoa(got.ProxyPort),
		)
	})
	t.Run("error - misspelled key", func(t *testing.T) {
		// given
		path := filepath.Join(t.TempDir(), "vm.yaml")
		require.NoError(t, os.WriteFile(path, []byte("version: 1\nmemory_mb: 16384\n"), 0o640))

		// when
		_, err := LoadVM(path)

		// then
		require.ErrorContains(t, err, "decoding")
	})
	t.Run("error - file missing", func(t *testing.T) {
		// given
		path := filepath.Join(t.TempDir(), "missing.yaml")

		// when
		_, err := LoadVM(path)

		// then
		require.ErrorIs(t, err, fs.ErrNotExist)
		require.ErrorContains(t, err, "loading vm config: ")
	})
}

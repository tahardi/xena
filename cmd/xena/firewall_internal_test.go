package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/firewall"
)

const (
	testVMAddr = "192.168.150.10"

	fakeNftOK    = "#!/bin/sh\nexit 0\n"
	fakeNftFail  = "#!/bin/sh\nexit 1\n"
	fakeNftFlush = "#!/bin/sh\n[ \"$1\" = add ]\n"
	fakeNftCut   = "#!/bin/sh\necho '{\"nftables\":[{\"set\":{\"elem\":[\"192.168.150.10\"]}}]}'\n"
	fakeNftEmpty = "#!/bin/sh\necho '{\"nftables\":[{\"set\":{\"name\":\"cut\"}}]}'\n"
)

func TestRunFirewall(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		vmConfig   string
		wantIs     error
		wantPrefix string
	}{
		{name: "error - no subcommand", wantIs: errUnknownCommand},
		{name: "error - unknown subcommand", args: []string{"bogus"}, wantIs: errUnknownCommand},
		{name: "error - cut without vm config", args: []string{"cut"}, wantPrefix: "loading vm config: "},
		{name: "error - resume without vm config", args: []string{"resume"}, wantPrefix: "loading vm config: "},
		{
			name:       "error - cut with no network in vm config",
			args:       []string{"cut"},
			vmConfig:   "version: 1\n",
			wantIs:     firewall.ErrInvalidAddress,
			wantPrefix: "checking address ",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			dir := t.TempDir()
			t.Setenv("XENA_REPO_CONFIG_DIR", dir)

			if tt.vmConfig != "" {
				require.NoError(t, os.WriteFile(filepath.Join(dir, "vm.yaml"), []byte(tt.vmConfig), 0o644))
			}

			// when
			err := runFirewall(t.Context(), tt.args, slog.New(slog.DiscardHandler))

			// then
			require.Error(t, err)

			if tt.wantIs != nil {
				require.ErrorIs(t, err, tt.wantIs)
			}

			assert.True(t, strings.HasPrefix(err.Error(), tt.wantPrefix), err.Error())
		})
	}
}

func TestApplyFirewall(t *testing.T) {
	tests := []struct {
		name       string
		verb       string
		nft        string
		marker     bool
		markerDir  bool
		wantMarker bool
		wantPrefix string
		wantLog    string
	}{
		{
			name:       "happy path - cut writes marker",
			verb:       "cut",
			nft:        fakeNftOK,
			wantMarker: true,
			wantLog:    "vm network cut",
		},
		{
			name:    "happy path - resume removes marker",
			verb:    "resume",
			nft:     fakeNftCut,
			marker:  true,
			wantLog: "vm network resumed",
		},
		{
			name:    "happy path - resume without marker",
			verb:    "resume",
			nft:     fakeNftCut,
			wantLog: "vm network resumed",
		},
		{
			name:    "happy path - resume with empty set removes stale marker",
			verb:    "resume",
			nft:     fakeNftEmpty,
			marker:  true,
			wantLog: "vm network resumed",
		},
		{name: "error - failed cut writes no marker", verb: "cut", nft: fakeNftFail, wantPrefix: "cutting vm network: "},
		{name: "error - failed flush writes no marker", verb: "cut", nft: fakeNftFlush, wantPrefix: "cutting vm network: "},
		{
			name:       "error - failed resume keeps marker",
			verb:       "resume",
			nft:        fakeNftFail,
			marker:     true,
			wantMarker: true,
			wantPrefix: "listing cut set: ",
		},
		{
			name:       "error - marker cannot be written",
			verb:       "cut",
			nft:        fakeNftOK,
			markerDir:  true,
			wantMarker: true,
			wantPrefix: "writing cut marker: ",
		},
		{
			name:       "error - marker cannot be removed",
			verb:       "resume",
			nft:        fakeNftCut,
			markerDir:  true,
			wantMarker: true,
			wantPrefix: "removing cut marker: ",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			dir := t.TempDir()
			nft := filepath.Join(dir, "nft")
			require.NoError(t, os.WriteFile(nft, []byte(tt.nft), 0o755))

			marker := filepath.Join(dir, "cut")
			t.Setenv("XENA_CUT_MARKER", marker)

			if tt.marker {
				require.NoError(t, os.WriteFile(marker, nil, 0o644))
			}

			if tt.markerDir {
				require.NoError(t, os.MkdirAll(filepath.Join(marker, "child"), 0o755))
			}

			var logs bytes.Buffer

			// when
			err := applyFirewall(
				t.Context(),
				firewall.NewFirewall(nft),
				tt.verb,
				testVMAddr,
				slog.New(slog.NewTextHandler(&logs, nil)),
			)

			// then
			if tt.wantPrefix != "" {
				require.Error(t, err)
				assert.True(t, strings.HasPrefix(err.Error(), tt.wantPrefix), err.Error())
				assert.Empty(t, logs.String())
			} else {
				require.NoError(t, err)
				assert.Contains(t, logs.String(), tt.wantLog)
			}

			info, statErr := os.Stat(marker)
			if !tt.wantMarker {
				require.ErrorIs(t, statErr, os.ErrNotExist)
				return
			}

			require.NoError(t, statErr)

			if tt.verb == "cut" && !info.IsDir() {
				data, readErr := os.ReadFile(marker)
				require.NoError(t, readErr)

				_, parseErr := time.Parse(time.RFC3339, strings.TrimSpace(string(data)))
				require.NoError(t, parseErr)
			}
		})
	}
}

package vm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/config"
)

var errReadState = errors.New("reading state")

func preparedPath(t *testing.T, m *Machine, now time.Time) string {
	t.Helper()

	seed, err := RenderPrepareSeed(NewSeedData(m.config, "", "", "", "", now))
	require.NoError(t, err)

	sum := sha256.Sum256([]byte(m.config.Image.SHA256 + string(seed.UserData)))

	return filepath.Join(m.dir, "images", "prepared-"+hex.EncodeToString(sum[:])[:12]+".qcow2")
}

func writeISO(t *testing.T, sources *string) func(args []string) {
	t.Helper()

	return func(args []string) {
		*sources = filepath.Dir(strings.TrimPrefix(args[0], "--network-config="))
		require.NoError(t, os.WriteFile(args[1], []byte("iso"), 0o600))
	}
}

func prepareHead(t *testing.T, sources *string) []response {
	t.Helper()

	return []response{
		{Match: "qemu-img convert -f qcow2 -O qcow2 /", Effect: createEmpty(t)},
		{Match: "qemu-img resize -f qcow2"},
		{Match: "cloud-localds", Effect: writeISO(t, sources)},
		{Match: lv + "define"},
	}
}

func prepareResponses(t *testing.T, sources *string) []response {
	t.Helper()

	return slices.Concat(
		prepareHead(t, sources),
		[]response{{Match: lv + "start xena-dev"}},
		readyResponses(resultDone),
		[]response{
			{Match: stateCall, Out: "running\n"},
			{Match: lv + "shutdown xena-dev"},
			{Match: stateCall, Out: "shut off\n"},
			{Match: lv + "undefine xena-dev"},
		},
	)
}

func prepareCalls(m *Machine, base, prepared, sources string) []string {
	tmp := prepared + ".tmp"

	return slices.Concat(
		[]string{
			"qemu-img convert -f qcow2 -O qcow2 " + base + " " + tmp,
			"qemu-img resize -f qcow2 " + tmp + " 20G",
			"cloud-localds --network-config=" + filepath.Join(sources, "network-config") + " " +
				filepath.Join(m.dir, "prepare-seed.iso") + " " + filepath.Join(sources, "user-data") + " " +
				filepath.Join(sources, "meta-data"),
			lv + "define",
			lv + "start xena-dev",
		},
		readyCalls(),
		[]string{stateCall, lv + "shutdown xena-dev", stateCall, lv + "undefine xena-dev"},
	)
}

func TestMachine_prepareImage(t *testing.T) {
	const day = 24 * time.Hour

	now := time.Date(2026, time.November, 23, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name          string
		age           time.Duration
		oldSHA        bool
		cut           bool
		responses     func(t *testing.T, sources *string) []response
		wantPrepare   bool
		wantErr       error
		wantErrSubstr string
		wantCalls     []string
	}{
		{
			name:      "happy path - reuses a fresh image",
			age:       day,
			responses: func(*testing.T, *string) []response { return nil },
		},
		{
			name:        "happy path - prepares a missing image",
			responses:   prepareResponses,
			wantPrepare: true,
		},
		{
			name:        "happy path - remakes an old image",
			age:         8 * day,
			responses:   prepareResponses,
			wantPrepare: true,
		},
		{
			name:        "happy path - new key for new inputs",
			age:         day,
			oldSHA:      true,
			responses:   prepareResponses,
			wantPrepare: true,
		},
		{
			name: "error - cloud-init fails",
			responses: func(t *testing.T, sources *string) []response {
				t.Helper()

				return slices.Concat(
					prepareHead(t, sources),
					[]response{{Match: lv + "start xena-dev"}},
					readyResponses(resultFailed),
					[]response{
						{Match: agentCall(outputOpen), Err: errFake},
						{Match: stateCall, Out: "running\n"},
						{Match: lv + "destroy xena-dev"},
						{Match: lv + "undefine xena-dev"},
					},
				)
			},
			wantErr:       ErrCloudInit,
			wantErrSubstr: "preparing image: ",
			wantCalls: slices.Concat(
				readyCalls(),
				[]string{agentCall(outputOpen), stateCall, lv + "destroy xena-dev", lv + "undefine xena-dev"},
			),
		},
		{
			name: "error - copying the base image fails",
			responses: func(*testing.T, *string) []response {
				return []response{
					{Match: "qemu-img convert", Err: errFake},
					{Match: stateCall, Out: "undefined\n"},
				}
			},
			wantErr:       errFake,
			wantErrSubstr: "preparing image: ",
			wantCalls:     []string{stateCall},
		},
		{
			name: "error - state read fails during cleanup",
			responses: func(t *testing.T, _ *string) []response {
				t.Helper()

				return []response{
					{Match: "qemu-img convert", Effect: createEmpty(t)},
					{Match: "qemu-img resize", Err: errFake},
					{Match: stateCall, Err: errReadState},
				}
			},
			wantErr:       errReadState,
			wantErrSubstr: "preparing image: ",
			wantCalls:     []string{stateCall},
		},
		{
			name: "error - network cut",
			cut:  true,
			responses: func(t *testing.T, sources *string) []response {
				t.Helper()

				return append(
					prepareHead(t, sources),
					response{Match: stateCall, Out: "shut off\n"},
					response{Match: lv + "undefine xena-dev"},
				)
			},
			wantErr:       ErrCut,
			wantErrSubstr: "preparing image: ",
			wantCalls:     []string{lv + "define", stateCall, lv + "undefine xena-dev"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			var sources string
			fake := newFakeExec(t, tt.responses(t, &sources))
			m := newTestMachine(t, fake, &fakeSecrets{}, &fakeRotator{})
			m.config.Image = config.VMImage{URL: "http://192.0.2.1/never", SHA256: strings.Repeat("ab", 32)}

			images := filepath.Join(m.dir, "images")
			require.NoError(t, os.MkdirAll(images, 0o700))
			base := filepath.Join(images, m.config.Image.SHA256[:12]+".img")
			require.NoError(t, os.WriteFile(base, []byte("base"), 0o600))
			stale := filepath.Join(images, "prepared-000000000000.qcow2.tmp")
			require.NoError(t, os.WriteFile(stale, nil, 0o600))

			existing := ""
			if tt.age > 0 {
				if tt.oldSHA {
					m.config.Image.SHA256 = strings.Repeat("cd", 32)
				}
				existing = preparedPath(t, m, now)
				require.NoError(t, os.WriteFile(existing, []byte("old"), 0o600))
				require.NoError(t, os.Chtimes(existing, now.Add(-tt.age), now.Add(-tt.age)))
				m.config.Image.SHA256 = strings.Repeat("ab", 32)
			}

			if tt.cut {
				require.NoError(t, os.WriteFile(config.CutMarker(), nil, 0o600))
			}

			want := preparedPath(t, m, now)

			// when
			got, err := m.prepareImage(context.Background(), base, now)

			// then
			prepareSeed := filepath.Join(m.dir, "prepare-seed.iso")
			require.NoFileExists(t, prepareSeed)
			require.NoFileExists(t, want+".tmp")

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				require.Contains(t, err.Error(), tt.wantErrSubstr)
				require.NoFileExists(t, want)

				if tt.cut {
					require.NotContains(t, fake.lines(), lv+"start xena-dev")
				}

				lines := fake.lines()
				require.Equal(t, tt.wantCalls, lines[len(lines)-len(tt.wantCalls):])
				return
			}

			require.NoError(t, err)
			require.Equal(t, want, got)
			require.FileExists(t, got)

			if !tt.wantPrepare {
				require.Empty(t, fake.lines())
				content, readErr := os.ReadFile(got)
				require.NoError(t, readErr)
				require.Equal(t, "old", string(content))
				return
			}

			require.Equal(t, prepareCalls(m, base, want, sources), fake.lines())
			require.NoFileExists(t, stale)

			if tt.oldSHA {
				require.NotEqual(t, want, existing)
				require.NoFileExists(t, existing)
			}

			content, readErr := os.ReadFile(got)
			require.NoError(t, readErr)
			require.Empty(t, content)

			xml := fake.stdinOf(lv + "define")[0]
			require.Contains(t, xml, "<source file='"+want+".tmp'>")
			require.Contains(t, xml, "<source file='"+prepareSeed+"'/>")
			require.NotContains(t, xml, "<encryption")
			require.NoDirExists(t, sources)
		})
	}
}

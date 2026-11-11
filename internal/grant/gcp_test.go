package grant_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/grant"
)

const (
	gcpKey = `{"type":"service_account","client_email":"xena-granter@example-grants.iam.gserviceaccount.com",` +
		`"private_key_id":"old-key-id","private_key":"made-up"}`
	gcpSecret = `{"key":` + gcpKey + `,"service_account":"xena-dev@example-sandbox.iam.gserviceaccount.com",` +
		`"project":"example-sandbox"}`
)

func TestGCP_Issue(t *testing.T) {
	tests := []struct {
		name         string
		secret       string
		lifetime     time.Duration
		out          string
		cmdErr       error
		wantLifetime string
		want         string
		wantExpires  time.Time
		wantErr      error
		wantPrefix   string
		wantCall     bool
	}{
		{
			name:         "happy path - caps at one hour",
			secret:       gcpSecret,
			lifetime:     4 * time.Hour,
			out:          "made-up-token\n",
			wantLifetime: "--lifetime=3600",
			want:         "made-up-token",
			wantExpires:  now.Add(time.Hour),
			wantCall:     true,
		},
		{
			name:         "happy path - shorter lifetime",
			secret:       gcpSecret,
			lifetime:     20 * time.Minute,
			out:          "made-up-token\n",
			wantLifetime: "--lifetime=1200",
			want:         "made-up-token",
			wantExpires:  now.Add(20 * time.Minute),
			wantCall:     true,
		},
		{
			name:     "error - secret missing service account",
			secret:   `{"key":` + gcpKey + `}`,
			lifetime: time.Hour,
			wantErr:  grant.ErrInvalidSecret,
		},
		{
			name:         "error - empty output",
			secret:       gcpSecret,
			lifetime:     time.Hour,
			out:          " \n",
			wantLifetime: "--lifetime=3600",
			wantErr:      grant.ErrEmptyToken,
			wantCall:     true,
		},
		{
			name:         "error - command fails",
			secret:       gcpSecret,
			lifetime:     time.Hour,
			cmdErr:       errFake,
			wantLifetime: "--lifetime=3600",
			wantPrefix:   "impersonating gcp service account",
			wantCall:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			tmp := t.TempDir()
			var keyData []byte
			var keyMode os.FileMode
			cmd := &fakeCommand{outs: [][]byte{[]byte(tt.out)}, errs: []error{tt.cmdErr}}
			cmd.onCall = func(env []string) {
				for _, kv := range env {
					path, ok := strings.CutPrefix(kv, "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE=")
					if !ok {
						continue
					}
					info, err := os.Stat(path)
					require.NoError(t, err)
					keyMode = info.Mode().Perm()
					keyData, err = os.ReadFile(path)
					require.NoError(t, err)
				}
			}
			g := grant.GCP{Cmd: cmd, TempDir: tmp}

			// when
			got, err := g.Issue(context.Background(), []byte(tt.secret), tt.lifetime, now)

			// then
			entries, readErr := os.ReadDir(tmp)
			require.NoError(t, readErr)
			assert.Empty(t, entries)
			if tt.wantCall {
				require.Len(t, cmd.calls, 1)
				assert.Equal(t, "gcloud", cmd.calls[0].name)
				assert.Equal(t, []string{
					"auth",
					"print-access-token",
					"--impersonate-service-account=xena-dev@example-sandbox.iam.gserviceaccount.com",
					tt.wantLifetime,
				}, cmd.calls[0].args)
				env := cmd.calls[0].env
				require.Len(t, env, 3)
				dir, ok := strings.CutPrefix(env[0], "CLOUDSDK_CONFIG=")
				require.True(t, ok, env[0])
				assert.Equal(t, tmp, filepath.Dir(dir))
				assert.Equal(t, "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE="+filepath.Join(dir, "key.json"), env[1])
				assert.Equal(t, "CLOUDSDK_CORE_DISABLE_PROMPTS=1", env[2])
				assert.JSONEq(t, gcpKey, string(keyData))
				assert.Equal(t, os.FileMode(0o600), keyMode)
			} else {
				assert.Empty(t, cmd.calls)
			}
			if tt.wantErr != nil || tt.wantPrefix != "" {
				require.Error(t, err)
				if tt.wantErr != nil {
					require.ErrorIs(t, err, tt.wantErr)
				}
				assert.True(t, strings.HasPrefix(err.Error(), tt.wantPrefix), err.Error())
				assert.NotContains(t, err.Error(), "made-up")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, string(got.Value))
			assert.Equal(t, tt.wantExpires, got.ExpiresAt)
		})
	}
}

func TestGCP_Names(t *testing.T) {
	// given
	g := grant.GCP{}

	// when
	got := []string{g.Name(), g.SecretName(), g.VMSecret()}

	// then
	assert.Equal(t, []string{"gcp", "gcp-grant", "gcp-token"}, got)
}

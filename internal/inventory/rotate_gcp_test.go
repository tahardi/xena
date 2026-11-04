package inventory_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/inventory"
)

const gcpAccount = "--iam-account=xena-granter@example-grants.iam.gserviceaccount.com"

const gcpSecret = `{"key":{"type":"service_account",` +
	`"client_email":"xena-granter@example-grants.iam.gserviceaccount.com",` +
	`"private_key_id":"old-key-id","private_key":"made-up"},` +
	`"service_account":"xena-dev@example-sandbox.iam.gserviceaccount.com","project":"example-sandbox"}`

const gcpNewKey = `{"type":"service_account",` +
	`"client_email":"xena-granter@example-grants.iam.gserviceaccount.com","private_key_id":"new-key-id"}`

const gcpNewSecret = `{"key":` + gcpNewKey + `,` +
	`"service_account":"xena-dev@example-sandbox.iam.gserviceaccount.com","project":"example-sandbox"}`

func envValue(env []string, key string) string {
	for _, e := range env {
		if v, ok := strings.CutPrefix(e, key+"="); ok {
			return v
		}
	}

	return ""
}

func TestGCPKey_Create(t *testing.T) {
	tests := []struct {
		name    string
		result  fakeResult
		want    string
		wantErr string
	}{
		{name: "happy path - creates key", want: gcpNewSecret},
		{name: "error - command fails", result: fakeResult{err: errFake}, wantErr: "creating gcp key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			var keyAtCall string
			cmd := &fakeCommand{
				results: map[string]fakeResult{"iam service-accounts": tt.result},
				hook: func(c fakeCall) {
					data, err := os.ReadFile(envValue(c.env, "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE"))
					require.NoError(t, err)
					keyAtCall = string(data)
					if tt.result.err == nil {
						require.NoError(t, os.WriteFile(c.args[4], []byte(gcpNewKey), 0o600))
					}
				},
			}
			key := inventory.GCPKey{Cmd: cmd, TempDir: t.TempDir()}

			// when
			got, err := key.Create(context.Background(), []byte(gcpSecret))

			// then
			require.Len(t, cmd.calls, 1)
			c := cmd.calls[0]
			dir := envValue(c.env, "CLOUDSDK_CONFIG")
			assert.Equal(t, "gcloud", c.name)
			assert.Equal(
				t,
				[]string{"iam", "service-accounts", "keys", "create", filepath.Join(dir, "new.json"), gcpAccount},
				c.args,
			)
			assert.Equal(t, []string{
				"CLOUDSDK_CONFIG=" + dir,
				"CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE=" + filepath.Join(dir, "key.json"),
				"CLOUDSDK_CORE_DISABLE_PROMPTS=1",
			}, c.env)
			assert.Contains(t, keyAtCall, "old-key-id")
			assert.NoDirExists(t, dir)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.True(t, strings.HasPrefix(err.Error(), tt.wantErr), err.Error())
				return
			}
			require.NoError(t, err)
			assert.JSONEq(t, tt.want, string(got))
		})
	}
}

func TestGCPKey_Revoke(t *testing.T) {
	t.Run("happy path - deletes old key with new key", func(t *testing.T) {
		// given
		var keyAtCall string
		cmd := &fakeCommand{hook: func(c fakeCall) {
			data, err := os.ReadFile(envValue(c.env, "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE"))
			require.NoError(t, err)
			keyAtCall = string(data)
		}}
		key := inventory.GCPKey{Cmd: cmd, TempDir: t.TempDir()}

		// when
		err := key.Revoke(context.Background(), []byte(gcpSecret), []byte(gcpNewSecret))

		// then
		require.NoError(t, err)
		require.Len(t, cmd.calls, 1)
		assert.Equal(
			t,
			[]string{"iam", "service-accounts", "keys", "delete", "old-key-id", gcpAccount, "--quiet"},
			cmd.calls[0].args,
		)
		assert.Contains(t, keyAtCall, "new-key-id")
		assert.NoDirExists(t, envValue(cmd.calls[0].env, "CLOUDSDK_CONFIG"))
	})
}

func TestGCPKey_Rejected(t *testing.T) {
	tests := []struct {
		name     string
		result   fakeResult
		canceled bool
		want     bool
		wantErr  error
	}{
		{name: "happy path - old key rejected", result: fakeResult{err: errFake}, want: true},
		{name: "happy path - old key still works", result: fakeResult{out: []byte("made-up-token")}, want: false},
		{name: "error - canceled", result: fakeResult{err: errFake}, canceled: true, wantErr: context.Canceled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			var keyAtCall string
			cmd := &fakeCommand{
				results: map[string]fakeResult{"auth print-access-token": tt.result},
				hook: func(c fakeCall) {
					data, err := os.ReadFile(envValue(c.env, "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE"))
					require.NoError(t, err)
					keyAtCall = string(data)
				},
			}
			key := inventory.GCPKey{Cmd: cmd, TempDir: t.TempDir()}
			ctx, cancel := context.WithCancel(context.Background())
			if tt.canceled {
				cancel()
			}
			defer cancel()

			// when
			got, err := key.Rejected(ctx, []byte(gcpSecret))

			// then
			require.ErrorIs(t, err, tt.wantErr)
			assert.Equal(t, tt.want, got)
			require.Len(t, cmd.calls, 1)
			assert.Equal(t, []string{"auth", "print-access-token"}, cmd.calls[0].args)
			assert.Contains(t, keyAtCall, "old-key-id")
		})
	}
}

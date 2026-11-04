package inventory_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/inventory"
)

const awsSecret = `{"access_key_id":"AKIAOLDEXAMPLE","secret_access_key":"made-up-secret",` +
	`"user_name":"xena-granter","role_arn":"arn:aws:iam::111122223333:role/xena-dev","region":"us-east-1"}`

const awsNewSecret = `{"access_key_id":"AKIANEWEXAMPLE","secret_access_key":"made-up-new",` +
	`"user_name":"xena-granter","role_arn":"arn:aws:iam::111122223333:role/xena-dev","region":"us-east-1"}`

func TestAWSKey_Create(t *testing.T) {
	tests := []struct {
		name    string
		result  fakeResult
		want    string
		wantErr string
	}{
		{
			name:   "happy path - creates key",
			result: fakeResult{out: []byte(`{"AccessKey":{"AccessKeyId":"AKIANEWEXAMPLE","SecretAccessKey":"made-up-new"}}`)},
			want:   awsNewSecret,
		},
		{
			name:    "error - output missing key",
			result:  fakeResult{out: []byte(`{"AccessKey":{}}`)},
			wantErr: "decoding aws access key",
		},
		{
			name:    "error - command fails",
			result:  fakeResult{err: errFake},
			wantErr: "creating aws access key",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			cmd := &fakeCommand{results: map[string]fakeResult{"iam create-access-key": tt.result}}
			key := inventory.AWSKey{Cmd: cmd}

			// when
			got, err := key.Create(context.Background(), []byte(awsSecret))

			// then
			require.Len(t, cmd.calls, 1)
			assert.Equal(t, "aws", cmd.calls[0].name)
			assert.Equal(
				t,
				[]string{"iam", "create-access-key", "--user-name", "xena-granter", "--output", "json"},
				cmd.calls[0].args,
			)
			assert.Equal(t, []string{
				"AWS_ACCESS_KEY_ID=AKIAOLDEXAMPLE",
				"AWS_SECRET_ACCESS_KEY=made-up-secret",
				"AWS_SHARED_CREDENTIALS_FILE=/dev/null",
				"AWS_CONFIG_FILE=/dev/null",
			}, cmd.calls[0].env)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.True(t, strings.HasPrefix(err.Error(), tt.wantErr), err.Error())
				assert.NotContains(t, err.Error(), "made-up-secret")
				return
			}
			require.NoError(t, err)
			assert.JSONEq(t, tt.want, string(got))
		})
	}
}

func TestAWSKey_Revoke(t *testing.T) {
	t.Run("happy path - deletes old key with new key", func(t *testing.T) {
		// given
		cmd := &fakeCommand{}
		key := inventory.AWSKey{Cmd: cmd}

		// when
		err := key.Revoke(context.Background(), []byte(awsSecret), []byte(awsNewSecret))

		// then
		require.NoError(t, err)
		require.Len(t, cmd.calls, 1)
		assert.Equal(
			t,
			[]string{"iam", "delete-access-key", "--user-name", "xena-granter", "--access-key-id", "AKIAOLDEXAMPLE"},
			cmd.calls[0].args,
		)
		assert.Contains(t, cmd.calls[0].env, "AWS_ACCESS_KEY_ID=AKIANEWEXAMPLE")
		assert.Contains(t, cmd.calls[0].env, "AWS_SECRET_ACCESS_KEY=made-up-new")
	})
}

func TestAWSKey_Rejected(t *testing.T) {
	tests := []struct {
		name     string
		result   fakeResult
		canceled bool
		want     bool
		wantErr  error
	}{
		{name: "happy path - old key rejected", result: fakeResult{err: errFake}, want: true},
		{name: "happy path - old key still works", result: fakeResult{out: []byte(`{}`)}, want: false},
		{name: "error - canceled", result: fakeResult{err: errFake}, canceled: true, wantErr: context.Canceled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			cmd := &fakeCommand{results: map[string]fakeResult{"sts get-caller-identity": tt.result}}
			key := inventory.AWSKey{Cmd: cmd}
			ctx, cancel := context.WithCancel(context.Background())
			if tt.canceled {
				cancel()
			}
			defer cancel()

			// when
			got, err := key.Rejected(ctx, []byte(awsSecret))

			// then
			require.ErrorIs(t, err, tt.wantErr)
			assert.Equal(t, tt.want, got)
			require.Len(t, cmd.calls, 1)
			assert.Equal(t, []string{"sts", "get-caller-identity"}, cmd.calls[0].args)
			assert.Contains(t, cmd.calls[0].env, "AWS_ACCESS_KEY_ID=AKIAOLDEXAMPLE")
		})
	}
}

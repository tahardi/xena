package grant_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/grant"
)

const awsSecret = `{"access_key_id":"AKIAOLDEXAMPLE","secret_access_key":"made-up-secret",` +
	`"user_name":"xena-granter","role_arn":"arn:aws:iam::111122223333:role/xena-dev","region":"us-east-1"}`

const awsMissingRole = `{"access_key_id":"AKIAOLDEXAMPLE","secret_access_key":"made-up-secret"}`

func TestAWS_Issue(t *testing.T) {
	tests := []struct {
		name       string
		secret     string
		out        string
		cmdErr     error
		want       string
		wantErr    error
		wantPrefix string
		wantCall   bool
	}{
		{
			name:   "happy path - assumes role",
			secret: awsSecret,
			out: `{"Credentials":{"AccessKeyId":"ASIANEWEXAMPLE","SecretAccessKey":"made-up-new",` +
				`"SessionToken":"made-up-session","Expiration":"2026-10-24T15:59:59Z"}}`,
			want: "[default]\naws_access_key_id = ASIANEWEXAMPLE\naws_secret_access_key = made-up-new\n" +
				"aws_session_token = made-up-session\n",
			wantCall: true,
		},
		{
			name:       "error - secret not json",
			secret:     `{`,
			wantPrefix: "decoding aws-grant secret",
		},
		{
			name:    "error - secret missing role",
			secret:  awsMissingRole,
			wantErr: grant.ErrInvalidSecret,
		},
		{
			name:       "error - command fails",
			secret:     awsSecret,
			cmdErr:     errFake,
			wantPrefix: "assuming aws role",
			wantCall:   true,
		},
		{
			name:       "error - output missing credentials",
			secret:     awsSecret,
			out:        `{"Credentials":{"Expiration":"2026-10-24T16:00:00Z"}}`,
			wantErr:    grant.ErrIncompleteCredential,
			wantPrefix: "decoding assume-role output",
			wantCall:   true,
		},
		{
			name:       "error - output not json",
			secret:     awsSecret,
			out:        `nope`,
			wantPrefix: "decoding assume-role output",
			wantCall:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			cmd := &fakeCommand{outs: [][]byte{[]byte(tt.out)}, errs: []error{tt.cmdErr}}
			a := grant.AWS{Cmd: cmd}

			// when
			got, err := a.Issue(context.Background(), []byte(tt.secret), 4*time.Hour, now)

			// then
			if tt.wantCall {
				require.Len(t, cmd.calls, 1)
				assert.Equal(t, "aws", cmd.calls[0].name)
				assert.Equal(t, []string{
					"sts",
					"assume-role",
					"--role-arn",
					"arn:aws:iam::111122223333:role/xena-dev",
					"--role-session-name",
					"xena-grant",
					"--duration-seconds",
					"14400",
					"--output",
					"json",
				}, cmd.calls[0].args)
				assert.Subset(t, cmd.calls[0].env, []string{
					"AWS_ACCESS_KEY_ID=AKIAOLDEXAMPLE",
					"AWS_SECRET_ACCESS_KEY=made-up-secret",
					"AWS_REGION=us-east-1",
					"AWS_SHARED_CREDENTIALS_FILE=/dev/null",
					"AWS_CONFIG_FILE=/dev/null",
				})
			} else {
				assert.Empty(t, cmd.calls)
			}

			if tt.wantErr != nil || tt.wantPrefix != "" {
				require.Error(t, err)

				if tt.wantErr != nil {
					require.ErrorIs(t, err, tt.wantErr)
				}

				assert.True(t, strings.HasPrefix(err.Error(), tt.wantPrefix), err.Error())
				assert.NotContains(t, err.Error(), "made-up-secret")
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, string(got.Value))
			assert.Equal(t, now.Add(4*time.Hour), got.ExpiresAt)
		})
	}
}

func TestAWS_Names(t *testing.T) {
	// given
	a := grant.AWS{}

	// when
	got := []string{a.Name(), a.SecretName(), a.VMSecret()}

	// then
	assert.Equal(t, []string{"aws", "aws-grant", "aws-credentials"}, got)
}

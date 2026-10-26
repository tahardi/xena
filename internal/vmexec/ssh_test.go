package vmexec

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

var errExitStatus = errors.New("exit status 2")

type fakeExec struct {
	called bool
	name   string
	args   []string
	stdin  string
	out    []byte
	err    error
}

func (f *fakeExec) run(_ context.Context, stdin io.Reader, name string, args ...string) ([]byte, error) {
	f.called = true
	f.name = name
	f.args = args

	if stdin != nil {
		b, err := io.ReadAll(stdin)
		if err != nil {
			return nil, err
		}
		f.stdin = string(b)
	}

	return f.out, f.err
}

func TestSSH_Run(t *testing.T) {
	tests := []struct {
		name       string
		verb       string
		args       []string
		stdin      io.Reader
		fakeOut    []byte
		fakeErr    error
		want       []byte
		wantArgs   []string
		wantSuffix []string
		wantStdin  string
		wantErr    error
		wantErrMsg string
	}{
		{
			name:    "happy path - health",
			verb:    "health",
			fakeOut: []byte("ok\n"),
			want:    []byte("ok\n"),
			wantArgs: []string{
				"-T",
				"-F", "/dev/null",
				"-i", "/k/automation_ed25519",
				"-o", "BatchMode=yes",
				"-o", "IdentitiesOnly=yes",
				"-o", "UserKnownHostsFile=/k/known_hosts",
				"-o", "StrictHostKeyChecking=yes",
				"-o", "ForwardX11=no",
				"-o", "ForwardAgent=no",
				"dev@192.168.150.10",
				"health",
			},
		},
		{
			name:       "happy path - token-put passes stdin",
			verb:       "token-put",
			stdin:      strings.NewReader("tok-fake-1"),
			wantSuffix: []string{"token-put"},
			wantStdin:  "tok-fake-1",
		},
		{
			name:       "happy path - secret-put with name",
			verb:       "secret-put",
			args:       []string{"jira-token"},
			wantSuffix: []string{"secret-put", "jira-token"},
		},
		{
			name:    "error - verb with shell characters",
			verb:    "health;id",
			wantErr: ErrInvalidArgument,
		},
		{
			name:    "error - argument with path",
			verb:    "guard",
			args:    []string{"../x"},
			wantErr: ErrInvalidArgument,
		},
		{
			name:    "error - bad second argument",
			verb:    "secret-put",
			args:    []string{"jira-token", "jira token"},
			wantErr: ErrInvalidArgument,
		},
		{
			name:    "error - empty verb",
			verb:    "",
			wantErr: ErrInvalidArgument,
		},
		{
			name:       "error - ssh fails",
			verb:       "health",
			fakeErr:    errExitStatus,
			wantErrMsg: "running health in vm: exit status 2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			fake := &fakeExec{out: tt.fakeOut, err: tt.fakeErr}
			s := SSH{
				Key:        "/k/automation_ed25519",
				KnownHosts: "/k/known_hosts",
				User:       "dev",
				Addr:       "192.168.150.10",
				run:        fake.run,
			}

			// when
			got, err := s.Run(context.Background(), tt.verb, tt.args, tt.stdin)

			// then
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				require.False(t, fake.called)
				return
			}

			if tt.wantErrMsg != "" {
				require.EqualError(t, err, tt.wantErrMsg)
				require.ErrorIs(t, err, errExitStatus)
				require.Nil(t, got)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
			require.Equal(t, "ssh", fake.name)
			require.Equal(t, tt.wantStdin, fake.stdin)

			if tt.wantArgs != nil {
				require.Equal(t, tt.wantArgs, fake.args)
			}

			if tt.wantSuffix != nil {
				require.Equal(t, tt.wantSuffix, fake.args[len(fake.args)-len(tt.wantSuffix):])
			}
		})
	}
}

func TestRunCommand(t *testing.T) {
	t.Run("happy path - passes stdin", func(t *testing.T) {
		// given
		stdin := strings.NewReader("tok-fake-1")

		// when
		out, err := runCommand(context.Background(), stdin, "sh", "-c", "cat")

		// then
		require.NoError(t, err)
		require.Equal(t, "tok-fake-1", string(out))
	})

	t.Run("error - drops stderr", func(t *testing.T) {
		// given
		script := "echo leaked-detail >&2; exit 2"

		// when
		_, err := runCommand(context.Background(), nil, "sh", "-c", script)

		// then
		var exitErr *exec.ExitError
		require.ErrorAs(t, err, &exitErr)
		require.Empty(t, exitErr.Stderr)
		require.NotContains(t, err.Error(), "leaked-detail")
	})
}

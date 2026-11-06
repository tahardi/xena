package audit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

var errUnexpectedCommand = errors.New("unexpected command")

type fakeResult struct {
	out string
	err error
}

type fakeCommander map[string]fakeResult

func (f fakeCommander) Output(_ context.Context, name string, args ...string) ([]byte, error) {
	key := name + " " + strings.Join(args, " ")
	result, ok := f[key]
	if !ok {
		return nil, fmt.Errorf("%w: %s", errUnexpectedCommand, key)
	}
	return []byte(result.out), result.err
}

func TestOSCommander_Output(t *testing.T) {
	tests := []struct {
		name    string
		script  string
		want    string
		wantErr string
	}{
		{
			name:   "happy path",
			script: "echo out; echo err >&2",
			want:   "out\nerr\n",
		},
		{
			name:    "error - exit status",
			script:  "echo out; exit 3",
			want:    "out\n",
			wantErr: "running /bin/sh",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			cmd := OSCommander{}

			// when
			got, err := cmd.Output(t.Context(), "/bin/sh", "-c", tt.script)

			// then
			require.Equal(t, tt.want, string(got))
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

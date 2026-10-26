package agent

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAgent_runGuard(t *testing.T) {
	tests := []struct {
		name       string
		guard      string
		script     string
		wantCode   int
		wantStdout string
		wantErr    error
	}{
		{name: "happy path - case passes", guard: "ok-case", script: "echo 'guard ran'\n", wantStdout: "guard ran\n"},
		{name: "happy path - case fails", guard: "fail-case", script: "exit 3\n", wantCode: 3},
		{
			name:       "happy path - clean environment",
			guard:      "env-case",
			script:     "echo \"${PATH}|${BASH_ENV:-unset}|${XENA_LEAK:-unset}\"\n",
			wantStdout: "/usr/sbin:/usr/bin:/sbin:/bin|unset|unset\n",
		},
		{name: "error - missing case", guard: "missing-case", wantCode: 2, wantErr: ErrRefusedVerb},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			h := newHarness(t, "")
			t.Setenv("BASH_ENV", filepath.Join(h.tmp, "evil.sh"))
			t.Setenv("XENA_LEAK", "leak")
			writeFile(t, filepath.Join(h.tmp, "evil.sh"), "touch \""+filepath.Join(h.tmp, "pwned")+"\"\n")

			if tt.script != "" {
				writeFile(t, filepath.Join(h.agent.GuardDir, tt.guard+".sh"), tt.script)
			}

			// when
			code, err := h.agent.runGuard(t.Context(), tt.guard)

			// then
			require.ErrorIs(t, err, tt.wantErr)
			require.Equal(t, tt.wantCode, code)
			require.Equal(t, tt.wantStdout, h.stdout.String())
			require.NoFileExists(t, filepath.Join(h.tmp, "pwned"))
		})
	}
}

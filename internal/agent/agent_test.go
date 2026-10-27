package agent

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAgent_Run(t *testing.T) {
	tests := []struct {
		name       string
		command    string
		stdin      string
		setup      func(t *testing.T, h harness)
		wantCode   int
		wantStdout string
		wantStderr string
	}{
		{name: "happy path - health", command: "health", wantCode: 0, wantStdout: "ok\n"},
		{name: "happy path - token-put", command: "token-put", stdin: "tok-fake-1", wantCode: 0},
		{name: "happy path - secret-put", command: "secret-put jira-token", stdin: "jira-fake", wantCode: 0},
		{name: "happy path - secret-clear", command: "secret-clear gcp-token", wantCode: 0},
		{name: "happy path - memory-export", command: "memory-export", wantCode: 0},
		{
			name:     "happy path - guard passes exit code through",
			command:  "guard fail-case",
			wantCode: 3,
			setup: func(t *testing.T, h harness) {
				t.Helper()
				writeFile(t, filepath.Join(h.agent.guardDir, "fail-case.sh"), "exit 3\n")
			},
		},
		{
			name:       "error - empty value",
			command:    "token-put",
			wantCode:   1,
			wantStderr: "refusing empty value\n",
		},
		{
			name:       "error - memory exists",
			command:    "memory-import",
			wantCode:   3,
			wantStderr: "refusing import: memory exists\n",
			setup: func(t *testing.T, h harness) {
				t.Helper()
				writeFile(t, filepath.Join(h.agent.home, ".claude-mem", "claude-mem.db"), "")
			},
		},
		{name: "error - unknown verb", command: "rm -rf /", wantCode: 2, wantStderr: "refusing verb\n"},
		{name: "error - extra argument", command: "health now", wantCode: 2, wantStderr: "refusing verb\n"},
		{name: "error - semicolon", command: "health;id", wantCode: 2, wantStderr: "refusing verb\n"},
		{name: "error - substitution", command: "health $(id)", wantCode: 2, wantStderr: "refusing verb\n"},
		{name: "error - uppercase", command: "HEALTH", wantCode: 2, wantStderr: "refusing verb\n"},
		{name: "error - empty", command: "", wantCode: 2, wantStderr: "refusing verb\n"},
		{name: "error - blank", command: "   ", wantCode: 2, wantStderr: "refusing verb\n"},
		{name: "error - token-put argument", command: "token-put x", wantCode: 2, wantStderr: "refusing verb\n"},
		{name: "error - export argument", command: "memory-export x", wantCode: 2, wantStderr: "refusing verb\n"},
		{name: "error - import argument", command: "memory-import x", wantCode: 2, wantStderr: "refusing verb\n"},
		{name: "error - guard no name", command: "guard", wantCode: 2, wantStderr: "refusing verb\n"},
		{name: "error - guard missing", command: "guard missing-case", wantCode: 2, wantStderr: "refusing verb\n"},
		{name: "error - guard path", command: "guard ../lib/ok-case", wantCode: 2, wantStderr: "refusing verb\n"},
		{
			name:       "error - secret-put github-token",
			command:    "secret-put github-token",
			stdin:      "x",
			wantCode:   2,
			wantStderr: "refusing verb\n",
		},
		{name: "error - secret-put path", command: "secret-put ../x", wantCode: 2, wantStderr: "refusing verb\n"},
		{name: "error - secret-put no name", command: "secret-put", wantCode: 2, wantStderr: "refusing verb\n"},
		{
			name:       "error - secret-clear github-token",
			command:    "secret-clear github-token",
			wantCode:   2,
			wantStderr: "refusing verb\n",
		},
		{name: "error - secret-clear no name", command: "secret-clear", wantCode: 2, wantStderr: "refusing verb\n"},
		{
			name:       "error - secret-clear extra argument",
			command:    "secret-clear jira-token x",
			wantCode:   2,
			wantStderr: "refusing verb\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			h := newHarness(t, tt.stdin)
			if tt.setup != nil {
				tt.setup(t, h)
			}

			// when
			code := h.agent.Run(context.Background(), tt.command)

			// then
			require.Equal(t, tt.wantCode, code, h.stderr.String())
			require.Equal(t, tt.wantStderr, h.stderr.String())

			if tt.wantStdout != "" {
				require.Equal(t, tt.wantStdout, h.stdout.String())
			}
		})
	}

	t.Run("error - github-token survives refused secret-clear", func(t *testing.T) {
		// given
		h := newHarness(t, "")
		token := filepath.Join(h.agent.home, ".config", "xena", "github-token")
		writeFile(t, token, "tok-fake-1")

		// when
		code := h.agent.Run(context.Background(), "secret-clear github-token")

		// then
		require.Equal(t, 2, code)
		require.FileExists(t, token)
	})
}

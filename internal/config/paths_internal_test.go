package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

type pathCase struct {
	name string
	env  string
	home string
	want string
}

func runPathCases(t *testing.T, envName string, dir func() string, cases []pathCase) {
	t.Helper()
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			// given
			t.Setenv(envName, tt.env)
			t.Setenv("HOME", tt.home)

			// when
			got := dir()

			// then
			require.Equal(t, tt.want, got)
		})
	}
}

func TestConfigDir(t *testing.T) {
	runPathCases(t, "XENA_CONFIG_DIR", ConfigDir, []pathCase{
		{name: "happy path - env set", env: "/tmp/x", home: "/home/test", want: "/tmp/x"},
		{name: "happy path - default", home: "/home/test", want: "/home/test/.config/xena"},
		{name: "happy path - home unknown", want: "/nonexistent/.config/xena"},
	})
}

func TestStateDir(t *testing.T) {
	runPathCases(t, "XENA_STATE_DIR", StateDir, []pathCase{
		{name: "happy path - env set", env: "/tmp/x", home: "/home/test", want: "/tmp/x"},
		{name: "happy path - default", home: "/home/test", want: "/home/test/.local/state/xena"},
		{name: "happy path - home unknown", want: "/nonexistent/.local/state/xena"},
	})
}

func TestSecretsDir(t *testing.T) {
	runPathCases(t, "XENA_SECRETS_DIR", SecretsDir, []pathCase{
		{name: "happy path - env set", env: "/tmp/x", home: "/home/test", want: "/tmp/x"},
		{name: "happy path - default", home: "/home/test", want: "/home/test/.local/share/xena/secrets"},
		{name: "happy path - home unknown", want: "/nonexistent/.local/share/xena/secrets"},
	})
}

func TestProxyStateDir(t *testing.T) {
	runPathCases(t, "XENA_PROXY_STATE_DIR", ProxyStateDir, []pathCase{
		{name: "happy path - env set", env: "/tmp/x", home: "/home/test", want: "/tmp/x"},
		{name: "happy path - default", home: "/home/test", want: "/var/lib/xena-proxy"},
	})
}

func TestWatchStateDir(t *testing.T) {
	runPathCases(t, "XENA_WATCH_STATE_DIR", WatchStateDir, []pathCase{
		{name: "happy path - env set", env: "/tmp/x", home: "/home/test", want: "/tmp/x"},
		{name: "happy path - default", home: "/home/test", want: "/var/lib/xena-watch"},
	})
}

func TestRepoConfigDir(t *testing.T) {
	runPathCases(t, "XENA_REPO_CONFIG_DIR", RepoConfigDir, []pathCase{
		{name: "happy path - env set", env: "/tmp/x", home: "/home/test", want: "/tmp/x"},
		{name: "happy path - default", home: "/home/test", want: "/usr/local/share/xena/config"},
	})
}

func TestVMDir(t *testing.T) {
	runPathCases(t, "XENA_VM_DIR", VMDir, []pathCase{
		{name: "happy path - env set", env: "/tmp/x", home: "/home/test", want: "/tmp/x"},
		{name: "happy path - default", home: "/home/test", want: "/var/lib/xena-vm"},
	})
}

func TestGatewayLogDir(t *testing.T) {
	runPathCases(t, "XENA_GATEWAY_LOG_DIR", GatewayLogDir, []pathCase{
		{name: "happy path - env set", env: "/tmp/x", home: "/home/test", want: "/tmp/x"},
		{name: "happy path - default", home: "/home/test", want: "/var/lib/xena-desktop"},
	})
}

func TestGuardRunDir(t *testing.T) {
	runPathCases(t, "XENA_GUARD_RUN_DIR", GuardRunDir, []pathCase{
		{name: "happy path - env set", env: "/tmp/x", home: "/home/test", want: "/tmp/x"},
		{name: "happy path - default", home: "/home/test", want: "/run/xena-guard"},
	})
}

func TestExposeStateDir(t *testing.T) {
	runPathCases(t, "XENA_EXPOSE_STATE_DIR", ExposeStateDir, []pathCase{
		{name: "happy path - env set", env: "/tmp/x", home: "/home/test", want: "/tmp/x"},
		{name: "happy path - default", home: "/home/test", want: "/var/lib/xena-expose"},
	})
}

func TestPromptSocket(t *testing.T) {
	runPathCases(t, "XENA_PROMPT_SOCKET", PromptSocket, []pathCase{
		{name: "happy path - env set", env: "/tmp/x", home: "/home/test", want: "/tmp/x"},
		{name: "happy path - default", home: "/home/test", want: "/run/xena-proxy/prompt.sock"},
	})
}

func TestCutMarker(t *testing.T) {
	runPathCases(t, "XENA_CUT_MARKER", CutMarker, []pathCase{
		{name: "happy path - env set", env: "/tmp/x", home: "/home/test", want: "/tmp/x"},
		{name: "happy path - default", home: "/home/test", want: "/var/lib/xena/cut"},
	})
}

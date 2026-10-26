package agent

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type harness struct {
	agent  Agent
	tmp    string
	stdout *bytes.Buffer
	stderr *bytes.Buffer
}

func newHarness(t *testing.T, stdin string) harness {
	t.Helper()

	bash, err := exec.LookPath("bash")
	require.NoError(t, err)

	sqlite, err := exec.LookPath("sqlite3")
	require.NoError(t, err)

	tmp := t.TempDir()
	home := filepath.Join(tmp, "home")
	guardDir := filepath.Join(tmp, "lib", "guard")
	require.NoError(t, os.MkdirAll(home, 0o700))
	require.NoError(t, os.MkdirAll(guardDir, 0o700))

	h := harness{tmp: tmp, stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	h.agent = Agent{
		Home:     home,
		GuardDir: guardDir,
		Bash:     bash,
		SQLite:   sqlite,
		Stdin:    strings.NewReader(stdin),
		Stdout:   h.stdout,
		Stderr:   h.stderr,
	}

	return h
}

func writeFile(t *testing.T, path, contents string) {
	t.Helper()

	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
}

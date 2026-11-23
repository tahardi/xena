package vm

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	sshCfg      = "ssh -F /c/ssh_config xena-dev -- "
	jiraEnv     = "JIRA_SITE=https://example.atlassian.net\nJIRA_EMAIL=bot@example.com\nJIRA_TOKEN=jira-fake-0000\n"
	versionCall = sshCfg + "claude --version"
	settingCall = sshCfg + "test -f /etc/claude-code/managed-settings.json"
	clearCall   = sshCfg + "rm -f /home/dev/.config/xena/github-token"
	daemonCall  = "systemctl --user restart xena-tokend.service"
	tokenCall   = sshCfg + "test -s /home/dev/.config/xena/github-token"
	healthCall  = "agent health"
	jiraPut     = "agent secret-put jira-token"
	linkCall    = sshCfg + "mkdir -p /home/dev/.config/jira && " +
		"ln -sfn /home/dev/.config/xena/jira-token /home/dev/.config/jira/env"
	cloneXena = sshCfg + "test -d /home/dev/Documents/code/xena || " +
		"git clone https://github.com/tahardi/xena /home/dev/Documents/code/xena"
	cloneMaple = sshCfg + "test -d /home/dev/Documents/code/maple || " +
		"git clone https://github.com/tahardi/maple /home/dev/Documents/code/maple"
	restoreCall = "memory restore true"
	loginCall   = "interactive-ssh -F /c/ssh_config -t xena-dev -- claude"
	credsCall   = sshCfg + "test -s /home/dev/.claude/.credentials.json"
	exitCall    = "ssh -F /c/ssh_config -O exit xena-dev"
	wantTouch   = "touch your YubiKey to open the SSH session to the VM"
	wantDaemon  = "touch your YubiKey to unlock the GitHub token service"
	wantWaiting = "starting the GitHub token service: take your finger off the YubiKey and touch it when the " +
		"desktop notification asks; if a touch does nothing, wait for the next notification"
	wantLogin = "Log in to Claude in the VM: type /login, choose your Claude subscription, open the link on this " +
		"desktop, check that the consent screen names Claude Code, paste the code, then type /exit."
)

type fakeAgent struct {
	exec *fakeExec
}

func (a fakeAgent) Run(ctx context.Context, verb string, args []string, stdin io.Reader) ([]byte, error) {
	return a.exec.run(ctx, stdin, "agent", append([]string{verb}, args...)...)
}

type fakeRestorer struct {
	exec *fakeExec
}

func (r fakeRestorer) Restore(ctx context.Context, reviewed bool) error {
	flag := "false"
	if reviewed {
		flag = "true"
	}

	_, err := r.exec.run(ctx, nil, "memory", "restore", flag)
	return err
}

func TestWriteSSHConfig(t *testing.T) {
	t.Run("happy path - writes the host entry", func(t *testing.T) {
		// given
		path := filepath.Join(t.TempDir(), "ssh_config")

		// when
		err := WriteSSHConfig(path, "192.168.150.10", "/h/.ssh/id_ed25519_sk", "/c/known_hosts", "/c")

		// then
		require.NoError(t, err)

		info, err := os.Stat(path)
		require.NoError(t, err)
		require.Equal(t, fs.FileMode(0o600), info.Mode().Perm())

		content, err := os.ReadFile(path)
		require.NoError(t, err)
		require.Equal(t, []string{
			"Host xena-dev",
			"  HostName 192.168.150.10",
			"  User dev",
			"  IdentityFile /h/.ssh/id_ed25519_sk",
			"  IdentitiesOnly yes",
			"  UserKnownHostsFile /c/known_hosts",
			"  StrictHostKeyChecking yes",
			"  ForwardX11 no",
			"  ForwardAgent no",
			"  ControlMaster auto",
			"  ControlPath /c/ssh-%C",
			"  ControlPersist 10m",
		}, strings.Split(strings.TrimSuffix(string(content), "\n"), "\n"))
	})

	t.Run("happy path - creates a missing parent directory", func(t *testing.T) {
		// given
		dir := filepath.Join(t.TempDir(), "nested")

		// when
		err := WriteSSHConfig(filepath.Join(dir, "ssh_config"), "192.168.150.10", "/h/key", "/c/known_hosts", "/c")

		// then
		require.NoError(t, err)

		info, err := os.Stat(dir)
		require.NoError(t, err)
		require.Equal(t, fs.FileMode(0o700), info.Mode().Perm())
	})

	t.Run("error - parent is a file", func(t *testing.T) {
		// given
		parent := filepath.Join(t.TempDir(), "file")
		require.NoError(t, os.WriteFile(parent, nil, 0o600))

		// when
		err := WriteSSHConfig(filepath.Join(parent, "ssh_config"), "192.168.150.10", "/h/key", "/c/known_hosts", "/c")

		// then
		requireErr(t, err, nil, "writing ssh config: ")
	})

	t.Run("error - not an address", func(t *testing.T) {
		// given
		path := filepath.Join(t.TempDir(), "ssh_config")

		// when
		err := WriteSSHConfig(path, "example", "/h/.ssh/id_ed25519_sk", "/c/known_hosts", "/c")

		// then
		require.ErrorIs(t, err, ErrInvalidAddress)

		_, err = os.Stat(path)
		require.ErrorIs(t, err, fs.ErrNotExist)
	})
}

func TestProvisioner_Provision(t *testing.T) {
	happy := func() []response {
		return []response{
			{Match: exitCall},
			{Match: healthCall, Out: "ok\n"},
			{Match: versionCall, Out: "2.1.0 (Claude Code)\n"},
			{Match: settingCall},
			{Match: clearCall},
			{Match: daemonCall},
			{Match: tokenCall, Err: errFake},
			{Match: tokenCall},
			{Match: jiraPut},
			{Match: linkCall},
			{Match: cloneXena},
			{Match: cloneMaple},
			{Match: restoreCall},
			{Match: credsCall, Err: errFake},
			{Match: loginCall},
			{Match: credsCall},
			{Match: exitCall},
		}
	}

	replace := func(match string, r response) []response {
		rs := happy()
		for i := range rs {
			if rs[i].Match == match {
				rs[i] = r
				return rs
			}
		}

		return rs
	}

	missedTouches := make([]string, 0, tokenAttempts/2)
	for range tokenAttempts / 2 {
		missedTouches = append(missedTouches, tokenCall)
	}

	tokenNeverLines := slices.Concat(
		[]string{exitCall, healthCall, versionCall, settingCall, clearCall, daemonCall},
		missedTouches,
		[]string{daemonCall},
		missedTouches,
		[]string{exitCall},
	)

	missedChecks := make([]response, 0, tokenAttempts/2)
	for range tokenAttempts / 2 {
		missedChecks = append(missedChecks, response{Match: tokenCall, Err: errFake})
	}

	tokenNever := slices.Concat(
		happy()[:6],
		missedChecks,
		[]response{{Match: daemonCall}},
		missedChecks,
		[]response{{Match: exitCall}},
	)

	secondRestartFails := slices.Concat(
		happy()[:6],
		missedChecks,
		[]response{{Match: daemonCall, Err: errFake}, {Match: exitCall}},
	)

	afterToken := happy()[8:]
	tokenRetry := slices.Concat(
		happy()[:6],
		missedChecks,
		[]response{{Match: daemonCall}, {Match: tokenCall}},
		afterToken,
	)

	allLines := []string{
		exitCall,
		healthCall,
		versionCall,
		settingCall,
		clearCall,
		daemonCall,
		tokenCall,
		tokenCall,
		jiraPut,
		linkCall,
		cloneXena,
		cloneMaple,
		restoreCall,
		credsCall,
		loginCall,
		credsCall,
		exitCall,
	}

	tokenRetryLines := slices.Concat(allLines[:6], missedTouches, []string{daemonCall, tokenCall}, allLines[8:])

	upTo := func(last string) []string {
		i := slices.Index(allLines[1:], last) + 1
		return append(slices.Clone(allLines[:i+1]), exitCall)
	}

	importErr := func(err error) error {
		require.Error(t, err)

		return fmt.Errorf("importing memory: %w", fmt.Errorf("running memory-import in vm: %w", err))
	}

	importExists := importErr(exec.CommandContext(t.Context(), "sh", "-c", "exit 3").Run())
	importFails := importErr(exec.CommandContext(t.Context(), "sh", "-c", "exit 1").Run())

	loggedIn := func() []response {
		rs := slices.DeleteFunc(happy(), func(r response) bool { return r.Match == loginCall })
		i := slices.IndexFunc(rs, func(r response) bool { return r.Match == credsCall })

		return slices.Delete(rs, i, i+1)
	}

	notLoggedIn := happy()
	afterLogin := slices.IndexFunc(notLoggedIn, func(r response) bool { return r.Match == loginCall }) + 1
	notLoggedIn[afterLogin].Err = errFake

	tests := []struct {
		name        string
		responses   []response
		repos       []string
		getErr      error
		noRestorer  bool
		wantLines   []string
		wantErr     error
		wantPrefix  string
		wantNoCalls bool
	}{
		{
			name:      "happy path - provisions the vm",
			responses: happy(),
			wantLines: allLines,
		},
		{
			name:       "happy path - no memory to restore",
			responses:  slices.DeleteFunc(happy(), func(r response) bool { return r.Match == restoreCall }),
			noRestorer: true,
			wantLines:  slices.DeleteFunc(slices.Clone(allLines), func(l string) bool { return l == restoreCall }),
		},
		{
			name:      "happy path - memory already in the vm",
			responses: replace(restoreCall, response{Match: restoreCall, Err: importExists}),
			wantLines: allLines,
		},
		{
			name:      "happy path - already logged in",
			responses: loggedIn(),
			wantLines: append(upTo(restoreCall)[:len(upTo(restoreCall))-1], credsCall, exitCall),
		},
		{
			name:       "error - memory import fails",
			responses:  replace(restoreCall, response{Match: restoreCall, Err: importFails}),
			wantLines:  upTo(restoreCall),
			wantPrefix: "restoring memory: ",
		},
		{
			name:       "error - unhealthy agent",
			responses:  replace(healthCall, response{Match: healthCall, Out: "nope\n"}),
			wantLines:  upTo(healthCall),
			wantPrefix: "checking vm health: ",
		},
		{
			name:      "error - wrong claude code version",
			responses: replace(versionCall, response{Match: versionCall, Out: "2.0.9 (Claude Code)\n"}),
			wantLines: upTo(versionCall),
			wantErr:   ErrWrongVersion,
		},
		{
			name:       "error - managed settings missing",
			responses:  replace(settingCall, response{Match: settingCall, Err: errFake}),
			wantLines:  upTo(settingCall),
			wantPrefix: "checking managed settings: ",
		},
		{
			name:      "happy path - restarts the token daemon when the first touch is missed",
			responses: tokenRetry,
			wantLines: tokenRetryLines,
		},
		{
			name:       "error - token never arrives",
			responses:  tokenNever,
			wantLines:  tokenNeverLines,
			wantErr:    ErrTimeout,
			wantPrefix: "pushing github token: ",
		},
		{
			name:       "error - jira token unreadable",
			responses:  happy(),
			getErr:     errFake,
			wantLines:  append(slices.Clone(allLines[:8]), exitCall),
			wantPrefix: "reading jira bot token: ",
		},
		{
			name:        "error - invalid repo",
			responses:   happy(),
			repos:       []string{"tahardi/xena", "tahardi/x;rm"},
			wantErr:     ErrInvalidRepo,
			wantNoCalls: true,
		},
		{
			name:        "error - repo name is a dot path",
			responses:   happy(),
			repos:       []string{"tahardi/.."},
			wantErr:     ErrInvalidRepo,
			wantNoCalls: true,
		},
		{
			name:       "error - claude version check fails",
			responses:  replace(versionCall, response{Match: versionCall, Err: errFake}),
			wantLines:  upTo(versionCall),
			wantPrefix: "checking claude code: ",
		},
		{
			name:       "error - clearing the old github token fails",
			responses:  replace(clearCall, response{Match: clearCall, Err: errFake}),
			wantLines:  upTo(clearCall),
			wantPrefix: "pushing github token: ",
		},
		{
			name:       "error - token daemon restart fails",
			responses:  replace(daemonCall, response{Match: daemonCall, Err: errFake}),
			wantLines:  upTo(daemonCall),
			wantPrefix: "pushing github token: ",
		},
		{
			name:       "error - second token daemon restart fails",
			responses:  secondRestartFails,
			wantLines:  slices.Concat(allLines[:6], missedTouches, []string{daemonCall, exitCall}),
			wantPrefix: "pushing github token: ",
		},
		{
			name:       "error - jira token push fails",
			responses:  replace(jiraPut, response{Match: jiraPut, Err: errFake}),
			wantLines:  upTo(jiraPut),
			wantPrefix: "pushing jira token: ",
		},
		{
			name:       "error - jira env link fails",
			responses:  replace(linkCall, response{Match: linkCall, Err: errFake}),
			wantLines:  upTo(linkCall),
			wantPrefix: "linking jira env: ",
		},
		{
			name:       "error - login session fails",
			responses:  replace(loginCall, response{Match: loginCall, Err: errFake}),
			wantLines:  upTo(loginCall),
			wantPrefix: "logging in to claude: ",
		},
		{
			name:       "error - clone fails",
			responses:  replace(cloneXena, response{Match: cloneXena, Err: errFake}),
			wantLines:  upTo(cloneXena),
			wantPrefix: "cloning tahardi/xena: ",
		},
		{
			name:       "error - restore fails",
			responses:  replace(restoreCall, response{Match: restoreCall, Err: errFake}),
			wantLines:  upTo(restoreCall),
			wantPrefix: "restoring memory: ",
		},
		{
			name:       "error - not logged in",
			responses:  notLoggedIn,
			wantLines:  allLines,
			wantErr:    ErrNotLoggedIn,
			wantPrefix: "logging in to claude: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			out := &bytes.Buffer{}
			outAt := map[string]string{}
			responses := slices.Clone(tt.responses)
			for i, r := range responses {
				if r.Match == versionCall || r.Match == loginCall || r.Match == daemonCall {
					responses[i].Effect = func([]string) { outAt[r.Match] = out.String() }
				}
			}

			fake := newFakeExec(t, responses)

			cfg := testConfig()
			cfg.Repos = []string{"tahardi/xena", "tahardi/maple"}
			if tt.repos != nil {
				cfg.Repos = tt.repos
			}

			var restorer MemoryRestorer = fakeRestorer{exec: fake}
			if tt.noRestorer {
				restorer = nil
			}

			p := NewProvisioner(
				cfg,
				"/c/ssh_config",
				fakeAgent{exec: fake},
				&fakeSecrets{key: jiraEnv, getErr: tt.getErr},
				restorer,
				out,
				0,
				slog.New(slog.DiscardHandler),
			)
			p.run = fake.run
			p.interactive = func(ctx context.Context, name string, args ...string) error {
				_, err := fake.run(ctx, nil, "interactive-"+name, args...)
				return err
			}

			// when
			err := p.Provision(context.Background())

			// then
			requireErr(t, err, tt.wantErr, tt.wantPrefix)

			lines := fake.lines()
			switch {
			case tt.wantNoCalls:
				require.Empty(t, lines)
			case tt.wantLines != nil:
				require.Equal(t, tt.wantLines, lines)
			default:
				require.Equal(t, exitCall, lines[len(lines)-1])
				require.NotContains(t, lines, jiraPut)
			}

			for _, c := range fake.calls {
				for _, arg := range c.Args {
					require.NotContains(t, arg, "jira-fake-0000")
				}
			}

			if jira := fake.stdinOf(jiraPut); len(jira) > 0 {
				require.Equal(t, []string{jiraEnv}, jira)
			}

			if slices.Contains(lines, versionCall) {
				require.Contains(t, outAt[versionCall], wantTouch)
			}

			if slices.Contains(lines, daemonCall) {
				require.NotContains(t, outAt[daemonCall], wantDaemon)
				restarts := len(slices.DeleteFunc(slices.Clone(lines), func(l string) bool { return l != daemonCall }))
				require.Equal(t, restarts, strings.Count(outAt[daemonCall], wantWaiting))
			}

			if slices.Contains(lines, loginCall) {
				require.Contains(t, outAt[loginCall], wantLogin)
			} else {
				require.NotContains(t, out.String(), wantLogin)
			}

			firstClone := slices.IndexFunc(lines, func(l string) bool { return strings.Contains(l, "git clone") })
			if firstClone >= 0 {
				tokenLine := slices.Index(lines, tokenCall)
				require.GreaterOrEqual(t, tokenLine, 0)
				require.Less(t, tokenLine, firstClone)
			}

			if restore := slices.Index(lines, restoreCall); restore >= 0 && slices.Contains(lines, loginCall) {
				require.Less(t, restore, slices.Index(lines, loginCall))
			}
		})
	}
}

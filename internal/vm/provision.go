package vm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/tahardi/xena/internal/config"
	"github.com/tahardi/xena/internal/vmexec"
)

const (
	tokenAttempts  = 60
	sshHost        = "xena-dev"
	vmHome         = "/home/dev"
	jiraBotEntry   = "jira-bot-token"
	jiraVMSecret   = "jira-token"
	managedSetting = "/etc/claude-code/managed-settings.json"
	loginText      = "Log in to Claude in the VM: type /login, choose your Claude subscription, " +
		"open the link on this desktop, check that the consent screen names Claude Code, paste the code, " +
		"then type /exit."
)

var (
	ErrInvalidAddress = errors.New("invalid address")
	ErrWrongVersion   = errors.New("wrong claude code version")
	ErrNotLoggedIn    = errors.New("claude not logged in")
	ErrInvalidRepo    = errors.New("invalid repo")

	errAgentNotOK = errors.New("vm agent did not answer ok")

	repoPattern = regexp.MustCompile(`^tahardi/[A-Za-z0-9_-][A-Za-z0-9._-]*$`)
)

type MemoryRestorer interface {
	Restore(ctx context.Context, reviewed bool) error
}

type interactiveFunc func(ctx context.Context, name string, args ...string) error

type Provisioner struct {
	config      config.VM
	sshConfig   string
	agent       vmexec.Runner
	secrets     SecretStore
	restorer    MemoryRestorer
	out         io.Writer
	pollEvery   time.Duration
	logger      *slog.Logger
	run         execFunc
	interactive interactiveFunc
}

func WriteSSHConfig(path, addr, identity, knownHosts, controlDir string) error {
	if !isIPv4(addr) {
		return fmt.Errorf("checking vm address %q: %w", addr, ErrInvalidAddress)
	}

	lines := []string{
		"Host " + sshHost,
		"  HostName " + addr,
		"  User dev",
		"  IdentityFile " + identity,
		"  IdentitiesOnly yes",
		"  UserKnownHostsFile " + knownHosts,
		"  StrictHostKeyChecking yes",
		"  ForwardX11 no",
		"  ForwardAgent no",
		"  ControlMaster auto",
		"  ControlPath " + filepath.Join(controlDir, "ssh-%C"),
		"  ControlPersist 10m",
	}

	if err := os.MkdirAll(filepath.Dir(path), privateDir); err != nil {
		return fmt.Errorf("writing ssh config: %w", err)
	}

	content := []byte(strings.Join(lines, "\n") + "\n")
	if err := config.WriteAtomic(path, content, privateFile); err != nil {
		return fmt.Errorf("writing ssh config: %w", err)
	}

	return nil
}

func NewProvisioner(
	cfg config.VM,
	sshConfig string,
	agent vmexec.Runner,
	secrets SecretStore,
	restorer MemoryRestorer,
	out io.Writer,
	pollEvery time.Duration,
	logger *slog.Logger,
) *Provisioner {
	return &Provisioner{
		config:      cfg,
		sshConfig:   sshConfig,
		agent:       agent,
		secrets:     secrets,
		restorer:    restorer,
		out:         out,
		pollEvery:   pollEvery,
		logger:      logger,
		run:         runCommand,
		interactive: runInteractive,
	}
}

func (p *Provisioner) Provision(ctx context.Context) error {
	for _, repo := range p.config.Repos {
		if !repoPattern.MatchString(repo) {
			return fmt.Errorf("checking repo %q: %w", repo, ErrInvalidRepo)
		}
	}

	p.closeMaster(ctx)
	defer p.closeMaster(ctx)

	reply, err := p.agent.Run(ctx, "health", nil, nil)
	if err != nil {
		return fmt.Errorf("checking vm health: %w", err)
	}

	if strings.TrimSpace(string(reply)) != "ok" {
		return fmt.Errorf("checking vm health: %w", errAgentNotOK)
	}

	steps := []func(context.Context) error{
		p.checkClaudeCode,
		p.pushGitHubToken,
		p.pushJiraToken,
		p.cloneRepos,
		p.restoreMemory,
		p.login,
	}
	for _, step := range steps {
		if err = step(ctx); err != nil {
			return err
		}
	}

	return nil
}

func (p *Provisioner) checkClaudeCode(ctx context.Context) error {
	_, _ = fmt.Fprintln(p.out, "touch your YubiKey to open the SSH session to the VM")

	out, err := p.remote(ctx, "claude --version")
	if err != nil {
		return fmt.Errorf("checking claude code: %w", err)
	}

	version, _, _ := strings.Cut(strings.TrimSpace(string(out)), " ")
	if version != p.config.ClaudeCodeVersion {
		return fmt.Errorf(
			"checking claude code: %w: got %q, want %q",
			ErrWrongVersion,
			version,
			p.config.ClaudeCodeVersion,
		)
	}

	if _, err = p.remote(ctx, "test -f "+managedSetting); err != nil {
		return fmt.Errorf("checking managed settings: %w", err)
	}

	return nil
}

func (p *Provisioner) pushGitHubToken(ctx context.Context) error {
	p.logger.Info("restarting the token daemon to push a fresh github token")

	_, _ = fmt.Fprintln(p.out, "touch your YubiKey to unlock the GitHub token service")

	if _, err := p.run(ctx, nil, "systemctl", "--user", "restart", "xena-tokend.service"); err != nil {
		return fmt.Errorf("pushing github token: %w", err)
	}

	var lastErr error
	for range tokenAttempts {
		if _, lastErr = p.remote(ctx, "test -s "+vmHome+"/.config/xena/github-token"); lastErr == nil {
			return nil
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("pushing github token: %w", ctx.Err())
		case <-time.After(p.pollEvery):
		}
	}

	return fmt.Errorf("pushing github token: %w: last error: %w", ErrTimeout, lastErr)
}

func (p *Provisioner) pushJiraToken(ctx context.Context) error {
	env, err := p.secrets.Get(ctx, jiraBotEntry)
	if err != nil {
		return fmt.Errorf("reading jira bot token: %w", err)
	}

	defer clear(env)

	if _, err = p.agent.Run(ctx, "secret-put", []string{jiraVMSecret}, bytes.NewReader(env)); err != nil {
		return fmt.Errorf("pushing jira token: %w", err)
	}

	link := "mkdir -p " + vmHome + "/.config/jira && ln -sfn " +
		vmHome + "/.config/xena/" + jiraVMSecret + " " + vmHome + "/.config/jira/env"
	if _, err = p.remote(ctx, link); err != nil {
		return fmt.Errorf("linking jira env: %w", err)
	}

	return nil
}

func (p *Provisioner) cloneRepos(ctx context.Context) error {
	for _, repo := range p.config.Repos {
		dest := vmHome + "/Documents/code/" + strings.TrimPrefix(repo, "tahardi/")

		p.logger.Info("cloning repo", "repo", repo)

		if _, err := p.remote(ctx, "test -d "+dest+" || git clone https://github.com/"+repo+" "+dest); err != nil {
			return fmt.Errorf("cloning %s: %w", repo, err)
		}
	}

	return nil
}

func (p *Provisioner) restoreMemory(ctx context.Context) error {
	if p.restorer == nil {
		p.logger.Info("no synced memory on this desktop, skipping restore")
		return nil
	}

	if err := p.restorer.Restore(ctx, false); err != nil {
		return fmt.Errorf("restoring memory: %w", err)
	}

	return nil
}

func (p *Provisioner) login(ctx context.Context) error {
	_, _ = fmt.Fprintln(p.out, loginText)

	if err := p.interactive(ctx, "ssh", "-F", p.sshConfig, "-t", sshHost, "--", "claude"); err != nil {
		return fmt.Errorf("logging in to claude: %w", err)
	}

	if _, err := p.remote(ctx, "test -s "+vmHome+"/.claude/.credentials.json"); err != nil {
		return fmt.Errorf("logging in to claude: %w: %w", ErrNotLoggedIn, err)
	}

	return nil
}

func (p *Provisioner) closeMaster(ctx context.Context) {
	_, _ = p.run(context.WithoutCancel(ctx), nil, "ssh", "-F", p.sshConfig, "-O", "exit", sshHost)
}

func (p *Provisioner) remote(ctx context.Context, command string) ([]byte, error) {
	return p.run(ctx, nil, "ssh", "-F", p.sshConfig, sshHost, "--", command)
}

func runInteractive(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("running %s: %w", name, err)
	}

	return nil
}

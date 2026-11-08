package health

import (
	"cmp"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/tahardi/xena/internal/config"
	"github.com/tahardi/xena/internal/inventory"
	"github.com/tahardi/xena/internal/vmexec"
)

var ErrNotOK = errors.New("check not ok")

const (
	checkTimeout = 5 * time.Second
	backupMaxAge = 48 * time.Hour
	imageMaxAge  = 30 * 24 * time.Hour
)

type Command func(ctx context.Context, name string, args ...string) ([]byte, error)

type Result struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

type Check struct {
	Name    string
	Timeout time.Duration
	Run     func(ctx context.Context) (string, error)
}

func ExecCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

func Checks(run Command, vm vmexec.Runner, vmName string, now func() time.Time) []Check {
	return []Check{
		serviceCheck("xena-proxy", run, "xena-proxy.service"),
		serviceCheck("xena-watch", run, "xena-watch.service"),
		serviceCheck("nftables", run, "xena-nftables.service"),
		{Name: "network", Run: func(ctx context.Context) (string, error) { return checkNetwork(ctx, run) }},
		serviceCheck("xena-prompt", run, "--user", "xena-prompt.service"),
		serviceCheck("xena-tokend", run, "--user", "xena-tokend.service"),
		serviceCheck("xena-vault", run, "--user", "xena-vault.service"),
		timerCheck("xena-guard", run),
		timerCheck("xena-audit", run),
		timerCheck("xena-memory-sync", run),
		timerCheck("xena-report", run),
		timerCheck("xena-backup", run),
		{Name: "backup", Run: func(ctx context.Context) (string, error) { return checkBackup(ctx, run, now()) }},
		{Name: "tokens", Run: func(context.Context) (string, error) { return checkTokens(now()) }},
		{Name: "vm", Run: func(ctx context.Context) (string, error) { return checkVM(ctx, run, vm, vmName) }},
		{Name: "vm-image", Run: func(context.Context) (string, error) { return checkImage(now()) }},
	}
}

func Run(ctx context.Context, checks []Check) []Result {
	out := make([]Result, 0, len(checks))
	for _, c := range checks {
		timeout := cmp.Or(c.Timeout, checkTimeout)
		checkCtx, cancel := context.WithTimeout(ctx, timeout)
		detail, err := c.Run(checkCtx)
		if err != nil && errors.Is(checkCtx.Err(), context.DeadlineExceeded) {
			detail = "timed out"
		}
		cancel()

		out = append(out, Result{Name: c.Name, OK: err == nil, Detail: detail})
	}

	return out
}

func serviceCheck(name string, run Command, unit ...string) Check {
	return Check{
		Name: name,
		Run: func(ctx context.Context) (string, error) {
			return isActive(ctx, run, unit...)
		},
	}
}

func timerCheck(unit string, run Command) Check {
	return Check{
		Name: unit + ".timer",
		Run: func(ctx context.Context) (string, error) {
			detail, err := isActive(ctx, run, "--user", unit+".timer")
			if err != nil {
				return detail, err
			}

			out, _ := run(ctx, "systemctl", "--user", "is-failed", unit+".service")
			if strings.TrimSpace(string(out)) == "failed" {
				return "last run failed", ErrNotOK
			}

			return detail, nil
		},
	}
}

func isActive(ctx context.Context, run Command, unit ...string) (string, error) {
	scope, name := unit[:len(unit)-1], unit[len(unit)-1]
	out, _ := run(ctx, "systemctl", slices.Concat(scope, []string{"is-active", name})...)
	state := strings.TrimSpace(string(out))
	if state == "active" {
		return state, nil
	}

	if state == "" {
		state = "unknown"
	}

	return state, ErrNotOK
}

func checkBackup(ctx context.Context, run Command, now time.Time) (string, error) {
	out, err := run(
		ctx,
		"systemctl",
		"--user",
		"show",
		"xena-backup.service",
		"--property=ExecMainExitTimestamp",
		"--timestamp=unix",
		"--value",
	)
	if err != nil {
		return "unknown", ErrNotOK
	}

	secs, err := strconv.ParseInt(strings.TrimPrefix(strings.TrimSpace(string(out)), "@"), 10, 64)
	if err != nil || secs <= 0 || now.Sub(time.Unix(secs, 0)) > backupMaxAge {
		return "stale", ErrNotOK
	}

	return time.Unix(secs, 0).Local().Format(time.RFC3339), nil
}

func checkTokens(now time.Time) (string, error) {
	inv, err := inventory.Load(filepath.Join(config.ConfigDir(), "inventory.yaml"))
	if errors.Is(err, fs.ErrNotExist) {
		return "no inventory", ErrNotOK
	}
	if err != nil {
		return "unreadable inventory", ErrNotOK
	}

	due := 0
	for _, f := range inventory.Check(inv, nil, now) {
		if f.Kind == inventory.KindOverdue || f.Kind == inventory.KindNearExpiry {
			due++
		}
	}

	detail := strconv.Itoa(due) + " due"
	if due > 0 {
		return detail, ErrNotOK
	}

	return detail, nil
}

func checkNetwork(ctx context.Context, run Command) (string, error) {
	out, _ := run(ctx, "virsh", "-r", "--connect", "qemu:///system", "net-info", "xena")

	for line := range strings.Lines(string(out)) {
		value, ok := strings.CutPrefix(line, "Active:")
		if !ok {
			continue
		}

		if strings.TrimSpace(value) == "yes" {
			return "active", nil
		}

		return "inactive", ErrNotOK
	}

	return "unknown", ErrNotOK
}

func checkVM(ctx context.Context, run Command, vm vmexec.Runner, vmName string) (string, error) {
	if vmName == "" {
		return "no vm config", ErrNotOK
	}

	out, _ := run(ctx, "virsh", "-r", "--connect", "qemu:///system", "domstate", vmName)
	state := strings.TrimSpace(string(out))
	switch state {
	case "shut off":
		return state, nil
	case "running":
		if vm == nil {
			return "agent not answering", ErrNotOK
		}

		reply, err := vm.Run(ctx, "health", nil, nil)
		if err != nil || strings.TrimSpace(string(reply)) != "ok" {
			return "agent not answering", ErrNotOK
		}

		return state, nil
	case "":
		return "unknown", ErrNotOK
	default:
		return state, ErrNotOK
	}
}

func checkImage(now time.Time) (string, error) {
	info, err := os.Stat(filepath.Join(config.StateDir(), "vm-built-at"))
	if err != nil {
		return "never built", ErrNotOK
	}

	if now.Sub(info.ModTime()) > imageMaxAge {
		return "rebuild due", ErrNotOK
	}

	return "built " + info.ModTime().Local().Format(time.DateOnly), nil
}

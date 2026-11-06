package health_test

import (
	"context"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/health"
	"github.com/tahardi/xena/internal/vmexec"
)

var (
	errExit    = errors.New("exit status 3")
	errNoAgent = errors.New("dialing vm")
)

const (
	backupShow = "systemctl --user show xena-backup.service --property=ExecMainExitTimestamp --timestamp=unix --value"
	virshState = "virsh -r --connect qemu:///system domstate xena-test"
)

const okInventory = `version: 1
entries:
  - name: a
    service: aws
    stored: secrets:a
    rotated: 2026-10-01
    rotation_days: 90
    can_spend: false
    rotate: Rotate a by hand.
`

const overdueInventory = `version: 1
entries:
  - name: a
    service: aws
    stored: secrets:a
    rotated: 2026-07-01
    rotation_days: 90
    can_spend: false
    rotate: Rotate a by hand.
`

type fakeOutput struct {
	out string
	err error
}

type fakeRunner struct {
	out string
	err error
}

func (f fakeRunner) Run(_ context.Context, verb string, _ []string, _ io.Reader) ([]byte, error) {
	if verb != "health" {
		return nil, errNoAgent
	}

	return []byte(f.out), f.err
}

func fakeCommand(outputs map[string]fakeOutput) health.Command {
	return func(_ context.Context, name string, args ...string) ([]byte, error) {
		got, ok := outputs[strings.Join(append([]string{name}, args...), " ")]
		if !ok {
			return nil, errExit
		}

		return []byte(got.out), got.err
	}
}

func okOutputs(now time.Time) map[string]fakeOutput {
	outputs := map[string]fakeOutput{
		backupShow: {out: unixStamp(now.Add(-time.Hour))},
		virshState: {out: "shut off\n\n"},
	}

	for _, unit := range []string{"xena-proxy", "xena-watch", "xena-nftables"} {
		outputs["systemctl is-active "+unit+".service"] = fakeOutput{out: "active\n"}
	}

	for _, unit := range []string{"xena-prompt", "xena-tokend", "xena-vault"} {
		outputs["systemctl --user is-active "+unit+".service"] = fakeOutput{out: "active\n"}
	}

	for _, unit := range []string{"xena-guard", "xena-audit", "xena-memory-sync", "xena-report", "xena-backup"} {
		outputs["systemctl --user is-active "+unit+".timer"] = fakeOutput{out: "active\n"}
		outputs["systemctl --user is-failed "+unit+".service"] = fakeOutput{out: "inactive\n", err: errExit}
	}

	return outputs
}

func unixStamp(t time.Time) string {
	return "@" + strconv.FormatInt(t.Unix(), 10) + "\n"
}

func TestRun(t *testing.T) {
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	local := time.Local
	time.Local = time.FixedZone("test", 14*60*60)
	t.Cleanup(func() { time.Local = local })

	tests := []struct {
		name        string
		outputs     map[string]fakeOutput
		runner      fakeRunner
		noRunner    bool
		inventory   string
		noInventory bool
		noVMName    bool
		builtAge    time.Duration
		noBuilt     bool
		extra       []health.Check
		want        map[string]health.Result
		wantAllOK   bool
	}{
		{
			name:      "happy path - everything ok with vm shut off",
			wantAllOK: true,
			want: map[string]health.Result{
				"vm":         {Name: "vm", OK: true, Detail: "shut off"},
				"xena-proxy": {Name: "xena-proxy", OK: true, Detail: "active"},
				"backup":     {Name: "backup", OK: true, Detail: "2026-10-25T01:00:00+14:00"},
				"vm-image":   {Name: "vm-image", OK: true, Detail: "built 2026-10-24"},
			},
		},
		{
			name:     "error - no vm config",
			noVMName: true,
			want:     map[string]health.Result{"vm": {Name: "vm", Detail: "no vm config"}},
		},
		{
			name: "error - check times out",
			extra: []health.Check{{
				Name:    "slow",
				Timeout: 10 * time.Millisecond,
				Run: func(ctx context.Context) (string, error) {
					<-ctx.Done()
					return "", ctx.Err()
				},
			}},
			want: map[string]health.Result{"slow": {Name: "slow", Detail: "timed out"}},
		},
		{
			name:    "error - inactive service",
			outputs: map[string]fakeOutput{"systemctl is-active xena-proxy.service": {out: "inactive\n", err: errExit}},
			want:    map[string]health.Result{"xena-proxy": {Name: "xena-proxy", Detail: "inactive"}},
		},
		{
			name: "error - inactive timer",
			outputs: map[string]fakeOutput{
				"systemctl --user is-active xena-report.timer": {out: "inactive\n", err: errExit},
			},
			want: map[string]health.Result{"xena-report.timer": {Name: "xena-report.timer", Detail: "inactive"}},
		},
		{
			name:    "error - timer service last run failed",
			outputs: map[string]fakeOutput{"systemctl --user is-failed xena-backup.service": {out: "failed\n"}},
			want: map[string]health.Result{
				"xena-backup.timer": {Name: "xena-backup.timer", Detail: "last run failed"},
			},
		},
		{
			name:    "happy path - running vm agent answers",
			outputs: map[string]fakeOutput{virshState: {out: "running\n\n"}},
			runner:  fakeRunner{out: "ok\n"},
			want:    map[string]health.Result{"vm": {Name: "vm", OK: true, Detail: "running"}},
		},
		{
			name:    "error - running vm agent error",
			outputs: map[string]fakeOutput{virshState: {out: "running\n\n"}},
			runner:  fakeRunner{err: errNoAgent},
			want:    map[string]health.Result{"vm": {Name: "vm", Detail: "agent not answering"}},
		},
		{
			name:    "error - running vm agent wrong output",
			outputs: map[string]fakeOutput{virshState: {out: "running\n\n"}},
			runner:  fakeRunner{out: "starting\n"},
			want:    map[string]health.Result{"vm": {Name: "vm", Detail: "agent not answering"}},
		},
		{
			name:    "error - paused vm",
			outputs: map[string]fakeOutput{virshState: {out: "paused\n\n"}},
			want:    map[string]health.Result{"vm": {Name: "vm", Detail: "paused"}},
		},
		{
			name:    "error - virsh fails",
			outputs: map[string]fakeOutput{virshState: {err: errExit}},
			want:    map[string]health.Result{"vm": {Name: "vm", Detail: "unknown"}},
		},
		{
			name:    "error - stale backup",
			outputs: map[string]fakeOutput{backupShow: {out: unixStamp(now.Add(-49 * time.Hour))}},
			want:    map[string]health.Result{"backup": {Name: "backup", Detail: "stale"}},
		},
		{
			name:    "error - backup never run",
			outputs: map[string]fakeOutput{backupShow: {out: "\n"}},
			want:    map[string]health.Result{"backup": {Name: "backup", Detail: "stale"}},
		},
		{
			name:      "error - overdue token",
			inventory: overdueInventory,
			want:      map[string]health.Result{"tokens": {Name: "tokens", Detail: "1 due"}},
		},
		{
			name:        "error - missing inventory",
			noInventory: true,
			want:        map[string]health.Result{"tokens": {Name: "tokens", Detail: "no inventory"}},
		},
		{
			name:      "error - near-expiry token",
			inventory: strings.Replace(okInventory, "rotated: 2026-10-01", "rotated: 2026-08-01", 1),
			want:      map[string]health.Result{"tokens": {Name: "tokens", Detail: "1 due"}},
		},
		{
			name:      "error - unreadable inventory",
			inventory: "version: 1\nentries: [\n",
			want:      map[string]health.Result{"tokens": {Name: "tokens", Detail: "unreadable inventory"}},
		},
		{
			name:     "error - running vm without runner",
			outputs:  map[string]fakeOutput{virshState: {out: "running\n\n"}},
			noRunner: true,
			want:     map[string]health.Result{"vm": {Name: "vm", Detail: "agent not answering"}},
		},
		{
			name:    "error - backup show fails",
			outputs: map[string]fakeOutput{backupShow: {err: errExit}},
			want:    map[string]health.Result{"backup": {Name: "backup", Detail: "unknown"}},
		},
		{
			name:    "error - backup show not a number",
			outputs: map[string]fakeOutput{backupShow: {out: "n/a\n"}},
			want:    map[string]health.Result{"backup": {Name: "backup", Detail: "stale"}},
		},
		{
			name:    "error - empty systemctl output",
			outputs: map[string]fakeOutput{"systemctl --user is-active xena-vault.service": {err: errExit}},
			want:    map[string]health.Result{"xena-vault": {Name: "xena-vault", Detail: "unknown"}},
		},
		{
			name:     "error - old vm image",
			builtAge: 31 * 24 * time.Hour,
			want:     map[string]health.Result{"vm-image": {Name: "vm-image", Detail: "rebuild due"}},
		},
		{
			name:    "error - vm never built",
			noBuilt: true,
			want:    map[string]health.Result{"vm-image": {Name: "vm-image", Detail: "never built"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			configDir := t.TempDir()
			stateDir := t.TempDir()
			t.Setenv("XENA_CONFIG_DIR", configDir)
			t.Setenv("XENA_STATE_DIR", stateDir)

			inventory := tt.inventory
			if inventory == "" {
				inventory = okInventory
			}
			if !tt.noInventory {
				require.NoError(t, os.WriteFile(filepath.Join(configDir, "inventory.yaml"), []byte(inventory), 0o600))
			}

			if !tt.noBuilt {
				builtAge := tt.builtAge
				if builtAge == 0 {
					builtAge = 24 * time.Hour
				}
				built := filepath.Join(stateDir, "vm-built-at")
				require.NoError(t, os.WriteFile(built, nil, 0o600))
				require.NoError(t, os.Chtimes(built, now.Add(-builtAge), now.Add(-builtAge)))
			}

			outputs := okOutputs(now)
			maps.Copy(outputs, tt.outputs)

			var runner vmexec.Runner = tt.runner
			if tt.noRunner {
				runner = nil
			}
			vmName := "xena-test"
			if tt.noVMName {
				vmName = ""
			}
			checks := health.Checks(fakeCommand(outputs), runner, vmName, func() time.Time { return now })
			checks = append(checks, tt.extra...)

			// when
			got := health.Run(context.Background(), checks)

			// then
			byName := map[string]health.Result{}
			for _, r := range got {
				byName[r.Name] = r
			}

			for name, want := range tt.want {
				assert.Equal(t, want, byName[name])
			}

			for _, r := range got {
				if _, named := tt.want[r.Name]; named {
					continue
				}
				assert.True(t, r.OK, "%s not ok: %s", r.Name, r.Detail)
			}

			if tt.wantAllOK {
				assert.Len(t, got, len(health.Checks(nil, nil, "", nil)))
			}
		})
	}
}

func TestChecks(t *testing.T) {
	// given
	want := []string{
		"xena-proxy",
		"xena-watch",
		"nftables",
		"xena-prompt",
		"xena-tokend",
		"xena-vault",
		"xena-guard.timer",
		"xena-audit.timer",
		"xena-memory-sync.timer",
		"xena-report.timer",
		"xena-backup.timer",
		"backup",
		"tokens",
		"vm",
		"vm-image",
	}

	// when
	checks := health.Checks(nil, nil, "", nil)

	// then
	got := make([]string, 0, len(checks))
	for _, c := range checks {
		got = append(got, c.Name)
	}
	assert.Equal(t, want, got)
}

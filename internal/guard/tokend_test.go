package guard_test

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/config"
	"github.com/tahardi/xena/internal/guard"
	"github.com/tahardi/xena/internal/logs"
)

const (
	daemonActiveKey = "systemctl --user is-active xena-tokend.service"
	daemonProbeKey  = "systemd-run --user --slice=tokend.slice --wait --pipe --quiet curl -sS --max-time 5 "
)

var errExit = errors.New("exit status 1")

func tokendDrop(dst, port string) string {
	return "xena-tokend-drop: IN= OUT=wlp2s0 SRC=192.0.2.20 DST=" + dst +
		" LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=1 DF PROTO=TCP SPT=40000 DPT=" + port + " WINDOW=64240 SYN URGP=0\n"
}

func TestTokendUnlisted_Run(t *testing.T) {
	now := time.Date(2026, 11, 17, 3, 0, 0, 500, time.UTC)
	probeKey := daemonProbeKey + "https://198.51.100.7/"
	journalKey := "journalctl -k -o cat --no-pager --since @" + strconv.FormatInt(now.Unix(), 10)
	active := fakeResult{out: "active\n"}
	blocked := fakeResult{out: "curl: (28) Connection timed out\n", err: errExit}

	tests := []struct {
		name     string
		commands fakeCommander
		wantPass bool
		wantErr  string
	}{
		{
			name: "happy path - curl fails and the kernel log holds the drop",
			commands: fakeCommander{
				daemonActiveKey: active,
				probeKey:        blocked,
				journalKey:      {out: "xena-drop: DST=10.0.0.1 DPT=80\n" + tokendDrop("198.51.100.7", "443")},
			},
			wantPass: true,
		},
		{
			name: "error - token daemon not active",
			commands: fakeCommander{
				daemonActiveKey: {out: "inactive\n", err: errExit},
			},
			wantErr: "starting xena-tokend before xena guard: token daemon not active",
		},
		{
			name: "error - curl exits zero",
			commands: fakeCommander{
				daemonActiveKey: active,
				probeKey:        {},
			},
			wantErr: "probing 198.51.100.7: curl exited zero",
		},
		{
			name: "error - no drop entry since the case started",
			commands: fakeCommander{
				daemonActiveKey: active,
				probeKey:        blocked,
				journalKey:      {},
			},
			wantErr: "finding a drop for 198.51.100.7: no xena-tokend-drop entry since the case started",
		},
		{
			name: "error - drop entry names another address",
			commands: fakeCommander{
				daemonActiveKey: active,
				probeKey:        blocked,
				journalKey:      {out: tokendDrop("198.51.100.8", "443")},
			},
			wantErr: "finding a drop for 198.51.100.7: no xena-tokend-drop entry since the case started",
		},
		{
			name: "error - drop entry names another port",
			commands: fakeCommander{
				daemonActiveKey: active,
				probeKey:        blocked,
				journalKey:      {out: tokendDrop("198.51.100.7", "4433")},
			},
			wantErr: "finding a drop for 198.51.100.7: no xena-tokend-drop entry since the case started",
		},
		{
			name: "error - reading the kernel log fails",
			commands: fakeCommander{
				daemonActiveKey: active,
				probeKey:        blocked,
				journalKey:      {err: errExit},
			},
			wantErr: "reading the kernel log",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			c := guard.NewTokendUnlisted(tt.commands)
			env := guard.Env{Now: func() time.Time { return now }}

			// when
			got := c.Run(context.Background(), env)

			// then
			assert.Equal(t, "tokend-unlisted", got.Case)
			assert.Equal(t, tt.wantPass, got.Passed)
			if tt.wantErr == "" {
				assert.Empty(t, got.Error)
				return
			}

			assert.Contains(t, got.Error, tt.wantErr)
		})
	}
}

func TestTokendUnlisted_Targets(t *testing.T) {
	// given
	c := guard.NewTokendUnlisted(fakeCommander{})

	// when
	got := c.Targets()

	// then
	assert.Equal(t, []string{"198.51.100.7"}, got)
}

func TestTokendProxyUnlisted_Run(t *testing.T) {
	now := time.Date(2026, 11, 17, 3, 0, 0, 500, time.UTC)
	start := now.Truncate(time.Second)
	probeKey := daemonProbeKey + "--unix-socket " + config.TokendSocket() +
		" -X CONNECT --request-target xena-guard-unlisted.invalid:443 http://localhost/"
	active := fakeResult{out: "active\n"}
	host := "xena-guard-unlisted.invalid"
	entry := func(at time.Time, host, decision string) logs.ProxyEntry {
		return logs.ProxyEntry{Time: at, Host: host, Port: 443, Decision: decision}
	}

	tests := []struct {
		name     string
		commands fakeCommander
		proxy    *fakeProxy
		wantPass bool
		wantErr  string
	}{
		{
			name:     "happy path - proxy denies the unlisted host",
			commands: fakeCommander{daemonActiveKey: active, probeKey: {}},
			proxy:    &fakeProxy{entries: []logs.ProxyEntry{entry(start, host, logs.DecisionDeny)}},
			wantPass: true,
		},
		{
			name:     "error - token daemon not active",
			commands: fakeCommander{daemonActiveKey: {out: "failed\n", err: errExit}},
			proxy:    &fakeProxy{},
			wantErr:  "starting xena-tokend before xena guard: token daemon not active",
		},
		{
			name:     "error - no entry for the host",
			commands: fakeCommander{daemonActiveKey: active, probeKey: {err: errExit}},
			proxy: &fakeProxy{entries: []logs.ProxyEntry{
				entry(start.Add(-time.Second), host, logs.DecisionDeny),
				entry(start, "api.github.com", logs.DecisionDeny),
			}},
			wantErr: "finding a deny for xena-guard-unlisted.invalid: no deny entry since the case started",
		},
		{
			name:     "error - entry allowed the host",
			commands: fakeCommander{daemonActiveKey: active, probeKey: {}},
			proxy:    &fakeProxy{entries: []logs.ProxyEntry{entry(start, host, logs.DecisionAllowOnce)}},
			wantErr:  "finding a deny for xena-guard-unlisted.invalid: no deny entry since the case started",
		},
		{
			name:     "error - entry timed out waiting for a prompt",
			commands: fakeCommander{daemonActiveKey: active, probeKey: {}},
			proxy:    &fakeProxy{entries: []logs.ProxyEntry{entry(start, host, logs.DecisionTimeout)}},
			wantErr:  "finding a deny for xena-guard-unlisted.invalid: no deny entry since the case started",
		},
		{
			name:     "error - reading the proxy log fails",
			commands: fakeCommander{daemonActiveKey: active, probeKey: {}},
			proxy:    &fakeProxy{err: errExit},
			wantErr:  "reading the proxy-tokend log",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			c := guard.NewTokendProxyUnlisted(tt.commands, tt.proxy)
			env := guard.Env{Now: func() time.Time { return now }}

			// when
			got := c.Run(context.Background(), env)

			// then
			assert.Equal(t, "tokend-proxy-unlisted", got.Case)
			assert.Equal(t, tt.wantPass, got.Passed)
			if tt.wantErr == "" {
				assert.Empty(t, got.Error)
				return
			}

			assert.Contains(t, got.Error, tt.wantErr)
		})
	}
}

func TestTokendProxyUnlisted_Targets(t *testing.T) {
	// given
	c := guard.NewTokendProxyUnlisted(fakeCommander{}, &fakeProxy{})

	// when
	got := c.Targets()

	// then
	require.Equal(t, []string{"xena-guard-unlisted.invalid"}, got)
}

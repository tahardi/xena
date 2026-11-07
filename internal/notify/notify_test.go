package notify_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/allowlist"
	"github.com/tahardi/xena/internal/notify"
)

var errExitStatus = errors.New("exit status 1")

type fakeRun struct {
	output []byte
	err    error
	called bool
	name   string
	args   []string
}

func (f *fakeRun) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.called = true
	f.name = name
	f.args = args
	return f.output, f.err
}

func TestDesktop_Ask(t *testing.T) {
	tests := []struct {
		name       string
		host       string
		port       int
		output     string
		runErr     error
		want       string
		wantArgs   []string
		wantLast   string
		wantErr    error
		wantErrMsg string
		wantNoRun  bool
	}{
		{
			name:   "once",
			host:   "example.com",
			port:   443,
			output: "once\n",
			want:   "once",
			wantArgs: []string{
				"--app-name=Xena",
				"--urgency=critical",
				"--action=once=Allow once",
				"--action=always=Allow always",
				"--action=deny=Deny",
				"--wait",
				"Xena: VM wants a new host",
				"example.com:443",
			},
		},
		{name: "always", host: "example.com", port: 443, output: "always\n", want: "always"},
		{name: "deny", host: "example.com", port: 8443, output: "deny", want: "deny", wantLast: "example.com:8443"},
		{name: "dismissed", host: "example.com", port: 443, output: "", want: ""},
		{name: "run error", host: "example.com", port: 443, runErr: errExitStatus, wantErrMsg: "running notify-send"},
		{name: "invalid host", host: "exa mple.com", port: 443, wantErr: allowlist.ErrInvalidHost, wantNoRun: true},
		{name: "markup host", host: "<b>x</b>.com", port: 443, wantErrMsg: "checking host", wantNoRun: true},
		{name: "uppercase host", host: "Example.com", port: 443, wantErr: notify.ErrUnsafeHost, wantNoRun: true},
		{name: "IP literal host", host: "192.0.2.10", port: 443, wantErr: allowlist.ErrIPLiteralHost, wantNoRun: true},
		{name: "port zero", host: "example.com", port: 0, wantErr: notify.ErrUnsafeHost, wantNoRun: true},
		{name: "port too high", host: "example.com", port: 65536, wantErr: notify.ErrUnsafeHost, wantNoRun: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			fake := &fakeRun{output: []byte(tt.output), err: tt.runErr}
			desktop := notify.Desktop{Run: fake.Run}

			// when
			got, err := desktop.Ask(t.Context(), tt.host, tt.port)

			// then
			if tt.wantNoRun {
				require.False(t, fake.called)
			}

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}

			if tt.wantErrMsg != "" {
				require.ErrorContains(t, err, tt.wantErrMsg)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
			require.Equal(t, "notify-send", fake.name)

			if tt.wantArgs != nil {
				require.Equal(t, tt.wantArgs, fake.args)
			}

			if tt.wantLast != "" {
				require.Equal(t, tt.wantLast, fake.args[len(fake.args)-1])
			}
		})
	}
}

func TestDesktop_Show(t *testing.T) {
	tests := []struct {
		name       string
		title      string
		body       string
		critical   bool
		runErr     error
		wantArgs   []string
		wantErrMsg string
	}{
		{
			name:     "critical",
			title:    "Xena alert: firewall-drop",
			body:     "high at 2026-10-01T10:00:00Z",
			critical: true,
			wantArgs: []string{
				"--app-name=Xena",
				"--urgency=critical",
				"Xena alert: firewall-drop",
				"high at 2026-10-01T10:00:00Z",
			},
		},
		{
			name:  "normal",
			title: "Xena alert: firewall-drop",
			body:  "high at 2026-10-01T10:00:00Z",
			wantArgs: []string{
				"--app-name=Xena",
				"--urgency=normal",
				"Xena alert: firewall-drop",
				"high at 2026-10-01T10:00:00Z",
			},
		},
		{
			name:  "escaped",
			title: "a<b>&c",
			body:  "<i>x</i>",
			wantArgs: []string{
				"--app-name=Xena",
				"--urgency=normal",
				"a&lt;b&gt;&amp;c",
				"&lt;i&gt;x&lt;/i&gt;",
			},
		},
		{
			name:       "run error",
			title:      "t",
			body:       "b",
			runErr:     errExitStatus,
			wantErrMsg: "running notify-send",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			fake := &fakeRun{err: tt.runErr}
			desktop := notify.Desktop{Run: fake.Run}

			// when
			err := desktop.Show(t.Context(), tt.title, tt.body, tt.critical)

			// then
			if tt.wantErrMsg != "" {
				require.ErrorContains(t, err, tt.wantErrMsg)
				return
			}

			require.NoError(t, err)
			require.Equal(t, "notify-send", fake.name)
			require.Equal(t, tt.wantArgs, fake.args)
		})
	}
}

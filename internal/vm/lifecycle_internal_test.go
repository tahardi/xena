package vm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/config"
)

var testKey = strings.Repeat("0123456789abcdef", 4)

const (
	lv         = "libvirt "
	stateCall  = lv + "domstate xena-dev"
	defineUUID = "6f1c2d3e-0000-4000-8000-000000000001"
)

type call struct {
	Name     string
	Args     []string
	Stdin    string
	Canceled bool
}

type response struct {
	Match  string
	Out    string
	Err    error
	Effect func(args []string)
}

type fakeExec struct {
	t         *testing.T
	responses []response
	used      []bool
	calls     []call
}

func newFakeExec(t *testing.T, responses []response) *fakeExec {
	t.Helper()

	return &fakeExec{t: t, responses: responses, used: make([]bool, len(responses))}
}

func (f *fakeExec) run(ctx context.Context, stdin io.Reader, name string, args ...string) ([]byte, error) {
	in := ""
	if stdin != nil {
		data, err := io.ReadAll(stdin)
		require.NoError(f.t, err)
		in = string(data)
	}

	f.calls = append(f.calls, call{Name: name, Args: args, Stdin: in, Canceled: ctx.Err() != nil})

	line := name + " " + strings.Join(args, " ")
	for i, r := range f.responses {
		if f.used[i] || !strings.HasPrefix(line, r.Match) {
			continue
		}

		f.used[i] = true
		if r.Effect != nil {
			r.Effect(args)
		}

		return []byte(r.Out), r.Err
	}

	f.t.Fatalf("unexpected call: %s", line)
	return nil, nil
}

func (f *fakeExec) lines() []string {
	if len(f.calls) == 0 {
		return nil
	}

	lines := make([]string, 0, len(f.calls))
	for _, c := range f.calls {
		lines = append(lines, c.Name+" "+strings.Join(c.Args, " "))
	}

	return lines
}

func (f *fakeExec) requireKeyNotInArgs(t *testing.T) {
	t.Helper()

	for _, c := range f.calls {
		for _, arg := range c.Args {
			require.NotContains(t, arg, testKey)
		}
	}
}

func (f *fakeExec) stdinOf(prefix string) []string {
	var stdins []string
	for i, line := range f.lines() {
		if strings.HasPrefix(line, prefix) {
			stdins = append(stdins, f.calls[i].Stdin)
		}
	}

	return stdins
}

type fakeHypervisor struct {
	exec *fakeExec
}

func (f fakeHypervisor) DomainState(ctx context.Context, name string) (string, error) {
	out, err := f.exec.run(ctx, nil, "libvirt", "domstate", name)
	return strings.TrimSpace(string(out)), err
}

func (f fakeHypervisor) DefineDomain(ctx context.Context, xml string) error {
	_, err := f.exec.run(ctx, strings.NewReader(xml), "libvirt", "define")
	return err
}

func (f fakeHypervisor) DefineSecret(ctx context.Context, xml string) (string, error) {
	out, err := f.exec.run(ctx, strings.NewReader(xml), "libvirt", "secret-define")
	return strings.TrimSpace(string(out)), err
}

func (f fakeHypervisor) SetSecretValue(ctx context.Context, uuid string, value []byte) error {
	_, err := f.exec.run(ctx, bytes.NewReader(value), "libvirt", "secret-set-value", uuid)
	return err
}

func (f fakeHypervisor) UndefineSecret(ctx context.Context, uuid string) error {
	_, err := f.exec.run(ctx, nil, "libvirt", "secret-undefine", uuid)
	return err
}

func (f fakeHypervisor) StartDomain(ctx context.Context, name string) error {
	_, err := f.exec.run(ctx, nil, "libvirt", "start", name)
	return err
}

func (f fakeHypervisor) ShutdownDomain(ctx context.Context, name string) error {
	_, err := f.exec.run(ctx, nil, "libvirt", "shutdown", name)
	return err
}

func (f fakeHypervisor) DestroyDomain(ctx context.Context, name string) error {
	_, err := f.exec.run(ctx, nil, "libvirt", "destroy", name)
	return err
}

func (f fakeHypervisor) UndefineDomain(ctx context.Context, name string) error {
	_, err := f.exec.run(ctx, nil, "libvirt", "undefine", name)
	return err
}

func (f fakeHypervisor) UpdateDevice(ctx context.Context, name, xml string) error {
	_, err := f.exec.run(ctx, strings.NewReader(xml), "libvirt", "update-device", name)
	return err
}

func (f fakeHypervisor) AgentCommand(ctx context.Context, name, command string) (string, error) {
	out, err := f.exec.run(ctx, nil, "libvirt", "qemu-agent-command", name, command)
	return string(out), err
}

func (fakeHypervisor) Close() error {
	return nil
}

type fakeSecrets struct {
	key    string
	getErr error
	gets   []string
	puts   map[string]string
}

func (s *fakeSecrets) Get(_ context.Context, name string) ([]byte, error) {
	s.gets = append(s.gets, name)
	if s.getErr != nil {
		return nil, s.getErr
	}

	return []byte(s.key), nil
}

func (s *fakeSecrets) Put(name string, value io.Reader) error {
	data, err := io.ReadAll(value)
	if err != nil {
		return err
	}

	if s.puts == nil {
		s.puts = map[string]string{}
	}
	s.puts[name] = string(data)

	return nil
}

type fakeRotator struct {
	calls int
	err   error
}

func (r *fakeRotator) RotateVMTokens(_ context.Context) error {
	r.calls++
	return r.err
}

func testConfig() config.VM {
	return config.VM{
		Name:      "xena-dev",
		CPUs:      8,
		MemoryMiB: 16384,
		DiskGiB:   120,
		Network: config.VMNetwork{
			Bridge:        "xena0",
			BridgeAddress: "192.168.150.1",
			VMAddress:     "192.168.150.10",
			Prefix:        24,
			MAC:           "52:54:00:78:65:6e",
		},
		ProxyPort:         3128,
		ClaudeCodeVersion: "2.1.0",
		NpmVersion:        "11.21.2",
		DotclaudeRef:      strings.Repeat("a", 40),
		Git:               config.VMGit{Name: "bot", Email: "bot@example.com"},
	}
}

func newTestMachine(t *testing.T, fake *fakeExec, store SecretStore, rotator TokenRotator) *Machine {
	t.Helper()

	t.Setenv("XENA_CUT_MARKER", filepath.Join(t.TempDir(), "cut"))

	m := NewMachine(
		testConfig(),
		t.TempDir(),
		filepath.Join(t.TempDir(), "known_hosts"),
		"",
		"",
		"",
		store,
		rotator,
		0,
		slog.New(slog.DiscardHandler),
	)
	m.run = fake.run
	m.virt = fakeHypervisor{exec: fake}

	return m
}

func requireErr(t *testing.T, err, wantErr error, wantPrefix string) {
	t.Helper()

	if wantErr == nil && wantPrefix == "" {
		require.NoError(t, err)
		return
	}

	require.Error(t, err)
	if wantErr != nil {
		require.ErrorIs(t, err, wantErr)
	}
	if wantPrefix != "" {
		require.True(t, strings.HasPrefix(err.Error(), wantPrefix), err.Error())
	}
}

const (
	pingCmd  = `{"execute":"guest-ping"}`
	bootOpen = `{"execute":"guest-file-open",` +
		`"arguments":{"path":"/var/lib/cloud/instance/boot-finished","mode":"r"}}`
	bootClose       = `{"execute":"guest-file-close","arguments":{"handle":1000}}`
	resultOpen      = `{"execute":"guest-file-open","arguments":{"path":"/run/cloud-init/result.json","mode":"r"}}`
	resultRead      = `{"execute":"guest-file-read","arguments":{"handle":1001,"count":4096}}`
	resultClose     = `{"execute":"guest-file-close","arguments":{"handle":1001}}`
	resultDone      = `{"v1":{"datasource":"DataSourceNoCloud","errors":[]}}`
	resultFailed    = `{"v1":{"datasource":"DataSourceNoCloud","errors":["scripts_user failed"]}}`
	secretDefineOut = defineUUID + "\n"
	outputOpen      = `{"execute":"guest-file-open",` +
		`"arguments":{"path":"/var/log/cloud-init-output.log","mode":"r"}}`
	outputSeek  = `{"execute":"guest-file-seek","arguments":{"handle":1003,"offset":-8192,"whence":"end"}}`
	outputRead  = `{"execute":"guest-file-read","arguments":{"handle":1003,"count":8192}}`
	outputClose = `{"execute":"guest-file-close","arguments":{"handle":1003}}`
	nologinOpen = `{"execute":"guest-file-open","arguments":{"path":"/run/nologin","mode":"r"}}`
	nologinShut = `{"execute":"guest-file-close","arguments":{"handle":1004}}`
)

func startResponses(startErr, undefineErr error) []response {
	return []response{
		{Match: stateCall, Out: "shut off\n\n"},
		{Match: lv + "secret-define", Out: secretDefineOut},
		{Match: lv + "secret-set-value"},
		{Match: lv + "start xena-dev", Err: startErr},
		{Match: lv + "secret-undefine " + defineUUID, Err: undefineErr},
	}
}

func loginResponses() []response {
	return []response{
		{Match: agentCall(pingCmd), Out: `{"return":{}}`},
		{Match: agentCall(nologinOpen), Err: errFake},
	}
}

func loginCalls() []string {
	return []string{agentCall(pingCmd), agentCall(nologinOpen)}
}

func startCalls() []string {
	return []string{
		stateCall,
		lv + "secret-define",
		lv + "secret-set-value " + defineUUID,
		lv + "start xena-dev",
		lv + "secret-undefine " + defineUUID,
	}
}

func readyResponses(result string) []response {
	return []response{
		{Match: agentCall(pingCmd), Out: `{"return":{}}`},
		{Match: agentCall(bootOpen), Out: `{"return":1000}`},
		{Match: agentCall(bootClose), Out: `{"return":{}}`},
		{Match: agentCall(resultOpen), Out: `{"return":1001}`},
		{Match: agentCall(resultRead), Out: agentRead(result)},
		{Match: agentCall(resultClose), Out: `{"return":{}}`},
	}
}

func readyCalls() []string {
	return []string{
		agentCall(pingCmd),
		agentCall(bootOpen),
		agentCall(bootClose),
		agentCall(resultOpen),
		agentCall(resultRead),
		agentCall(resultClose),
	}
}

func repeat(r response, n int) []response {
	out := make([]response, n)
	for i := range out {
		out[i] = r
	}

	return out
}

func repeatPair(first, second response, n int) []response {
	out := make([]response, 0, 2*n)
	for range n {
		out = append(out, first, second)
	}

	return out
}

func repeatPairLine(first, second string, n int) []string {
	out := make([]string, 0, 2*n)
	for range n {
		out = append(out, first, second)
	}

	return out
}

func repeatLine(line string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = line
	}

	return out
}

func TestMachine_State(t *testing.T) {
	tests := []struct {
		name      string
		responses []response
		wantCalls []string
		want      string
	}{
		{
			name:      "happy path - undefined",
			responses: []response{{Match: stateCall, Out: "undefined\n"}},
			wantCalls: []string{stateCall},
			want:      "undefined",
		},
		{
			name:      "happy path - running",
			responses: []response{{Match: stateCall, Out: "running\n\n"}},
			wantCalls: []string{stateCall},
			want:      "running",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			fake := newFakeExec(t, tt.responses)
			m := newTestMachine(t, fake, &fakeSecrets{}, &fakeRotator{})

			// when
			got, err := m.State(context.Background())

			// then
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
			require.Equal(t, tt.wantCalls, fake.lines())
		})
	}
}

func TestMachine_Define(t *testing.T) {
	// given
	fake := newFakeExec(t, []response{{Match: lv + "define"}})
	m := newTestMachine(t, fake, &fakeSecrets{}, &fakeRotator{})

	// when
	err := m.Define(context.Background())

	// then
	require.NoError(t, err)
	require.Equal(t, []string{lv + "define"}, fake.lines())

	xml := fake.calls[0].Stdin
	for _, want := range []string{
		"<name>xena-dev</name>",
		"<memory unit='MiB'>16384</memory>",
		"<vcpu>8</vcpu>",
		"<encryption format='luks'>",
		"<secret type='passphrase' usage='" + m.DiskPath() + "'/>",
		"<source network='xena'/>",
		"<mac address='52:54:00:78:65:6e'/>",
		"org.qemu.guest_agent.0",
		"<target dev='sda' bus='sata'/>",
	} {
		require.Contains(t, xml, want)
	}
	require.NotContains(t, xml, "<graphics")
}

func TestMachine_Start(t *testing.T) {
	tests := []struct {
		name          string
		cut           bool
		cancel        bool
		getErr        error
		responses     []response
		wantCalls     []string
		wantGets      []string
		wantErr       error
		wantErrPrefix string
	}{
		{
			name:      "happy path - starts with ephemeral secret and waits for logins",
			responses: slices.Concat(startResponses(nil, nil), loginResponses()),
			wantCalls: slices.Concat(startCalls(), loginCalls()),
			wantGets:  []string{"vm-disk-key"},
		},
		{
			name:      "happy path - already running still waits for logins",
			responses: slices.Concat([]response{{Match: stateCall, Out: "running\n"}}, loginResponses()),
			wantCalls: slices.Concat([]string{stateCall}, loginCalls()),
		},
		{
			name: "happy path - waits while boot blocks logins",
			responses: []response{
				{Match: stateCall, Out: "running\n"},
				{Match: agentCall(pingCmd), Err: errFake},
				{Match: agentCall(pingCmd), Out: `{"return":{}}`},
				{Match: agentCall(nologinOpen), Out: `{"return":1004}`},
				{Match: agentCall(nologinShut), Out: `{"return":{}}`},
				{Match: agentCall(nologinOpen), Err: errFake},
			},
			wantCalls: []string{
				stateCall,
				agentCall(pingCmd),
				agentCall(pingCmd),
				agentCall(nologinOpen),
				agentCall(nologinShut),
				agentCall(nologinOpen),
			},
		},
		{
			name: "error - boot never allows logins",
			responses: slices.Concat(
				[]response{{Match: stateCall, Out: "running\n"}, {Match: agentCall(pingCmd), Out: `{"return":{}}`}},
				repeatPair(
					response{Match: agentCall(nologinOpen), Out: `{"return":1004}`},
					response{Match: agentCall(nologinShut), Out: `{"return":{}}`},
					readyAttempts,
				),
			),
			wantCalls: slices.Concat(
				[]string{stateCall, agentCall(pingCmd)},
				repeatPairLine(agentCall(nologinOpen), agentCall(nologinShut), readyAttempts),
			),
			wantErr:       ErrTimeout,
			wantErrPrefix: "waiting for login: ",
		},
		{
			name:          "error - start fails",
			responses:     startResponses(errFake, nil),
			wantCalls:     startCalls(),
			wantGets:      []string{"vm-disk-key"},
			wantErrPrefix: "starting vm: ",
		},
		{
			name:          "error - secret undefine fails",
			responses:     startResponses(nil, errFake),
			wantCalls:     startCalls(),
			wantGets:      []string{"vm-disk-key"},
			wantErrPrefix: "undefining disk secret: ",
		},
		{
			name:          "error - disk key unreadable",
			getErr:        errFake,
			responses:     []response{{Match: stateCall, Out: "shut off\n"}},
			wantCalls:     []string{stateCall},
			wantGets:      []string{"vm-disk-key"},
			wantErrPrefix: "reading disk key: ",
		},
		{
			name:          "error - interrupted start still undefines secret",
			cancel:        true,
			responses:     startResponses(errFake, nil),
			wantCalls:     startCalls(),
			wantGets:      []string{"vm-disk-key"},
			wantErrPrefix: "starting vm: ",
		},
		{
			name:      "error - not defined",
			responses: []response{{Match: stateCall, Out: "undefined\n"}},
			wantCalls: []string{stateCall},
			wantErr:   ErrUndefined,
		},
		{
			name:    "error - network cut",
			cut:     true,
			wantErr: ErrCut,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			responses := tt.responses
			if tt.cancel {
				for i := range responses {
					if responses[i].Match == lv+"start xena-dev" {
						responses[i].Effect = func([]string) { cancel() }
					}
				}
			}

			fake := newFakeExec(t, responses)
			store := &fakeSecrets{key: testKey, getErr: tt.getErr}
			m := newTestMachine(t, fake, store, &fakeRotator{})

			if tt.cut {
				marker := filepath.Join(t.TempDir(), "cut")
				require.NoError(t, os.WriteFile(marker, nil, 0o600))
				t.Setenv("XENA_CUT_MARKER", marker)
			}

			// when
			err := m.Start(ctx)

			// then
			requireErr(t, err, tt.wantErr, tt.wantErrPrefix)
			require.Equal(t, tt.wantCalls, fake.lines())

			for _, c := range fake.calls {
				if c.Name == "libvirt" && slices.Contains(c.Args, "secret-undefine") {
					require.False(t, c.Canceled)
				}
			}

			require.Equal(t, tt.wantGets, store.gets)
			fake.requireKeyNotInArgs(t)

			for _, stdin := range fake.stdinOf(lv + "secret-define") {
				require.Contains(t, stdin, "ephemeral='yes'")
				require.Contains(t, stdin, "private='yes'")
				require.Contains(t, stdin, "<volume>"+m.DiskPath()+"</volume>")
			}

			for _, stdin := range fake.stdinOf(lv + "secret-set-value") {
				require.Equal(t, testKey, stdin)
			}
		})
	}
}

func TestMachine_Stop(t *testing.T) {
	running := response{Match: stateCall, Out: "running\n"}

	tests := []struct {
		name          string
		responses     []response
		wantCalls     []string
		wantErrPrefix string
	}{
		{
			name: "happy path - shuts down",
			responses: []response{
				running,
				{Match: lv + "shutdown xena-dev"},
				running,
				running,
				{Match: stateCall, Out: "shut off\n"},
			},
			wantCalls: []string{
				stateCall,
				lv + "shutdown xena-dev",
				stateCall,
				stateCall,
				stateCall,
			},
		},
		{
			name: "happy path - forces off after timeout",
			responses: append(
				[]response{running, {Match: lv + "shutdown xena-dev"}},
				append(repeat(running, stopAttempts), response{Match: lv + "destroy xena-dev"})...,
			),
			wantCalls: append(
				[]string{stateCall, lv + "shutdown xena-dev"},
				append(repeatLine(stateCall, stopAttempts), lv+"destroy xena-dev")...,
			),
		},
		{
			name:      "happy path - already shut off",
			responses: []response{{Match: stateCall, Out: "shut off\n"}},
			wantCalls: []string{stateCall},
		},
		{
			name: "error - shutdown fails",
			responses: []response{
				running,
				{Match: lv + "shutdown xena-dev", Err: errFake},
			},
			wantCalls:     []string{stateCall, lv + "shutdown xena-dev"},
			wantErrPrefix: "stopping vm: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			fake := newFakeExec(t, tt.responses)
			m := newTestMachine(t, fake, &fakeSecrets{}, &fakeRotator{})

			// when
			err := m.Stop(context.Background())

			// then
			requireErr(t, err, nil, tt.wantErrPrefix)
			require.Equal(t, tt.wantCalls, fake.lines())
		})
	}
}

func TestMachine_Destroy(t *testing.T) {
	tests := []struct {
		name          string
		responses     []response
		wantCalls     []string
		wantErrPrefix string
	}{
		{
			name: "happy path - running domain",
			responses: []response{
				{Match: stateCall, Out: "running\n"},
				{Match: lv + "destroy xena-dev"},
				{Match: lv + "undefine xena-dev"},
			},
			wantCalls: []string{stateCall, lv + "destroy xena-dev", lv + "undefine xena-dev"},
		},
		{
			name: "happy path - shut off domain",
			responses: []response{
				{Match: stateCall, Out: "shut off\n"},
				{Match: lv + "undefine xena-dev"},
			},
			wantCalls: []string{stateCall, lv + "undefine xena-dev"},
		},
		{
			name:      "happy path - undefined domain",
			responses: []response{{Match: stateCall, Out: "undefined\n"}},
			wantCalls: []string{stateCall},
		},
		{
			name: "error - undefine fails keeps disk",
			responses: []response{
				{Match: stateCall, Out: "shut off\n"},
				{Match: lv + "undefine xena-dev", Err: errFake},
			},
			wantCalls:     []string{stateCall, lv + "undefine xena-dev"},
			wantErrPrefix: "undefining vm: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			fake := newFakeExec(t, tt.responses)
			m := newTestMachine(t, fake, &fakeSecrets{}, &fakeRotator{})

			files := []string{m.DiskPath(), m.SeedPath(), m.knownHosts}
			for _, file := range files {
				require.NoError(t, os.WriteFile(file, nil, 0o600))
			}

			// when
			err := m.Destroy(context.Background())

			// then
			requireErr(t, err, nil, tt.wantErrPrefix)
			require.Equal(t, tt.wantCalls, fake.lines())

			for _, file := range files {
				if tt.wantErrPrefix != "" {
					require.FileExists(t, file)
					continue
				}

				require.NoFileExists(t, file)
			}
		})
	}
}

func TestMachine_WaitReady(t *testing.T) {
	tests := []struct {
		name          string
		responses     []response
		wantCalls     []string
		wantLines     []string
		wantErr       error
		wantErrPrefix string
	}{
		{
			name: "happy path - waits for agent and cloud-init",
			responses: append([]response{
				{Match: agentCall(pingCmd), Err: errFake},
				{Match: agentCall(pingCmd), Err: errFake},
				{Match: agentCall(bootOpen), Err: errFake},
			}, readyResponses(resultDone)...),
			wantCalls: append(
				[]string{agentCall(pingCmd), agentCall(pingCmd), agentCall(pingCmd), agentCall(bootOpen)},
				readyCalls()[1:]...,
			),
		},
		{
			name: "error - cloud-init reports errors and logs its output",
			responses: slices.Concat(readyResponses(resultFailed), []response{
				{Match: agentCall(outputOpen), Out: `{"return":1003}`},
				{Match: agentCall(outputSeek), Out: `{"return":{"position":0,"eof":false}}`},
				{Match: agentCall(outputRead), Out: agentRead("ok\nnpm ERR! network\n")},
				{Match: agentCall(outputClose), Out: `{"return":{}}`},
			}),
			wantCalls: slices.Concat(
				readyCalls(),
				[]string{agentCall(outputOpen), agentCall(outputSeek), agentCall(outputRead), agentCall(outputClose)},
			),
			wantLines:     []string{"ok", "npm ERR! network"},
			wantErr:       ErrCloudInit,
			wantErrPrefix: "waiting for vm: cloud-init failed: scripts_user failed; see /var/log/cloud-init-output.log",
		},
		{
			name: "happy path - first boot outlasts the start wait",
			responses: append(
				repeat(response{Match: agentCall(pingCmd), Err: errFake}, readyAttempts),
				readyResponses(resultDone)...,
			),
			wantCalls: append(repeatLine(agentCall(pingCmd), readyAttempts), readyCalls()...),
		},
		{
			name:          "error - agent never answers",
			responses:     repeat(response{Match: agentCall(pingCmd), Err: errFake}, firstBootAttempts),
			wantCalls:     repeatLine(agentCall(pingCmd), firstBootAttempts),
			wantErr:       ErrTimeout,
			wantErrPrefix: "waiting for guest agent: timed out: last error: exit status 1",
		},
		{
			name: "error - boot never finishes",
			responses: append(
				[]response{{Match: agentCall(pingCmd), Out: `{"return":{}}`}},
				repeat(response{Match: agentCall(bootOpen), Err: errFake}, firstBootAttempts)...,
			),
			wantCalls:     append([]string{agentCall(pingCmd)}, repeatLine(agentCall(bootOpen), firstBootAttempts)...),
			wantErr:       ErrTimeout,
			wantErrPrefix: "waiting for cloud-init: ",
		},
		{
			name:          "error - cloud-init result not json",
			responses:     append(readyResponses("not json"), response{Match: agentCall(outputOpen), Err: errFake}),
			wantCalls:     append(readyCalls(), agentCall(outputOpen)),
			wantErrPrefix: "waiting for vm: parsing cloud-init result: ",
		},
		{
			name:          "error - cloud-init result without v1",
			responses:     append(readyResponses(`{}`), response{Match: agentCall(outputOpen), Err: errFake}),
			wantCalls:     append(readyCalls(), agentCall(outputOpen)),
			wantErr:       ErrCloudInit,
			wantErrPrefix: "waiting for vm: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			fake := newFakeExec(t, tt.responses)
			m := newTestMachine(t, fake, &fakeSecrets{}, &fakeRotator{})

			var logs bytes.Buffer
			m.logger = slog.New(slog.NewJSONHandler(&logs, nil))

			// when
			err := m.WaitReady(context.Background())

			// then
			requireErr(t, err, tt.wantErr, tt.wantErrPrefix)
			require.Equal(t, tt.wantCalls, fake.lines())

			var gotLines []string
			for line := range strings.Lines(logs.String()) {
				var record struct {
					Msg  string `json:"msg"`
					Line string `json:"line"`
				}
				require.NoError(t, json.Unmarshal([]byte(line), &record))
				if record.Msg == "cloud-init output" {
					gotLines = append(gotLines, record.Line)
				}
			}
			require.Equal(t, tt.wantLines, gotLines)
		})
	}
}

func TestMachine_EjectSeed(t *testing.T) {
	// given
	fake := newFakeExec(t, []response{{Match: lv + "update-device xena-dev"}})
	m := newTestMachine(t, fake, &fakeSecrets{}, &fakeRotator{})
	require.NoError(t, os.WriteFile(m.SeedPath(), nil, 0o600))

	// when
	err := m.EjectSeed(context.Background())

	// then
	require.NoError(t, err)
	require.Equal(t, []string{lv + "update-device xena-dev"}, fake.lines())
	require.Equal(
		t,
		[]string{`<disk type='file' device='cdrom'><driver name='qemu' type='raw'/>` +
			`<target dev='sda' bus='sata'/><readonly/></disk>`},
		fake.stdinOf(lv+"update-device"),
	)
	require.NoFileExists(t, m.SeedPath())
}

func TestMachine_Build(t *testing.T) {
	tests := []struct {
		name          string
		exists        bool
		diskExists    bool
		diskHidden    bool
		noDir         bool
		wantCalls     []string
		wantErr       error
		wantErrPrefix string
	}{
		{name: "happy path - builds and boots"},
		{
			name:      "error - domain exists",
			exists:    true,
			wantCalls: []string{stateCall},
			wantErr:   ErrExists,
		},
		{
			name:       "error - old disk still present",
			diskExists: true,
			wantCalls:  []string{stateCall},
			wantErr:    ErrDiskExists,
		},
		{
			name:          "error - disk check fails",
			diskHidden:    true,
			wantCalls:     []string{stateCall},
			wantErrPrefix: "checking vm disk: ",
		},
		{
			name:          "error - vm dir missing",
			noDir:         true,
			wantErrPrefix: "checking vm dir: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			configDir := t.TempDir()
			stateDir := t.TempDir()
			t.Setenv("XENA_CONFIG_DIR", configDir)
			t.Setenv("XENA_STATE_DIR", stateDir)

			keyDir := t.TempDir()
			keyFiles := map[string]string{"interactive": "", "backup": "", "carry": ""}
			for name := range keyFiles {
				keyFiles[name] = filepath.Join(keyDir, name+".pub")
				content := "sk-ssh-ed25519@openssh.com " + ed25519Blob(t, "sk-ssh-ed25519@openssh.com", nil) + " " + name
				require.NoError(t, os.WriteFile(keyFiles[name], []byte(content+"\n"), 0o600))
			}

			automation := filepath.Join(configDir, "automation_ed25519")
			require.NoError(t, os.WriteFile(automation, []byte("old"), 0o600))

			hostKey := ed25519Blob(t, "ssh-ed25519", nil)
			var seedSources string

			head := []response{{Match: stateCall, Out: "undefined\n"}}
			if tt.exists {
				head = []response{{Match: stateCall, Out: "shut off\n"}}
			}
			responses := slices.Concat(
				head,
				[]response{
					{Match: "ssh-keygen", Effect: func(_ []string) {
						require.NoFileExists(t, automation)
						pub := "ssh-ed25519 " + ed25519Blob(t, "ssh-ed25519", nil) + " xena-automation\n"
						require.NoError(t, os.WriteFile(automation, []byte("private"), 0o600))
						require.NoError(t, os.WriteFile(automation+".pub", []byte(pub), 0o600))
					}},
					{Match: "cloud-localds", Effect: func(args []string) {
						seedSources = filepath.Dir(strings.TrimPrefix(args[0], "--network-config="))
						for _, file := range []string{"network-config", "user-data", "meta-data"} {
							require.FileExists(t, filepath.Join(seedSources, file))
						}
						require.NoError(t, os.WriteFile(args[1], []byte("iso"), 0o600))
					}},
					{Match: "qemu-img convert", Effect: createEmpty(t)},
					{Match: "qemu-img resize"},
					{Match: lv + "define"},
				},
				startResponses(nil, nil),
				readyResponses(resultDone),
				hostKeyResponses("ssh-ed25519 "+hostKey+" root@xena-dev\n"),
				[]response{{Match: lv + "update-device xena-dev"}},
			)

			fake := newFakeExec(t, responses)
			store := &fakeSecrets{key: testKey}
			m := newTestMachine(t, fake, store, &fakeRotator{})
			m.interactiveKey = keyFiles["interactive"]
			m.backupKey = keyFiles["backup"]
			m.carryKey = keyFiles["carry"]

			image := []byte("fake image bytes")
			sum := sha256.Sum256(image)
			m.config.Image = config.VMImage{URL: "http://192.0.2.1/never", SHA256: hex.EncodeToString(sum[:])}
			images := filepath.Join(m.dir, "images")
			require.NoError(t, os.MkdirAll(images, 0o700))
			base := filepath.Join(images, m.config.Image.SHA256[:12]+".img")
			require.NoError(t, os.WriteFile(base, image, 0o600))

			if tt.diskExists {
				require.NoError(t, os.WriteFile(m.DiskPath(), []byte("old disk"), 0o600))
			}

			if tt.noDir {
				m.dir = filepath.Join(t.TempDir(), "missing")
			}

			if tt.diskHidden {
				require.NoError(t, os.Chmod(m.dir, 0o600))
				t.Cleanup(func() { _ = os.Chmod(m.dir, 0o700) })
			}

			now := time.Date(2026, time.November, 15, 12, 0, 0, 0, time.UTC)

			// when
			err := m.Build(context.Background(), http.DefaultClient, now)

			// then
			if tt.wantErr != nil || tt.wantErrPrefix != "" {
				requireErr(t, err, tt.wantErr, tt.wantErrPrefix)
				require.Equal(t, tt.wantCalls, fake.lines())
				require.Empty(t, store.puts)
				return
			}

			require.NoError(t, err)

			disk := m.DiskPath()
			want := slices.Concat(
				[]string{
					stateCall,
					"ssh-keygen -q -t ed25519 -N  -C xena-automation -f " + automation,
					"cloud-localds --network-config=" + filepath.Join(seedSources, "network-config") + " " +
						m.SeedPath() + " " + filepath.Join(seedSources, "user-data") + " " +
						filepath.Join(seedSources, "meta-data"),
					strings.Replace(convertCall(disk), "/img/base.img", base, 1),
					resizeCall(disk),
					lv + "define",
				},
				startCalls(),
				readyCalls(),
				[]string{agentCall(hostKeyOpen), agentCall(hostKeyRead), agentCall(hostKeyClose)},
				[]string{lv + "update-device xena-dev"},
			)
			require.Equal(t, want, fake.lines())

			for _, line := range fake.lines() {
				require.NotContains(t, line, "autostart")
			}

			diskKey := store.puts["vm-disk-key"]
			require.Regexp(t, `^[0-9a-f]{64}$`, diskKey)
			require.Equal(t, []string{diskKey, diskKey}, fake.stdinOf("qemu-img"))
			for _, line := range fake.lines() {
				require.NotContains(t, line, diskKey)
			}
			fake.requireKeyNotInArgs(t)

			builtAt, readErr := os.ReadFile(filepath.Join(stateDir, "vm-built-at"))
			require.NoError(t, readErr)
			parsed, parseErr := time.Parse(time.RFC3339, strings.TrimSpace(string(builtAt)))
			require.NoError(t, parseErr)
			require.True(t, parsed.Equal(now))

			require.NoDirExists(t, seedSources)
			require.NoFileExists(t, m.SeedPath())
			require.FileExists(t, m.knownHosts)
		})
	}
}

func TestRunCommand(t *testing.T) {
	long := strings.Repeat("x", 500)

	tests := []struct {
		name          string
		args          []string
		stdin         string
		want          string
		wantErrPrefix string
		wantNotIn     string
	}{
		{name: "happy path - passes stdin", args: []string{"cat"}, stdin: "hello", want: "hello"},
		{
			name:          "error - keeps last stderr line, capped",
			args:          []string{"sh", "-c", "echo first >&2; echo " + long + " >&2; exit 3"},
			wantErrPrefix: "running sh: exit status 3: " + strings.Repeat("x", stderrLimit),
			wantNotIn:     "first",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			stdin := strings.NewReader(tt.stdin)

			// when
			out, err := runCommand(context.Background(), stdin, tt.args[0], tt.args[1:]...)

			// then
			if tt.wantErrPrefix == "" {
				require.NoError(t, err)
				require.Equal(t, tt.want, string(out))
				return
			}

			require.Error(t, err)
			require.Equal(t, tt.wantErrPrefix, err.Error())
			require.NotContains(t, err.Error(), tt.wantNotIn)
		})
	}
}

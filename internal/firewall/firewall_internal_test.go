package firewall

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	nftPath  = "/usr/sbin/nft"
	vmAddr   = "192.168.150.10"
	fromAddr = "192.0.2.5"

	exposedFixture = `{"nftables":[{"metainfo":{"json_schema_version":1}},` +
		`{"map":{"family":"inet","name":"exposed","table":"xena","type":["ipv4_addr","inet_service"],` +
		`"handle":3,"map":["ipv4_addr","inet_service"],"elem":[` +
		`[{"concat":["192.0.2.5",8081]},{"concat":["192.168.150.10",8081]}],` +
		`[{"concat":["192.0.2.5",19000]},{"concat":["192.168.150.10",19000]}]]}}]}`
	exposedTimeoutFixture = `{"nftables":[{"metainfo":{"json_schema_version":1}},` +
		`{"map":{"family":"inet","name":"exposed","table":"xena","type":["ipv4_addr","inet_service"],` +
		`"handle":3,"map":["ipv4_addr","inet_service"],"elem":[` +
		`[{"elem":{"val":{"concat":["192.0.2.5",8081]},"timeout":14400,"expires":14390}},` +
		`{"concat":["192.168.150.10",8081]}]]}}]}`
	twoSourcesFixture = `{"nftables":[{"map":{"elem":[` +
		`[{"concat":["192.0.2.5",8081]},{"concat":["192.168.150.10",8081]}],` +
		`[{"concat":["192.0.2.6",8081]},{"concat":["192.168.150.10",8081]}]]}}]}`
	emptyExposedFixture     = `{"nftables":[{"map":{"name":"exposed"}}]}`
	noListFixture           = `{"nftables":[{"metainfo":{"json_schema_version":1}}]}`
	malformedExposedFixture = `{"nftables":[{"map":{"elem":[[{"concat":["192.0.2.5"]},{"concat":[]}]]}}]}`
	wrongTypesFixture       = `{"nftables":[{"map":{"elem":[[{"concat":[5,"x"]},{"concat":[]}]]}}]}`
	wrongPortTypeFixture    = `{"nftables":[{"map":{"elem":[[{"concat":["192.0.2.5","x"]},{"concat":[]}]]}}]}`
)

var (
	errNft = errors.New("nft failed")

	listExposedArgv = []string{"--json", "list", "map", "inet", "xena", "exposed"}
	flushArgv       = []string{
		"flush", "map", "inet", "xena", "exposed", ";",
		"flush", "set", "inet", "xena", "forwarded",
	}
	cutArgv = []string{
		"add", "element", "inet", "xena", "cut", "{ 192.168.150.10 }", ";",
		"flush", "map", "inet", "xena", "exposed", ";",
		"flush", "set", "inet", "xena", "forwarded",
	}
	resumeArgv   = []string{"destroy", "element", "inet", "xena", "cut", "{ 192.168.150.10 }"}
	unexposeArgv = []string{
		"destroy", "element", "inet", "xena", "exposed", "{ 192.0.2.5 . 8081 }", ";",
		"destroy", "element", "inet", "xena", "forwarded", "{ 192.0.2.5 . 8081 }",
	}
)

type fakeStep struct {
	out string
	err error
}

type fakeNft struct {
	steps []fakeStep
	names []string
	calls [][]string
}

func (f *fakeNft) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.names = append(f.names, name)
	f.calls = append(f.calls, args)

	if len(f.steps) == 0 {
		return nil, nil
	}

	step := f.steps[0]
	f.steps = f.steps[1:]

	return []byte(step.out), step.err
}

func newFake(steps ...fakeStep) (*Firewall, *fakeNft) {
	fake := &fakeNft{steps: steps}
	f := NewFirewall(nftPath)
	f.run = fake.run

	return f, fake
}

func exposeArgv(port, seconds string) []string {
	return []string{
		"add", "element", "inet", "xena", "exposed",
		"{ 192.0.2.5 . " + port + " timeout " + seconds + "s : 192.168.150.10 . " + port + " }", ";",
		"add", "element", "inet", "xena", "forwarded",
		"{ 192.0.2.5 . " + port + " timeout " + seconds + "s }",
	}
}

func assertCalls(t *testing.T, fake *fakeNft, want [][]string) {
	t.Helper()

	assert.Equal(t, want, fake.calls)

	for _, name := range fake.names {
		assert.Equal(t, nftPath, name)
	}
}

func TestFirewall_Cut(t *testing.T) {
	tests := []struct {
		name       string
		addr       string
		steps      []fakeStep
		want       [][]string
		wantIs     error
		wantPrefix string
	}{
		{
			name: "happy path - adds address and flushes forwards in one call",
			addr: vmAddr,
			want: [][]string{cutArgv},
		},
		{name: "error - not an address", addr: "not-an-ip", wantIs: ErrInvalidAddress},
		{name: "error - ipv6 address", addr: "2001:db8::1", wantIs: ErrInvalidAddress},
		{name: "error - ipv4 mapped ipv6 address", addr: "::ffff:192.168.150.10", wantIs: ErrInvalidAddress},
		{
			name:       "error - nft fails",
			addr:       vmAddr,
			steps:      []fakeStep{{err: errNft}},
			want:       [][]string{cutArgv},
			wantIs:     errNft,
			wantPrefix: "cutting vm network: ",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			f, fake := newFake(tt.steps...)

			// when
			err := f.Cut(t.Context(), tt.addr)

			// then
			assertCalls(t, fake, tt.want)
			assertError(t, err, tt.wantIs, tt.wantPrefix)
		})
	}
}

func TestFirewall_IsCut(t *testing.T) {
	tests := []struct {
		name   string
		addr   string
		marker bool
		want   bool
		wantIs error
	}{
		{name: "happy path - marker present", addr: vmAddr, marker: true, want: true},
		{name: "happy path - marker absent", addr: vmAddr},
		{name: "error - invalid address", addr: "not-an-ip", wantIs: ErrInvalidAddress},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			marker := filepath.Join(t.TempDir(), "cut")
			t.Setenv("XENA_CUT_MARKER", marker)

			if tt.marker {
				require.NoError(t, os.WriteFile(marker, []byte("2026-11-06T00:00:00Z\n"), 0o644))
			}

			f, fake := newFake()

			// when
			got, err := f.IsCut(t.Context(), tt.addr)

			// then
			assert.Empty(t, fake.calls)
			assert.Equal(t, tt.want, got)
			assertError(t, err, tt.wantIs, "")
		})
	}

	t.Run("error - marker cannot be checked", func(t *testing.T) {
		// given
		file := filepath.Join(t.TempDir(), "file")
		require.NoError(t, os.WriteFile(file, nil, 0o644))
		t.Setenv("XENA_CUT_MARKER", filepath.Join(file, "cut"))
		f, _ := newFake()

		// when
		_, err := f.IsCut(t.Context(), vmAddr)

		// then
		assertError(t, err, nil, "checking cut marker: ")
	})
}

func TestFirewall_Resume(t *testing.T) {
	tests := []struct {
		name       string
		addr       string
		steps      []fakeStep
		want       [][]string
		wantIs     error
		wantPrefix string
	}{
		{
			name: "happy path - destroys the address whether or not it is listed",
			addr: vmAddr,
			want: [][]string{resumeArgv},
		},
		{
			name:       "error - nft fails",
			addr:       vmAddr,
			steps:      []fakeStep{{err: errNft}},
			want:       [][]string{resumeArgv},
			wantIs:     errNft,
			wantPrefix: "resuming vm network: ",
		},
		{name: "error - invalid address", addr: "not-an-ip", wantIs: ErrInvalidAddress},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			f, fake := newFake(tt.steps...)

			// when
			err := f.Resume(t.Context(), tt.addr)

			// then
			assertCalls(t, fake, tt.want)
			assertError(t, err, tt.wantIs, tt.wantPrefix)
		})
	}
}

func TestFirewall_Expose(t *testing.T) {
	tests := []struct {
		name       string
		port       int
		from       string
		vm         string
		ttl        time.Duration
		steps      []fakeStep
		want       [][]string
		wantIs     error
		wantPrefix string
	}{
		{
			name: "happy path - adds forward and open entry with timeout",
			port: 8081,
			from: fromAddr,
			vm:   vmAddr,
			ttl:  4 * time.Hour,
			want: [][]string{exposeArgv("8081", "14400")},
		},
		{
			name: "happy path - one second is the shortest ttl",
			port: 8081,
			from: fromAddr,
			vm:   vmAddr,
			ttl:  time.Second,
			want: [][]string{exposeArgv("8081", "1")},
		},
		{
			name: "happy path - partial seconds round down",
			port: 8081,
			from: fromAddr,
			vm:   vmAddr,
			ttl:  1500 * time.Millisecond,
			want: [][]string{exposeArgv("8081", "1")},
		},
		{
			name: "happy path - lowest port",
			port: 1,
			from: fromAddr,
			vm:   vmAddr,
			ttl:  time.Second,
			want: [][]string{exposeArgv("1", "1")},
		},
		{
			name: "happy path - highest port",
			port: 65535,
			from: fromAddr,
			vm:   vmAddr,
			ttl:  time.Second,
			want: [][]string{exposeArgv("65535", "1")},
		},
		{name: "error - port 0", port: 0, from: fromAddr, vm: vmAddr, ttl: time.Hour, wantIs: ErrInvalidPort},
		{name: "error - port 65536", port: 65536, from: fromAddr, vm: vmAddr, ttl: time.Hour, wantIs: ErrInvalidPort},
		{
			name:   "error - from is a name",
			port:   8081,
			from:   "example.com",
			vm:     vmAddr,
			ttl:    time.Hour,
			wantIs: ErrInvalidAddress,
		},
		{
			name:   "error - vm is a name",
			port:   8081,
			from:   fromAddr,
			vm:     "example.com",
			ttl:    time.Hour,
			wantIs: ErrInvalidAddress,
		},
		{name: "error - ttl 0", port: 8081, from: fromAddr, vm: vmAddr, wantIs: ErrInvalidTTL},
		{name: "error - negative ttl", port: 8081, from: fromAddr, vm: vmAddr, ttl: -time.Hour, wantIs: ErrInvalidTTL},
		{
			name:   "error - ttl under one second",
			port:   8081,
			from:   fromAddr,
			vm:     vmAddr,
			ttl:    time.Second - time.Nanosecond,
			wantIs: ErrInvalidTTL,
		},
		{
			name:       "error - nft fails",
			port:       8081,
			from:       fromAddr,
			vm:         vmAddr,
			ttl:        4 * time.Hour,
			steps:      []fakeStep{{err: errNft}},
			want:       [][]string{exposeArgv("8081", "14400")},
			wantIs:     errNft,
			wantPrefix: "exposing port 8081: ",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			f, fake := newFake(tt.steps...)

			// when
			err := f.Expose(t.Context(), tt.port, tt.from, tt.vm, tt.ttl)

			// then
			assertCalls(t, fake, tt.want)
			assertError(t, err, tt.wantIs, tt.wantPrefix)
		})
	}
}

func TestFirewall_Unexpose(t *testing.T) {
	tests := []struct {
		name       string
		port       int
		steps      []fakeStep
		want       [][]string
		wantIs     error
		wantPrefix string
	}{
		{
			name:  "happy path - destroys only the matching port",
			port:  8081,
			steps: []fakeStep{{out: exposedFixture}},
			want:  [][]string{listExposedArgv, unexposeArgv},
		},
		{
			name:  "happy path - element with timeout",
			port:  8081,
			steps: []fakeStep{{out: exposedTimeoutFixture}},
			want:  [][]string{listExposedArgv, unexposeArgv},
		},
		{
			name:  "happy path - destroys every source on the port in one call",
			port:  8081,
			steps: []fakeStep{{out: twoSourcesFixture}},
			want: [][]string{
				listExposedArgv,
				append(
					append([]string{}, unexposeArgv...),
					";", "destroy", "element", "inet", "xena", "exposed", "{ 192.0.2.6 . 8081 }",
					";", "destroy", "element", "inet", "xena", "forwarded", "{ 192.0.2.6 . 8081 }",
				),
			},
		},
		{
			name:  "happy path - closed port makes only the list call",
			port:  3000,
			steps: []fakeStep{{out: exposedFixture}},
			want:  [][]string{listExposedArgv},
		},
		{
			name:  "happy path - empty map makes only the list call",
			port:  8081,
			steps: []fakeStep{{out: emptyExposedFixture}},
			want:  [][]string{listExposedArgv},
		},
		{name: "error - port 0", port: 0, wantIs: ErrInvalidPort},
		{
			name:       "error - output has no map",
			port:       8081,
			steps:      []fakeStep{{out: noListFixture}},
			want:       [][]string{listExposedArgv},
			wantPrefix: "parsing nft output: ",
		},
		{
			name:       "error - address is not a string",
			port:       8081,
			steps:      []fakeStep{{out: wrongTypesFixture}},
			want:       [][]string{listExposedArgv},
			wantPrefix: "parsing nft output: ",
		},
		{
			name:       "error - port is not a number",
			port:       8081,
			steps:      []fakeStep{{out: wrongPortTypeFixture}},
			want:       [][]string{listExposedArgv},
			wantPrefix: "parsing nft output: ",
		},
		{
			name:       "error - list fails",
			port:       8081,
			steps:      []fakeStep{{err: errNft}},
			want:       [][]string{listExposedArgv},
			wantIs:     errNft,
			wantPrefix: "unexposing port 8081: ",
		},
		{
			name:       "error - list output is not json",
			port:       8081,
			steps:      []fakeStep{{out: "not json"}},
			want:       [][]string{listExposedArgv},
			wantPrefix: "parsing nft output: ",
		},
		{
			name:       "error - unknown element shape",
			port:       8081,
			steps:      []fakeStep{{out: malformedExposedFixture}},
			want:       [][]string{listExposedArgv},
			wantPrefix: "parsing nft output: ",
		},
		{
			name:       "error - destroy fails",
			port:       8081,
			steps:      []fakeStep{{out: exposedFixture}, {err: errNft}},
			want:       [][]string{listExposedArgv, unexposeArgv},
			wantIs:     errNft,
			wantPrefix: "unexposing port 8081: ",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			f, fake := newFake(tt.steps...)

			// when
			err := f.Unexpose(t.Context(), tt.port)

			// then
			assertCalls(t, fake, tt.want)
			assertError(t, err, tt.wantIs, tt.wantPrefix)
		})
	}
}

func TestFirewall_UnexposeAll(t *testing.T) {
	tests := []struct {
		name       string
		steps      []fakeStep
		wantIs     error
		wantPrefix string
	}{
		{name: "happy path - flushes forwards and open entries in one call"},
		{
			name:       "error - nft fails",
			steps:      []fakeStep{{err: errNft}},
			wantIs:     errNft,
			wantPrefix: "unexposing all ports: ",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			f, fake := newFake(tt.steps...)

			// when
			err := f.UnexposeAll(t.Context())

			// then
			assertCalls(t, fake, [][]string{flushArgv})
			assertError(t, err, tt.wantIs, tt.wantPrefix)
		})
	}
}

func TestRunCommand(t *testing.T) {
	tests := []struct {
		name    string
		script  string
		want    string
		wantErr string
	}{
		{name: "happy path - returns stdout only", script: "echo out; echo noise >&2", want: "out\n"},
		{name: "error - keeps stderr reason", script: "echo 'no such table' >&2; exit 1", wantErr: "no such table"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			ctx := t.Context()

			// when
			got, err := runCommand(ctx, "sh", "-c", tt.script)

			// then
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, string(got))
		})
	}
}

func assertError(t *testing.T, err, wantIs error, wantPrefix string) {
	t.Helper()

	if wantIs == nil && wantPrefix == "" {
		require.NoError(t, err)
		return
	}

	require.Error(t, err)

	if wantIs != nil {
		require.ErrorIs(t, err, wantIs)
	}

	if wantPrefix != "" {
		assert.True(t, strings.HasPrefix(err.Error(), wantPrefix), err.Error())
	}
}

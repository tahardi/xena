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

	cutSetFixture = `{"nftables":[{"metainfo":{"json_schema_version":1}},` +
		`{"set":{"family":"inet","name":"cut","table":"xena","type":"ipv4_addr","handle":2,` +
		`"elem":["192.168.150.10"]}}]}`
	otherCutSetFixture = `{"nftables":[{"metainfo":{"json_schema_version":1}},` +
		`{"set":{"family":"inet","name":"cut","table":"xena","type":"ipv4_addr","handle":2,` +
		`"elem":["192.168.150.11"]}}]}`
	emptyCutSetFixture = `{"nftables":[{"metainfo":{"json_schema_version":1}},` +
		`{"set":{"family":"inet","name":"cut","table":"xena","type":"ipv4_addr","handle":2}}]}`
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

	listCutArgv     = []string{"--json", "list", "set", "inet", "xena", "cut"}
	listExposedArgv = []string{"--json", "list", "map", "inet", "xena", "exposed"}
	flushArgv       = []string{"flush", "map", "inet", "xena", "exposed"}
	addCutArgv      = []string{"add", "element", "inet", "xena", "cut", "{ 192.168.150.10 }"}
	deleteCutArgv   = []string{"delete", "element", "inet", "xena", "cut", "{ 192.168.150.10 }"}
	deleteExposed   = []string{"delete", "element", "inet", "xena", "exposed", "{ 192.0.2.5 . 8081 }"}
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
			name: "happy path - adds address then flushes forwards",
			addr: vmAddr,
			want: [][]string{addCutArgv, flushArgv},
		},
		{name: "error - not an address", addr: "not-an-ip", wantIs: ErrInvalidAddress},
		{name: "error - ipv6 address", addr: "2001:db8::1", wantIs: ErrInvalidAddress},
		{name: "error - ipv4 mapped ipv6 address", addr: "::ffff:192.168.150.10", wantIs: ErrInvalidAddress},
		{
			name:       "error - add fails",
			addr:       vmAddr,
			steps:      []fakeStep{{err: errNft}},
			want:       [][]string{addCutArgv},
			wantIs:     errNft,
			wantPrefix: "cutting vm network: ",
		},
		{
			name:       "error - flush fails",
			addr:       vmAddr,
			steps:      []fakeStep{{}, {err: errNft}},
			want:       [][]string{addCutArgv, flushArgv},
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
			name:  "happy path - listed address is deleted",
			addr:  vmAddr,
			steps: []fakeStep{{out: cutSetFixture}},
			want:  [][]string{listCutArgv, deleteCutArgv},
		},
		{
			name:  "happy path - empty set makes only the list call",
			addr:  vmAddr,
			steps: []fakeStep{{out: emptyCutSetFixture}},
			want:  [][]string{listCutArgv},
		},
		{
			name:  "happy path - other address makes only the list call",
			addr:  vmAddr,
			steps: []fakeStep{{out: otherCutSetFixture}},
			want:  [][]string{listCutArgv},
		},
		{
			name:       "error - list output is not json",
			addr:       vmAddr,
			steps:      []fakeStep{{out: "not json"}},
			want:       [][]string{listCutArgv},
			wantPrefix: "parsing nft output: ",
		},
		{
			name:       "error - output has no set",
			addr:       vmAddr,
			steps:      []fakeStep{{out: noListFixture}},
			want:       [][]string{listCutArgv},
			wantPrefix: "parsing nft output: ",
		},
		{
			name:       "error - list fails",
			addr:       vmAddr,
			steps:      []fakeStep{{err: errNft}},
			want:       [][]string{listCutArgv},
			wantPrefix: "listing cut set: ",
		},
		{
			name:       "error - delete fails",
			addr:       vmAddr,
			steps:      []fakeStep{{out: cutSetFixture}, {err: errNft}},
			want:       [][]string{listCutArgv, deleteCutArgv},
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
	addArgv := []string{
		"add", "element", "inet", "xena", "exposed",
		"{ 192.0.2.5 . 8081 timeout 14400s : 192.168.150.10 . 8081 }",
	}

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
			name: "happy path - adds forward with timeout",
			port: 8081,
			from: fromAddr,
			vm:   vmAddr,
			ttl:  4 * time.Hour,
			want: [][]string{addArgv},
		},
		{
			name: "happy path - one second is the shortest ttl",
			port: 8081,
			from: fromAddr,
			vm:   vmAddr,
			ttl:  time.Second,
			want: [][]string{{
				"add", "element", "inet", "xena", "exposed",
				"{ 192.0.2.5 . 8081 timeout 1s : 192.168.150.10 . 8081 }",
			}},
		},
		{
			name: "happy path - partial seconds round down",
			port: 8081,
			from: fromAddr,
			vm:   vmAddr,
			ttl:  1500 * time.Millisecond,
			want: [][]string{{
				"add", "element", "inet", "xena", "exposed",
				"{ 192.0.2.5 . 8081 timeout 1s : 192.168.150.10 . 8081 }",
			}},
		},
		{
			name: "happy path - lowest port",
			port: 1,
			from: fromAddr,
			vm:   vmAddr,
			ttl:  time.Second,
			want: [][]string{{
				"add", "element", "inet", "xena", "exposed",
				"{ 192.0.2.5 . 1 timeout 1s : 192.168.150.10 . 1 }",
			}},
		},
		{
			name: "happy path - highest port",
			port: 65535,
			from: fromAddr,
			vm:   vmAddr,
			ttl:  time.Second,
			want: [][]string{{
				"add", "element", "inet", "xena", "exposed",
				"{ 192.0.2.5 . 65535 timeout 1s : 192.168.150.10 . 65535 }",
			}},
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
			want:       [][]string{addArgv},
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
			name:  "happy path - deletes only the matching port",
			port:  8081,
			steps: []fakeStep{{out: exposedFixture}},
			want:  [][]string{listExposedArgv, deleteExposed},
		},
		{
			name:  "happy path - element with timeout",
			port:  8081,
			steps: []fakeStep{{out: exposedTimeoutFixture}},
			want:  [][]string{listExposedArgv, deleteExposed},
		},
		{
			name:  "happy path - closed port makes only the list call",
			port:  3000,
			steps: []fakeStep{{out: exposedFixture}},
			want:  [][]string{listExposedArgv},
		},
		{
			name:  "happy path - deletes every source on the port",
			port:  8081,
			steps: []fakeStep{{out: twoSourcesFixture}},
			want: [][]string{
				listExposedArgv,
				deleteExposed,
				{"delete", "element", "inet", "xena", "exposed", "{ 192.0.2.6 . 8081 }"},
			},
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
			name:       "error - delete fails",
			port:       8081,
			steps:      []fakeStep{{out: exposedFixture}, {err: errNft}},
			want:       [][]string{listExposedArgv, deleteExposed},
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
		wantPrefix string
	}{
		{name: "happy path - flushes the map"},
		{name: "error - nft fails", steps: []fakeStep{{err: errNft}}, wantPrefix: "unexposing all ports: "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			f, fake := newFake(tt.steps...)

			// when
			err := f.UnexposeAll(t.Context())

			// then
			assertCalls(t, fake, [][]string{flushArgv})
			assertError(t, err, nil, tt.wantPrefix)
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

package guard_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/config"
	"github.com/tahardi/xena/internal/guard"
	"github.com/tahardi/xena/internal/logs"
)

var (
	errFake      = errors.New("fake failure")
	evidenceTime = time.Date(2026, 10, 25, 3, 0, 0, 0, time.UTC)
)

func TestNetCase_Run(t *testing.T) {
	now := time.Date(2026, 10, 25, 3, 0, 0, 0, time.UTC)
	after := now.Add(time.Second)
	literal := []string{logs.DecisionRefuseIPLiteral}
	proxyWant := []guard.ProxyExpect{{Host: "198.51.100.7", Port: 443, Decisions: literal}}
	dropWant := []guard.DropExpect{{Dst: "198.51.100.7", Port: 443, Proto: "TCP"}}
	refusal := logs.ProxyEntry{Time: after, Host: "198.51.100.7", Port: 443, Decision: logs.DecisionRefuseIPLiteral}
	drop := guard.Drop{Time: after, Src: "192.168.150.10", Dst: "198.51.100.7", DstPort: 443, Proto: "TCP"}
	blocked := "blocked https://198.51.100.7/\nblocked 198.51.100.7:443\n"

	tests := []struct {
		name            string
		proxyWant       []guard.ProxyExpect
		dropWant        []guard.DropExpect
		output          string
		vmErr           error
		entries         []logs.ProxyEntry
		proxyErr        error
		drops           []guard.Drop
		dropsErr        error
		cut             bool
		cutErr          error
		precheck        func(ctx context.Context) error
		wantErr         string
		wantEvidence    []string
		wantEvidenceLen int
		wantEvidenceMax int
		wantNoVM        bool
	}{
		{
			name:    "happy path - proxy and drop evidence",
			output:  blocked,
			entries: []logs.ProxyEntry{refusal},
			drops:   []guard.Drop{drop},
			wantEvidence: []string{
				"vm: blocked https://198.51.100.7/",
				"vm: blocked 198.51.100.7:443",
				"proxy: 198.51.100.7:443 refuse-ip-literal at " + after.Local().Format(time.TimeOnly),
				"drop: 192.168.150.10 -> 198.51.100.7:443/TCP at " + after.Local().Format(time.TimeOnly),
			},
		},
		{
			name:    "error - VM reports connected",
			output:  "connected 198.51.100.7:443\n",
			entries: []logs.ProxyEntry{refusal},
			drops:   []guard.Drop{drop},
			wantErr: "VM connected to 198.51.100.7:443",
		},
		{
			name:    "error - VM reports connected and exits non-zero",
			output:  "blocked 198.51.100.7:80\nconnected 198.51.100.7:443\n",
			vmErr:   errFake,
			entries: []logs.ProxyEntry{refusal},
			drops:   []guard.Drop{drop},
			wantErr: "VM connected to 198.51.100.7:443",
		},
		{
			name:         "error - VM connected line carries no control characters",
			output:       "connected \x1b[31mevil\a\n",
			wantErr:      "VM connected to [31mevil",
			wantEvidence: []string{"vm: connected [31mevil"},
		},
		{
			name:            "error - connected line past the evidence cap still fails",
			output:          strings.Repeat("blocked x\n", 150) + "connected 198.51.100.7:443\n",
			wantErr:         "VM connected to 198.51.100.7:443",
			wantEvidenceLen: 100,
		},
		{
			name:            "error - long VM line is cut",
			output:          "connected " + strings.Repeat("a", 1000) + "\n",
			wantErr:         "VM connected to aaa",
			wantEvidenceMax: 300 + len("vm: "),
		},
		{
			name:    "error - VM script fails",
			vmErr:   errFake,
			entries: []logs.ProxyEntry{refusal},
			drops:   []guard.Drop{drop},
			wantErr: "running VM script",
		},
		{
			name:    "error - missing proxy evidence",
			output:  blocked,
			drops:   []guard.Drop{drop},
			wantErr: "no proxy log entry for 198.51.100.7:443",
		},
		{
			name:    "error - missing drop evidence",
			output:  blocked,
			entries: []logs.ProxyEntry{refusal},
			wantErr: "no firewall drop for 198.51.100.7:443/TCP",
		},
		{
			name:   "error - proxy allowed the host",
			output: blocked,
			entries: []logs.ProxyEntry{
				{Time: after, Host: "198.51.100.7", Port: 443, Decision: logs.DecisionAllow},
			},
			drops:   []guard.Drop{drop},
			wantErr: "proxy allowed 198.51.100.7:443",
		},
		{
			name:   "error - proxy allowed after a refusal",
			output: blocked,
			entries: []logs.ProxyEntry{
				refusal,
				{Time: after, Host: "198.51.100.7", Port: 443, Decision: logs.DecisionAllowOnce},
			},
			drops:   []guard.Drop{drop},
			wantErr: "proxy allowed 198.51.100.7:443",
		},
		{
			name:   "error - wrong proxy decision",
			output: blocked,
			entries: []logs.ProxyEntry{
				{Time: after, Host: "198.51.100.7", Port: 443, Decision: logs.DecisionDeny},
			},
			drops:   []guard.Drop{drop},
			wantErr: "no proxy log entry for 198.51.100.7:443",
		},
		{
			name:   "error - evidence before the case started",
			output: blocked,
			entries: []logs.ProxyEntry{
				{Time: now.Add(-time.Minute), Host: "198.51.100.7", Port: 443, Decision: logs.DecisionRefuseIPLiteral},
			},
			drops: []guard.Drop{
				{Time: now.Add(-time.Minute), Src: "192.168.150.10", Dst: "198.51.100.7", DstPort: 443, Proto: "TCP"},
			},
			wantErr: "no proxy log entry for 198.51.100.7:443",
		},
		{
			name:   "happy path - allow before the case started is ignored",
			output: blocked,
			entries: []logs.ProxyEntry{
				{Time: now.Add(-time.Minute), Host: "198.51.100.7", Port: 443, Decision: logs.DecisionAllow},
				refusal,
			},
			drops: []guard.Drop{drop},
		},
		{
			name:    "error - drop from another source",
			output:  blocked,
			entries: []logs.ProxyEntry{refusal},
			drops: []guard.Drop{
				{Time: after, Src: "192.168.150.99", Dst: "198.51.100.7", DstPort: 443, Proto: "TCP"},
			},
			wantErr: "no firewall drop for 198.51.100.7:443/TCP",
		},
		{
			name:    "error - drop with another protocol",
			output:  blocked,
			entries: []logs.ProxyEntry{refusal},
			drops: []guard.Drop{
				{Time: after, Src: "192.168.150.10", Dst: "198.51.100.7", DstPort: 443, Proto: "UDP"},
			},
			wantErr: "no firewall drop for 198.51.100.7:443/TCP",
		},
		{
			name:    "error - drop on another port",
			output:  blocked,
			entries: []logs.ProxyEntry{refusal},
			drops: []guard.Drop{
				{Time: after, Src: "192.168.150.10", Dst: "198.51.100.7", DstPort: 80, Proto: "TCP"},
			},
			wantErr: "no firewall drop for 198.51.100.7:443/TCP",
		},
		{
			name:      "happy path - ipv6 drop ignores source",
			proxyWant: []guard.ProxyExpect{},
			dropWant:  []guard.DropExpect{{Dst: "ff02::1", Proto: "ICMPv6"}},
			drops:     []guard.Drop{{Time: after, Src: "fe80::5054:ff:fe00:1", Dst: "ff02::1", Proto: "ICMPv6"}},
		},
		{
			name:      "happy path - bracketed ipv6 host",
			proxyWant: []guard.ProxyExpect{{Host: "2001:db8::7", Port: 443, Decisions: literal}},
			dropWant:  []guard.DropExpect{},
			entries: []logs.ProxyEntry{
				{Time: after, Host: "[2001:db8::7]", Port: 443, Decision: logs.DecisionRefuseIPLiteral},
			},
		},
		{
			name:     "error - network is cut",
			cut:      true,
			wantErr:  "VM network is cut",
			wantNoVM: true,
		},
		{
			name:     "error - cut check fails",
			cutErr:   errFake,
			wantErr:  "checking cut",
			wantNoVM: true,
		},
		{
			name: "error - precheck fails",
			precheck: func(context.Context) error {
				return guard.ErrRebindHost
			},
			wantErr:  "rebind host not configured",
			wantNoVM: true,
		},
		{
			name:     "error - proxy log unreadable",
			output:   blocked,
			proxyErr: errFake,
			wantErr:  errFake.Error(),
		},
		{
			name:     "error - drops unreadable",
			output:   blocked,
			entries:  []logs.ProxyEntry{refusal},
			dropsErr: errFake,
			wantErr:  errFake.Error(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			if tt.proxyWant == nil {
				tt.proxyWant = proxyWant
			}

			if tt.dropWant == nil {
				tt.dropWant = dropWant
			}

			vm := &fakeVM{output: map[string]string{"net-test": tt.output}, err: tt.vmErr}
			env := guard.Env{
				VM:       vm,
				Proxy:    &fakeProxy{entries: tt.entries, err: tt.proxyErr},
				Drops:    &fakeDrops{drops: tt.drops, err: tt.dropsErr},
				Firewall: &fakeCut{cut: tt.cut, err: tt.cutErr},
				VMAddr:   "192.168.150.10",
				Now:      func() time.Time { return now },
			}
			netCase := guard.NewNetCase("net-test", "net-test", tt.proxyWant, tt.dropWant, tt.precheck)

			// when
			got := netCase.Run(context.Background(), env)

			// then
			if tt.wantNoVM {
				assert.Empty(t, vm.calls)
			} else {
				assert.Equal(t, []string{"guard net-test"}, vm.calls)
			}

			assert.Equal(t, "net-test", got.Case)
			if tt.wantEvidenceLen != 0 {
				assert.Len(t, got.Evidence, tt.wantEvidenceLen)
			}

			if tt.wantEvidenceMax != 0 {
				require.NotEmpty(t, got.Evidence)
				assert.LessOrEqual(t, len(got.Evidence[0]), tt.wantEvidenceMax)
			}

			if tt.wantErr != "" {
				assert.False(t, got.Passed)
				assert.Contains(t, got.Error, tt.wantErr)
				if tt.wantEvidence != nil {
					assert.Equal(t, tt.wantEvidence, got.Evidence)
				}

				return
			}

			assert.True(t, got.Passed, got.Error)
			if tt.wantEvidence != nil {
				assert.Equal(t, tt.wantEvidence, got.Evidence)
			}
		})
	}

	t.Run("happy path - evidence arrives while settling", func(t *testing.T) {
		// given
		seen := time.Now().Add(time.Second)
		lateRefusal := refusal
		lateRefusal.Time = seen

		lateDrop := drop
		lateDrop.Time = seen

		env := guard.Env{
			VM:       &fakeVM{},
			Proxy:    &fakeProxy{entries: []logs.ProxyEntry{lateRefusal}, emptyCalls: 1},
			Drops:    &fakeDrops{drops: []guard.Drop{lateDrop}},
			Firewall: &fakeCut{},
			VMAddr:   "192.168.150.10",
			Now:      time.Now,
			Settle:   5 * time.Second,
		}

		// when
		got := guard.NewNetCase("net-test", "net-test", proxyWant, dropWant, nil).Run(context.Background(), env)

		// then
		assert.True(t, got.Passed, got.Error)
	})

	t.Run("error - settle time runs out", func(t *testing.T) {
		// given
		env := guard.Env{
			VM:       &fakeVM{},
			Proxy:    &fakeProxy{},
			Drops:    &fakeDrops{},
			Firewall: &fakeCut{},
			VMAddr:   "192.168.150.10",
			Now:      time.Now,
			Settle:   time.Millisecond,
		}

		// when
		got := guard.NewNetCase("net-test", "net-test", proxyWant, nil, nil).Run(context.Background(), env)

		// then
		assert.False(t, got.Passed)
		assert.Contains(t, got.Error, "no proxy log entry")
	})

	t.Run("error - context ends while settling", func(t *testing.T) {
		// given
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		env := guard.Env{
			VM:       &fakeVM{},
			Proxy:    &fakeProxy{},
			Drops:    &fakeDrops{},
			Firewall: &fakeCut{},
			VMAddr:   "192.168.150.10",
			Now:      time.Now,
			Settle:   time.Hour,
		}

		// when
		got := guard.NewNetCase("net-test", "net-test", proxyWant, nil, nil).Run(ctx, env)

		// then
		assert.False(t, got.Passed)
		assert.Contains(t, got.Error, "no proxy log entry")
	})
}

func TestNetworkCases(t *testing.T) {
	bridge := "192.168.150.1"
	literal := []string{logs.DecisionRefuseIPLiteral}
	asked := []string{logs.DecisionDeny, logs.DecisionTimeout}
	oddPort := []string{logs.DecisionRefusePort, logs.DecisionDeny, logs.DecisionTimeout}
	netConfig := guard.NetConfig{
		BridgeAddr: bridge,
		ProxyPort:  3128,
		Lookup: func(context.Context, string) ([]string, error) {
			return []string{"127.0.0.1"}, nil
		},
	}

	expected := []struct {
		name  string
		proxy []guard.ProxyExpect
		drops []guard.DropExpect
	}{
		{
			name:  "net-unlisted",
			proxy: []guard.ProxyExpect{{Host: "xena-guard-unlisted.invalid", Port: 443, Decisions: asked}},
		},
		{
			name: "net-ip-literal",
			proxy: []guard.ProxyExpect{
				{Host: "198.51.100.7", Port: 443, Decisions: literal},
				{Host: "198.51.100.7", Port: 80, Decisions: literal},
			},
			drops: []guard.DropExpect{{Dst: "198.51.100.7", Port: 443, Proto: "TCP"}},
		},
		{
			name:  "net-lan",
			proxy: []guard.ProxyExpect{{Host: "10.0.0.10", Port: 443, Decisions: literal}},
			drops: []guard.DropExpect{
				{Dst: "10.0.0.10", Port: 22, Proto: "TCP"},
				{Dst: "172.16.0.10", Port: 22, Proto: "TCP"},
				{Dst: "192.168.1.10", Port: 22, Proto: "TCP"},
			},
		},
		{
			name: "net-desktop-ports",
			drops: []guard.DropExpect{
				{Dst: bridge, Port: 22, Proto: "TCP"},
				{Dst: bridge, Port: 80, Proto: "TCP"},
				{Dst: bridge, Port: 443, Proto: "TCP"},
				{Dst: bridge, Port: 631, Proto: "TCP"},
				{Dst: bridge, Port: 8080, Proto: "TCP"},
				{Dst: bridge, Port: 5353, Proto: "UDP"},
			},
		},
		{
			name: "net-router",
			drops: []guard.DropExpect{
				{Dst: "192.168.0.1", Port: 80, Proto: "TCP"},
				{Dst: "192.168.1.1", Port: 80, Proto: "TCP"},
				{Dst: "10.0.0.1", Port: 80, Proto: "TCP"},
			},
		},
		{
			name:  "net-metadata",
			proxy: []guard.ProxyExpect{{Host: "169.254.169.254", Port: 80, Decisions: literal}},
			drops: []guard.DropExpect{{Dst: "169.254.169.254", Port: 80, Proto: "TCP"}},
		},
		{
			name:  "net-ipv6",
			proxy: []guard.ProxyExpect{{Host: "2001:db8::7", Port: 443, Decisions: literal}},
		},
		{
			name:  "net-odd-port",
			proxy: []guard.ProxyExpect{{Host: "github.com", Port: 22, Decisions: oddPort}},
		},
		{
			name: "net-dns-tunnel",
			drops: []guard.DropExpect{
				{Dst: bridge, Port: 53, Proto: "UDP"},
				{Dst: "1.1.1.1", Port: 53, Proto: "UDP"},
				{Dst: "9.9.9.9", Port: 53, Proto: "UDP"},
				{Dst: "1.1.1.1", Port: 53, Proto: "TCP"},
			},
		},
		{
			name: "net-rebind",
			proxy: []guard.ProxyExpect{
				{Host: "xena-guard-rebind.test", Port: 443, Decisions: []string{logs.DecisionRefuseAddress}},
			},
		},
	}

	t.Run("happy path - names in order", func(t *testing.T) {
		// given
		want := make([]string, 0, len(expected))
		for _, e := range expected {
			want = append(want, e.name)
		}

		// when
		cases := guard.NetworkCases(netConfig)

		// then
		got := make([]string, 0, len(cases))
		for _, c := range cases {
			got = append(got, c.Name())
		}

		assert.Equal(t, want, got)
	})

	t.Run("happy path - scripts match the repo config", func(t *testing.T) {
		// given
		vm, err := config.LoadVM("../../config/vm.yaml")
		require.NoError(t, err)

		wantBridge := vm.Network.BridgeAddress
		if wantBridge == "" {
			wantBridge = bridge
		}

		wantPort := vm.ProxyPort
		if wantPort == 0 {
			wantPort = 3128
		}

		// when
		cases := guard.NetworkCases(netConfig)

		// then
		for _, c := range cases {
			data, err := os.ReadFile(filepath.Join("../../vm/guard", c.Name()+".sh"))
			require.NoError(t, err)

			script := string(data)
			require.True(t, strings.HasPrefix(script, "#!/usr/bin/env bash\nset -euo pipefail\n"), c.Name())

			if strings.Contains(script, "192.168.150.") {
				assert.Contains(t, script, wantBridge, c.Name())
			}

			if strings.Contains(script, "proxy=") {
				assert.Contains(t, script, "proxy=http://"+wantBridge+":"+strconv.Itoa(wantPort)+"\n", c.Name())
			}

			if strings.Contains(script, "/usr/bin/curl") {
				assert.Contains(t, script, "--fail", c.Name())
			}
		}
	})

	for _, e := range expected {
		t.Run("happy path - "+e.name+" needs every expected record", func(t *testing.T) {
			// given
			selected, err := guard.Select(guard.NetworkCases(netConfig), []string{e.name})
			require.NoError(t, err)

			entries, drops := expectedEvidence(e.proxy, e.drops)

			// when
			got := selected[0].Run(context.Background(), evidenceEnv(entries, drops))

			// then
			assert.True(t, got.Passed, got.Error)

			for i := range entries {
				partial := slices.Delete(slices.Clone(entries), i, i+1)
				result := selected[0].Run(context.Background(), evidenceEnv(partial, drops))
				assert.False(t, result.Passed, "without proxy record %d", i)
			}

			for i := range drops {
				partial := slices.Delete(slices.Clone(drops), i, i+1)
				result := selected[0].Run(context.Background(), evidenceEnv(entries, partial))
				assert.False(t, result.Passed, "without drop record %d", i)
			}

			for i, want := range e.proxy {
				for _, decision := range want.Decisions {
					other := slices.Clone(entries)
					other[i].Decision = decision
					result := selected[0].Run(context.Background(), evidenceEnv(other, drops))
					assert.True(t, result.Passed, "decision %s: %s", decision, result.Error)
				}
			}
		})
	}

	rebindTests := []struct {
		name       string
		answer     []string
		err        error
		wantPassed bool
		wantErr    string
	}{
		{name: "error - rebind resolves elsewhere", answer: []string{"10.0.0.1"}, wantErr: "rebind host not configured"},
		{
			name:    "error - rebind has an extra answer",
			answer:  []string{"127.0.0.1", "10.0.0.1"},
			wantErr: "rebind host not configured",
		},
		{name: "error - rebind lookup fails", err: errFake, wantErr: "rebind host not configured"},
		{name: "happy path - rebind resolves only to loopback", answer: []string{"127.0.0.1"}, wantPassed: true},
	}

	for _, tt := range rebindTests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			cfg := netConfig
			cfg.Lookup = func(context.Context, string) ([]string, error) { return tt.answer, tt.err }

			selected, err := guard.Select(guard.NetworkCases(cfg), []string{"net-rebind"})
			require.NoError(t, err)

			entries, _ := expectedEvidence(
				[]guard.ProxyExpect{{
					Host:      "xena-guard-rebind.test",
					Port:      443,
					Decisions: []string{logs.DecisionRefuseAddress},
				}},
				nil,
			)

			// when
			got := selected[0].Run(context.Background(), evidenceEnv(entries, nil))

			// then
			assert.Equal(t, tt.wantPassed, got.Passed)
			assert.Contains(t, got.Error, tt.wantErr)
		})
	}
}

func expectedEvidence(proxy []guard.ProxyExpect, drops []guard.DropExpect) ([]logs.ProxyEntry, []guard.Drop) {
	seen := evidenceTime.Add(time.Second)

	entries := make([]logs.ProxyEntry, 0, len(proxy))
	for _, want := range proxy {
		entries = append(entries, logs.ProxyEntry{
			Time:     seen,
			Host:     want.Host,
			Port:     want.Port,
			Decision: want.Decisions[0],
		})
	}

	found := make([]guard.Drop, 0, len(drops))
	for _, want := range drops {
		found = append(found, guard.Drop{
			Time:    seen,
			Src:     "192.168.150.10",
			Dst:     want.Dst,
			DstPort: want.Port,
			Proto:   want.Proto,
		})
	}

	return entries, found
}

func evidenceEnv(entries []logs.ProxyEntry, drops []guard.Drop) guard.Env {
	return guard.Env{
		VM:       &fakeVM{},
		Proxy:    &fakeProxy{entries: entries},
		Drops:    &fakeDrops{drops: drops},
		Firewall: &fakeCut{},
		VMAddr:   "192.168.150.10",
		Now:      func() time.Time { return evidenceTime },
	}
}

func TestNetCase_Targets(t *testing.T) {
	tests := []struct {
		name string
		want []string
	}{
		{name: "net-lan", want: []string{"10.0.0.10", "10.0.0.10", "172.16.0.10", "192.168.1.10"}},
		{name: "net-odd-port", want: []string{}},
	}

	for _, tt := range tests {
		t.Run("happy path - "+tt.name, func(t *testing.T) {
			// given
			cases := guard.NetworkCases(guard.NetConfig{BridgeAddr: "192.168.150.1", ProxyPort: 3128})

			selected, err := guard.Select(cases, []string{tt.name})
			require.NoError(t, err)

			target, ok := selected[0].(guard.Targeter)
			require.True(t, ok)

			// when
			got := target.Targets()

			// then
			assert.ElementsMatch(t, tt.want, got)
		})
	}
}

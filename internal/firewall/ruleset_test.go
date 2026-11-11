package firewall_test

import (
	"encoding/xml"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var hardening = []string{
	"PrivateDevices=yes\n",
	"ProtectKernelTunables=yes\n",
	"ProtectKernelModules=yes\n",
	"ProtectKernelLogs=yes\n",
	"ProtectControlGroups=yes\n",
	"RestrictNamespaces=yes\n",
	"MemoryDenyWriteExecute=yes\n",
	"SystemCallArchitectures=native\n",
	"SystemCallFilter=@system-service\n",
}

type libvirtNetwork struct {
	Name   string `xml:"name"`
	UUID   string `xml:"uuid"`
	Bridge struct {
		Name string `xml:"name,attr"`
	} `xml:"bridge"`
	DNS struct {
		Enable string `xml:"enable,attr"`
	} `xml:"dns"`
	Forward []struct {
		Mode string `xml:"mode,attr"`
	} `xml:"forward"`
	IP []struct {
		Address string     `xml:"address,attr"`
		Prefix  string     `xml:"prefix,attr"`
		DHCP    []struct{} `xml:"dhcp"`
	} `xml:"ip"`
	DHCP []struct{} `xml:"dhcp"`
}

func TestRuleset(t *testing.T) {
	t.Run("happy path - libvirt network", func(t *testing.T) {
		// given
		data, err := os.ReadFile("../../deploy/libvirt/xena-net.xml")
		require.NoError(t, err)

		// when
		var network libvirtNetwork
		err = xml.Unmarshal(data, &network)

		// then
		require.NoError(t, err)
		assert.Equal(t, "xena", network.Name)
		assert.Regexp(t, `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`, network.UUID)
		assert.Equal(t, "xena0", network.Bridge.Name)
		assert.Equal(t, "no", network.DNS.Enable)
		require.Len(t, network.Forward, 1)
		assert.Equal(t, "open", network.Forward[0].Mode)
		require.Len(t, network.IP, 1)
		assert.Equal(t, "192.168.150.1", network.IP[0].Address)
		assert.Equal(t, "24", network.IP[0].Prefix)
		assert.Empty(t, network.IP[0].DHCP)
		assert.Empty(t, network.DHCP)
		assert.NotContains(t, string(data), "dhcp")
	})

	t.Run("happy path - reload header", func(t *testing.T) {
		// given
		data, err := os.ReadFile("../../deploy/nftables/xena.nft")
		require.NoError(t, err)

		// when
		ok := strings.HasPrefix(string(data), "table inet xena {}\ndelete table inet xena\n")

		// then
		assert.True(t, ok)
	})

	tests := []struct {
		name string
		want string
	}{
		{name: "happy path - cut set", want: "set cut"},
		{name: "happy path - element timeouts", want: "flags timeout"},
		{name: "happy path - filter priority", want: "priority filter;"},
		{name: "happy path - ipv4 set type", want: "type ipv4_addr"},
		{name: "happy path - exposed map", want: "map exposed"},
		{name: "happy path - input chain", want: "chain input_vm"},
		{name: "happy path - forward chain", want: "chain forward_vm"},
		{name: "happy path - nat chain", want: "chain prerouting_nat"},
		{name: "happy path - bridge match", want: `iifname "xena0"`},
		{name: "happy path - proxy rule", want: "ip saddr 192.168.150.10 tcp dport 3128"},
		{name: "happy path - drop log", want: `log prefix "xena-drop: "`},
		{name: "happy path - silent noise", want: "meta pkttype { broadcast, multicast } drop"},
		{name: "happy path - dnat only forward", want: "ct status dnat"},
		{name: "happy path - cut applies to input", want: "\t\tip saddr @cut drop\n"},
		{name: "happy path - cut applies to forward", want: `iifname "xena0" ip saddr @cut drop`},
		{name: "happy path - dnat reads exposed", want: "map @exposed"},
		{name: "happy path - proxy takes only new connections", want: "tcp dport 3128 ct state new accept"},
		{name: "happy path - forwarded set", want: "set forwarded"},
		{name: "happy path - dnat needs an open entry", want: `oifname "xena0" ct status dnat ip saddr . tcp dport @forwarded accept`},
		{
			name: "happy path - dnat replies need an open entry",
			want: "ct status dnat ct state established ip daddr . tcp sport @forwarded accept",
		},
		{name: "happy path - only ipv4 replies accepted", want: "meta nfproto ipv4 ct state established,related accept"},
		{name: "happy path - drop logs are rate limited", want: `limit rate 10/second burst 50 packets log prefix "xena-drop: "`},
		{name: "happy path - forward drops after log", want: "\t\tiifname \"xena0\" drop\n"},
		{name: "happy path - other traffic to the bridge drops", want: `oifname "xena0" drop`},
		{
			name: "happy path - tokend output chain",
			want: "chain output_tokend {\n\t\ttype filter hook output priority filter; policy accept;\n\t}\n",
		},
		{name: "happy path - tokend chain", want: "chain tokend"},
		{name: "happy path - tokend ssh rule", want: "ip daddr 192.168.150.10 tcp dport 22 accept"},
		{name: "happy path - tokend drop log", want: `log prefix "xena-tokend-drop: " level warn`},
		{
			name: "happy path - tokend drop log is rate limited",
			want: `limit rate 10/second burst 50 packets log prefix "xena-tokend-drop: "`,
		},
		{name: "happy path - tokend drops after log", want: "log prefix \"xena-tokend-drop: \" level warn\n\t\tdrop\n\t}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			data, err := os.ReadFile("../../deploy/nftables/xena.nft")
			require.NoError(t, err)

			// when
			got := string(data)

			// then
			assert.Contains(t, got, tt.want)
		})
	}

	orders := []struct {
		name   string
		first  string
		second string
	}{
		{
			name:   "happy path - cut comes before established replies",
			first:  "ip saddr @cut drop",
			second: "meta nfproto ipv4 ct state established,related accept",
		},
		{
			name:   "happy path - cut comes before proxy accept",
			first:  "ip saddr @cut drop",
			second: "tcp dport 3128 ct state new accept",
		},
		{
			name:   "happy path - noise drops before input log",
			first:  "meta pkttype { broadcast, multicast } drop",
			second: `log prefix "xena-drop: "`,
		},
		{
			name:   "happy path - forward cut comes before dnat accept",
			first:  `iifname "xena0" ip saddr @cut drop`,
			second: `iifname "xena0" ct status dnat ct state established`,
		},
		{
			name:   "happy path - forward noise drops before forward log",
			first:  `iifname "xena0" meta pkttype { broadcast, multicast } drop`,
			second: `iifname "xena0" limit rate`,
		},
		{
			name:   "happy path - tokend ssh before tokend log",
			first:  "ip daddr 192.168.150.10 tcp dport 22 accept",
			second: `log prefix "xena-tokend-drop: "`,
		},
	}
	for _, tt := range orders {
		t.Run(tt.name, func(t *testing.T) {
			// given
			data, err := os.ReadFile("../../deploy/nftables/xena.nft")
			require.NoError(t, err)

			// when
			first := strings.Index(string(data), tt.first)
			second := strings.Index(string(data), tt.second)

			// then
			require.GreaterOrEqual(t, first, 0)
			require.GreaterOrEqual(t, second, 0)
			assert.Less(t, first, second)
		})
	}

	t.Run("happy path - boot file has no cgroup match", func(t *testing.T) {
		// given
		data, err := os.ReadFile("../../deploy/nftables/xena.nft")
		require.NoError(t, err)

		// when
		got := string(data)

		// then
		assert.NotContains(t, got, "socket cgroupv2")
	})

	t.Run("happy path - polkit lets anyone start only the fence", func(t *testing.T) {
		// given
		data, err := os.ReadFile("../../deploy/polkit/50-xena.rules")
		require.NoError(t, err)
		rule := `if (/^xena-tokend-fence@[0-9]+\.service$/.test(unit) && action.lookup("verb") === "start") {` +
			"\n      return polkit.Result.YES;"

		// when
		fence := strings.Index(string(data), rule)
		admin := strings.Index(string(data), "AUTH_ADMIN")

		// then
		require.GreaterOrEqual(t, fence, 0)
		assert.Less(t, fence, admin)
		assert.Equal(t, 1, strings.Count(string(data), "polkit.Result.YES"))
	})

	units := []struct {
		name    string
		path    string
		want    []string
		notWant []string
	}{
		{
			name:    "happy path - cut unit is hardened and never starts by itself",
			path:    "../../deploy/systemd/xena-cut.service",
			want:    hardening,
			notWant: []string{"[Install]"},
		},
		{
			name:    "happy path - resume unit is hardened and never starts by itself",
			path:    "../../deploy/systemd/xena-resume.service",
			want:    hardening,
			notWant: []string{"[Install]"},
		},
		{
			name: "happy path - table load restores a cut",
			path: "../../deploy/systemd/xena-nftables.service",
			want: []string{"ExecStartPost=/usr/local/bin/xena firewall reapply\n"},
		},
		{
			name: "happy path - table loads before libvirt",
			path: "../../deploy/systemd/xena-nftables.service",
			want: []string{"Before=libvirtd.service xena-proxy.service\n"},
		},
		{
			name: "happy path - fence unit",
			path: "../../deploy/systemd/xena-tokend-fence@.service",
			want: []string{
				"Type=oneshot\n",
				"ExecStart=/usr/sbin/nft 'flush chain inet xena output_tokend; " +
					"add rule inet xena output_tokend socket cgroupv2 level 4 " +
					"\"user.slice/user-%i.slice/user@%i.service/tokend.slice\" jump tokend'\n",
				"CapabilityBoundingSet=CAP_NET_ADMIN\n",
				"RestrictAddressFamilies=AF_NETLINK AF_UNIX\n",
			},
			notWant: []string{"[Install]"},
		},
	}
	for _, tt := range units {
		t.Run(tt.name, func(t *testing.T) {
			// given
			data, err := os.ReadFile(tt.path)
			require.NoError(t, err)

			// when
			got := string(data)

			// then
			for _, want := range tt.want {
				assert.Contains(t, got, want)
			}

			for _, notWant := range tt.notWant {
				assert.NotContains(t, got, notWant)
			}
		})
	}
}

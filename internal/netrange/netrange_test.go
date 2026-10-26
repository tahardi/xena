package netrange_test

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tahardi/xena/internal/netrange"
)

func TestRefused(t *testing.T) {
	tests := []struct {
		name string
		addr netip.Addr
		want bool
	}{
		{name: "zero address", addr: netip.Addr{}, want: true},
		{name: "this network", addr: netip.MustParseAddr("0.0.0.0"), want: true},
		{name: "this network high end", addr: netip.MustParseAddr("0.255.255.255"), want: true},
		{name: "RFC1918 10", addr: netip.MustParseAddr("10.1.2.3"), want: true},
		{name: "CGNAT low", addr: netip.MustParseAddr("100.64.0.1"), want: true},
		{name: "CGNAT high", addr: netip.MustParseAddr("100.127.255.254"), want: true},
		{name: "just below CGNAT", addr: netip.MustParseAddr("100.63.255.255"), want: false},
		{name: "just below 10/8", addr: netip.MustParseAddr("9.255.255.255"), want: false},
		{name: "just above 10/8", addr: netip.MustParseAddr("11.0.0.0"), want: false},
		{name: "just above 198.18/15", addr: netip.MustParseAddr("198.20.0.1"), want: false},
		{name: "just below multicast", addr: netip.MustParseAddr("223.255.255.255"), want: false},
		{name: "just above CGNAT", addr: netip.MustParseAddr("100.128.0.1"), want: false},
		{name: "loopback", addr: netip.MustParseAddr("127.0.0.1"), want: true},
		{name: "loopback other", addr: netip.MustParseAddr("127.8.9.10"), want: true},
		{name: "link-local", addr: netip.MustParseAddr("169.254.1.1"), want: true},
		{name: "cloud metadata", addr: netip.MustParseAddr("169.254.169.254"), want: true},
		{name: "RFC1918 172 low", addr: netip.MustParseAddr("172.16.0.1"), want: true},
		{name: "RFC1918 172 high", addr: netip.MustParseAddr("172.31.255.254"), want: true},
		{name: "just above 172.16/12", addr: netip.MustParseAddr("172.32.0.1"), want: false},
		{name: "IETF protocol assignments", addr: netip.MustParseAddr("192.0.0.170"), want: true},
		{name: "RFC1918 192.168", addr: netip.MustParseAddr("192.168.1.1"), want: true},
		{name: "VM bridge", addr: netip.MustParseAddr("192.168.150.1"), want: true},
		{name: "benchmarking", addr: netip.MustParseAddr("198.18.0.1"), want: true},
		{name: "multicast", addr: netip.MustParseAddr("224.0.0.251"), want: true},
		{name: "reserved", addr: netip.MustParseAddr("240.0.0.1"), want: true},
		{name: "broadcast", addr: netip.MustParseAddr("255.255.255.255"), want: true},
		{name: "documentation 1", addr: netip.MustParseAddr("192.0.2.10"), want: false},
		{name: "documentation 2", addr: netip.MustParseAddr("198.51.100.7"), want: false},
		{name: "documentation 3", addr: netip.MustParseAddr("203.0.113.5"), want: false},
		{name: "IPv6 unspecified", addr: netip.MustParseAddr("::"), want: true},
		{name: "IPv6 loopback", addr: netip.MustParseAddr("::1"), want: true},
		{name: "IPv4-compatible loopback", addr: netip.MustParseAddr("::7f00:1"), want: true},
		{name: "IPv4-mapped loopback", addr: netip.MustParseAddr("::ffff:127.0.0.1"), want: true},
		{name: "IPv4-mapped metadata", addr: netip.MustParseAddr("::ffff:169.254.169.254"), want: true},
		{name: "IPv4-mapped private", addr: netip.MustParseAddr("::ffff:10.0.0.1"), want: true},
		{name: "IPv4-mapped documentation", addr: netip.MustParseAddr("::ffff:192.0.2.10"), want: false},
		{name: "NAT64 well-known", addr: netip.MustParseAddr("64:ff9b::a00:1"), want: true},
		{name: "NAT64 well-known public", addr: netip.MustParseAddr("64:ff9b::c000:20a"), want: true},
		{name: "NAT64 local-use", addr: netip.MustParseAddr("64:ff9b:1::1"), want: true},
		{name: "discard-only", addr: netip.MustParseAddr("100::1"), want: true},
		{name: "Teredo", addr: netip.MustParseAddr("2001::1"), want: true},
		{name: "6to4", addr: netip.MustParseAddr("2002:c000:20a::1"), want: true},
		{name: "unique local fc", addr: netip.MustParseAddr("fc00::1"), want: true},
		{name: "unique local fd", addr: netip.MustParseAddr("fd12:3456::1"), want: true},
		{name: "IPv6 link-local", addr: netip.MustParseAddr("fe80::1"), want: true},
		{name: "link-local with zone", addr: netip.MustParseAddr("fe80::1%eth0"), want: true},
		{name: "site-local (deprecated)", addr: netip.MustParseAddr("fec0::1"), want: true},
		{name: "IPv6 multicast", addr: netip.MustParseAddr("ff02::1"), want: true},
		{name: "IPv6 documentation", addr: netip.MustParseAddr("2001:db8::1"), want: false},
		{name: "IPv6 documentation with zone", addr: netip.MustParseAddr("2001:db8::1%eth0"), want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			addr := tt.addr

			// when
			got := netrange.Refused(addr)

			// then
			require.Equal(t, tt.want, got)
		})
	}
}

func TestIsIPLiteral(t *testing.T) {
	tests := []struct {
		name string
		host string
		want bool
	}{
		{name: "dotted IPv4", host: "192.0.2.10", want: true},
		{name: "dotted IPv4 trailing dot", host: "192.0.2.10.", want: true},
		{name: "short IPv4", host: "127.1", want: true},
		{name: "decimal IPv4", host: "2130706433", want: true},
		{name: "hex IPv4", host: "0x7f000001", want: true},
		{name: "hex first octet", host: "0x7f.0.0.1", want: true},
		{name: "octal first octet", host: "0177.0.0.1", want: true},
		{name: "bare IPv6", host: "2001:db8::1", want: true},
		{name: "bracketed IPv6", host: "[2001:db8::1]", want: true},
		{name: "mapped IPv6", host: "::ffff:127.0.0.1", want: true},
		{name: "IPv6 with zone", host: "fe80::1%eth0", want: true},
		{name: "bracketed IPv6 with escaped zone", host: "[fe80::1%25eth0]", want: true},
		{name: "numeric last label", host: "example.123", want: true},
		{name: "hex last label", host: "example.0x1f", want: true},
		{name: "name", host: "example.com", want: false},
		{name: "name with leading digit", host: "1password.example", want: false},
		{name: "name with trailing dot", host: "example.com.", want: false},
		{name: "punycode name", host: "xn--bcher-kva.example", want: false},
		{name: "hex-looking middle label", host: "0x7f.example", want: false},
		{name: "empty", host: "", want: false},
		{name: "bare dot", host: ".", want: false},
		{name: "uppercase hex first octet", host: "0X7F.0.0.1", want: true},
		{name: "bare hex prefix", host: "0x", want: true},
		{name: "IPv4 inside IPv6", host: "::127.0.0.1", want: true},
		{name: "escaped zone without brackets", host: "fe80::1%25eth0", want: true},
		{name: "two trailing dots", host: "192.0.2.10..", want: false},
		{name: "unbalanced bracket", host: "[::1", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			host := tt.host

			// when
			got := netrange.IsIPLiteral(host)

			// then
			require.Equal(t, tt.want, got)
		})
	}
}

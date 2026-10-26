package netrange

import (
	"net/netip"
	"regexp"
	"strings"
)

var refusedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("fec0::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

var numericLabel = regexp.MustCompile(`^(0[xX][0-9a-fA-F]*|[0-9]+)$`)

func Refused(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return true
	}

	ip = ip.Unmap()
	for _, prefix := range refusedPrefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func IsIPLiteral(host string) bool {
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}

	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return false
	}

	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	if _, err := netip.ParseAddr(strings.Replace(host, "%25", "%", 1)); err == nil {
		return true
	}

	labels := strings.Split(host, ".")
	return numericLabel.MatchString(labels[len(labels)-1])
}

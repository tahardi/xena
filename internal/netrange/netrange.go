package netrange

import (
	"net/netip"
	"regexp"
	"strings"
)

// The agent inside the VM is untrusted. Its only way out is the proxy, which should let it reach public hosts on the
// allowlist and nothing else. A hostname is not enough to enforce that: an allowlisted or approved name can resolve
// to any address, and an attacker who controls a name's DNS can point it at an internal address (DNS rebinding).
// So the proxy checks the resolved address too, and refuses every range below.
//
// These ranges hold things that are reachable from this desktop but must never be reachable from the agent:
//   - The desktop itself (loopback): the proxy, secrets store, prompt service, and anything else listening locally.
//   - The home network (private LAN, link-local, unique local, the VM bridge): the router's admin page, NAS,
//     printers, cameras, and other devices that often have weak or no login because they trust the local network.
//   - Cloud metadata (169.254.169.254): hands out machine credentials to anything that asks.
//   - Private overlay networks (CGNAT space, used by Tailscale): every other machine on the tailnet.
//   - Multicast and broadcast: reach every device on the network at once and can be used to discover targets.
//
// Services in these ranges usually assume any caller is already trusted, so one request from the agent could read
// secrets, change settings, or give it a foothold on another machine.
//
// Some IPv6 ranges (NAT64, Teredo, 6to4, IPv4-compatible) wrap an IPv4 address inside an IPv6 one. They are refused
// so a private IPv4 address cannot be smuggled past this check in IPv6 form. Reserved, discard, and benchmarking
// ranges have no legitimate public destination, so refusing them costs nothing.
var refusedPrefixes = []netip.Prefix{
	// "This network": 0.0.0.0 can mean the local host on some stacks.
	netip.MustParsePrefix("0.0.0.0/8"),
	// Private LAN addresses (RFC 1918).
	netip.MustParsePrefix("10.0.0.0/8"),
	// Carrier-grade NAT space; can reach the ISP's shared network or Tailscale peers.
	netip.MustParsePrefix("100.64.0.0/10"),
	// Loopback: the machine itself, where desktop services listen.
	netip.MustParsePrefix("127.0.0.0/8"),
	// Link-local, including the cloud metadata address 169.254.169.254.
	netip.MustParsePrefix("169.254.0.0/16"),
	// Private LAN addresses (RFC 1918); also Docker's default networks.
	netip.MustParsePrefix("172.16.0.0/12"),
	// IETF protocol assignments, such as NAT64 and DS-Lite gateways; never a public site.
	netip.MustParsePrefix("192.0.0.0/24"),
	// Private LAN addresses (RFC 1918): home router, LAN devices, and the VM bridge 192.168.150.0/24.
	netip.MustParsePrefix("192.168.0.0/16"),
	// Benchmarking range; some appliances and proxies use it internally.
	netip.MustParsePrefix("198.18.0.0/15"),
	// Multicast: reaches every listener on the LAN, such as mDNS and SSDP.
	netip.MustParsePrefix("224.0.0.0/4"),
	// Reserved and limited broadcast (255.255.255.255).
	netip.MustParsePrefix("240.0.0.0/4"),
	// IPv6 unspecified (::), loopback (::1), and IPv4-compatible forms that can hide a private IPv4.
	netip.MustParsePrefix("::/96"),
	// NAT64 well-known prefix: wraps any IPv4 address, private ones included.
	netip.MustParsePrefix("64:ff9b::/96"),
	// NAT64 local-use prefix: wraps IPv4 addresses on a local translator.
	netip.MustParsePrefix("64:ff9b:1::/48"),
	// Discard-only range; no legitimate destination.
	netip.MustParsePrefix("100::/64"),
	// Teredo tunnels: embed an IPv4 address and tunnel through it.
	netip.MustParsePrefix("2001::/32"),
	// 6to4 tunnels: embed an IPv4 address, which can be private.
	netip.MustParsePrefix("2002::/16"),
	// IPv6 unique local addresses, the IPv6 version of a private LAN.
	netip.MustParsePrefix("fc00::/7"),
	// IPv6 link-local: the router and devices on the same LAN segment.
	netip.MustParsePrefix("fe80::/10"),
	// Deprecated IPv6 site-local; some old networks still use it as private space.
	netip.MustParsePrefix("fec0::/10"),
	// IPv6 multicast: reaches every listener on the LAN.
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

package audit

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/tahardi/xena/internal/logs"
)

const localAddressField = 4

var errNoPort = errors.New("no port")

type Listeners struct {
	cmd     Commander
	allowed []string
}

func NewListeners(cmd Commander, allowed []string) *Listeners {
	return &Listeners{cmd: cmd, allowed: allowed}
}

func (*Listeners) Name() string {
	return "desktop-listeners"
}

func (l *Listeners) Run(ctx context.Context) ([]Finding, error) {
	out, err := l.cmd.Output(ctx, "ss", "-tulpnH")
	if err != nil {
		return nil, fmt.Errorf("reading listeners: %w", err)
	}

	var findings []Finding
	seen := map[string]bool{}
	for line := range strings.Lines(string(out)) {
		fields := strings.Fields(line)
		if len(fields) <= localAddressField {
			continue
		}

		host, iface, port, err := splitListener(fields[localAddressField])
		if err != nil {
			return nil, err
		}

		address := net.JoinHostPort(host, port)
		if iface != "" {
			address = net.JoinHostPort(host+"%"+iface, port)
		}
		if isLoopback(host) || slices.Contains(l.allowed, address) || l.interfaceAllowed(iface) {
			continue
		}

		message := "listening on " + fields[0] + " " + address
		if seen[message] {
			continue
		}
		seen[message] = true

		findings = append(findings, Finding{
			Severity: logs.SeverityHigh,
			Message:  message,
			Fix: "Stop the service or bind it to 127.0.0.1; if it must stay, add the address or its " +
				"%interface to extra_listeners in audit.yaml.",
		})
	}
	return findings, nil
}

func (l *Listeners) interfaceAllowed(iface string) bool {
	return iface != "" && slices.Contains(l.allowed, "%"+iface)
}

func splitListener(local string) (string, string, string, error) {
	hostPart, port, ok := strings.CutLast(local, ":")
	if !ok {
		return "", "", "", fmt.Errorf("parsing listener %q: %w", local, errNoPort)
	}

	host, iface, _ := strings.Cut(hostPart, "%")
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	return host, iface, port, nil
}

func isLoopback(host string) bool {
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}

package guard

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/tahardi/xena/internal/logs"
)

const (
	rebindHost   = "xena-guard-rebind.test"
	loopback     = "127.0.0.1"
	pollInterval = 250 * time.Millisecond

	maxVMLines      = 100
	maxVMLineLength = 300

	portSSH   = 22
	portDNS   = 53
	portHTTP  = 80
	portHTTPS = 443
	portCUPS  = 631
	portMDNS  = 5353
	portAlt   = 8080

	protoTCP = "TCP"
	protoUDP = "UDP"
)

var ErrRebindHost = errors.New("rebind host not configured: add 127.0.0.1 xena-guard-rebind.test to /etc/hosts")

type ProxyExpect struct {
	Host      string
	Port      int
	Decisions []string
	NoWindow  bool
}

type DropExpect struct {
	Dst   string
	Port  int
	Proto string
}

type NetConfig struct {
	BridgeAddr string
	ProxyPort  int
	Lookup     func(ctx context.Context, host string) ([]string, error)
}

type NetCase struct {
	caseName string
	script   string
	proxy    []ProxyExpect
	drops    []DropExpect
	precheck func(ctx context.Context) error
}

type verdict struct {
	evidence []string
	missing  string
	fatal    string
}

func NewNetCase(
	caseName string,
	script string,
	proxy []ProxyExpect,
	drops []DropExpect,
	precheck func(ctx context.Context) error,
) *NetCase {
	return &NetCase{caseName: caseName, script: script, proxy: proxy, drops: drops, precheck: precheck}
}

func (c *NetCase) Name() string {
	return c.caseName
}

func (c *NetCase) Targets() []string {
	targets := make([]string, 0, len(c.proxy)+len(c.drops))
	for _, want := range c.proxy {
		if !want.NoWindow {
			targets = append(targets, want.Host)
		}
	}

	for _, want := range c.drops {
		targets = append(targets, want.Dst)
	}

	return targets
}

func (c *NetCase) Run(ctx context.Context, env Env) Result {
	cut, err := env.Firewall.IsCut(ctx, env.VMAddr)
	if err != nil {
		return Fail(c.caseName, "checking cut: "+err.Error())
	}

	if cut {
		return Fail(c.caseName, "VM network is cut; run xena resume before xena guard")
	}

	if c.precheck != nil {
		if err := c.precheck(ctx); err != nil {
			return Fail(c.caseName, err.Error())
		}
	}

	start := env.Now().Truncate(time.Second)

	out, err := env.VM.Run(ctx, "guard", []string{c.script}, nil)

	evidence, connected := readVMOutput(out)
	if connected != "" {
		return Fail(c.caseName, "VM connected to "+connected, evidence...)
	}

	if err != nil {
		return Fail(c.caseName, "running VM script: "+err.Error(), evidence...)
	}

	return c.confirm(ctx, env, start, evidence)
}

func (c *NetCase) confirm(ctx context.Context, env Env, start time.Time, vmEvidence []string) Result {
	deadline := env.Now().Add(env.Settle)

	for {
		found := c.check(ctx, env, start)
		evidence := slices.Concat(vmEvidence, found.evidence)

		if found.fatal != "" {
			return Fail(c.caseName, found.fatal, evidence...)
		}

		if found.missing == "" {
			return Pass(c.caseName, evidence...)
		}

		if !env.Now().Before(deadline) {
			return Fail(c.caseName, found.missing, evidence...)
		}

		select {
		case <-ctx.Done():
			return Fail(c.caseName, found.missing, evidence...)
		case <-time.After(pollInterval):
		}
	}
}

func (c *NetCase) check(ctx context.Context, env Env, start time.Time) verdict {
	var result verdict

	if len(c.proxy) > 0 {
		entries, err := env.Proxy.Entries(start)
		if err != nil {
			return verdict{fatal: err.Error()}
		}

		c.checkProxy(entries, start, &result)
		if result.fatal != "" {
			return result
		}
	}

	if len(c.drops) > 0 {
		drops, err := env.Drops.Drops(ctx, start)
		if err != nil {
			return verdict{fatal: err.Error()}
		}

		c.checkDrops(drops, env.VMAddr, start, &result)
	}

	return result
}

func (c *NetCase) checkProxy(entries []logs.ProxyEntry, start time.Time, result *verdict) {
	for _, want := range c.proxy {
		target := fmt.Sprintf("%s:%d", want.Host, want.Port)
		met := false

		for _, entry := range entries {
			if entry.Time.Before(start) || strings.Trim(entry.Host, "[]") != want.Host || entry.Port != want.Port {
				continue
			}

			if strings.HasPrefix(entry.Decision, logs.DecisionAllow) {
				result.fatal = "proxy allowed " + target
				return
			}

			if !met && slices.Contains(want.Decisions, entry.Decision) {
				met = true
				line := fmt.Sprintf("proxy: %s %s at %s", target, entry.Decision, clock(entry.Time))
				result.evidence = append(result.evidence, line)
			}
		}

		if !met && result.missing == "" {
			result.missing = "no proxy log entry for " + target
		}
	}
}

func (c *NetCase) checkDrops(drops []Drop, vmAddr string, start time.Time, result *verdict) {
	for _, want := range c.drops {
		i := slices.IndexFunc(drops, func(d Drop) bool {
			return !d.Time.Before(start) && want.matches(d, vmAddr)
		})

		target := fmt.Sprintf("%s:%d/%s", want.Dst, want.Port, want.Proto)
		if i < 0 {
			if result.missing == "" {
				result.missing = "no firewall drop for " + target
			}

			continue
		}

		line := fmt.Sprintf("drop: %s -> %s at %s", drops[i].Src, target, clock(drops[i].Time))
		result.evidence = append(result.evidence, line)
	}
}

func (w DropExpect) matches(d Drop, vmAddr string) bool {
	if d.Dst != w.Dst || (w.Port != 0 && d.DstPort != w.Port) || (w.Proto != "" && d.Proto != w.Proto) {
		return false
	}

	return strings.Contains(w.Dst, ":") || d.Src == vmAddr
}

func readVMOutput(out []byte) ([]string, string) {
	evidence := []string{}
	connected := ""

	for line := range strings.Lines(string(out)) {
		line = cleanVMLine(line)
		if line == "" {
			continue
		}

		if len(evidence) < maxVMLines {
			evidence = append(evidence, "vm: "+line)
		}

		if target, ok := strings.CutPrefix(line, "connected "); ok && connected == "" {
			connected = target
		}
	}

	return evidence, connected
}

func cleanVMLine(line string) string {
	runes := []rune(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}

		return r
	}, line))

	return strings.TrimSpace(string(runes[:min(len(runes), maxVMLineLength)]))
}

func clock(t time.Time) string {
	return t.Local().Format(time.TimeOnly)
}

func NetworkCases(cfg NetConfig) []Case {
	bridge := cfg.BridgeAddr
	literal := []string{logs.DecisionRefuseIPLiteral}
	asked := []string{logs.DecisionDeny, logs.DecisionTimeout}
	oddPort := []string{logs.DecisionRefusePort, logs.DecisionDeny, logs.DecisionTimeout}

	rebind := func(ctx context.Context) error {
		answer, err := cfg.Lookup(ctx, rebindHost)
		if err != nil || !slices.Equal(answer, []string{loopback}) {
			return ErrRebindHost
		}

		return nil
	}

	return []Case{
		NewNetCase(
			"net-unlisted",
			"net-unlisted",
			[]ProxyExpect{{Host: "xena-guard-unlisted.invalid", Port: portHTTPS, Decisions: asked}},
			nil,
			nil,
		),
		NewNetCase(
			"net-ip-literal",
			"net-ip-literal",
			[]ProxyExpect{
				{Host: "198.51.100.7", Port: portHTTPS, Decisions: literal},
				{Host: "198.51.100.7", Port: portHTTP, Decisions: literal},
			},
			[]DropExpect{{Dst: "198.51.100.7", Port: portHTTPS, Proto: protoTCP}},
			nil,
		),
		NewNetCase(
			"net-lan",
			"net-lan",
			[]ProxyExpect{{Host: "10.0.0.10", Port: portHTTPS, Decisions: literal}},
			[]DropExpect{
				{Dst: "10.0.0.10", Port: portSSH, Proto: protoTCP},
				{Dst: "172.16.0.10", Port: portSSH, Proto: protoTCP},
				{Dst: "192.168.1.10", Port: portSSH, Proto: protoTCP},
			},
			nil,
		),
		NewNetCase(
			"net-desktop-ports",
			"net-desktop-ports",
			nil,
			[]DropExpect{
				{Dst: bridge, Port: portSSH, Proto: protoTCP},
				{Dst: bridge, Port: portHTTP, Proto: protoTCP},
				{Dst: bridge, Port: portHTTPS, Proto: protoTCP},
				{Dst: bridge, Port: portCUPS, Proto: protoTCP},
				{Dst: bridge, Port: portAlt, Proto: protoTCP},
				{Dst: bridge, Port: portMDNS, Proto: protoUDP},
			},
			nil,
		),
		NewNetCase(
			"net-router",
			"net-router",
			nil,
			[]DropExpect{
				{Dst: "192.168.0.1", Port: portHTTP, Proto: protoTCP},
				{Dst: "192.168.1.1", Port: portHTTP, Proto: protoTCP},
				{Dst: "10.0.0.1", Port: portHTTP, Proto: protoTCP},
			},
			nil,
		),
		NewNetCase(
			"net-metadata",
			"net-metadata",
			[]ProxyExpect{{Host: "169.254.169.254", Port: portHTTP, Decisions: literal}},
			[]DropExpect{{Dst: "169.254.169.254", Port: portHTTP, Proto: protoTCP}},
			nil,
		),
		NewNetCase(
			"net-ipv6",
			"net-ipv6",
			[]ProxyExpect{{Host: "2001:db8::7", Port: portHTTPS, Decisions: literal}},
			nil,
			nil,
		),
		NewNetCase(
			"net-odd-port",
			"net-odd-port",
			[]ProxyExpect{{Host: "github.com", Port: portSSH, Decisions: oddPort, NoWindow: true}},
			nil,
			nil,
		),
		NewNetCase(
			"net-dns-tunnel",
			"net-dns-tunnel",
			nil,
			[]DropExpect{
				{Dst: bridge, Port: portDNS, Proto: protoUDP},
				{Dst: "1.1.1.1", Port: portDNS, Proto: protoUDP},
				{Dst: "9.9.9.9", Port: portDNS, Proto: protoUDP},
				{Dst: "1.1.1.1", Port: portDNS, Proto: protoTCP},
			},
			nil,
		),
		NewNetCase(
			"net-rebind",
			"net-rebind",
			[]ProxyExpect{{Host: rebindHost, Port: portHTTPS, Decisions: []string{logs.DecisionRefuseAddress}}},
			nil,
			rebind,
		),
	}
}

package allowlist

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"

	"github.com/tahardi/xena/internal/config"
	"github.com/tahardi/xena/internal/netrange"
)

var (
	ErrInvalidHost           = errors.New("invalid host")
	ErrNonASCIIHost          = errors.New("non-ASCII host")
	ErrIPLiteralHost         = errors.New("IP literal host")
	ErrBroadWildcard         = errors.New("wildcard too broad")
	ErrSharedHostingWildcard = errors.New("wildcard on shared hosting domain")
	ErrInvalidPort           = errors.New("invalid port")
)

const (
	CurrentVersion = 1

	defaultPort    = 443
	maxPort        = 65535
	maxHostLength  = 253
	maxLabelLength = 63
	wildcardPrefix = "*."
	fileMode       = 0o640
)

type Rule struct {
	Host  string `yaml:"host"`
	Ports []int  `yaml:"ports,omitempty"`
}

type Allowlist struct {
	Version int    `yaml:"version"`
	Hosts   []Rule `yaml:"hosts"`
}

func Load(path string) (Allowlist, error) {
	list, err := config.Load[Allowlist](path, CurrentVersion, nil)
	if err != nil {
		return Allowlist{}, fmt.Errorf("loading allowlist %s: %w", path, err)
	}

	for i := range list.Hosts {
		if err := validateRule(&list.Hosts[i]); err != nil {
			return Allowlist{}, fmt.Errorf("loading allowlist %s: %w", path, err)
		}
	}
	return list, nil
}

func Normalize(host string) (string, error) {
	name := strings.TrimSuffix(host, ".")
	for i := range len(name) {
		if name[i] >= utf8.RuneSelf {
			return "", fmt.Errorf("normalizing host %q: %w", host, ErrNonASCIIHost)
		}
	}

	name = strings.ToLower(name)
	if netrange.IsIPLiteral(name) {
		return "", fmt.Errorf("normalizing host %q: %w", host, ErrIPLiteralHost)
	}

	if name == "" || len(name) > maxHostLength {
		return "", fmt.Errorf("normalizing host %q: %w", host, ErrInvalidHost)
	}
	for label := range strings.SplitSeq(name, ".") {
		if !validLabel(label) {
			return "", fmt.Errorf("normalizing host %q: %w", host, ErrInvalidHost)
		}
	}
	return name, nil
}

func (a Allowlist) Merge(overlay Allowlist) Allowlist {
	return Allowlist{Version: CurrentVersion, Hosts: slices.Concat(a.Hosts, overlay.Hosts)}
}

func (a Allowlist) Ports(host string) []int {
	name, err := Normalize(host)
	if err != nil {
		return nil
	}

	var ports []int
	for _, rule := range a.Hosts {
		domain, wildcard := strings.CutPrefix(rule.Host, wildcardPrefix)
		if (wildcard && strings.HasSuffix(name, "."+domain)) || (!wildcard && rule.Host == name) {
			ports = append(ports, rule.Ports...)
		}
	}

	slices.Sort(ports)
	return slices.Compact(ports)
}

func (a Allowlist) Allows(host string, port int) bool {
	if !validPort(port) {
		return false
	}
	return slices.Contains(a.Ports(host), port)
}

func (a Allowlist) Add(host string, port int) (Allowlist, error) {
	name, err := Normalize(host)
	if err != nil {
		return Allowlist{}, fmt.Errorf("adding host: %w", err)
	}

	if !validPort(port) {
		return Allowlist{}, fmt.Errorf("adding port %d for host %q: %w", port, name, ErrInvalidPort)
	}

	out := Allowlist{Version: a.Version, Hosts: slices.Clone(a.Hosts)}

	i := slices.IndexFunc(out.Hosts, func(rule Rule) bool { return rule.Host == name })
	if i < 0 {
		out.Hosts = append(out.Hosts, Rule{Host: name, Ports: []int{port}})
		return out, nil
	}

	ports := append(slices.Clone(out.Hosts[i].Ports), port)
	slices.Sort(ports)
	out.Hosts[i].Ports = slices.Compact(ports)
	return out, nil
}

func (a Allowlist) Save(path string) error {
	a.Version = CurrentVersion

	data, err := yaml.Marshal(a)
	if err != nil {
		return fmt.Errorf("saving allowlist %s: %w", path, err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".allowlist-*")
	if err != nil {
		return fmt.Errorf("saving allowlist %s: %w", path, err)
	}
	defer os.Remove(tmp.Name())

	if err := writeSynced(tmp, data); err != nil {
		return fmt.Errorf("saving allowlist %s: %w", path, err)
	}

	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("saving allowlist %s: %w", path, err)
	}
	return nil
}

func validateRule(rule *Rule) error {
	host, err := normalizeRuleHost(rule.Host)
	if err != nil {
		return fmt.Errorf("validating host %q: %w", rule.Host, err)
	}
	rule.Host = host

	if len(rule.Ports) == 0 {
		rule.Ports = []int{defaultPort}
	}

	for _, port := range rule.Ports {
		if !validPort(port) {
			return fmt.Errorf("validating port %d for host %q: %w", port, rule.Host, ErrInvalidPort)
		}
	}
	return nil
}

func normalizeRuleHost(host string) (string, error) {
	rest, wildcard := strings.CutPrefix(host, wildcardPrefix)
	if !wildcard {
		if strings.Contains(host, "*") {
			return "", ErrInvalidHost
		}
		return Normalize(host)
	}

	if strings.Contains(rest, "*") {
		return "", ErrInvalidHost
	}

	domain, err := Normalize(rest)
	if err != nil {
		return "", err
	}

	if !strings.Contains(domain, ".") {
		return "", ErrBroadWildcard
	}
	if isSharedHosting(domain) {
		return "", ErrSharedHostingWildcard
	}
	return wildcardPrefix + domain, nil
}

func validLabel(label string) bool {
	if label == "" || len(label) > maxLabelLength || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}

	for _, c := range []byte(label) {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

func validPort(port int) bool {
	return port >= 1 && port <= maxPort
}

func writeSynced(f *os.File, data []byte) error {
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("writing %s: %w", f.Name(), err)
	}

	if err := f.Chmod(fileMode); err != nil {
		f.Close()
		return fmt.Errorf("setting mode of %s: %w", f.Name(), err)
	}

	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("syncing %s: %w", f.Name(), err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("closing %s: %w", f.Name(), err)
	}
	return nil
}

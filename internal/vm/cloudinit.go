package vm

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"path"
	"regexp"
	"text/template"
	"time"

	"github.com/tahardi/xena"
	"github.com/tahardi/xena/internal/config"
)

const (
	cloudInitDir = "vm/cloud-init"
	filesDir     = cloudInitDir + "/files"
	guardGlob    = "vm/guard/*.sh"
	dateLayout   = "2006-01-02"
	rebuildDays  = 30
)

var (
	ErrInvalidSeedData = errors.New("invalid seed data")

	skKeyPattern         = regexp.MustCompile(`^sk-ssh-ed25519@openssh\.com [A-Za-z0-9+/=]+( [^\n]*)?$`)
	automationKeyPattern = regexp.MustCompile(`^ssh-ed25519 [A-Za-z0-9+/=]+( [^\n]*)?$`)
	versionPattern       = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	refPattern           = regexp.MustCompile(`^[0-9a-f]{40}$`)
	macPattern           = regexp.MustCompile(`^52:54:00(:[0-9a-f]{2}){3}$`)
	hostnamePattern      = regexp.MustCompile(`^[a-z0-9-]+$`)
	instanceIDPattern    = regexp.MustCompile(`^[A-Za-z0-9-]+$`)
	gitIdentityPattern   = regexp.MustCompile(`^[^\n\r"\\]*$`)
)

type SeedData struct {
	Hostname, InstanceID, MAC, VMAddress, BridgeAddress string
	Prefix, ProxyPort                                   int
	InteractiveKey, BackupKey, CarryKey, AutomationKey  string
	ClaudeCodeVersion, DotclaudeRef, GitName, GitEmail  string
	BuiltAt                                             time.Time
}

type Seed struct {
	UserData, MetaData, NetworkConfig []byte
}

func NewSeedData(
	c config.VM,
	interactiveKey, backupKey, carryKey, automationKey string,
	now time.Time,
) SeedData {
	return SeedData{
		Hostname:          c.Name,
		InstanceID:        fmt.Sprintf("%s-%d", c.Name, now.Unix()),
		MAC:               c.Network.MAC,
		VMAddress:         c.Network.VMAddress,
		BridgeAddress:     c.Network.BridgeAddress,
		Prefix:            c.Network.Prefix,
		ProxyPort:         c.ProxyPort,
		InteractiveKey:    interactiveKey,
		BackupKey:         backupKey,
		CarryKey:          carryKey,
		AutomationKey:     automationKey,
		ClaudeCodeVersion: c.ClaudeCodeVersion,
		DotclaudeRef:      c.DotclaudeRef,
		GitName:           c.Git.Name,
		GitEmail:          c.Git.Email,
		BuiltAt:           now,
	}
}

func (d SeedData) BuiltOn() string {
	return d.BuiltAt.Format(dateLayout)
}

func (d SeedData) RebuildBy() string {
	return d.BuiltAt.AddDate(0, 0, rebuildDays).Format(dateLayout)
}

func RenderSeed(d SeedData) (Seed, error) {
	if err := validateSeedData(d); err != nil {
		return Seed{}, fmt.Errorf("validating seed data: %w", err)
	}

	funcs := seedFuncs(d)

	userData, err := execute(cloudInitDir+"/user-data.tmpl", d, funcs)
	if err != nil {
		return Seed{}, fmt.Errorf("rendering seed: %w", err)
	}

	metaData, err := execute(cloudInitDir+"/meta-data.tmpl", d, funcs)
	if err != nil {
		return Seed{}, fmt.Errorf("rendering seed: %w", err)
	}

	networkConfig, err := execute(cloudInitDir+"/network-config.tmpl", d, funcs)
	if err != nil {
		return Seed{}, fmt.Errorf("rendering seed: %w", err)
	}

	return Seed{UserData: []byte(userData), MetaData: []byte(metaData), NetworkConfig: []byte(networkConfig)}, nil
}

func validateSeedData(d SeedData) error {
	checks := []struct {
		name  string
		valid bool
	}{
		{"interactive key", skKeyPattern.MatchString(d.InteractiveKey)},
		{"backup key", skKeyPattern.MatchString(d.BackupKey)},
		{"carry key", skKeyPattern.MatchString(d.CarryKey)},
		{"automation key", automationKeyPattern.MatchString(d.AutomationKey)},
		{"claude code version", versionPattern.MatchString(d.ClaudeCodeVersion)},
		{"dotclaude ref", refPattern.MatchString(d.DotclaudeRef)},
		{"vm address", isIPv4(d.VMAddress)},
		{"bridge address", isIPv4(d.BridgeAddress)},
		{"mac", macPattern.MatchString(d.MAC)},
		{"hostname", hostnamePattern.MatchString(d.Hostname)},
		{"instance id", instanceIDPattern.MatchString(d.InstanceID)},
		{"git name", gitIdentityPattern.MatchString(d.GitName)},
		{"git email", gitIdentityPattern.MatchString(d.GitEmail)},
	}
	for _, check := range checks {
		if !check.valid {
			return fmt.Errorf("%w: %s", ErrInvalidSeedData, check.name)
		}
	}

	return nil
}

func isIPv4(address string) bool {
	parsed, err := netip.ParseAddr(address)
	return err == nil && parsed.Is4()
}

func seedFuncs(d SeedData) template.FuncMap {
	return template.FuncMap{
		"render": func(name string) (string, error) {
			return execute(filesDir+"/"+name, d, nil)
		},
		"raw": func(file string) (string, error) {
			content, err := xena.VMFiles.ReadFile(file)
			if err != nil {
				return "", fmt.Errorf("reading embedded file: %w", err)
			}
			return string(content), nil
		},
		"guardFiles": guardFiles,
		"b64": func(s string) string {
			return base64.StdEncoding.EncodeToString([]byte(s))
		},
	}
}

func guardFiles() ([]string, error) {
	matches, err := fs.Glob(xena.VMFiles, guardGlob)
	if err != nil {
		return nil, fmt.Errorf("listing guard files: %w", err)
	}

	names := make([]string, 0, len(matches))
	for _, match := range matches {
		names = append(names, path.Base(match))
	}

	return names, nil
}

func execute(file string, d SeedData, funcs template.FuncMap) (string, error) {
	content, err := xena.VMFiles.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("reading template: %w", err)
	}

	tmpl, err := template.New(path.Base(file)).Funcs(funcs).Parse(string(content))
	if err != nil {
		return "", fmt.Errorf("parsing template %s: %w", file, err)
	}

	var out bytes.Buffer
	if err = tmpl.Execute(&out, d); err != nil {
		return "", fmt.Errorf("executing template %s: %w", file, err)
	}

	return out.String(), nil
}

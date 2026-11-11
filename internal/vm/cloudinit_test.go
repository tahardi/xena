package vm_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"github.com/tahardi/xena"
	"github.com/tahardi/xena/internal/config"
	"github.com/tahardi/xena/internal/vm"
)

const (
	skKeyType   = "sk-ssh-ed25519@openssh.com"
	plainType   = "ssh-ed25519"
	proxyURL    = "http://192.168.150.1:3128"
	testRef     = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	agentPath   = "/usr/local/lib/xena/xena-agent"
	guardDir    = "/usr/local/lib/xena/guard/"
	firstboot   = "/usr/local/lib/xena/firstboot.sh"
	fakeGitHub  = "ghs_FAKEsecret000000000000000000000000"
	fakeJira    = "ATATTFAKEsecret0000"
	fakeClaude  = "sk-ant-FAKEsecret0000"
	fakeDiskKey = "FAKE-DISK-KEY-0000"
)

type seedFile struct {
	Path        string `yaml:"path"`
	Owner       string `yaml:"owner"`
	Permissions string `yaml:"permissions"`
	Encoding    string `yaml:"encoding"`
	Content     string `yaml:"content"`
	Append      bool   `yaml:"append"`
	Defer       bool   `yaml:"defer"`
	decoded     string
}

func sshBlob(t *testing.T, keyType string) string {
	t.Helper()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	blob := appendSSHString(nil, []byte(keyType))
	blob = appendSSHString(blob, pub)
	if keyType == skKeyType {
		blob = appendSSHString(blob, []byte("ssh:"))
	}

	return base64.StdEncoding.EncodeToString(blob)
}

func appendSSHString(buf, value []byte) []byte {
	// Test key fields are a few dozen bytes, far below the uint32 limit.
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(value))) //nolint:gosec
	return append(buf, value...)
}

func validSeedData(t *testing.T) vm.SeedData {
	t.Helper()

	return vm.SeedData{
		Hostname:          "xena-dev",
		InstanceID:        "xena-dev-1792800000",
		MAC:               "52:54:00:78:65:6e",
		VMAddress:         "192.168.150.10",
		Prefix:            24,
		BridgeAddress:     "192.168.150.1",
		ProxyPort:         3128,
		InteractiveKey:    skKeyType + " " + sshBlob(t, skKeyType) + " taylor@desktop",
		BackupKey:         skKeyType + " " + sshBlob(t, skKeyType) + " taylor@backup",
		CarryKey:          skKeyType + " " + sshBlob(t, skKeyType) + " xena-5c-nfc-2",
		AutomationKey:     plainType + " " + sshBlob(t, plainType) + " xena-automation",
		ClaudeCodeVersion: "2.1.0",
		DotclaudeRef:      testRef,
		GitName:           "xena-dev[bot]",
		GitEmail:          "1+xena-dev[bot]@users.noreply.github.com",
		BuiltAt:           time.Date(2026, time.November, 2, 0, 0, 0, 0, time.UTC),
	}
}

func parseUserData(t *testing.T, seed vm.Seed) (map[string]any, map[string]seedFile) {
	t.Helper()

	first, _, found := strings.Cut(string(seed.UserData), "\n")
	require.True(t, found)
	require.Equal(t, "#cloud-config", first)

	var doc map[string]any
	require.NoError(t, yaml.Unmarshal(seed.UserData, &doc))

	var parsed struct {
		WriteFiles []seedFile `yaml:"write_files"`
	}
	require.NoError(t, yaml.Unmarshal(seed.UserData, &parsed))

	files := make(map[string]seedFile, len(parsed.WriteFiles))
	for _, file := range parsed.WriteFiles {
		require.Equal(t, "b64", file.Encoding, file.Path)

		decoded, err := base64.StdEncoding.DecodeString(file.Content)
		require.NoError(t, err, file.Path)

		file.decoded = string(decoded)
		files[file.Path] = file
	}

	return doc, files
}

func TestNewSeedData(t *testing.T) {
	// given
	c := config.VM{
		Name: "xena-dev",
		Network: config.VMNetwork{
			BridgeAddress: "192.168.150.1",
			VMAddress:     "192.168.150.10",
			Prefix:        24,
			MAC:           "52:54:00:78:65:6e",
		},
		ProxyPort:         3128,
		ClaudeCodeVersion: "2.1.0",
		DotclaudeRef:      testRef,
		Git:               config.VMGit{Name: "bot", Email: "bot@example.com"},
	}
	now := time.Date(2026, time.November, 2, 0, 0, 0, 0, time.UTC)

	// when
	got := vm.NewSeedData(c, "interactive", "backup", "carry", "automation", now)

	// then
	require.Equal(t, vm.SeedData{
		Hostname:          "xena-dev",
		InstanceID:        "xena-dev-" + strconv.FormatInt(now.Unix(), 10),
		MAC:               "52:54:00:78:65:6e",
		VMAddress:         "192.168.150.10",
		BridgeAddress:     "192.168.150.1",
		Prefix:            24,
		ProxyPort:         3128,
		InteractiveKey:    "interactive",
		BackupKey:         "backup",
		CarryKey:          "carry",
		AutomationKey:     "automation",
		ClaudeCodeVersion: "2.1.0",
		DotclaudeRef:      testRef,
		GitName:           "bot",
		GitEmail:          "bot@example.com",
		BuiltAt:           now,
	}, got)
}

func TestRenderSeed(t *testing.T) {
	// given
	seedData := validSeedData(t)
	seed, err := vm.RenderSeed(seedData)
	require.NoError(t, err)

	doc, files := parseUserData(t, seed)

	t.Run("happy path - user", func(t *testing.T) {
		// given
		users, ok := doc["users"].([]any)
		require.True(t, ok)

		// when
		user, ok := users[0].(map[string]any)

		// then
		require.True(t, ok)
		require.Len(t, users, 1)
		require.Equal(t, "dev", user["name"])
		require.NotContains(t, user, "sudo")
		require.NotContains(t, user, "groups")
		require.Equal(t, true, user["lock_passwd"])
		require.Equal(t, "/bin/bash", user["shell"])
		require.Equal(t, true, doc["disable_root"])
		require.Equal(t, false, doc["ssh_pwauth"])
		require.Equal(t, []any{"ed25519"}, doc["ssh_genkeytypes"])
	})

	t.Run("happy path - owners", func(t *testing.T) {
		// given
		devPrefix := "/home/dev/"

		// when
		got := files

		// then
		for filePath, file := range got {
			if strings.HasPrefix(filePath, devPrefix) {
				require.Equal(t, "dev:dev", file.Owner, filePath)
				require.True(t, file.Defer, filePath)
				continue
			}

			require.Equal(t, "root:root", file.Owner, filePath)
			require.False(t, file.Defer, filePath)
		}
	})

	t.Run("happy path - docker proxy", func(t *testing.T) {
		// given
		dropIn := "/home/dev/.config/systemd/user/docker.service.d/proxy.conf"

		// when
		file, found := files[dropIn]

		// then
		require.True(t, found)
		require.Contains(t, file.decoded, "Environment=HTTP_PROXY="+proxyURL)
		require.Contains(t, file.decoded, "Environment=HTTPS_PROXY="+proxyURL)
	})

	t.Run("happy path - empty git identity", func(t *testing.T) {
		// given
		data := validSeedData(t)
		data.GitName = ""
		data.GitEmail = ""

		// when
		_, renderErr := vm.RenderSeed(data)

		// then
		require.NoError(t, renderErr)
	})

	t.Run("happy path - sshd", func(t *testing.T) {
		// given
		want := []string{
			"PasswordAuthentication no",
			"KbdInteractiveAuthentication no",
			"PermitRootLogin no",
			"AuthenticationMethods publickey",
			"AllowUsers dev",
			"AuthorizedKeysFile /etc/ssh/authorized_keys/%u",
			"AllowAgentForwarding no",
			"AllowTcpForwarding no",
			"PubkeyAuthOptions touch-required",
			"X11Forwarding no",
			"PermitTunnel no",
			"PermitUserEnvironment no",
			"AllowStreamLocalForwarding remote",
			"StreamLocalBindUnlink yes",
			"HostKey /etc/ssh/ssh_host_ed25519_key",
			"ListenAddress 192.168.150.10",
		}

		// when
		lines := strings.Split(files["/etc/ssh/sshd_config.d/10-xena.conf"].decoded, "\n")

		// then
		for _, line := range want {
			require.Contains(t, lines, line)
		}
	})

	t.Run("happy path - keys", func(t *testing.T) {
		// given
		file := files["/etc/ssh/authorized_keys/dev"]

		// when
		lines := strings.Split(strings.TrimRight(file.decoded, "\n"), "\n")

		// then
		require.Equal(t, "root:root", file.Owner)
		require.Equal(t, "0644", file.Permissions)
		require.Equal(t, []string{
			seedData.InteractiveKey,
			seedData.BackupKey,
			seedData.CarryKey,
			`restrict,command="` + agentPath + `" ` + seedData.AutomationKey,
		}, lines)
	})

	t.Run("happy path - agent", func(t *testing.T) {
		// given
		want, readErr := xena.VMFiles.ReadFile("vm/agent/xena-agent")
		require.NoError(t, readErr)

		// when
		file := files[agentPath]

		// then
		require.Equal(t, "root:root", file.Owner)
		require.Equal(t, "0755", file.Permissions)
		require.Equal(t, string(want), file.decoded)
	})

	t.Run("happy path - guard scripts", func(t *testing.T) {
		// given
		scripts, globErr := fs.Glob(xena.VMFiles, "vm/guard/*.sh")
		require.NoError(t, globErr)

		// when
		_, keepFound := files[guardDir+".keep"]

		// then
		require.False(t, keepFound)
		require.NotEmpty(t, scripts)

		for _, script := range scripts {
			want, readErr := xena.VMFiles.ReadFile(script)
			require.NoError(t, readErr)

			file := files[guardDir+path.Base(script)]
			require.Equal(t, "root:root", file.Owner)
			require.Equal(t, "0755", file.Permissions)
			require.Equal(t, string(want), file.decoded)
		}
	})

	t.Run("happy path - proxy", func(t *testing.T) {
		// given
		file := files["/etc/environment"]

		// when
		apt, ok := doc["apt"].(map[string]any)

		// then
		require.True(t, ok)
		require.True(t, file.Append)
		for _, want := range []string{
			"HTTP_PROXY=" + proxyURL,
			"HTTPS_PROXY=" + proxyURL,
			"http_proxy=" + proxyURL,
			"https_proxy=" + proxyURL,
			"NO_PROXY=localhost,127.0.0.1",
			"NPM_CONFIG_GLOBALCONFIG=/etc/npmrc",
		} {
			require.Contains(t, file.decoded, want)
		}
		require.Equal(t, proxyURL, apt["http_proxy"])
		require.Equal(t, proxyURL, apt["https_proxy"])
	})

	t.Run("happy path - packages", func(t *testing.T) {
		// given
		want := []any{
			"qemu-guest-agent", "unattended-upgrades", "docker.io", "rootlesskit", "uidmap", "slirp4netns",
			"dbus-user-session", "socat", "tmux", "git", "gh", "jq", "sqlite3", "coreutils", "findutils", "nodejs",
			"npm",
		}

		// when
		got, ok := doc["packages"].([]any)
		upgrades := files["/etc/apt/apt.conf.d/20auto-upgrades"].decoded

		// then
		require.True(t, ok)
		require.Subset(t, got, want)
		require.Contains(t, upgrades, `APT::Periodic::Unattended-Upgrade "1";`)
		require.Contains(t, upgrades, `Unattended-Upgrade::Automatic-Reboot "false";`)
	})

	t.Run("happy path - package rules", func(t *testing.T) {
		// given
		pnpm := files["/home/dev/.config/pnpm/rc"]
		packageAge := files["/usr/local/lib/xena/package-age"]

		// when
		npmrc := files["/etc/npmrc"].decoded
		timer := files["/etc/systemd/system/xena-package-age.timer"].decoded

		// then
		require.Contains(t, npmrc, "ignore-scripts=true")
		require.Contains(t, npmrc, "min-release-age=7")
		require.Equal(t, "dev:dev", pnpm.Owner)
		require.True(t, pnpm.Defer)
		require.Contains(t, pnpm.decoded, "minimum-release-age=10080")
		require.Contains(t, files["/etc/pip.conf"].decoded, "only-binary = :all:")
		require.Equal(t, "root:root", packageAge.Owner)
		require.Equal(t, "0755", packageAge.Permissions)
		require.Contains(t, packageAge.decoded, "exclude-newer")
		require.Contains(t, packageAge.decoded, "7 days ago")
		require.Contains(t, packageAge.decoded, "no-build = true")
		require.Contains(t, timer, "OnCalendar=daily")
		require.Contains(t, timer, "Persistent=true")
		require.Contains(
			t,
			files["/etc/systemd/system/xena-package-age.service"].decoded,
			"ExecStart=/usr/local/lib/xena/package-age",
		)
	})

	t.Run("happy path - first boot", func(t *testing.T) {
		// given
		want := []string{
			"@anthropic-ai/claude-code@2.1.0",
			`checkout --detach "` + testRef + `"`,
			"install.sh vm",
			"apt-get purge -y snapd",
			"systemctl disable --now docker.service docker.socket containerd.service",
			"loginctl enable-linger dev",
		}

		// when
		script := files[firstboot]

		// then
		require.Equal(t, "0755", script.Permissions)
		for _, line := range want {
			require.Contains(t, script.decoded, line)
		}
		require.Equal(t, []any{[]any{firstboot}}, doc["runcmd"])
		require.Contains(t, script.decoded, "systemctl start qemu-guest-agent")

		home := strings.Index(script.decoded, "export HOME=/root")
		checkout := strings.Index(script.decoded, "checkout --detach")
		install := strings.Index(script.decoded, "install.sh vm")
		require.GreaterOrEqual(t, home, 0)
		require.Less(t, home, install)
		require.Less(t, checkout, install)
	})

	t.Run("happy path - git and gh", func(t *testing.T) {
		// given
		helperFile := "/home/dev/.config/xena/github-token"

		// when
		gitconfig := files["/etc/gitconfig"].decoded
		wrapper := files["/usr/local/bin/gh"].decoded

		// then
		require.Contains(t, gitconfig, "name = xena-dev[bot]")
		require.Contains(t, gitconfig, helperFile)
		require.Contains(t, wrapper, "exec /usr/bin/gh")
		require.Contains(t, wrapper, helperFile)
	})

	t.Run("happy path - rebuild reminder", func(t *testing.T) {
		// given
		file := files["/etc/update-motd.d/99-xena-rebuild"]

		// when
		text := file.decoded

		// then
		require.Equal(t, "0755", file.Permissions)
		require.Contains(t, text, "2026-11-02")
		require.Contains(t, text, "2026-12-02")
	})

	t.Run("happy path - network", func(t *testing.T) {
		// given
		var parsed struct {
			Network struct {
				Version   int `yaml:"version"`
				Ethernets map[string]map[string]any
			} `yaml:"network"`
		}

		// when
		unmarshalErr := yaml.Unmarshal(seed.NetworkConfig, &parsed)

		// then
		require.NoError(t, unmarshalErr)
		require.Equal(t, 2, parsed.Network.Version)
		require.Len(t, parsed.Network.Ethernets, 1)
		for _, ethernet := range parsed.Network.Ethernets {
			require.Equal(t, map[string]any{"macaddress": "52:54:00:78:65:6e"}, ethernet["match"])
			require.Equal(t, []any{"192.168.150.10/24"}, ethernet["addresses"])
			require.Equal(t, false, ethernet["dhcp4"])
			require.Equal(t, false, ethernet["dhcp6"])
			require.Equal(t, false, ethernet["accept-ra"])
			require.Equal(t, []any{}, ethernet["link-local"])
			require.Equal(t, []any{map[string]any{"to": "default", "via": "192.168.150.1"}}, ethernet["routes"])
			require.NotContains(t, ethernet, "nameservers")
		}
		require.Contains(t, files["/etc/sysctl.d/60-xena.conf"].decoded, "net.ipv6.conf.all.disable_ipv6 = 1")
		require.Contains(t, files["/etc/systemd/resolved.conf.d/xena.conf"].decoded, "LLMNR=no")
		require.Contains(t, files["/etc/systemd/resolved.conf.d/xena.conf"].decoded, "MulticastDNS=no")
	})

	t.Run("happy path - meta-data", func(t *testing.T) {
		// given
		want := "instance-id: xena-dev-1792800000\nlocal-hostname: xena-dev\n"

		// when
		got := string(seed.MetaData)

		// then
		require.Equal(t, want, got)
	})

	t.Run("happy path - no secrets", func(t *testing.T) {
		// given
		secretsDir := t.TempDir()
		t.Setenv("GITHUB_TOKEN", fakeGitHub)
		t.Setenv("JIRA_API_TOKEN", fakeJira)
		t.Setenv("ANTHROPIC_API_KEY", fakeClaude)
		t.Setenv("XENA_SECRETS_DIR", secretsDir)
		require.NoError(t, os.WriteFile(filepath.Join(secretsDir, "vm-disk-key.age"), []byte(fakeDiskKey), 0o600))

		// when
		rendered, renderErr := vm.RenderSeed(seedData)

		// then
		require.NoError(t, renderErr)

		_, renderedFiles := parseUserData(t, rendered)
		agent := renderedFiles[agentPath]
		userData := strings.ReplaceAll(string(rendered.UserData), agent.Content, "")
		outputs := []string{userData, string(rendered.MetaData), string(rendered.NetworkConfig)}
		for filePath, file := range renderedFiles {
			if filePath != agentPath {
				outputs = append(outputs, file.decoded)
			}
		}
		for _, secret := range []string{fakeGitHub, fakeJira, fakeClaude, fakeDiskKey} {
			require.NotContains(t, agent.decoded, secret)
		}

		patterns := []*regexp.Regexp{
			regexp.MustCompile(`ghs_`),
			regexp.MustCompile(`ghp_`),
			regexp.MustCompile(`github_pat_`),
			regexp.MustCompile(`ATATT`),
			regexp.MustCompile(`sk-ant-`),
			regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
			regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
		}
		for _, output := range outputs {
			for _, secret := range []string{fakeGitHub, fakeJira, fakeClaude, fakeDiskKey} {
				require.NotContains(t, output, secret)
			}
			for _, pattern := range patterns {
				require.False(t, pattern.MatchString(output), pattern.String())
			}
		}
	})

	sk := skKeyType + " " + sshBlob(t, skKeyType) + " x"
	plain := plainType + " " + sshBlob(t, plainType) + " x"
	errorTests := []struct {
		name   string
		mutate func(*vm.SeedData)
	}{
		{name: "error - interactive key not sk", mutate: func(d *vm.SeedData) { d.InteractiveKey = plain }},
		{name: "error - backup key not sk", mutate: func(d *vm.SeedData) { d.BackupKey = plain }},
		{name: "error - carry key not sk", mutate: func(d *vm.SeedData) { d.CarryKey = plain }},
		{name: "error - automation key is sk", mutate: func(d *vm.SeedData) { d.AutomationKey = sk }},
		{name: "error - interactive key has newline", mutate: func(d *vm.SeedData) { d.InteractiveKey = sk + "\n" + sk }},
		{name: "error - backup key has newline", mutate: func(d *vm.SeedData) { d.BackupKey = sk + "\n" + sk }},
		{name: "error - carry key has newline", mutate: func(d *vm.SeedData) { d.CarryKey = sk + "\n" + sk }},
		{name: "error - automation key has newline", mutate: func(d *vm.SeedData) { d.AutomationKey = plain + "\n" }},
		{name: "error - key has leading option", mutate: func(d *vm.SeedData) { d.AutomationKey = `command="x" ` + plain }},
		{name: "error - claude version latest", mutate: func(d *vm.SeedData) { d.ClaudeCodeVersion = "latest" }},
		{name: "error - dotclaude ref main", mutate: func(d *vm.SeedData) { d.DotclaudeRef = "main" }},
		{name: "error - vm address example", mutate: func(d *vm.SeedData) { d.VMAddress = "example" }},
		{name: "error - vm address ipv6", mutate: func(d *vm.SeedData) { d.VMAddress = "fd00::1" }},
		{name: "error - bridge address example", mutate: func(d *vm.SeedData) { d.BridgeAddress = "example" }},
		{name: "error - mac wrong prefix", mutate: func(d *vm.SeedData) { d.MAC = "aa:bb:cc:dd:ee:ff" }},
		{name: "error - empty carry key", mutate: func(d *vm.SeedData) { d.CarryKey = "" }},
		{name: "error - sk key has leading option", mutate: func(d *vm.SeedData) { d.BackupKey = `command="x" ` + sk }},
		{name: "error - short dotclaude ref", mutate: func(d *vm.SeedData) { d.DotclaudeRef = strings.Repeat("a", 39) }},
		{name: "error - hostname has newline", mutate: func(d *vm.SeedData) { d.Hostname = "xena\nx: y" }},
		{name: "error - instance id has newline", mutate: func(d *vm.SeedData) { d.InstanceID = "xena\nx: y" }},
		{name: "error - git name has newline", mutate: func(d *vm.SeedData) { d.GitName = "bot\n[credential]" }},
		{name: "error - git email has newline", mutate: func(d *vm.SeedData) { d.GitEmail = "a@b\n[credential]" }},
		{name: "error - prefix zero", mutate: func(d *vm.SeedData) { d.Prefix = 0 }},
		{name: "error - prefix above 32", mutate: func(d *vm.SeedData) { d.Prefix = 33 }},
		{name: "error - proxy port zero", mutate: func(d *vm.SeedData) { d.ProxyPort = 0 }},
		{name: "error - proxy port above 65535", mutate: func(d *vm.SeedData) { d.ProxyPort = 65536 }},
	}
	for _, tt := range errorTests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			data := validSeedData(t)
			tt.mutate(&data)

			// when
			_, renderErr := vm.RenderSeed(data)

			// then
			require.ErrorIs(t, renderErr, vm.ErrInvalidSeedData)
			require.ErrorContains(t, renderErr, "validating seed data: ")
		})
	}
}

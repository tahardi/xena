package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const profilePath = "../../deploy/apparmor/usr.local.bin.xena-tokend"

func TestTokendProfile(t *testing.T) {
	tests := []struct {
		name  string
		check func(t *testing.T, lines []string)
	}{
		{
			name: "happy path - attaches to the binary and to disconnected paths",
			check: func(t *testing.T, lines []string) {
				t.Helper()

				require.Contains(t, lines, "profile xena-tokend /usr/local/bin/xena-tokend flags=(attach_disconnected) {")
			},
		},
		{
			name: "happy path - runs children under the profile",
			check: func(t *testing.T, lines []string) {
				t.Helper()

				for _, want := range []string{
					"/usr/bin/age rix,",
					"owner @{HOME}/.cargo/bin/age-plugin-yubikey rix,",
					"/usr/bin/ssh rix,",
					"/usr/bin/notify-send rix,",
				} {
					require.Contains(t, lines, want)
				}
			},
		},
		{
			name: "happy path - writes only to dev null, its controlling terminal, the pcscd socket, and the tokend socket",
			check: func(t *testing.T, lines []string) {
				t.Helper()

				var writes []string
				for _, rule := range fileRules(lines) {
					if strings.ContainsAny(rulePerms(rule), "wakl") {
						writes = append(writes, rule)
					}
				}

				require.Equal(t, []string{
					"/dev/null rw,",
					"/dev/tty rw,",
					"/run/pcscd/pcscd.comm rw,",
					"/run/xena-proxy/tokend.sock rw,",
				}, writes)
			},
		},
		{
			name: "happy path - reads only the xena files the daemon uses",
			check: func(t *testing.T, lines []string) {
				t.Helper()

				var xenaRules []string
				for _, rule := range fileRules(lines) {
					if strings.Contains(rule, "/xena/") {
						xenaRules = append(xenaRules, rule)
					}
				}

				require.Equal(t, []string{
					"owner @{HOME}/.config/xena/github-app.yaml r,",
					"owner @{HOME}/.config/xena/age-identities.txt r,",
					"owner @{HOME}/.config/xena/automation_ed25519{,.pub,-cert.pub} r,",
					"owner @{HOME}/.config/xena/known_hosts r,",
					"owner @{HOME}/.local/share/xena/secrets/github-app-key.age r,",
					"/usr/local/share/xena/config/vm.yaml r,",
				}, xenaRules)
			},
		},
		{
			name: "happy path - runs no child outside the profile",
			check: func(t *testing.T, lines []string) {
				t.Helper()

				for _, rule := range fileRules(lines) {
					require.NotRegexp(t, `[uUpPcC]i?x`, rulePerms(rule), "child escapes the profile: %s", rule)
				}
			},
		},
		{
			name: "happy path - uses only inet, inet6, and unix networks",
			check: func(t *testing.T, lines []string) {
				t.Helper()

				var networks []string
				for _, line := range lines {
					if strings.HasPrefix(line, "network") {
						networks = append(networks, line)
					}
				}

				require.Equal(t, []string{
					"network inet stream,",
					"network inet6 stream,",
					"network inet dgram,",
					"network inet6 dgram,",
					"network unix stream,",
				}, networks)
			},
		},
		{
			name: "happy path - grants no capabilities",
			check: func(t *testing.T, lines []string) {
				t.Helper()

				for _, line := range lines {
					require.False(t, strings.HasPrefix(line, "capability"), "capability rule: %s", line)
				}
			},
		},
		{
			name: "happy path - reads cgroup limits for the go runtime",
			check: func(t *testing.T, lines []string) {
				t.Helper()

				for _, want := range []string{
					"@{PROC}/@{pid}/cgroup r,",
					"@{PROC}/@{pid}/mountinfo r,",
					"@{sys}/fs/cgroup/{,**/}cpu.max r,",
				} {
					require.Contains(t, lines, want)
				}
			},
		},
		{
			name: "happy path - sends desktop notifications",
			check: func(t *testing.T, lines []string) {
				t.Helper()

				for _, want := range []string{
					"dbus send",
					"bus=session",
					"path=/org/freedesktop/Notifications",
					"interface=org.freedesktop.Notifications",
					"member={GetCapabilities,GetServerInformation,Notify}",
					"peer=(label=unconfined),",
				} {
					require.Contains(t, lines, want)
				}

				for _, line := range lines {
					require.NotContains(t, line, "peer=(name=")
				}
			},
		},
		{
			name: "happy path - has one dbus rule and it only sends",
			check: func(t *testing.T, lines []string) {
				t.Helper()

				var rules []string
				for _, line := range lines {
					if strings.HasPrefix(line, "dbus") {
						rules = append(rules, line)
					}
				}

				require.Equal(t, []string{"dbus send"}, rules)
			},
		},
		{
			name: "happy path - leaves out the consoles abstraction",
			check: func(t *testing.T, lines []string) {
				t.Helper()

				require.NotContains(t, lines, "include <abstractions/consoles>")
			},
		},
		{
			name: "happy path - has no deny rules",
			check: func(t *testing.T, lines []string) {
				t.Helper()

				for _, line := range lines {
					require.False(t, strings.HasPrefix(line, "deny"), "deny rule hides denials: %s", line)
				}
			},
		},
		{
			name: "happy path - compiles",
			check: func(t *testing.T, _ []string) {
				t.Helper()

				if _, err := exec.LookPath("apparmor_parser"); err != nil {
					t.Skip("apparmor_parser not installed")
				}

				cmd := exec.CommandContext(
					t.Context(),
					"apparmor_parser",
					"-Q",
					"-K",
					"-I",
					"/etc/apparmor.d",
					profilePath,
				)

				out, err := cmd.CombinedOutput()
				require.NoError(t, err, string(out))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// given
			profile, err := os.ReadFile(profilePath)
			require.NoError(t, err)

			// when
			var lines []string
			for line := range strings.SplitSeq(string(profile), "\n") {
				lines = append(lines, strings.TrimSpace(line))
			}

			// then
			tt.check(t, lines)
		})
	}
}

func fileRules(lines []string) []string {
	var rules []string
	for _, line := range lines {
		path := line
		for _, qualifier := range []string{"audit ", "allow ", "owner "} {
			path = strings.TrimPrefix(path, qualifier)
		}

		isPath := strings.HasPrefix(path, "/") || strings.HasPrefix(path, "@{")
		if isPath && strings.HasSuffix(line, ",") {
			rules = append(rules, line)
		}
	}

	return rules
}

func rulePerms(rule string) string {
	fields := strings.Fields(strings.TrimSuffix(rule, ","))

	return fields[len(fields)-1]
}

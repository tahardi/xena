package config

import (
	"os"
	"path/filepath"
)

func ConfigDir() string {
	return fromEnv("XENA_CONFIG_DIR", homePath(".config", "xena"))
}

func StateDir() string {
	return fromEnv("XENA_STATE_DIR", homePath(".local", "state", "xena"))
}

func SecretsDir() string {
	return fromEnv("XENA_SECRETS_DIR", homePath(".local", "share", "xena", "secrets"))
}

func ProxyStateDir() string {
	return fromEnv("XENA_PROXY_STATE_DIR", "/var/lib/xena-proxy")
}

func WatchStateDir() string {
	return fromEnv("XENA_WATCH_STATE_DIR", "/var/lib/xena-watch")
}

func RepoConfigDir() string {
	return fromEnv("XENA_REPO_CONFIG_DIR", "/usr/local/share/xena/config")
}

func VMDir() string {
	return fromEnv("XENA_VM_DIR", "/var/lib/xena-vm")
}

func GatewayLogDir() string {
	return fromEnv("XENA_GATEWAY_LOG_DIR", "/var/lib/xena-desktop")
}

func GuardRunDir() string {
	return fromEnv("XENA_GUARD_RUN_DIR", "/run/xena-guard")
}

func ExposeStateDir() string {
	return fromEnv("XENA_EXPOSE_STATE_DIR", "/var/lib/xena-expose")
}

func PromptSocket() string {
	return fromEnv("XENA_PROMPT_SOCKET", "/run/xena-proxy/prompt.sock")
}

func CutMarker() string {
	return fromEnv("XENA_CUT_MARKER", "/var/lib/xena/cut")
}

func fromEnv(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func homePath(parts ...string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/nonexistent"
	}
	return filepath.Join(append([]string{home}, parts...)...)
}

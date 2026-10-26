package config

import "fmt"

const VMVersion = 1

type VM struct {
	Version              int       `yaml:"version"`
	Name                 string    `yaml:"name"`
	Image                VMImage   `yaml:"image"`
	CPUs                 int       `yaml:"cpus"`
	MemoryMiB            int       `yaml:"memory_mib"`
	DiskGiB              int       `yaml:"disk_gib"`
	Network              VMNetwork `yaml:"network"`
	ProxyPort            int       `yaml:"proxy_port"`
	Grant                VMGrant   `yaml:"grant"`
	Expose               VMExpose  `yaml:"expose"`
	PromptTimeoutSeconds int       `yaml:"prompt_timeout_seconds"`
	ClaudeCodeVersion    string    `yaml:"claude_code_version"`
	DotclaudeRef         string    `yaml:"dotclaude_ref"`
	Repos                []string  `yaml:"repos"`
	Git                  VMGit     `yaml:"git"`
}

type VMImage struct {
	URL    string `yaml:"url"`
	SHA256 string `yaml:"sha256"`
}

type VMNetwork struct {
	Bridge        string `yaml:"bridge"`
	BridgeAddress string `yaml:"bridge_address"`
	VMAddress     string `yaml:"vm_address"`
	Prefix        int    `yaml:"prefix"`
	MAC           string `yaml:"mac"`
}

type VMGrant struct {
	DefaultHours int `yaml:"default_hours"`
	MaxHours     int `yaml:"max_hours"`
}

type VMExpose struct {
	IPhoneAddress string `yaml:"iphone_address"`
	DefaultHours  int    `yaml:"default_hours"`
	MaxHours      int    `yaml:"max_hours"`
}

type VMGit struct {
	Name  string `yaml:"name"`
	Email string `yaml:"email"`
}

func LoadVM(path string) (VM, error) {
	vm, err := Load[VM](path, VMVersion, nil)
	if err != nil {
		return VM{}, fmt.Errorf("loading vm config: %w", err)
	}
	return vm, nil
}

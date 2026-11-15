package vm

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"text/template"
	"time"

	"github.com/tahardi/xena/internal/config"
)

const (
	stopAttempts  = 60
	readyAttempts = 120
	libvirtURI    = "qemu:///system"
	diskKeyName   = "vm-disk-key"
	stateRunning  = "running"
	stateShutOff  = "shut off"
	stateUndef    = "undefined"
	networkName   = "xena"
	seedDevice    = "sda"
	bootFinished  = "/var/lib/cloud/instance/boot-finished"
	cloudResult   = "/run/cloud-init/result.json"
	diskKeyBytes  = 32
	privateDir    = 0o700
	privateFile   = 0o600
	imagePrefix   = 12

	domainXML = `<domain type='kvm'>
  <name>{{x .Name}}</name>
  <memory unit='MiB'>{{.MemoryMiB}}</memory>
  <vcpu>{{.CPUs}}</vcpu>
  <os>
    <type arch='x86_64' machine='q35'>hvm</type>
    <boot dev='hd'/>
  </os>
  <features>
    <acpi/>
    <apic/>
  </features>
  <cpu mode='host-passthrough'/>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='{{x .Disk}}'>
        <encryption format='luks'>
          <secret type='passphrase' usage='{{x .Disk}}'/>
        </encryption>
      </source>
      <target dev='vda' bus='virtio'/>
    </disk>
    <disk type='file' device='cdrom'>
      <driver name='qemu' type='raw'/>
      <source file='{{x .Seed}}'/>
      <target dev='sda' bus='sata'/>
      <readonly/>
    </disk>
    <interface type='network'>
      <source network='{{x .Network}}'/>
      <mac address='{{x .MAC}}'/>
      <model type='virtio'/>
    </interface>
    <channel type='unix'>
      <target type='virtio' name='org.qemu.guest_agent.0'/>
    </channel>
    <serial type='pty'>
      <target port='0'/>
    </serial>
    <console type='pty'>
      <target type='serial' port='0'/>
    </console>
    <rng model='virtio'>
      <backend model='random'>/dev/urandom</backend>
    </rng>
  </devices>
</domain>
`

	secretXML = `<secret ephemeral='yes' private='yes'>` +
		`<usage type='volume'><volume>{{x .}}</volume></usage></secret>`
)

var (
	ErrRunning   = errors.New("vm is running")
	ErrExists    = errors.New("vm exists")
	ErrTimeout   = errors.New("timed out")
	ErrCut       = errors.New("vm network is cut")
	ErrUndefined = errors.New("vm is not defined")
	ErrCloudInit = errors.New("cloud-init failed")

	errInvalidImageSHA = errors.New("invalid image sha256")
	errSecretUUID      = errors.New("no secret uuid in virsh output")

	secretUUIDPattern = regexp.MustCompile(`^Secret ([0-9a-f-]{36}) created`)
	xmlFuncs          = template.FuncMap{"x": xmlText}
	domainTemplate    = template.Must(template.New("domain").Funcs(xmlFuncs).Parse(domainXML))
	secretTemplate    = template.Must(template.New("secret").Funcs(xmlFuncs).Parse(secretXML))
)

type domainData struct {
	Name, Disk, Seed, Network, MAC string
	MemoryMiB, CPUs                int
}

type execFunc func(ctx context.Context, stdin io.Reader, name string, args ...string) ([]byte, error)

type SecretStore interface {
	Get(ctx context.Context, name string) ([]byte, error)
	Put(name string, value io.Reader) error
}

type TokenRotator interface {
	RotateVMTokens(ctx context.Context) error
}

type Machine struct {
	config         config.VM
	dir            string
	knownHosts     string
	interactiveKey string
	backupKey      string
	carryKey       string
	secrets        SecretStore
	rotator        TokenRotator
	pollEvery      time.Duration
	run            execFunc
}

func NewMachine(
	cfg config.VM,
	dir, knownHosts string,
	interactiveKey, backupKey, carryKey string,
	secrets SecretStore,
	rotator TokenRotator,
	pollEvery time.Duration,
) *Machine {
	return &Machine{
		config:         cfg,
		dir:            dir,
		knownHosts:     knownHosts,
		interactiveKey: interactiveKey,
		backupKey:      backupKey,
		carryKey:       carryKey,
		secrets:        secrets,
		rotator:        rotator,
		pollEvery:      pollEvery,
		run:            runCommand,
	}
}

func (m *Machine) State(ctx context.Context) (string, error) {
	out, err := m.virsh(ctx, nil, "list", "--all", "--name")
	if err != nil {
		return "", fmt.Errorf("listing domains: %w", err)
	}

	if !slices.Contains(strings.Fields(string(out)), m.config.Name) {
		return stateUndef, nil
	}

	out, err = m.virsh(ctx, nil, "domstate", m.config.Name)
	if err != nil {
		return "", fmt.Errorf("reading vm state: %w", err)
	}

	return strings.TrimSpace(string(out)), nil
}

func (m *Machine) SeedPath() string {
	return filepath.Join(m.dir, m.config.Name+"-seed.iso")
}

func (m *Machine) Define(ctx context.Context) error {
	var xml bytes.Buffer
	err := domainTemplate.Execute(&xml, domainData{
		Name:      m.config.Name,
		Disk:      m.DiskPath(),
		Seed:      m.SeedPath(),
		Network:   networkName,
		MAC:       m.config.Network.MAC,
		MemoryMiB: m.config.MemoryMiB,
		CPUs:      m.config.CPUs,
	})
	if err != nil {
		return fmt.Errorf("rendering domain: %w", err)
	}

	if _, err = m.virsh(ctx, &xml, "define", "/dev/stdin"); err != nil {
		return fmt.Errorf("defining vm: %w", err)
	}

	return nil
}

func (m *Machine) Start(ctx context.Context) error {
	if _, err := os.Stat(config.CutMarker()); err == nil {
		return fmt.Errorf("starting vm: %w", ErrCut)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("checking cut marker: %w", err)
	}

	state, err := m.State(ctx)
	if err != nil {
		return fmt.Errorf("starting vm: %w", err)
	}

	switch state {
	case stateRunning:
		return nil
	case stateUndef:
		return fmt.Errorf("starting vm: %w", ErrUndefined)
	}

	key, err := m.secrets.Get(ctx, diskKeyName)
	if err != nil {
		return fmt.Errorf("reading disk key: %w", err)
	}
	defer clear(key)

	uuid, err := m.defineSecret(ctx)
	if err != nil {
		return fmt.Errorf("defining disk secret: %w", err)
	}

	err = m.startWithSecret(ctx, uuid, key)

	if _, undefineErr := m.virsh(ctx, nil, "secret-undefine", uuid); undefineErr != nil {
		return errors.Join(err, fmt.Errorf("undefining disk secret: %w", undefineErr))
	}

	return err
}

func (m *Machine) Stop(ctx context.Context) error {
	state, err := m.State(ctx)
	if err != nil {
		return fmt.Errorf("stopping vm: %w", err)
	}

	if state == stateShutOff || state == stateUndef {
		return nil
	}

	if _, err = m.virsh(ctx, nil, "shutdown", m.config.Name); err != nil {
		return fmt.Errorf("stopping vm: %w", err)
	}

	for range stopAttempts {
		out, err := m.virsh(ctx, nil, "domstate", m.config.Name)
		if err != nil {
			return fmt.Errorf("reading vm state: %w", err)
		}

		if strings.TrimSpace(string(out)) == stateShutOff {
			return nil
		}

		if err = m.sleep(ctx); err != nil {
			return fmt.Errorf("stopping vm: %w", err)
		}
	}

	if _, err = m.virsh(ctx, nil, "destroy", m.config.Name); err != nil {
		return fmt.Errorf("forcing vm off: %w", err)
	}

	return nil
}

func (m *Machine) Destroy(ctx context.Context) error {
	state, err := m.State(ctx)
	if err != nil {
		return fmt.Errorf("destroying vm: %w", err)
	}

	if state != stateUndef {
		if state != stateShutOff {
			if _, err = m.virsh(ctx, nil, "destroy", m.config.Name); err != nil {
				return fmt.Errorf("destroying vm: %w", err)
			}
		}

		if _, err = m.virsh(ctx, nil, "undefine", m.config.Name); err != nil {
			return fmt.Errorf("undefining vm: %w", err)
		}
	}

	for _, file := range []string{m.DiskPath(), m.SeedPath(), m.knownHosts} {
		if err = removeIfExists(file); err != nil {
			return fmt.Errorf("removing %s: %w", file, err)
		}
	}

	return nil
}

func (m *Machine) WaitReady(ctx context.Context) error {
	err := m.poll(ctx, func() error {
		return m.agent(ctx, "guest-ping", nil, nil)
	})
	if err != nil {
		return fmt.Errorf("waiting for guest agent: %w", err)
	}

	err = m.poll(ctx, func() error {
		handle, err := m.openGuestFile(ctx, bootFinished)
		if err != nil {
			return err
		}

		return m.closeGuestFile(ctx, handle)
	})
	if err != nil {
		return fmt.Errorf("waiting for cloud-init: %w", err)
	}

	var result []byte
	err = m.poll(ctx, func() error {
		result, err = m.readGuestFile(ctx, cloudResult)
		return err
	})
	if err != nil {
		return fmt.Errorf("waiting for cloud-init result: %w", err)
	}

	if err = checkCloudInit(result); err != nil {
		return fmt.Errorf("waiting for vm: %w", err)
	}

	return nil
}

func checkCloudInit(result []byte) error {
	var parsed struct {
		V1 *struct {
			Errors []json.RawMessage `json:"errors"`
		} `json:"v1"`
	}
	if err := json.Unmarshal(result, &parsed); err != nil {
		return fmt.Errorf("parsing cloud-init result: %w", err)
	}

	if parsed.V1 == nil || len(parsed.V1.Errors) > 0 {
		return ErrCloudInit
	}

	return nil
}

func (m *Machine) EjectSeed(ctx context.Context) error {
	_, err := m.virsh(ctx, nil, "change-media", m.config.Name, seedDevice, "--eject", "--live", "--config")
	if err != nil {
		return fmt.Errorf("ejecting seed: %w", err)
	}

	if err = removeIfExists(m.SeedPath()); err != nil {
		return fmt.Errorf("removing seed: %w", err)
	}

	return nil
}

func (m *Machine) Build(ctx context.Context, client *http.Client, now time.Time) error {
	state, err := m.State(ctx)
	if err != nil {
		return fmt.Errorf("building vm: %w", err)
	}

	if state != stateUndef {
		return fmt.Errorf("building vm: %w", ErrExists)
	}

	if _, err = os.Stat(m.dir); err != nil {
		return fmt.Errorf("checking vm dir: %w", err)
	}

	base, err := m.fetchBaseImage(ctx, client)
	if err != nil {
		return fmt.Errorf("fetching image: %w", err)
	}

	automationKey, err := m.makeAutomationKey(ctx)
	if err != nil {
		return fmt.Errorf("making automation key: %w", err)
	}

	if err = m.makeSeedISO(ctx, automationKey, now); err != nil {
		return fmt.Errorf("making seed iso: %w", err)
	}

	if err = m.createEncryptedDisk(ctx, base); err != nil {
		return err
	}

	if err = m.Define(ctx); err != nil {
		return err
	}

	if err = m.Start(ctx); err != nil {
		return err
	}

	if err = m.WaitReady(ctx); err != nil {
		return err
	}

	if err = m.PinHostKey(ctx); err != nil {
		return err
	}

	if err = m.EjectSeed(ctx); err != nil {
		return err
	}

	if err = recordBuildTime(now); err != nil {
		return fmt.Errorf("recording build time: %w", err)
	}

	return nil
}

func (m *Machine) defineSecret(ctx context.Context) (string, error) {
	var xml bytes.Buffer
	if err := secretTemplate.Execute(&xml, m.DiskPath()); err != nil {
		return "", err
	}

	out, err := m.virsh(ctx, &xml, "secret-define", "/dev/stdin")
	if err != nil {
		return "", err
	}

	match := secretUUIDPattern.FindSubmatch(out)
	if match == nil {
		return "", errSecretUUID
	}

	return string(match[1]), nil
}

func (m *Machine) startWithSecret(ctx context.Context, uuid string, key []byte) error {
	_, err := m.virsh(
		ctx,
		bytes.NewReader(key),
		"secret-set-value",
		"--secret", uuid,
		"--file", "/dev/stdin",
		"--plain",
	)
	if err != nil {
		return fmt.Errorf("setting disk secret: %w", err)
	}

	if _, err = m.virsh(ctx, nil, "start", m.config.Name); err != nil {
		return fmt.Errorf("starting vm: %w", err)
	}

	return nil
}

func (m *Machine) fetchBaseImage(ctx context.Context, client *http.Client) (string, error) {
	sum := m.config.Image.SHA256
	if len(sum) < imagePrefix {
		return "", errInvalidImageSHA
	}

	images := filepath.Join(m.dir, "images")
	if err := os.MkdirAll(images, privateDir); err != nil {
		return "", err
	}

	base := filepath.Join(images, sum[:imagePrefix]+".img")
	if err := FetchImage(ctx, client, m.config.Image.URL, sum, base); err != nil {
		return "", err
	}

	return base, nil
}

func (m *Machine) makeAutomationKey(ctx context.Context) (string, error) {
	path := filepath.Join(config.ConfigDir(), "automation_ed25519")

	old, err := filepath.Glob(path + "*")
	if err != nil {
		return "", err
	}

	for _, file := range old {
		if err = os.Remove(file); err != nil {
			return "", err
		}
	}

	_, err = m.run(ctx, nil, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "xena-automation", "-f", path)
	if err != nil {
		return "", err
	}

	return readPublicKey(path + ".pub")
}

func (m *Machine) makeSeedISO(ctx context.Context, automationKey string, now time.Time) error {
	paths := [...]string{m.interactiveKey, m.backupKey, m.carryKey}
	var keys [len(paths)]string
	for i, path := range paths {
		key, err := readPublicKey(path)
		if err != nil {
			return err
		}
		keys[i] = key
	}

	seed, err := RenderSeed(NewSeedData(m.config, keys[0], keys[1], keys[2], automationKey, now))
	if err != nil {
		return err
	}

	tmp, err := os.MkdirTemp("", "xena-seed-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	files := map[string][]byte{
		"user-data":      seed.UserData,
		"meta-data":      seed.MetaData,
		"network-config": seed.NetworkConfig,
	}
	for name, content := range files {
		if err = os.WriteFile(filepath.Join(tmp, name), content, privateFile); err != nil {
			return err
		}
	}

	_, err = m.run(
		ctx,
		nil,
		"cloud-localds",
		"--network-config="+filepath.Join(tmp, "network-config"),
		m.SeedPath(),
		filepath.Join(tmp, "user-data"),
		filepath.Join(tmp, "meta-data"),
	)

	return err
}

func (m *Machine) createEncryptedDisk(ctx context.Context, base string) error {
	raw := make([]byte, diskKeyBytes)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Errorf("generating disk key: %w", err)
	}

	key := make([]byte, hex.EncodedLen(len(raw)))
	hex.Encode(key, raw)
	clear(raw)
	defer clear(key)

	if err := m.secrets.Put(diskKeyName, bytes.NewReader(key)); err != nil {
		return fmt.Errorf("storing disk key: %w", err)
	}

	return m.CreateDisk(ctx, base, key)
}

func recordBuildTime(now time.Time) error {
	dir := config.StateDir()
	if err := os.MkdirAll(dir, privateDir); err != nil {
		return err
	}

	return config.WriteAtomic(filepath.Join(dir, "vm-built-at"), []byte(now.Format(time.RFC3339)+"\n"), privateFile)
}

func readPublicKey(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(content)), nil
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	return nil
}

func (m *Machine) poll(ctx context.Context, attempt func() error) error {
	for range readyAttempts {
		if attempt() == nil {
			return nil
		}

		if err := m.sleep(ctx); err != nil {
			return err
		}
	}

	return ErrTimeout
}

func (m *Machine) sleep(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(m.pollEvery):
		return nil
	}
}

func xmlText(s string) (string, error) {
	var out strings.Builder
	if err := xml.EscapeText(&out, []byte(s)); err != nil {
		return "", err
	}

	return out.String(), nil
}

func (m *Machine) virsh(ctx context.Context, stdin io.Reader, args ...string) ([]byte, error) {
	return m.run(ctx, stdin, "virsh", append([]string{"-c", libvirtURI}, args...)...)
}

func runCommand(ctx context.Context, stdin io.Reader, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = stdin
	cmd.Stderr = io.Discard

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("running %s: %w", name, err)
	}

	return out, nil
}

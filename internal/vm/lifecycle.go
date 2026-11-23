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
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/tahardi/xena/internal/config"
)

const (
	stopAttempts      = 60
	readyAttempts     = 120
	firstBootAttempts = 360
	diskKeyName       = "vm-disk-key"
	StateRunning      = "running"
	stateShutOff      = "shut off"
	stateUndef        = "undefined"
	networkName       = "xena"
	seedDevice        = "sda"
	bootFinished      = "/var/lib/cloud/instance/boot-finished"
	cloudResult       = "/run/cloud-init/result.json"
	cloudOutput       = "/var/log/cloud-init-output.log"
	nologinPath       = "/run/nologin"
	diskKeyBytes      = 32
	privateDir        = 0o700
	privateFile       = 0o600
	imagesDirMode     = 0o711
	imagePrefix       = 12
	stderrLimit       = 200
	progressEvery     = 30 * time.Second

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
{{- if .Encrypted}}
        <encryption format='luks'>
          <secret type='passphrase' usage='{{x .Disk}}'/>
        </encryption>
{{- end}}
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

	ejectXML = `<disk type='file' device='cdrom'><driver name='qemu' type='raw'/>` +
		`<target dev='{{x .}}' bus='sata'/><readonly/></disk>`
)

var (
	ErrRunning    = errors.New("vm is running")
	ErrNotRunning = errors.New("vm is not running")
	ErrExists     = errors.New("vm exists")
	ErrTimeout    = errors.New("timed out")
	ErrCut        = errors.New("vm network is cut")
	ErrUndefined  = errors.New("vm is not defined")
	ErrCloudInit  = errors.New("cloud-init failed")

	errInvalidImageSHA = errors.New("invalid image sha256")
	errBooting         = errors.New("vm is still booting")

	xmlFuncs       = template.FuncMap{"x": xmlText}
	domainTemplate = template.Must(template.New("domain").Funcs(xmlFuncs).Parse(domainXML))
	secretTemplate = template.Must(template.New("secret").Funcs(xmlFuncs).Parse(secretXML))
	ejectTemplate  = template.Must(template.New("eject").Funcs(xmlFuncs).Parse(ejectXML))
)

type domainData struct {
	Name, Disk, Seed, Network, MAC string
	MemoryMiB, CPUs                int
	Encrypted                      bool
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
	logger         *slog.Logger
	run            execFunc
	virt           hypervisor
}

func NewMachine(
	cfg config.VM,
	dir, knownHosts string,
	interactiveKey, backupKey, carryKey string,
	secrets SecretStore,
	rotator TokenRotator,
	pollEvery time.Duration,
	logger *slog.Logger,
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
		logger:         logger,
		run:            runCommand,
		virt:           newLibvirtConn(),
	}
}

func (m *Machine) Close() error {
	return m.virt.Close()
}

func (m *Machine) State(ctx context.Context) (string, error) {
	state, err := m.virt.DomainState(ctx, m.config.Name)
	if err != nil {
		return "", fmt.Errorf("reading vm state: %w", err)
	}

	return state, nil
}

func (m *Machine) SeedPath() string {
	return filepath.Join(m.dir, m.config.Name+"-seed.iso")
}

func (m *Machine) Define(ctx context.Context) error {
	return m.defineDomain(ctx, m.DiskPath(), m.SeedPath(), true)
}

func (m *Machine) Start(ctx context.Context) error {
	if err := m.start(ctx); err != nil {
		return err
	}

	m.logger.Info("vm is on, waiting until it accepts logins", "name", m.config.Name)

	return m.waitLogin(ctx)
}

func (m *Machine) Stop(ctx context.Context) error {
	state, err := m.State(ctx)
	if err != nil {
		return fmt.Errorf("stopping vm: %w", err)
	}

	if state == stateShutOff || state == stateUndef {
		return nil
	}

	m.logger.Info("shutting down vm", "name", m.config.Name)

	if err = m.virt.ShutdownDomain(ctx, m.config.Name); err != nil {
		return fmt.Errorf("stopping vm: %w", err)
	}

	for range stopAttempts {
		state, err := m.virt.DomainState(ctx, m.config.Name)
		if err != nil {
			return fmt.Errorf("reading vm state: %w", err)
		}

		if state == stateShutOff {
			return nil
		}

		if err = m.sleep(ctx); err != nil {
			return fmt.Errorf("stopping vm: %w", err)
		}
	}

	m.logger.Warn("vm did not shut down in time, forcing it off", "name", m.config.Name)

	if err = m.virt.DestroyDomain(ctx, m.config.Name); err != nil {
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
			if err = m.virt.DestroyDomain(ctx, m.config.Name); err != nil {
				return fmt.Errorf("destroying vm: %w", err)
			}
		}

		if err = m.virt.UndefineDomain(ctx, m.config.Name); err != nil {
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
	err := m.poll(ctx, "guest agent", firstBootAttempts, func() error {
		return m.agent(ctx, "guest-ping", nil, nil)
	})
	if err != nil {
		return fmt.Errorf("waiting for guest agent: %w", err)
	}

	m.logger.Info("guest agent is up, waiting for cloud-init to finish", "name", m.config.Name)

	err = m.poll(ctx, "cloud-init to finish", firstBootAttempts, func() error {
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
	err = m.poll(ctx, "cloud-init result", readyAttempts, func() error {
		result, err = m.readGuestFile(ctx, cloudResult)
		return err
	})
	if err != nil {
		return fmt.Errorf("waiting for cloud-init result: %w", err)
	}

	if err = checkCloudInit(result); err != nil {
		m.logCloudInitOutput(ctx)
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

	if parsed.V1 == nil {
		return fmt.Errorf("%w: no v1 result", ErrCloudInit)
	}

	if len(parsed.V1.Errors) == 0 {
		return nil
	}

	messages := make([]string, 0, len(parsed.V1.Errors))
	for _, raw := range parsed.V1.Errors {
		var message string
		if json.Unmarshal(raw, &message) != nil {
			message = string(raw)
		}
		messages = append(messages, message)
	}

	return fmt.Errorf(
		"%w: %s; see /var/log/cloud-init-output.log in the vm",
		ErrCloudInit,
		strings.Join(messages, "; "),
	)
}

func (m *Machine) EjectSeed(ctx context.Context) error {
	var xml bytes.Buffer
	if err := ejectTemplate.Execute(&xml, seedDevice); err != nil {
		return fmt.Errorf("rendering eject: %w", err)
	}

	if err := m.virt.UpdateDevice(ctx, m.config.Name, xml.String()); err != nil {
		return fmt.Errorf("ejecting seed: %w", err)
	}

	if err := removeIfExists(m.SeedPath()); err != nil {
		return fmt.Errorf("removing seed: %w", err)
	}

	return nil
}

func (m *Machine) Build(ctx context.Context, client *http.Client, now time.Time) error {
	if _, err := os.Stat(m.dir); err != nil {
		return fmt.Errorf("checking vm dir: %w", err)
	}

	state, err := m.State(ctx)
	if err != nil {
		return fmt.Errorf("building vm: %w", err)
	}

	if state != stateUndef {
		return fmt.Errorf("building vm: %w", ErrExists)
	}

	if _, err = os.Stat(m.DiskPath()); err == nil {
		return fmt.Errorf("building vm: %w: %s; run xena vm destroy first", ErrDiskExists, m.DiskPath())
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("checking vm disk: %w", err)
	}

	m.logger.Info("fetching base image", "url", m.config.Image.URL)

	base, err := m.fetchBaseImage(ctx, client)
	if err != nil {
		return fmt.Errorf("fetching image: %w", err)
	}

	prepared, err := m.prepareImage(ctx, base, now)
	if err != nil {
		return err
	}

	automationKey, err := m.makeAutomationKey(ctx)
	if err != nil {
		return fmt.Errorf("making automation key: %w", err)
	}

	if err = m.makeSeedISO(ctx, automationKey, now); err != nil {
		return fmt.Errorf("making seed iso: %w", err)
	}

	m.logger.Info("creating encrypted vm disk", "path", m.DiskPath())

	if err = m.createEncryptedDisk(ctx, prepared); err != nil {
		return err
	}

	if err = m.Define(ctx); err != nil {
		return err
	}

	m.logger.Info("starting vm", "name", m.config.Name)

	if err = m.start(ctx); err != nil {
		return err
	}

	m.logger.Info("vm is on, waiting for first-boot setup", "name", m.config.Name)

	if err = m.WaitReady(ctx); err != nil {
		return err
	}

	if err = m.PinHostKey(ctx); err != nil {
		return err
	}

	m.logger.Info("vm host key pinned", "path", m.knownHosts)

	if err = m.EjectSeed(ctx); err != nil {
		return err
	}

	if err = recordBuildTime(now); err != nil {
		return fmt.Errorf("recording build time: %w", err)
	}

	m.logger.Info("vm built", "name", m.config.Name)

	return nil
}

func (m *Machine) defineDomain(ctx context.Context, disk, seed string, encrypted bool) error {
	var xml bytes.Buffer
	err := domainTemplate.Execute(&xml, domainData{
		Name:      m.config.Name,
		Disk:      disk,
		Seed:      seed,
		Network:   networkName,
		MAC:       m.config.Network.MAC,
		MemoryMiB: m.config.MemoryMiB,
		CPUs:      m.config.CPUs,
		Encrypted: encrypted,
	})
	if err != nil {
		return fmt.Errorf("rendering domain: %w", err)
	}

	if err = m.virt.DefineDomain(ctx, xml.String()); err != nil {
		return fmt.Errorf("defining vm: %w", err)
	}

	return nil
}

func (m *Machine) logCloudInitOutput(ctx context.Context) {
	lines, err := m.guestFileTail(ctx, cloudOutput)
	if err != nil {
		m.logger.Warn("reading cloud-init output failed", "error", err)
		return
	}

	for _, line := range lines {
		m.logger.Error("cloud-init output", "line", line)
	}
}

func checkCut() error {
	if _, err := os.Stat(config.CutMarker()); err == nil {
		return fmt.Errorf("starting vm: %w", ErrCut)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("checking cut marker: %w", err)
	}

	return nil
}

func (m *Machine) start(ctx context.Context) error {
	if err := checkCut(); err != nil {
		return err
	}

	state, err := m.State(ctx)
	if err != nil {
		return fmt.Errorf("starting vm: %w", err)
	}

	switch state {
	case StateRunning:
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

	if undefineErr := m.virt.UndefineSecret(context.WithoutCancel(ctx), uuid); undefineErr != nil {
		return errors.Join(err, fmt.Errorf("undefining disk secret: %w", undefineErr))
	}

	return err
}

func (m *Machine) waitLogin(ctx context.Context) error {
	err := m.poll(ctx, "guest agent", readyAttempts, func() error {
		return m.agent(ctx, "guest-ping", nil, nil)
	})
	if err != nil {
		return fmt.Errorf("waiting for guest agent: %w", err)
	}

	err = m.poll(ctx, "boot to allow logins", readyAttempts, func() error {
		handle, err := m.openGuestFile(ctx, nologinPath)
		if err != nil {
			return nil
		}

		_ = m.closeGuestFile(ctx, handle)

		return errBooting
	})
	if err != nil {
		return fmt.Errorf("waiting for login: %w", err)
	}

	return nil
}

func (m *Machine) defineSecret(ctx context.Context) (string, error) {
	var xml bytes.Buffer
	if err := secretTemplate.Execute(&xml, m.DiskPath()); err != nil {
		return "", err
	}

	return m.virt.DefineSecret(ctx, xml.String())
}

func (m *Machine) startWithSecret(ctx context.Context, uuid string, key []byte) error {
	if err := m.virt.SetSecretValue(ctx, uuid, key); err != nil {
		return fmt.Errorf("setting disk secret: %w", err)
	}

	if err := m.virt.StartDomain(ctx, m.config.Name); err != nil {
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
	if err := os.MkdirAll(images, imagesDirMode); err != nil {
		return "", err
	}

	if err := os.Chmod(images, imagesDirMode); err != nil {
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

	return m.writeSeedISO(ctx, seed, m.SeedPath())
}

func (m *Machine) writeSeedISO(ctx context.Context, seed Seed, path string) error {
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
		path,
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

func lastLine(stderr []byte) string {
	lines := strings.Split(strings.TrimSpace(string(stderr)), "\n")
	line := strings.TrimSpace(lines[len(lines)-1])

	return line[:min(len(line), stderrLimit)]
}

func removeIfExists(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	return nil
}

func (m *Machine) poll(ctx context.Context, what string, attempts int, attempt func() error) error {
	start := time.Now()
	lastReport := start

	var lastErr error
	for range attempts {
		if lastErr = attempt(); lastErr == nil {
			return nil
		}

		if time.Since(lastReport) >= progressEvery {
			m.logger.Info("still waiting", "for", what, "elapsed", time.Since(start).Round(time.Second).String())
			lastReport = time.Now()
		}

		if err := m.sleep(ctx); err != nil {
			return err
		}
	}

	return fmt.Errorf("%w: last error: %w", ErrTimeout, lastErr)
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

func runCommand(ctx context.Context, stdin io.Reader, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = stdin

	out, err := cmd.Output()
	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
		return nil, fmt.Errorf("running %s: %w: %s", name, err, lastLine(exitErr.Stderr))
	}

	if err != nil {
		return nil, fmt.Errorf("running %s: %w", name, err)
	}

	return out, nil
}

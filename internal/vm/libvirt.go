package vm

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/digitalocean/go-libvirt"
	"github.com/digitalocean/go-libvirt/socket/dialers"
)

var errUnknownSecret = errors.New("unknown secret")

var domainStates = map[libvirt.DomainState]string{
	libvirt.DomainNostate:     "no state",
	libvirt.DomainRunning:     stateRunning,
	libvirt.DomainBlocked:     "idle",
	libvirt.DomainPaused:      "paused",
	libvirt.DomainShutdown:    "in shutdown",
	libvirt.DomainShutoff:     stateShutOff,
	libvirt.DomainCrashed:     "crashed",
	libvirt.DomainPmsuspended: "pmsuspended",
}

type hypervisor interface {
	DomainState(ctx context.Context, name string) (string, error)
	DefineDomain(ctx context.Context, xml string) error
	DefineSecret(ctx context.Context, xml string) (string, error)
	SetSecretValue(ctx context.Context, uuid string, value []byte) error
	UndefineSecret(ctx context.Context, uuid string) error
	StartDomain(ctx context.Context, name string) error
	ShutdownDomain(ctx context.Context, name string) error
	DestroyDomain(ctx context.Context, name string) error
	UndefineDomain(ctx context.Context, name string) error
	UpdateDevice(ctx context.Context, name, xml string) error
	AgentCommand(ctx context.Context, name, command string) (string, error)
	Close() error
}

type libvirtConn struct {
	client  *libvirt.Libvirt
	secrets map[string]libvirt.Secret
}

func newLibvirtConn() *libvirtConn {
	return &libvirtConn{secrets: map[string]libvirt.Secret{}}
}

func (c *libvirtConn) DomainState(ctx context.Context, name string) (string, error) {
	dom, err := c.domain(ctx, name)
	if libvirt.IsNotFound(err) {
		return stateUndef, nil
	}

	if err != nil {
		return "", err
	}

	state, _, err := c.client.DomainGetState(dom, 0)
	if err != nil {
		return "", err
	}

	if s, ok := domainStates[libvirt.DomainState(state)]; ok {
		return s, nil
	}

	return "unknown", nil
}

func (c *libvirtConn) DefineDomain(ctx context.Context, xml string) error {
	client, err := c.connect(ctx)
	if err != nil {
		return err
	}

	_, err = client.DomainDefineXML(xml)

	return err
}

func (c *libvirtConn) DefineSecret(ctx context.Context, xml string) (string, error) {
	client, err := c.connect(ctx)
	if err != nil {
		return "", err
	}

	secret, err := client.SecretDefineXML(xml, 0)
	if err != nil {
		return "", err
	}

	uuid := formatUUID(secret.UUID)
	c.secrets[uuid] = secret

	return uuid, nil
}

func (c *libvirtConn) SetSecretValue(ctx context.Context, uuid string, value []byte) error {
	secret, err := c.secret(ctx, uuid)
	if err != nil {
		return err
	}

	return c.client.SecretSetValue(secret, value, 0)
}

func (c *libvirtConn) UndefineSecret(ctx context.Context, uuid string) error {
	secret, err := c.secret(ctx, uuid)
	if err != nil {
		return err
	}

	if err = c.client.SecretUndefine(secret); err != nil {
		return err
	}

	delete(c.secrets, uuid)

	return nil
}

func (c *libvirtConn) StartDomain(ctx context.Context, name string) error {
	return c.onDomain(ctx, name, (*libvirt.Libvirt).DomainCreate)
}

func (c *libvirtConn) ShutdownDomain(ctx context.Context, name string) error {
	return c.onDomain(ctx, name, (*libvirt.Libvirt).DomainShutdown)
}

func (c *libvirtConn) DestroyDomain(ctx context.Context, name string) error {
	return c.onDomain(ctx, name, (*libvirt.Libvirt).DomainDestroy)
}

func (c *libvirtConn) UndefineDomain(ctx context.Context, name string) error {
	return c.onDomain(ctx, name, (*libvirt.Libvirt).DomainUndefine)
}

func (c *libvirtConn) UpdateDevice(ctx context.Context, name, xml string) error {
	return c.onDomain(ctx, name, func(client *libvirt.Libvirt, dom libvirt.Domain) error {
		return client.DomainUpdateDeviceFlags(
			dom,
			xml,
			libvirt.DomainDeviceModifyLive|libvirt.DomainDeviceModifyConfig,
		)
	})
}

func (c *libvirtConn) AgentCommand(ctx context.Context, name, command string) (string, error) {
	dom, err := c.domain(ctx, name)
	if err != nil {
		return "", err
	}

	out, err := c.client.QEMUDomainAgentCommand(dom, command, int32(libvirt.DomainAgentResponseTimeoutDefault), 0)
	if err != nil {
		return "", err
	}

	if len(out) == 0 {
		return "", nil
	}

	return out[0], nil
}

func (c *libvirtConn) Close() error {
	if c.client == nil {
		return nil
	}

	err := c.client.Disconnect()
	c.client = nil

	return err
}

func (c *libvirtConn) connect(ctx context.Context) (*libvirt.Libvirt, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if c.client != nil {
		return c.client, nil
	}

	client := libvirt.NewWithDialer(dialers.NewLocal())
	if err := client.ConnectToURI(libvirt.QEMUSystem); err != nil {
		return nil, fmt.Errorf("connecting to libvirt: %w", err)
	}

	c.client = client

	return client, nil
}

func (c *libvirtConn) domain(ctx context.Context, name string) (libvirt.Domain, error) {
	client, err := c.connect(ctx)
	if err != nil {
		return libvirt.Domain{}, err
	}

	return client.DomainLookupByName(name)
}

func (c *libvirtConn) onDomain(ctx context.Context, name string, action func(*libvirt.Libvirt, libvirt.Domain) error) error {
	dom, err := c.domain(ctx, name)
	if err != nil {
		return err
	}

	return action(c.client, dom)
}

func (c *libvirtConn) secret(ctx context.Context, uuid string) (libvirt.Secret, error) {
	if _, err := c.connect(ctx); err != nil {
		return libvirt.Secret{}, err
	}

	secret, ok := c.secrets[uuid]
	if !ok {
		return libvirt.Secret{}, fmt.Errorf("%w: %s", errUnknownSecret, uuid)
	}

	return secret, nil
}

func formatUUID(uuid libvirt.UUID) string {
	h := hex.EncodeToString(uuid[:])
	return strings.Join([]string{h[0:8], h[8:12], h[12:16], h[16:20], h[20:32]}, "-")
}

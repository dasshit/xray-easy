package domain

import (
	"errors"
	"regexp"
	"strings"
	"time"
)

var (
	deviceNamePattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	fingerprints      = map[string]struct{}{
		"chrome": {}, "firefox": {}, "safari": {}, "edge": {},
		"ios": {}, "android": {}, "random": {},
	}
)

var ErrClientRevoked = errors.New("revoked client cannot be enabled")

// Client is an Xray device profile and its credentials. It contains secrets
// used by the control plane, so transport responses must map it explicitly.
type Client struct {
	ID                string
	Name              string
	UUID              string
	Email             string
	ShortID           string
	ClientFingerprint string
	Enabled           bool
	Revoked           bool
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

type ClientState struct {
	Enabled bool
	Revoked bool
}

func NewClient(id, name, fingerprint string) (Client, error) {
	name = strings.TrimSpace(name)
	fingerprint = strings.TrimSpace(fingerprint)
	if id == "" {
		return Client{}, errors.New("client id is required")
	}
	if !deviceNamePattern.MatchString(name) {
		return Client{}, errors.New("name must contain ASCII letters, digits or '-' and be 1-64 characters")
	}
	if fingerprint != "" && !SupportsFingerprint(fingerprint) {
		return Client{}, errors.New("unsupported client fingerprint")
	}
	return Client{ID: id, Name: name, ClientFingerprint: fingerprint, Enabled: true}, nil
}

func SupportsFingerprint(value string) bool {
	_, ok := fingerprints[value]
	return ok
}

func (c Client) CanConnect() bool { return c.Enabled && !c.Revoked }

func (c Client) Enable() (Client, error) {
	if c.Revoked {
		return Client{}, ErrClientRevoked
	}
	c.Enabled = true
	return c, nil
}

func (c Client) Disable() Client {
	c.Enabled = false
	return c
}

func (c Client) Revoke() Client {
	c.Enabled = false
	c.Revoked = true
	return c
}

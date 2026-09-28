package domain

import (
	"errors"
	"testing"
)

func TestClientLifecycle(t *testing.T) {
	client, err := NewClient("device-1", "my-phone", "safari")
	if err != nil {
		t.Fatal(err)
	}
	if !client.CanConnect() {
		t.Fatal("new profile must be connectable")
	}

	disabled := client.Disable()
	if disabled.CanConnect() || disabled.Revoked {
		t.Fatalf("unexpected disabled state: %+v", disabled)
	}
	revoked := disabled.Revoke()
	if revoked.CanConnect() || !revoked.Revoked || revoked.Enabled {
		t.Fatalf("unexpected revoked state: %+v", revoked)
	}
	if _, err := revoked.Enable(); !errors.Is(err, ErrClientRevoked) {
		t.Fatalf("enabling revoked profile error = %v", err)
	}
}

func TestNewClientValidation(t *testing.T) {
	for _, input := range []struct{ id, name, fingerprint string }{
		{"", "phone", "chrome"},
		{"id", "phone name", "chrome"},
		{"id", "phone", "unknown"},
	} {
		if _, err := NewClient(input.id, input.name, input.fingerprint); err == nil {
			t.Errorf("NewClient(%q, %q, %q) unexpectedly succeeded", input.id, input.name, input.fingerprint)
		}
	}
}

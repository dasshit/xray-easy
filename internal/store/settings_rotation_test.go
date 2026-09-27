package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestUpdateSettingsAndClientStatesIsAtomic(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Initialize(ctx, "admin", "password-hash", "old.example", 443); err != nil {
		t.Fatal(err)
	}
	initial, err := db.GetSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	initial.RealityTarget = "old-target.example:443"
	initial.RealitySNI = "old-target.example"
	if err := db.UpdateSettings(ctx, initial); err != nil {
		t.Fatal(err)
	}

	candidate := initial
	candidate.PublicHost = "new.example"
	candidate.RealityTarget = "new-target.example:443"
	candidate.RealitySNI = "new-target.example"
	if err := db.UpdateSettingsAndClientStates(ctx, candidate, map[string]ClientState{"missing-device": {Revoked: true}}); err == nil {
		t.Fatal("expected unknown device to abort the transaction")
	}
	unchanged, err := db.GetSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.PublicHost != initial.PublicHost || unchanged.RealityTarget != initial.RealityTarget {
		t.Fatalf("settings partially committed after failed client update: %+v", unchanged)
	}

	client := Client{ID: "device-1", Name: "phone", Enabled: true}
	if err := db.CreateClient(ctx, client, "uuid", "email", "short-id"); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateSettingsAndClientStates(ctx, candidate, map[string]ClientState{client.ID: {Enabled: false, Revoked: true}}); err != nil {
		t.Fatal(err)
	}
	committed, err := db.GetSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	updatedClient, err := db.GetClient(ctx, client.ID)
	if err != nil {
		t.Fatal(err)
	}
	if committed.PublicHost != candidate.PublicHost || committed.RealityTarget != candidate.RealityTarget {
		t.Fatalf("settings were not committed: %+v", committed)
	}
	if updatedClient.Enabled || !updatedClient.Revoked {
		t.Fatalf("device was not revoked: %+v", updatedClient)
	}
}

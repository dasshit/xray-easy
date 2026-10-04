package store

import (
	"strings"
	"testing"
	"time"
)

func TestReadOnlyQueriesReportMalformedPersistedRows(t *testing.T) {
	db, ctx := openTestStore(t, "malformed-rows.db")
	client := createTestClient(t, db, ctx, "phone")
	if _, err := db.db.Exec(`UPDATE clients SET expires_at='not-a-timestamp' WHERE id=?`, client.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := CountExpiredEnabledClientsFromDatabase(ctx, db.dbPath, time.Now()); err == nil || !strings.Contains(err.Error(), "parse client expiry") {
		t.Fatalf("CountExpiredEnabledClientsFromDatabase() error = %v", err)
	}
	if _, err := db.GetClient(ctx, client.ID); err == nil || !strings.Contains(err.Error(), "expiry timestamp is invalid") {
		t.Fatalf("GetClient() accepted an invalid expiry: %v", err)
	}
	if _, err := db.ListClients(ctx); err == nil || !strings.Contains(err.Error(), "expiry timestamp is invalid") {
		t.Fatalf("ListClients() accepted an invalid expiry: %v", err)
	}
}

func TestTrafficSnapshotQueriesReportMalformedCounters(t *testing.T) {
	db, ctx := openTestStore(t, "malformed-counters.db")
	client := createTestClient(t, db, ctx, "counter-test")
	if _, err := db.db.Exec(`INSERT INTO traffic_snapshots(client_id,raw_upload,raw_download,total_upload,total_download,last_seen_at,last_polled_at) VALUES(?,'not-a-counter',0,0,0,'','')`, client.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ListTrafficSnapshots(ctx); err == nil {
		t.Fatal("ListTrafficSnapshots() accepted a non-numeric counter")
	}
	if _, err := db.db.Exec(`INSERT INTO awg_traffic_snapshots(peer_name,raw_upload,raw_download,total_upload,total_download,source_ip,last_seen_at,last_polled_at) VALUES('bad','not-a-counter',0,0,0,'','','')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ListAWGTrafficSnapshots(ctx); err == nil {
		t.Fatal("ListAWGTrafficSnapshots() accepted a non-numeric counter")
	}
}

func TestGetClientReportsMalformedPersistedStateFields(t *testing.T) {
	db, ctx := openTestStore(t, "malformed-state.db")
	client := createTestClient(t, db, ctx, "malformed-state")
	if _, err := db.db.ExecContext(ctx, `UPDATE clients SET enabled='not-an-integer' WHERE id=?`, client.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetClient(ctx, client.ID); err == nil || !strings.Contains(err.Error(), "converting driver.Value type string") {
		t.Fatalf("GetClient() error = %v, want malformed integer scan error", err)
	}
}

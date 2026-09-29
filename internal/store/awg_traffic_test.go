package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestAWGTrafficSnapshotsRoundTripUpdateAndDelete(t *testing.T) {
	db, ctx := openTestStore(t, "awg-traffic.db")
	firstSeen := time.Date(2026, 9, 30, 12, 0, 0, 123, time.FixedZone("test", 3*60*60))
	firstPoll := firstSeen.Add(10 * time.Second)
	initial := AWGTrafficSnapshot{
		PeerName: "phone-1", RawUpload: 120, RawDownload: 240,
		TotalUpload: 320, TotalDownload: 640, SourceIP: "2001:db8::1",
		LastSeenAt: firstSeen, LastPolledAt: firstPoll,
	}
	if err := db.UpsertAWGTrafficSnapshot(ctx, initial); err != nil {
		t.Fatal(err)
	}

	updated := initial
	updated.RawUpload = 180
	updated.TotalUpload = 380
	updated.SourceIP = "198.51.100.4"
	updated.LastSeenAt = firstSeen.Add(time.Minute)
	updated.LastPolledAt = firstPoll.Add(time.Minute)
	if err := db.UpsertAWGTrafficSnapshot(ctx, updated); err != nil {
		t.Fatal(err)
	}

	got, err := db.ListAWGTrafficSnapshots(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got["phone-1"].RawUpload != 180 || got["phone-1"].TotalUpload != 380 || got["phone-1"].SourceIP != "198.51.100.4" {
		t.Fatalf("updated AWG snapshots = %+v", got)
	}
	if !got["phone-1"].LastSeenAt.Equal(updated.LastSeenAt) || !got["phone-1"].LastPolledAt.Equal(updated.LastPolledAt) {
		t.Fatalf("AWG timestamps were not preserved: %+v", got["phone-1"])
	}

	if err := db.DeleteAWGTrafficSnapshot(ctx, "phone-1"); err != nil {
		t.Fatal(err)
	}
	got, err = db.ListAWGTrafficSnapshots(ctx)
	if err != nil || len(got) != 0 {
		t.Fatalf("deleted AWG snapshots = %+v, %v", got, err)
	}
}

func TestAWGTrafficSnapshotsRejectEmptyPeerNameAndHonorCanceledContext(t *testing.T) {
	db, ctx := openTestStore(t, "awg-traffic-errors.db")
	if err := db.UpsertAWGTrafficSnapshot(ctx, AWGTrafficSnapshot{}); err == nil || !strings.Contains(err.Error(), "peer name is required") {
		t.Fatalf("empty peer name error = %v", err)
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := db.UpsertAWGTrafficSnapshot(canceled, AWGTrafficSnapshot{PeerName: "phone-1"}); err == nil {
		t.Fatal("upsert succeeded with canceled context")
	}
	if _, err := db.ListAWGTrafficSnapshots(canceled); err == nil {
		t.Fatal("list succeeded with canceled context")
	}
	if err := db.DeleteAWGTrafficSnapshot(canceled, "phone-1"); err == nil {
		t.Fatal("delete succeeded with canceled context")
	}
}

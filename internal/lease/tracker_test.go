package lease

import (
	"testing"
	"time"
)

func testTracker(t *testing.T) *Tracker {
	t.Helper()
	tracker, err := NewTracker(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	return tracker
}

func leaseSnapshot(generation string, sequence uint64, sampledAt time.Time, ips ...string) Snapshot {
	snapshot := Snapshot{Available: true, Full: true, Generation: generation, Sequence: sequence, SampledAt: sampledAt}
	for _, ip := range ips {
		snapshot.Leases = append(snapshot.Leases, Observation{Key: LeaseKey{Protocol: "vless", Email: "profile@xray-easy", SourceIP: ip}, LastActivity: sampledAt, FirstSeen: sampledAt})
	}
	return snapshot
}

func TestTrackerAllowsSecondLeaseForGraceThenClosesOldest(t *testing.T) {
	tracker := testTracker(t)
	start := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	if got := tracker.Apply(leaseSnapshot("generation-a", 1, start, "192.0.2.1"), start); len(got) != 0 {
		t.Fatalf("first lease decisions = %+v", got)
	}
	second := start.Add(5 * time.Second)
	if got := tracker.Apply(leaseSnapshot("generation-a", 2, second, "192.0.2.1", "2001:db8::2"), second); len(got) != 0 {
		t.Fatalf("new second lease was disconnected immediately: %+v", got)
	}
	deadline, ok := tracker.NextDeadline()
	if !ok || !deadline.Equal(second.Add(30*time.Second)) {
		t.Fatalf("second lease grace deadline = %v, %t", deadline, ok)
	}
	if got := tracker.Due(deadline.Add(-time.Nanosecond)); len(got) != 0 {
		t.Fatalf("lease was disconnected before grace expired: %+v", got)
	}
	decisions := tracker.Due(deadline)
	if len(decisions) != 1 || decisions[0].Lease.SourceIP != "192.0.2.1" || decisions[0].Reason != "dual_lease_grace_expired" {
		t.Fatalf("grace-expiry decision = %+v", decisions)
	}
	tracker.Complete(decisions[0].Lease, true, deadline)
	active := tracker.ActiveLeases()
	if len(active) != 1 || active[0].SourceIP != "2001:db8::2" {
		t.Fatalf("active leases after oldest close = %+v", active)
	}
}

func TestTrackerThirdLeaseImmediatelyClosesOnlyOldest(t *testing.T) {
	tracker := testTracker(t)
	start := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	tracker.Apply(leaseSnapshot("generation-a", 1, start, "192.0.2.1"), start)
	second := start.Add(time.Second)
	tracker.Apply(leaseSnapshot("generation-a", 2, second, "192.0.2.1", "192.0.2.2"), second)
	third := start.Add(2 * time.Second)
	decisions := tracker.Apply(leaseSnapshot("generation-a", 3, third, "192.0.2.1", "192.0.2.2", "192.0.2.3"), third)
	if len(decisions) != 1 || decisions[0].Lease.SourceIP != "192.0.2.1" || decisions[0].Reason != "max_active_leases_exceeded" {
		t.Fatalf("third lease decision = %+v", decisions)
	}
	tracker.Complete(decisions[0].Lease, true, third)
	active := tracker.ActiveLeases()
	if len(active) != 2 || active[0].SourceIP != "192.0.2.2" || active[1].SourceIP != "192.0.2.3" {
		t.Fatalf("active leases after third lease enforcement = %+v", active)
	}
	deadline, ok := tracker.NextDeadline()
	if !ok || !deadline.Equal(third.Add(30*time.Second)) {
		t.Fatalf("remaining pair deadline = %v, %t", deadline, ok)
	}
}

func TestTrackerOrdersProfilesAndUsesRetryDeadlineForThirdLease(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	tracker := testTracker(t)
	snapshot := Snapshot{Available: true, Full: true, Generation: "runtime-a", Sequence: 1, SampledAt: now}
	for _, lease := range []LeaseKey{
		{Protocol: "vless", Email: "z-profile", SourceIP: "192.0.2.1"},
		{Protocol: "vless", Email: "z-profile", SourceIP: "192.0.2.2"},
		{Protocol: "vless", Email: "a-profile", SourceIP: "192.0.2.3"},
		{Protocol: "vless", Email: "a-profile", SourceIP: "192.0.2.4"},
		{Protocol: "trojan", Email: "profile", SourceIP: "192.0.2.5"},
		{Protocol: "trojan", Email: "profile", SourceIP: "192.0.2.6"},
		{Protocol: "trojan", Email: "profile", SourceIP: "192.0.2.7"},
	} {
		snapshot.Leases = append(snapshot.Leases, Observation{Key: lease, LastActivity: now, FirstSeen: now})
	}
	decisions := tracker.Apply(snapshot, now)
	if len(decisions) != 1 || decisions[0].Lease.SourceIP != "192.0.2.5" {
		t.Fatalf("third lease decision = %+v", decisions)
	}
	tracker.Complete(decisions[0].Lease, false, now)
	deadline, ok := tracker.NextDeadline()
	if !ok || !deadline.Equal(now.Add(time.Second)) {
		t.Fatalf("earliest retry deadline = %v, %t", deadline, ok)
	}
	active := tracker.ActiveLeases()
	want := []LeaseKey{
		{Protocol: "trojan", Email: "profile", SourceIP: "192.0.2.5"},
		{Protocol: "trojan", Email: "profile", SourceIP: "192.0.2.6"},
		{Protocol: "trojan", Email: "profile", SourceIP: "192.0.2.7"},
		{Protocol: "vless", Email: "a-profile", SourceIP: "192.0.2.3"},
		{Protocol: "vless", Email: "a-profile", SourceIP: "192.0.2.4"},
		{Protocol: "vless", Email: "z-profile", SourceIP: "192.0.2.1"},
		{Protocol: "vless", Email: "z-profile", SourceIP: "192.0.2.2"},
	}
	if len(active) != len(want) {
		t.Fatalf("active lease count = %d, want %d (%+v)", len(active), len(want), active)
	}
	for index := range want {
		if active[index] != want[index] {
			t.Fatalf("active leases[%d] = %+v, want %+v", index, active[index], want[index])
		}
	}
}

func TestTrackerRestoresChronologicalOrderFromFullSnapshot(t *testing.T) {
	tracker := testTracker(t)
	firstSeen := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	now := firstSeen.Add(time.Hour)
	snapshot := Snapshot{Available: true, Full: true, Generation: "runtime-restarted", Sequence: 1, SampledAt: now, Leases: []Observation{
		{Key: LeaseKey{Protocol: "vless", Email: "profile@xray-easy", SourceIP: "192.0.2.30"}, LastActivity: now, FirstSeen: firstSeen},
		{Key: LeaseKey{Protocol: "vless", Email: "profile@xray-easy", SourceIP: "192.0.2.20"}, LastActivity: now, FirstSeen: firstSeen.Add(time.Minute)},
	}}
	if decisions := tracker.Apply(snapshot, now); len(decisions) != 0 {
		t.Fatalf("restored second lease was disconnected immediately: %+v", decisions)
	}
	deadline, ok := tracker.NextDeadline()
	if !ok || !deadline.Equal(now.Add(30*time.Second)) {
		t.Fatalf("restored grace deadline = %v, %t", deadline, ok)
	}
	decisions := tracker.Due(deadline)
	if len(decisions) != 1 || decisions[0].Lease.SourceIP != "192.0.2.30" {
		t.Fatalf("restored oldest lease decision = %+v", decisions)
	}
}

func TestTrackerCancelsConflictWhenLeaseGoesOfflineAndHonorsProtocolScope(t *testing.T) {
	tracker := testTracker(t)
	start := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	tracker.Apply(leaseSnapshot("generation-a", 1, start, "192.0.2.1"), start)
	second := start.Add(time.Second)
	tracker.Apply(leaseSnapshot("generation-a", 2, second, "192.0.2.1", "192.0.2.2"), second)
	// A complete snapshot that no longer contains the old source removes its lease.
	third := second.Add(time.Second)
	tracker.Apply(leaseSnapshot("generation-a", 3, third, "192.0.2.2"), third)
	if _, ok := tracker.NextDeadline(); ok {
		t.Fatal("offline transition did not cancel the second-lease grace timer")
	}
	ignored := Snapshot{Available: true, Full: true, Generation: "generation-a", Sequence: 4, SampledAt: third.Add(time.Second), Leases: []Observation{
		{Key: LeaseKey{Protocol: "vless", Email: "profile@xray-easy", SourceIP: "192.0.2.2"}, LastActivity: third.Add(time.Second)},
		{Key: LeaseKey{Protocol: "hysteria2", Email: "profile@xray-easy", SourceIP: "192.0.2.3"}, LastActivity: third.Add(time.Second)},
	}}
	if decisions := tracker.Apply(ignored, ignored.SampledAt); len(decisions) != 0 || len(tracker.ActiveLeases()) != 1 {
		t.Fatalf("unsupported protocol affected lease policy: decisions=%+v active=%+v", decisions, tracker.ActiveLeases())
	}
}

func TestTrackerIgnoresUnavailablePartialAndStaleSnapshots(t *testing.T) {
	tracker := testTracker(t)
	start := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	tracker.Apply(leaseSnapshot("generation-a", 5, start, "192.0.2.1"), start)
	if got := tracker.Apply(Snapshot{Generation: "generation-a", Sequence: 6}, start.Add(time.Second)); len(got) != 0 {
		t.Fatalf("unavailable snapshot decisions = %+v", got)
	}
	if got := tracker.Apply(Snapshot{Available: true, Full: false, Generation: "generation-a", Sequence: 7}, start.Add(2*time.Second)); len(got) != 0 {
		t.Fatalf("partial snapshot decisions = %+v", got)
	}
	if got := tracker.Apply(leaseSnapshot("generation-a", 4, start.Add(3*time.Second), "192.0.2.2"), start.Add(3*time.Second)); len(got) != 0 {
		t.Fatalf("stale sequence decisions = %+v", got)
	}
	if got := tracker.Apply(leaseSnapshot("generation-b", 1, start.Add(4*time.Second), "192.0.2.9"), start.Add(4*time.Second)); len(got) != 0 {
		t.Fatalf("new generation first snapshot decisions = %+v", got)
	}
	active := tracker.ActiveLeases()
	if len(active) != 1 || active[0].SourceIP != "192.0.2.9" {
		t.Fatalf("leases after source generation change = %+v", active)
	}
}

func TestTrackerPausesDeadlinesWhenTelemetryDisconnects(t *testing.T) {
	tracker := testTracker(t)
	start := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	tracker.Apply(leaseSnapshot("generation-a", 1, start, "192.0.2.1"), start)
	second := start.Add(time.Second)
	tracker.Apply(leaseSnapshot("generation-a", 2, second, "192.0.2.1", "192.0.2.2"), second)
	tracker.SetUnavailable()
	if tracker.Available() {
		t.Fatal("tracker remained available after stream disconnected")
	}
	if _, ok := tracker.NextDeadline(); ok {
		t.Fatal("tracker scheduled enforcement without a live source")
	}
	reconnected := second.Add(40 * time.Second)
	if decisions := tracker.Apply(leaseSnapshot("generation-a", 3, reconnected, "192.0.2.1", "192.0.2.2"), reconnected); len(decisions) != 1 {
		t.Fatalf("reconciled conflict after source recovered = %+v", decisions)
	}
}

func TestTrackerRetriesFailedDisconnectAndSuppressesPendingDuplicate(t *testing.T) {
	tracker := testTracker(t)
	start := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	tracker.Apply(leaseSnapshot("generation-a", 1, start, "192.0.2.1"), start)
	second := start.Add(time.Second)
	tracker.Apply(leaseSnapshot("generation-a", 2, second, "192.0.2.1", "192.0.2.2"), second)
	deadline, _ := tracker.NextDeadline()
	decision := tracker.Due(deadline)
	if len(decision) != 1 {
		t.Fatalf("due decision = %+v", decision)
	}
	if got := tracker.Due(deadline.Add(time.Second)); len(got) != 0 {
		t.Fatalf("pending lease was scheduled twice: %+v", got)
	}
	tracker.Complete(decision[0].Lease, false, deadline)
	retryAt, ok := tracker.NextDeadline()
	if !ok || !retryAt.Equal(deadline.Add(time.Second)) {
		t.Fatalf("retry deadline = %v, %t", retryAt, ok)
	}
	if got := tracker.Due(retryAt.Add(-time.Nanosecond)); len(got) != 0 {
		t.Fatalf("disconnect retry happened early: %+v", got)
	}
	if got := tracker.Due(retryAt); len(got) != 1 || got[0].Lease != decision[0].Lease {
		t.Fatalf("disconnect retry = %+v", got)
	}
}

func TestTrackerCanonicalizesAndRejectsInvalidObservations(t *testing.T) {
	tracker := testTracker(t)
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	snapshot := Snapshot{Available: true, Full: true, Generation: "g", Sequence: 1, SampledAt: now, Leases: []Observation{
		{Key: LeaseKey{Protocol: " VLESS ", Email: " device@xray-easy ", SourceIP: "::ffff:192.0.2.4"}, LastActivity: now},
		{Key: LeaseKey{Protocol: "vless", Email: "bad", SourceIP: "fe80::1%en0"}, LastActivity: now},
		{Key: LeaseKey{Protocol: "vmess", Email: "missing-activity", SourceIP: "192.0.2.6"}},
	}}
	tracker.Apply(snapshot, now)
	active := tracker.ActiveLeases()
	if len(active) != 1 || active[0] != (LeaseKey{Protocol: "vless", Email: "device@xray-easy", SourceIP: "192.0.2.4"}) {
		t.Fatalf("canonical active leases = %+v", active)
	}
}

func TestTrackerValidatesPolicy(t *testing.T) {
	config := DefaultConfig()
	config.MaxActiveLeases = 3
	if _, err := NewTracker(config); err == nil || err.Error() != "maximum active leases must be 2" {
		t.Fatal("accepted an unsupported active-lease limit")
	}
	config = DefaultConfig()
	config.GracePeriod = 0
	if _, err := NewTracker(config); err == nil {
		t.Fatal("accepted an invalid grace period")
	}
	config = DefaultConfig()
	config.RetryDelay = time.Minute + time.Nanosecond
	if _, err := NewTracker(config); err == nil {
		t.Fatal("accepted an excessive retry delay")
	}
}

func TestTrackerMarkPendingCompletesAndReactivatesAClosedLease(t *testing.T) {
	tracker := testTracker(t)
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	key := LeaseKey{Protocol: "trojan", Email: "profile", SourceIP: "192.0.2.1"}
	snapshot := Snapshot{Available: true, Full: true, Generation: "runtime-a", Sequence: 1, Leases: []Observation{{Key: key, LastActivity: now, FirstSeen: now}}}
	tracker.Apply(snapshot, now)
	if tracker.MarkPending(key) != true || tracker.MarkPending(key) {
		t.Fatal("MarkPending did not reject a duplicate pending operation")
	}
	tracker.Complete(key, true, now.Add(time.Second))
	if tracker.MarkPending(key) {
		t.Fatal("terminated lease was allowed to be marked pending")
	}
	snapshot.Sequence = 2
	snapshot.Leases[0].FirstSeen = now.Add(2 * time.Second)
	snapshot.Leases[0].LastActivity = now.Add(2 * time.Second)
	tracker.Apply(snapshot, now.Add(2*time.Second))
	if active := tracker.ActiveLeases(); len(active) != 1 || active[0] != key {
		t.Fatalf("new connection from a closed source was not reactivated: %+v", active)
	}
}

func TestTrackerRejectsFutureActivityAndDefaultsInvalidConnectionStart(t *testing.T) {
	tracker := testTracker(t)
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	snapshot := Snapshot{Available: true, Full: true, Generation: "runtime-a", Sequence: 1, Leases: []Observation{
		{Key: LeaseKey{Protocol: "vless", Email: "future", SourceIP: "192.0.2.1"}, LastActivity: now.Add(2 * time.Minute), FirstSeen: now},
		{Key: LeaseKey{Protocol: "vless", Email: "invalid-start", SourceIP: "192.0.2.2"}, LastActivity: now, FirstSeen: now.Add(2 * time.Minute)},
	}}
	tracker.Apply(snapshot, now)
	active := tracker.ActiveLeases()
	if len(active) != 1 || active[0].Email != "invalid-start" {
		t.Fatalf("future activity validation produced leases %+v", active)
	}
	state := tracker.leases[active[0]]
	if !state.firstSeen.Equal(now) {
		t.Fatalf("invalid connection start was not replaced with snapshot time: %v", state.firstSeen)
	}
}

func TestTrackerNilAndEmptyStateHelpersAreSafe(t *testing.T) {
	var tracker *Tracker
	now := time.Now().UTC()
	deadline, scheduled := tracker.NextDeadline()
	if tracker.Apply(Snapshot{}, now) != nil || tracker.Due(now) != nil || !deadline.IsZero() || scheduled || tracker.ActiveLeases() != nil {
		t.Fatal("nil tracker returned state or a policy decision")
	}
	tracker = testTracker(t)
	if tracker.decisions(now, false) != nil {
		t.Fatal("unavailable tracker made a decision")
	}
	deadline, scheduled = tracker.NextDeadline()
	if tracker.Due(now) != nil || !deadline.IsZero() || scheduled || len(tracker.profiles()) != 0 || len(tracker.activeFor(profileKey{})) != 0 {
		t.Fatal("empty tracker reported active policy state")
	}
	if state := tracker.oldest(nil); state != nil {
		t.Fatalf("oldest empty lease set = %+v", state)
	}
	if decision, ok := tracker.scheduleOldest(nil, "empty", now); ok || decision.Lease != (LeaseKey{}) {
		t.Fatalf("empty schedule decision = %+v, %t", decision, ok)
	}
	tracker.Complete(LeaseKey{}, true, now)
}

func TestTrackerSuppressesEarlyThirdLeaseRetryAndGuardsClosedOrPendingState(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	tracker := testTracker(t)
	leases := []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}
	tracker.Apply(leaseSnapshot("runtime-a", 1, now, leases...), now)
	first := LeaseKey{Protocol: "vless", Email: "profile@xray-easy", SourceIP: leases[0]}
	tracker.Complete(first, false, now)
	if got := tracker.Due(now); len(got) != 0 {
		t.Fatalf("third lease retry was scheduled before retryAt: %+v", got)
	}
	active := tracker.activeFor(profileFor(first))
	state := tracker.leases[first]
	state.pending = true
	if _, ok := tracker.scheduleOldest(active, "test", now.Add(time.Hour)); ok {
		t.Fatal("pending lease was scheduled again")
	}
	state.pending = false
	state.closedAt = now
	if _, ok := tracker.scheduleOldest(active, "test", now.Add(time.Hour)); ok {
		t.Fatal("closed lease was scheduled again")
	}
	state.closedAt = time.Time{}
	state.retryAt = now.Add(time.Hour)
	if _, ok := tracker.scheduleOldest(active, "test", now); ok {
		t.Fatal("lease before retryAt was scheduled")
	}
}

func TestTrackerObservationValidationRejectsMalformedEmailAndFutureTimestamp(t *testing.T) {
	tracker := testTracker(t)
	now := time.Now().UTC()
	snapshot := Snapshot{Available: true, Full: true, Generation: "runtime-a", Sequence: 1, Leases: []Observation{
		{Key: LeaseKey{Protocol: "vless", Email: "bad\x00email", SourceIP: "192.0.2.1"}, LastActivity: now, FirstSeen: now},
		{Key: LeaseKey{Protocol: "vmess", Email: "future", SourceIP: "192.0.2.2"}, LastActivity: now, FirstSeen: now.Add(2 * time.Minute)},
	}}
	tracker.Apply(snapshot, now)
	if active := tracker.ActiveLeases(); len(active) != 1 || active[0].SourceIP != "192.0.2.2" {
		t.Fatalf("malformed observations produced active leases %+v", active)
	}
}

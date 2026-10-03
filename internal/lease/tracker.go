// Package lease implements the source-IP lease policy for Xray profiles.
package lease

import (
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Config defines the bounded lease policy.
type Config struct {
	// MaxActiveLeases is the supported maximum source IP count per profile.
	MaxActiveLeases int
	// GracePeriod is how long two source IP leases may overlap.
	GracePeriod time.Duration
	// RetryDelay is the wait before retrying a transient disconnect failure.
	RetryDelay time.Duration
}

// DefaultConfig returns the product defaults for the optional lease service.
func DefaultConfig() Config {
	return Config{MaxActiveLeases: 2, GracePeriod: 30 * time.Second, RetryDelay: time.Second}
}

// Validate checks that the policy has safe, bounded values.
func (c Config) Validate() error {
	if c.MaxActiveLeases != 2 {
		return errInvalidConfig("maximum active leases must be 2")
	}
	if c.GracePeriod <= 0 || c.GracePeriod > 10*time.Minute {
		return errInvalidConfig("grace period must be between 0 and 10 minutes")
	}
	if c.RetryDelay <= 0 || c.RetryDelay > time.Minute {
		return errInvalidConfig("retry delay must be between 0 and 1 minute")
	}
	return nil
}

// LeaseKey identifies a profile's observed network lease.
type LeaseKey struct {
	// Protocol is the supported Xray inbound protocol name.
	Protocol string
	// Email is the authenticated Xray profile identity.
	Email string
	// SourceIP is the canonical remote address of the lease.
	SourceIP string
}

// Observation is one active profile/source-IP pair from a complete snapshot.
type Observation struct {
	// Key identifies the observed profile and remote source address.
	Key LeaseKey
	// LastActivity is the latest profile traffic observation timestamp.
	LastActivity time.Time
	// FirstSeen is the start of the continuous runtime source-IP lease.
	FirstSeen time.Time
}

// Snapshot is a Controller telemetry snapshot used to reconcile observed leases.
type Snapshot struct {
	// Available indicates that Xray telemetry is reachable.
	Available bool
	// Full indicates that Leases represents a complete state snapshot.
	Full bool
	// Generation identifies the runtime process generation.
	Generation string
	// Sequence orders snapshots within Generation.
	Sequence uint64
	// SampledAt is when Controller assembled this snapshot.
	SampledAt time.Time
	// Leases contains active supported profile/source-IP observations.
	Leases []Observation
}

// Decision identifies one lease to close and why the policy selected it.
type Decision struct {
	// Lease is the oldest source-IP identity selected for disconnect.
	Lease LeaseKey
	// Reason describes the policy rule that selected Lease.
	Reason string
}

// profileKey groups source leases by Xray protocol and profile identity.
type profileKey struct {
	protocol string
	email    string
}

// leaseState holds the transient policy state for one observed source lease.
type leaseState struct {
	firstSeen time.Time
	closedAt  time.Time
	pending   bool
	retryAt   time.Time
}

// Tracker reconciles full snapshots and produces lease termination decisions.
type Tracker struct {
	config     Config
	available  bool
	generation string
	sequence   uint64
	leases     map[LeaseKey]*leaseState
	grace      map[profileKey]time.Time
}

// NewTracker creates an empty policy state machine.
func NewTracker(config Config) (*Tracker, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	return &Tracker{config: config, leases: make(map[LeaseKey]*leaseState), grace: make(map[profileKey]time.Time)}, nil
}

// Apply accepts a fresh complete snapshot, reconciles offline leases and returns
// any immediate third-lease enforcement decisions.
func (t *Tracker) Apply(snapshot Snapshot, now time.Time) []Decision {
	if t == nil {
		return nil
	}
	if !snapshot.Available || !snapshot.Full || strings.TrimSpace(snapshot.Generation) == "" || snapshot.Sequence == 0 {
		t.available = false
		return nil
	}
	if snapshot.Generation != t.generation {
		t.leases = make(map[LeaseKey]*leaseState)
		t.grace = make(map[profileKey]time.Time)
		t.generation = snapshot.Generation
		t.sequence = 0
	}
	if snapshot.Sequence <= t.sequence {
		return nil
	}
	t.available = true
	t.sequence = snapshot.Sequence
	observed := make(map[LeaseKey]time.Time, len(snapshot.Leases))
	for _, observation := range snapshot.Leases {
		key, ok := canonicalLeaseKey(observation.Key)
		if !ok || observation.LastActivity.IsZero() || observation.LastActivity.After(now.Add(time.Minute)) {
			continue
		}
		firstSeen := observation.FirstSeen
		if firstSeen.IsZero() || firstSeen.After(now.Add(time.Minute)) {
			firstSeen = now
		}
		observed[key] = firstSeen
	}
	for key := range t.leases {
		if _, ok := observed[key]; !ok {
			delete(t.leases, key)
		}
	}
	for key, firstSeen := range observed {
		state := t.leases[key]
		if state == nil {
			t.leases[key] = &leaseState{firstSeen: firstSeen}
			continue
		}
		if !state.closedAt.IsZero() && firstSeen.After(state.closedAt) {
			state.closedAt = time.Time{}
			state.firstSeen = firstSeen
			state.pending = false
			state.retryAt = time.Time{}
		}
	}
	return t.decisions(now, true)
}

// Due returns decisions whose grace or retry deadlines have elapsed.
func (t *Tracker) Due(now time.Time) []Decision {
	if t == nil || !t.available {
		return nil
	}
	return t.decisions(now, false)
}

// SetUnavailable pauses enforcement while a complete Controller snapshot is
// unavailable. Observed state is retained so a same-generation full snapshot
// can resume without resetting an active grace window.
func (t *Tracker) SetUnavailable() {
	if t != nil {
		t.available = false
	}
}

// Available reports whether the tracker has accepted a usable full snapshot.
func (t *Tracker) Available() bool { return t != nil && t.available }

// MarkPending prevents duplicate disconnect RPCs for the same lease.
func (t *Tracker) MarkPending(key LeaseKey) bool {
	state := t.leases[key]
	if state == nil || state.pending || !state.closedAt.IsZero() {
		return false
	}
	state.pending = true
	return true
}

// Complete records a disconnect outcome and makes failed operations retryable.
func (t *Tracker) Complete(key LeaseKey, succeeded bool, now time.Time) {
	state := t.leases[key]
	if state == nil || !state.pending {
		return
	}
	state.pending = false
	if succeeded {
		state.closedAt = now
		state.retryAt = time.Time{}
		profile := profileFor(key)
		if t.activeCount(profile) == 2 {
			t.grace[profile] = now.Add(t.config.GracePeriod)
		} else if t.activeCount(profile) <= 1 {
			delete(t.grace, profile)
		}
		return
	}
	state.retryAt = now.Add(t.config.RetryDelay)
}

// NextDeadline returns the next grace or retry deadline while the source is
// available. It returns false when no timer should currently run.
func (t *Tracker) NextDeadline() (time.Time, bool) {
	if t == nil || !t.available {
		return time.Time{}, false
	}
	var earliest time.Time
	for _, profile := range t.profiles() {
		active := t.activeFor(profile)
		if len(active) > t.config.MaxActiveLeases {
			if candidate := t.oldest(active); candidate != nil && !candidate.pending {
				deadline := candidate.retryAt
				if !deadline.IsZero() && (earliest.IsZero() || deadline.Before(earliest)) {
					earliest = deadline
				}
			}
			continue
		}
		if len(active) == 2 {
			deadline := t.grace[profile]
			if deadline.IsZero() {
				for _, key := range active {
					if state := t.leases[key]; state != nil && !state.retryAt.IsZero() && (deadline.IsZero() || state.retryAt.Before(deadline)) {
						deadline = state.retryAt
					}
				}
			}
			if !deadline.IsZero() && (earliest.IsZero() || deadline.Before(earliest)) {
				earliest = deadline
			}
		}
	}
	return earliest, !earliest.IsZero()
}

// ActiveLeases returns a stable copy of currently eligible observed leases.
func (t *Tracker) ActiveLeases() []LeaseKey {
	if t == nil {
		return nil
	}
	result := make([]LeaseKey, 0, len(t.leases))
	for key, state := range t.leases {
		if state.closedAt.IsZero() {
			result = append(result, key)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Protocol != result[j].Protocol {
			return result[i].Protocol < result[j].Protocol
		}
		if result[i].Email != result[j].Email {
			return result[i].Email < result[j].Email
		}
		return result[i].SourceIP < result[j].SourceIP
	})
	return result
}

// decisions selects the oldest lease when its grace, limit, or retry rule is due.
func (t *Tracker) decisions(now time.Time, immediateThird bool) []Decision {
	if !t.available {
		return nil
	}
	profiles := t.profiles()
	var decisions []Decision
	for _, profile := range profiles {
		active := t.activeFor(profile)
		if len(active) <= 1 {
			delete(t.grace, profile)
			continue
		}
		pending := false
		for _, key := range active {
			if state := t.leases[key]; state != nil && state.pending {
				pending = true
				break
			}
		}
		if pending {
			continue
		}
		if len(active) > t.config.MaxActiveLeases {
			oldest := t.oldest(active)
			if !immediateThird && (oldest == nil || oldest.pending || (oldest.retryAt.IsZero() == false && now.Before(oldest.retryAt))) {
				continue
			}
			if decision, ok := t.scheduleOldest(active, "max_active_leases_exceeded", now); ok {
				decisions = append(decisions, decision)
			}
			// The remaining two leases receive a fresh grace window.
			t.grace[profile] = now.Add(t.config.GracePeriod)
			continue
		}
		deadline, exists := t.grace[profile]
		if !exists {
			for _, key := range active {
				if state := t.leases[key]; state != nil && !state.retryAt.IsZero() && (deadline.IsZero() || state.retryAt.Before(deadline)) {
					deadline = state.retryAt
				}
			}
			if deadline.IsZero() {
				deadline = now.Add(t.config.GracePeriod)
			}
			t.grace[profile] = deadline
		}
		if !now.Before(deadline) {
			if decision, ok := t.scheduleOldest(active, "dual_lease_grace_expired", now); ok {
				decisions = append(decisions, decision)
				delete(t.grace, profile)
			}
		}
	}
	return decisions
}

// scheduleOldest marks the oldest eligible lease pending and returns its action.
func (t *Tracker) scheduleOldest(active []LeaseKey, reason string, now time.Time) (Decision, bool) {
	if len(active) == 0 {
		return Decision{}, false
	}
	sort.Slice(active, func(i, j int) bool {
		left, right := t.leases[active[i]], t.leases[active[j]]
		if !left.firstSeen.Equal(right.firstSeen) {
			return left.firstSeen.Before(right.firstSeen)
		}
		return active[i].SourceIP < active[j].SourceIP
	})
	state := t.leases[active[0]]
	if state.pending || !state.closedAt.IsZero() || (!state.retryAt.IsZero() && now.Before(state.retryAt)) {
		return Decision{}, false
	}
	state.pending = true
	return Decision{Lease: active[0], Reason: reason}, true
}

// profiles returns profiles that still have an observed non-terminated lease.
func (t *Tracker) profiles() []profileKey {
	set := make(map[profileKey]struct{}, len(t.leases))
	for key, state := range t.leases {
		if state.closedAt.IsZero() {
			set[profileFor(key)] = struct{}{}
		}
	}
	result := make([]profileKey, 0, len(set))
	for key := range set {
		result = append(result, key)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].protocol != result[j].protocol {
			return result[i].protocol < result[j].protocol
		}
		return result[i].email < result[j].email
	})
	return result
}

// oldest sorts active keys by connection time and returns the first state.
func (t *Tracker) oldest(active []LeaseKey) *leaseState {
	if len(active) == 0 {
		return nil
	}
	sort.Slice(active, func(i, j int) bool {
		left, right := t.leases[active[i]], t.leases[active[j]]
		if !left.firstSeen.Equal(right.firstSeen) {
			return left.firstSeen.Before(right.firstSeen)
		}
		return active[i].SourceIP < active[j].SourceIP
	})
	return t.leases[active[0]]
}

// activeFor returns observed leases for one profile that are not terminated.
func (t *Tracker) activeFor(profile profileKey) []LeaseKey {
	var active []LeaseKey
	for key, state := range t.leases {
		if profileFor(key) == profile && state.closedAt.IsZero() {
			active = append(active, key)
		}
	}
	return active
}

// activeCount reports the non-terminated lease count for one profile.
func (t *Tracker) activeCount(profile profileKey) int { return len(t.activeFor(profile)) }

// profileFor extracts a profile grouping key from a lease identity.
func profileFor(key LeaseKey) profileKey { return profileKey{protocol: key.Protocol, email: key.Email} }

// canonicalLeaseKey validates a lease identity and normalizes its protocol and IP.
func canonicalLeaseKey(key LeaseKey) (LeaseKey, bool) {
	key.Protocol = strings.ToLower(strings.TrimSpace(key.Protocol))
	key.Email = strings.TrimSpace(key.Email)
	address, err := netip.ParseAddr(strings.TrimSpace(key.SourceIP))
	if err != nil || address.Zone() != "" || key.Email == "" || len(key.Email) > 256 || strings.ContainsAny(key.Email, "\r\n\x00") {
		return LeaseKey{}, false
	}
	switch key.Protocol {
	case "vless", "vmess", "trojan":
	default:
		return LeaseKey{}, false
	}
	key.SourceIP = address.Unmap().String()
	return key, true
}

// configError represents an invalid lease policy configuration.
type configError string

// Error returns the configuration validation message.
func (e configError) Error() string { return string(e) }

// errInvalidConfig creates a validation error for an unsupported policy value.
func errInvalidConfig(message string) error { return configError(message) }

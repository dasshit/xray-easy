package store

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"xray-easy/internal/domain"
)

func TestShortIDReserveRejectsInvalidAndDuplicateGeneratedValues(t *testing.T) {
	db, ctx := openTestStore(t, "short-id-errors.db")
	valid := func() (string, error) { return "1111111111111111", nil }
	if err := db.EnsureReservedShortIDs(ctx, 0, valid); err == nil {
		t.Fatal("zero reserve size was accepted")
	}
	if err := db.EnsureReservedShortIDs(ctx, 1, nil); err == nil {
		t.Fatal("nil short ID generator was accepted")
	}
	if _, _, err := db.CreateClientWithReservedShortID(ctx, domain.Client{}, "uuid", "email", 1, valid); err == nil {
		t.Fatal("missing client ID was accepted")
	}
	if _, _, err := db.CreateClientWithReservedShortID(ctx, domain.Client{ID: "phone"}, "uuid", "email", 0, valid); err == nil {
		t.Fatal("zero reserve size was accepted for client creation")
	}
	failed := func() (string, error) { return "", errors.New("random source failed") }
	if err := db.EnsureReservedShortIDs(ctx, 1, failed); err == nil {
		t.Fatal("generator failure was ignored")
	}
	if ids, err := db.ListReservedShortIDs(ctx); err != nil || len(ids) != 0 {
		t.Fatalf("failed allocation left reserved IDs: %v, %v", ids, err)
	}
	sequence := []string{"", "0000000000000000", "1111111111111111"}
	index := 0
	if err := db.EnsureReservedShortIDs(ctx, 1, func() (string, error) {
		value := sequence[index]
		index++
		return value, nil
	}); err != nil {
		t.Fatalf("valid ID after rejected candidates: %v", err)
	}
	if err := db.EnsureReservedShortIDs(ctx, 2, valid); err == nil {
		t.Fatal("32 duplicate generated IDs were accepted")
	}
	if ids, err := db.ListReservedShortIDs(ctx); err != nil || len(ids) != 1 || ids[0] != "1111111111111111" {
		t.Fatalf("failed refill changed the existing reserve: %v, %v", ids, err)
	}
}

func TestChangeAdminPasswordRevokesSessionsAtomically(t *testing.T) {
	db, ctx := openTestStore(t, "password-change.db")
	admin := initTestAdmin(t, db, ctx)
	token, err := db.CreateSession(ctx, admin.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.ChangeAdminPassword(ctx, "", "new-hash"); err == nil {
		t.Fatal("empty admin ID was accepted")
	}
	if err := db.ChangeAdminPassword(ctx, admin.ID, ""); err == nil {
		t.Fatal("empty password hash was accepted")
	}
	if err := db.ChangeAdminPassword(ctx, "missing", "new-hash"); err == nil {
		t.Fatal("unknown administrator was updated")
	}
	if _, err := db.SessionAdmin(ctx, token); err != nil {
		t.Fatalf("failed change revoked session: %v", err)
	}
	if err := db.ChangeAdminPassword(ctx, admin.ID, "new-hash"); err != nil {
		t.Fatal(err)
	}
	updated, err := db.FirstAdmin(ctx)
	if err != nil || updated.PasswordHash != "new-hash" {
		t.Fatalf("password hash was not updated: %+v, %v", updated, err)
	}
	if _, err := db.SessionAdmin(ctx, token); err == nil {
		t.Fatal("password change did not revoke the existing session")
	}
}

func TestShortIDClaimRollbackPreservesReservation(t *testing.T) {
	db, ctx := openTestStore(t, "short-id-rollback.db")
	if err := db.CreateClient(ctx, domain.Client{ID: "phone", Name: "phone", Enabled: true}, "uuid-old", "old@example.test", "aaaaaaaaaaaaaaaa"); err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureReservedShortIDs(ctx, 1, func() (string, error) { return "bbbbbbbbbbbbbbbb", nil }); err != nil {
		t.Fatal(err)
	}
	if _, _, err := db.CreateClientWithReservedShortID(ctx, domain.Client{ID: "phone", Name: "duplicate", Enabled: true}, "uuid-new", "new@example.test", 1, nil); err == nil {
		t.Fatal("nil generator was accepted")
	}
	if _, _, err := db.CreateClientWithReservedShortID(ctx, domain.Client{ID: "phone", Name: "duplicate", Enabled: true}, "uuid-new", "new@example.test", 1, func() (string, error) { return "cccccccccccccccc", nil }); err == nil {
		t.Fatal("duplicate client ID was accepted")
	}
	ids, err := db.ListReservedShortIDs(ctx)
	if err != nil || len(ids) != 1 || ids[0] != "bbbbbbbbbbbbbbbb" {
		t.Fatalf("failed client insert consumed reserve: %v, %v", ids, err)
	}
}

func TestShortIDClaimReportsAReservationClaimedConcurrently(t *testing.T) {
	db, ctx := openTestStore(t, "short-id-concurrent-claim.db")
	if err := db.SeedReservedShortIDs(ctx, 1, func() (string, error) { return "bbbbbbbbbbbbbbbb", nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.Exec(`CREATE TRIGGER ignore_reserved_short_id_claim BEFORE UPDATE OF assigned_client_id ON reality_short_ids BEGIN SELECT RAISE(IGNORE); END`); err != nil {
		t.Fatal(err)
	}
	_, _, err := db.CreateClientWithReservedShortID(ctx, domain.Client{ID: "phone", Name: "phone", Enabled: true}, "uuid-phone", "phone@example.test", 1, func() (string, error) {
		return "cccccccccccccccc", nil
	})
	if err == nil || !strings.Contains(err.Error(), "claimed concurrently") {
		t.Fatalf("short ID claim error = %v, want concurrent-claim error", err)
	}
	if clients, listErr := db.ListClients(ctx); listErr != nil || len(clients) != 0 {
		t.Fatalf("failed concurrent claim inserted a client: %+v, %v", clients, listErr)
	}
	if reserved, listErr := db.ListReservedShortIDs(ctx); listErr != nil || len(reserved) != 1 || reserved[0] != "bbbbbbbbbbbbbbbb" {
		t.Fatalf("failed concurrent claim consumed reservation: %v, %v", reserved, listErr)
	}
}

func TestCreateClientWithReservedShortIDRollsBackGenerationAndMutationFailures(t *testing.T) {
	t.Run("reject unsupported protocol", func(t *testing.T) {
		db, ctx := openTestStore(t, "short-id-unsupported-protocol.db")
		client := domain.Client{ID: "phone", Protocol: domain.ProtocolVMess}
		if _, _, err := db.CreateClientWithReservedShortID(ctx, client, "uuid", "phone@example.test", 1, func() (string, error) { return "0123456789abcdef", nil }); err == nil || !strings.Contains(err.Error(), "only VLESS") {
			t.Fatalf("non-VLESS short-ID allocation error = %v", err)
		}
	})

	t.Run("exhausted generator error", func(t *testing.T) {
		db, ctx := openTestStore(t, "short-id-exhausted-generator.db")
		if err := db.SeedReservedShortIDs(ctx, 1, func() (string, error) { return "1111111111111111", nil }); err != nil {
			t.Fatal(err)
		}
		if _, err := db.db.Exec(`UPDATE reality_short_ids SET assigned_client_id='old-phone'`); err != nil {
			t.Fatal(err)
		}
		if _, _, err := db.CreateClientWithReservedShortID(ctx, domain.Client{ID: "new-phone"}, "uuid", "new@example.test", 1, func() (string, error) { return "", errors.New("entropy failed") }); err == nil || !strings.Contains(err.Error(), "entropy failed") {
			t.Fatalf("exhausted reserve generator error = %v", err)
		}
	})

	t.Run("assigned short-ID insert trigger", func(t *testing.T) {
		db, ctx := openTestStore(t, "short-id-assigned-insert-trigger.db")
		if err := db.SeedReservedShortIDs(ctx, 1, func() (string, error) { return "1111111111111111", nil }); err != nil {
			t.Fatal(err)
		}
		if _, err := db.db.Exec(`UPDATE reality_short_ids SET assigned_client_id='old-phone'`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.db.Exec(`CREATE TRIGGER block_assigned_short_id BEFORE INSERT ON reality_short_ids WHEN NEW.assigned_client_id IS NOT NULL BEGIN SELECT RAISE(ABORT, 'assigned insert blocked'); END`); err != nil {
			t.Fatal(err)
		}
		_, _, err := db.CreateClientWithReservedShortID(ctx, domain.Client{ID: "new-phone"}, "uuid", "new@example.test", 1, func() (string, error) { return "2222222222222222", nil })
		if err == nil || !strings.Contains(err.Error(), "assigned insert blocked") {
			t.Fatalf("assigned short-ID insert error = %v", err)
		}
		if clients, listErr := db.ListClients(ctx); listErr != nil || len(clients) != 0 {
			t.Fatalf("failed short-ID insert persisted client: %+v, %v", clients, listErr)
		}
	})

	t.Run("reserve refill error after exhaustion", func(t *testing.T) {
		db, ctx := openTestStore(t, "short-id-refill-trigger.db")
		if err := db.SeedReservedShortIDs(ctx, 1, func() (string, error) { return "1111111111111111", nil }); err != nil {
			t.Fatal(err)
		}
		if _, err := db.db.Exec(`UPDATE reality_short_ids SET assigned_client_id='old-phone'`); err != nil {
			t.Fatal(err)
		}
		calls := 0
		_, _, err := db.CreateClientWithReservedShortID(ctx, domain.Client{ID: "new-phone"}, "uuid", "new@example.test", 1, func() (string, error) {
			calls++
			if calls == 1 {
				return "2222222222222222", nil
			}
			return "", errors.New("reserve refill failed")
		})
		if err == nil || !strings.Contains(err.Error(), "reserve refill failed") {
			t.Fatalf("reserve refill error = %v", err)
		}
		if clients, listErr := db.ListClients(ctx); listErr != nil || len(clients) != 0 {
			t.Fatalf("failed refill persisted client: %+v, %v", clients, listErr)
		}
	})

	t.Run("claim update trigger", func(t *testing.T) {
		db, ctx := openTestStore(t, "short-id-claim-update-trigger.db")
		if err := db.SeedReservedShortIDs(ctx, 1, func() (string, error) { return "1111111111111111", nil }); err != nil {
			t.Fatal(err)
		}
		if _, err := db.db.Exec(`CREATE TRIGGER block_short_id_claim BEFORE UPDATE OF assigned_client_id ON reality_short_ids BEGIN SELECT RAISE(ABORT, 'claim update blocked'); END`); err != nil {
			t.Fatal(err)
		}
		_, _, err := db.CreateClientWithReservedShortID(ctx, domain.Client{ID: "phone"}, "uuid", "phone@example.test", 1, func() (string, error) { return "2222222222222222", nil })
		if err == nil || !strings.Contains(err.Error(), "claim update blocked") {
			t.Fatalf("short-ID claim update error = %v", err)
		}
	})

	t.Run("pool initialization marker trigger", func(t *testing.T) {
		db, ctx := openTestStore(t, "short-id-marker-trigger.db")
		if err := db.SeedReservedShortIDs(ctx, 1, func() (string, error) { return "1111111111111111", nil }); err != nil {
			t.Fatal(err)
		}
		if _, err := db.db.Exec(`DELETE FROM schema_migrations WHERE version=3`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.db.Exec(`CREATE TRIGGER block_short_id_marker BEFORE INSERT ON schema_migrations WHEN NEW.version=3 BEGIN SELECT RAISE(ABORT, 'marker blocked'); END`); err != nil {
			t.Fatal(err)
		}
		_, _, err := db.CreateClientWithReservedShortID(ctx, domain.Client{ID: "phone"}, "uuid", "phone@example.test", 1, func() (string, error) { return "2222222222222222", nil })
		if err == nil || !strings.Contains(err.Error(), "marker blocked") {
			t.Fatalf("short-ID marker insertion error = %v", err)
		}
		if clients, listErr := db.ListClients(ctx); listErr != nil || len(clients) != 0 {
			t.Fatalf("failed marker insert persisted client: %+v, %v", clients, listErr)
		}
	})
}

func TestInitialShortIDReserveDrainsWithoutBackgroundRefill(t *testing.T) {
	db, ctx := openTestStore(t, "short-id-drain.db")
	next := 0
	generate := func() (string, error) {
		next++
		return fmt.Sprintf("%016x", next), nil
	}
	if err := db.SeedReservedShortIDs(ctx, 2, generate); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		id := fmt.Sprintf("phone-%d", i)
		if _, exhausted, err := db.CreateClientWithReservedShortID(ctx, domain.Client{ID: id, Name: id, Enabled: true}, "uuid-"+id, id+"@example.test", 2, generate); err != nil || exhausted {
			t.Fatalf("claim initial reserve: exhausted=%v, err=%v", exhausted, err)
		}
		if err := db.SeedReservedShortIDs(ctx, 2, generate); err != nil {
			t.Fatal(err)
		}
	}
	if ids, err := db.ListReservedShortIDs(ctx); err != nil || len(ids) != 0 {
		t.Fatalf("background seeding refilled a draining reserve: %v, %v", ids, err)
	}
	if _, exhausted, err := db.CreateClientWithReservedShortID(ctx, domain.Client{ID: "overflow", Name: "overflow", Enabled: true}, "uuid-overflow", "overflow@example.test", 2, generate); err != nil || !exhausted {
		t.Fatalf("exhaustion did not trigger replacement and refill: %v, %v", exhausted, err)
	}
	if ids, err := db.ListReservedShortIDs(ctx); err != nil || len(ids) != 2 {
		t.Fatalf("reserve was not refilled after exhaustion: %v, %v", ids, err)
	}
}

func TestLegacyClientsGetInitialReserveOnlyOnce(t *testing.T) {
	db, ctx := openTestStore(t, "legacy-short-id-pool.db")
	createTestClient(t, db, ctx, "legacy")
	next := 0
	generate := func() (string, error) {
		next++
		return fmt.Sprintf("%016x", next), nil
	}
	if err := db.SeedReservedShortIDs(ctx, 2, generate); err != nil {
		t.Fatal(err)
	}
	if ids, err := db.ListReservedShortIDs(ctx); err != nil || len(ids) != 2 {
		t.Fatalf("legacy reserve = %v, %v; want two IDs", ids, err)
	}
	if _, exhausted, err := db.CreateClientWithReservedShortID(ctx, domain.Client{ID: "new", Name: "new", Enabled: true}, "uuid-new", "new@example.test", 2, generate); err != nil || exhausted {
		t.Fatalf("claim legacy reserve: exhausted=%v, err=%v", exhausted, err)
	}
	if err := db.SeedReservedShortIDs(ctx, 2, generate); err != nil {
		t.Fatal(err)
	}
	if ids, err := db.ListReservedShortIDs(ctx); err != nil || len(ids) != 1 {
		t.Fatalf("legacy reserve refilled after claim: %v, %v", ids, err)
	}
}

func TestFirstClientCreatesInitialShortIDReserveAtomically(t *testing.T) {
	db, ctx := openTestStore(t, "cold-start-short-ids.db")
	next := 0
	generate := func() (string, error) {
		next++
		return fmt.Sprintf("%016x", next), nil
	}
	shortID, exhausted, err := db.CreateClientWithReservedShortID(ctx, domain.Client{ID: "phone", Name: "phone", Enabled: true}, "uuid-phone", "phone@example.test", 3, generate)
	if err != nil || exhausted || shortID == "" {
		t.Fatalf("cold-start client = %q, exhausted=%v, err=%v", shortID, exhausted, err)
	}
	if ids, err := db.ListReservedShortIDs(ctx); err != nil || len(ids) != 2 {
		t.Fatalf("cold-start reserve = %v, %v", ids, err)
	}
	if err := db.SeedReservedShortIDs(ctx, 3, generate); err != nil {
		t.Fatal(err)
	}
	if ids, err := db.ListReservedShortIDs(ctx); err != nil || len(ids) != 2 {
		t.Fatalf("cold-start reserve refilled after claim: %v, %v", ids, err)
	}
	if err := db.SeedReservedShortIDs(ctx, 0, generate); err == nil {
		t.Fatal("zero initial reserve size was accepted")
	}
	if err := db.SeedReservedShortIDs(ctx, 3, nil); err == nil {
		t.Fatal("nil initial reserve generator was accepted")
	}
}

package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestReadOnlyHelpersReportMissingDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "state.db")
	if err := ValidateDatabase(path); err == nil {
		t.Fatal("ValidateDatabase accepted a missing database")
	}
	if _, err := ReadSettingsFromDatabase(path); err == nil {
		t.Fatal("ReadSettingsFromDatabase accepted a missing database")
	}
	if _, err := CountExpiredEnabledClientsFromDatabase(context.Background(), path, time.Now()); err == nil {
		t.Fatal("CountExpiredEnabledClientsFromDatabase accepted a missing database")
	}
}

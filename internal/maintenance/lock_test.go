package maintenance

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAcquireEmptyPathReturnsNoopLock(t *testing.T) {
	lock, err := Acquire(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if lock == nil {
		t.Fatal("Acquire returned nil lock")
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := (*Lock)(nil).Close(); err != nil {
		t.Fatalf("closing nil lock: %v", err)
	}
}

func TestAcquireSerializesCallersAndHonorsCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "maintenance.lock")
	first, err := Acquire(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("lock file mode = %v, %v", info, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	started := time.Now()
	second, err := Acquire(ctx, path)
	if err == nil {
		_ = second.Close()
		t.Fatal("second caller acquired a held lock")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked Acquire error = %v, want deadline exceeded", err)
	}
	if time.Since(started) < 100*time.Millisecond {
		t.Fatal("Acquire returned before observing cancellation while waiting")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	third, err := Acquire(context.Background(), path)
	if err != nil {
		t.Fatalf("lock was not released after Close: %v", err)
	}
	if err := third.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAcquireReturnsParentPathError(t *testing.T) {
	root := t.TempDir()
	parentFile := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(parentFile, []byte("block"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(context.Background(), filepath.Join(parentFile, "maintenance.lock")); err == nil {
		t.Fatal("Acquire succeeded below a regular file")
	}
}

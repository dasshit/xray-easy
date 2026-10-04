// Package maintenance provides process-wide locks for destructive and configuration operations.
package maintenance

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// Lock is an advisory inter-process maintenance lock. The daemon takes it
// around Xray-changing operations; CLI backup/restore commands take it for
// their whole critical section.
type Lock struct {
	file *os.File
}

// Acquire performs the operation represented by its name.
func Acquire(ctx context.Context, path string) (*Lock, error) {
	return acquire(ctx, path, unix.Flock)
}

func acquire(ctx context.Context, path string, flock func(fd int, how int) error) (*Lock, error) {
	if path == "" {
		return &Lock{}, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		err = flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return &Lock{file: file}, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			_ = file.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// Close releases resources held by the value.
func (l *Lock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	err := unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
	closeErr := l.file.Close()
	if err != nil {
		return err
	}
	return closeErr
}

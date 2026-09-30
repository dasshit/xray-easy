package main

import (
	"errors"
	"io"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

type emptyTerminalReader struct{}

func (emptyTerminalReader) Read([]byte) (int, error) { return 0, nil }

func TestReadPasswordLineNoEchoRestoresTerminalAndHandlesFailures(t *testing.T) {
	original := &unix.Termios{Lflag: unix.ECHO | 1}

	t.Run("successful read restores original mode", func(t *testing.T) {
		var modes []unix.Termios
		password, err := readPasswordLineNoEchoWith(7,
			func(fd int) (*unix.Termios, error) {
				if fd != 7 {
					t.Fatalf("terminal descriptor = %d", fd)
				}
				return original, nil
			},
			func(_ int, mode *unix.Termios) error {
				modes = append(modes, *mode)
				return nil
			},
			func() ([]byte, error) { return []byte("secret"), nil },
		)
		if err != nil || string(password) != "secret" {
			t.Fatalf("password read = %q, %v", password, err)
		}
		if len(modes) != 2 || modes[0].Lflag&unix.ECHO != 0 || modes[1] != *original {
			t.Fatalf("terminal modes were not hidden then restored: %+v", modes)
		}
	})

	t.Run("non terminal is reported before changing mode", func(t *testing.T) {
		setCalls := 0
		password, err := readPasswordLineNoEchoWith(7,
			func(int) (*unix.Termios, error) { return nil, errors.New("not a tty") },
			func(int, *unix.Termios) error { setCalls++; return nil },
			func() ([]byte, error) { t.Fatal("read should not run"); return nil, nil },
		)
		if password != nil || err == nil || err.Error() != "input is not a terminal" || setCalls != 0 {
			t.Fatalf("non-terminal result = %q, %v; set calls=%d", password, err, setCalls)
		}
	})

	t.Run("failed echo disable does not read password", func(t *testing.T) {
		wantErr := errors.New("set mode failed")
		readCalled := false
		password, err := readPasswordLineNoEchoWith(7,
			func(int) (*unix.Termios, error) { return original, nil },
			func(int, *unix.Termios) error { return wantErr },
			func() ([]byte, error) { readCalled = true; return nil, nil },
		)
		if password != nil || !errors.Is(err, wantErr) || readCalled {
			t.Fatalf("failed echo disable result = %q, %v; readCalled=%v", password, err, readCalled)
		}
	})

	t.Run("failed restoration clears password bytes", func(t *testing.T) {
		wantErr := errors.New("restore mode failed")
		secret := []byte("secret")
		setCalls := 0
		password, err := readPasswordLineNoEchoWith(7,
			func(int) (*unix.Termios, error) { return original, nil },
			func(int, *unix.Termios) error {
				setCalls++
				if setCalls == 2 {
					return wantErr
				}
				return nil
			},
			func() ([]byte, error) { return secret, nil },
		)
		if password != nil || !errors.Is(err, wantErr) || string(secret) != "\x00\x00\x00\x00\x00\x00" {
			t.Fatalf("restoration failure result = %q, %v; secret buffer=%v", password, err, secret)
		}
	})

	t.Run("partial line is cleared after read error", func(t *testing.T) {
		password, err := readTerminalLineFrom(strings.NewReader("partial"))
		if password != nil || !errors.Is(err, io.EOF) {
			t.Fatalf("partial password at EOF = %q, %v", password, err)
		}
	})

	t.Run("zero-byte read without error is rejected", func(t *testing.T) {
		password, err := readTerminalLineFrom(emptyTerminalReader{})
		if password != nil || err == nil || err.Error() != "terminal returned no input" {
			t.Fatalf("empty terminal read = %q, %v", password, err)
		}
	})
}

func TestReadPasswordLineNoEchoRejectsInvalidDescriptor(t *testing.T) {
	if _, err := readPasswordLineNoEcho(-1); err == nil || err.Error() != "input is not a terminal" {
		t.Fatalf("readPasswordLineNoEcho on invalid descriptor = %v", err)
	}
}

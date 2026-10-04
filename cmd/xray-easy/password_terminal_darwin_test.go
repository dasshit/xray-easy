//go:build darwin

package main

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestSetTerminalModeRejectsInvalidDescriptor(t *testing.T) {
	if err := setTerminalMode(-1, &unix.Termios{}); err == nil {
		t.Fatal("setTerminalMode accepted an invalid file descriptor")
	}
}

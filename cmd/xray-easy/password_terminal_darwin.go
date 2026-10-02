//go:build darwin

package main

import "golang.org/x/sys/unix"

// getTerminalMode returns the requested value.
func getTerminalMode(fd int) (*unix.Termios, error) {
	return unix.IoctlGetTermios(fd, unix.TIOCGETA)
}

// setTerminalMode updates the requested value.
func setTerminalMode(fd int, mode *unix.Termios) error {
	return unix.IoctlSetTermios(fd, unix.TIOCSETA, mode)
}

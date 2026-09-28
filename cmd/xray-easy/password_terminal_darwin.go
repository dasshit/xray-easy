//go:build darwin

package main

import "golang.org/x/sys/unix"

func getTerminalMode(fd int) (*unix.Termios, error) {
	return unix.IoctlGetTermios(fd, unix.TIOCGETA)
}

func setTerminalMode(fd int, mode *unix.Termios) error {
	return unix.IoctlSetTermios(fd, unix.TIOCSETA, mode)
}

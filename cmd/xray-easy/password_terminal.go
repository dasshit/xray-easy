package main

import (
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// readPasswordLineNoEcho reads the requested value.
func readPasswordLineNoEcho(fd int) (password []byte, resultErr error) {
	return readPasswordLineNoEchoWith(fd, getTerminalMode, setTerminalMode, readTerminalLine)
}

// readPasswordLineNoEchoWith reads the requested value.
func readPasswordLineNoEchoWith(fd int, getMode func(int) (*unix.Termios, error), setMode func(int, *unix.Termios) error, readLine func() ([]byte, error)) (password []byte, resultErr error) {
	original, err := getMode(fd)
	if err != nil {
		return nil, errors.New("input is not a terminal")
	}
	hidden := *original
	hidden.Lflag &^= unix.ECHO
	if err := setMode(fd, &hidden); err != nil {
		return nil, err
	}
	defer func() {
		if err := setMode(fd, original); err != nil && resultErr == nil {
			clear(password)
			password = nil
			resultErr = err
		}
	}()
	return readLine()
}

// readTerminalLine reads the requested value.
func readTerminalLine() ([]byte, error) {
	return readTerminalLineFrom(os.Stdin)
}

// readTerminalLineFrom reads the requested value.
func readTerminalLineFrom(input io.Reader) ([]byte, error) {
	password := make([]byte, 0, 64)
	var next [1]byte
	for {
		n, err := input.Read(next[:])
		if err != nil {
			clear(password)
			return nil, err
		}
		if n == 0 {
			clear(password)
			return nil, errors.New("terminal returned no input")
		}
		if next[0] == '\n' || next[0] == '\r' {
			return password, nil
		}
		password = append(password, next[0])
	}
}

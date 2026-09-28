package main

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func readPasswordLineNoEcho(fd int) (password []byte, resultErr error) {
	original, err := getTerminalMode(fd)
	if err != nil {
		return nil, errors.New("input is not a terminal")
	}
	hidden := *original
	hidden.Lflag &^= unix.ECHO
	if err := setTerminalMode(fd, &hidden); err != nil {
		return nil, err
	}
	defer func() {
		if err := setTerminalMode(fd, original); err != nil && resultErr == nil {
			clear(password)
			password = nil
			resultErr = err
		}
	}()
	return readTerminalLine()
}

func readTerminalLine() ([]byte, error) {
	password := make([]byte, 0, 64)
	var next [1]byte
	for {
		n, err := os.Stdin.Read(next[:])
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

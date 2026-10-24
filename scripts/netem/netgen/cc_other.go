//go:build !linux

package main

import (
	"errors"
	"syscall"
)

// setCongestion: only Linux chooses a socket's congestion control.
func setCongestion(c syscall.RawConn, name string) error {
	return errors.New("-cc: Linux only")
}

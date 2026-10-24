//go:build linux

package main

import "syscall"

// setCongestion gives a socket the congestion control `name`
// (TCP_CONGESTION), before it connects or listens.
func setCongestion(c syscall.RawConn, name string) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = syscall.SetsockoptString(int(fd), syscall.IPPROTO_TCP, syscall.TCP_CONGESTION, name)
	}); err != nil {
		return err
	}
	return serr
}

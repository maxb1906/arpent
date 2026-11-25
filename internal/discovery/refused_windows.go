package discovery

import (
	"errors"
	"syscall"
)

// WSAECONNREFUSED (10061) : Windows n'utilise pas syscall.ECONNREFUSED.
const wsaeConnRefused = syscall.Errno(10061)

func isRefused(err error) bool {
	return errors.Is(err, wsaeConnRefused) || errors.Is(err, syscall.ECONNREFUSED)
}

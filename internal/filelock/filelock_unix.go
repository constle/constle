//go:build unix

// Package filelock provides blocking advisory file locks for the durable
// per-user stores (the spending ledger, the a2a replay store): Shared for
// readers, Exclusive for writers. Locks BLOCK until granted, so concurrent
// constle processes touching the same state serialize instead of failing.
//
// Every OS-specific lock syscall stays behind these build-tagged files:
// calling syscall.Flock directly from a shared .go file broke the native
// Windows build (syscall.Flock/LOCK_* are undefined for GOOS=windows) — a
// regression this package exists to prevent.
package filelock

import (
	"os"
	"syscall"
)

// On unix the advisory lock is flock(2).
func Shared(f *os.File) error    { return syscall.Flock(int(f.Fd()), syscall.LOCK_SH) }
func Exclusive(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX) }
func Unlock(f *os.File) error    { return syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }

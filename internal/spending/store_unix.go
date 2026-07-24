//go:build unix

package spending

import (
	"os"
	"syscall"
)

// Advisory file locking on unix uses flock(2). These wrap the exact calls the
// DailyStore relies on (see store.go): TodayTotal takes a shared lock, Append
// an exclusive one. Both BLOCK until the lock is granted, so concurrent
// constle processes charging the same DID serialize.
//
// The Windows counterpart (LockFileEx) lives in store_windows.go. Keep every
// OS-specific lock syscall behind these build-tagged files: calling
// syscall.Flock directly from a shared .go file broke the native Windows build
// (syscall.Flock/LOCK_* are undefined for GOOS=windows) — a regression this
// split exists to prevent.
func lockShared(f *os.File) error    { return syscall.Flock(int(f.Fd()), syscall.LOCK_SH) }
func lockExclusive(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX) }
func unlockFile(f *os.File) error    { return syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }

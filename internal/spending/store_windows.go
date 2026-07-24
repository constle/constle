//go:build windows

package spending

import (
	"os"

	"golang.org/x/sys/windows"
)

// Advisory file locking on Windows uses LockFileEx/UnlockFileEx — the portable
// counterpart to unix flock(2) in store_unix.go. It preserves the DailyStore
// contract (see store.go):
//
//   - shared lock  -> flags 0                       (many readers, no writer)
//   - exclusive    -> LOCKFILE_EXCLUSIVE_LOCK        (one writer, no readers)
//   - blocking     -> LOCKFILE_FAIL_IMMEDIATELY is deliberately NOT set, so a
//     contended lock waits rather than failing — matching flock's blocking
//     semantics, which is what makes "concurrent charges serialize" hold.
//
// The whole file is locked as a single region starting at offset 0 (the zero
// Overlapped) spanning the maximum length; lock and unlock use the identical
// range, as Windows requires. Locks are released explicitly by unlockFile and,
// as a backstop, by the OS when the file handle is closed.
const (
	lockRangeLow  = ^uint32(0) // low 32 bits of the locked byte count
	lockRangeHigh = ^uint32(0) // high 32 bits — together, the maximum range
)

func lockShared(f *os.File) error    { return lockFileEx(f, 0) }
func lockExclusive(f *os.File) error { return lockFileEx(f, windows.LOCKFILE_EXCLUSIVE_LOCK) }

func lockFileEx(f *os.File, flags uint32) error {
	return windows.LockFileEx(
		windows.Handle(f.Fd()), flags, 0,
		lockRangeLow, lockRangeHigh, &windows.Overlapped{},
	)
}

func unlockFile(f *os.File) error {
	return windows.UnlockFileEx(
		windows.Handle(f.Fd()), 0,
		lockRangeLow, lockRangeHigh, &windows.Overlapped{},
	)
}

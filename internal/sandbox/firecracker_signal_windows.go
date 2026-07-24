//go:build windows

package sandbox

import "os"

// Windows counterpart of firecracker_signal_unix.go. The Firecracker backend
// never runs on Windows (no KVM, no firecracker binary), so these paths are
// unreachable at runtime and exist only so the package compiles for
// GOOS=windows (cmd/constle imports it). Windows has no SIGTERM; both fall back
// to a best-effort TerminateProcess.
func termProcess(pid int) error { return winTerminate(pid) }
func killProcess(pid int) error { return winTerminate(pid) }

func winTerminate(pid int) error {
	if pid <= 0 {
		return nil
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return nil
	}
	return p.Kill()
}

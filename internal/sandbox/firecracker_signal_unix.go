//go:build unix

package sandbox

import "syscall"

// termProcess / killProcess signal a firecracker sidecar (squid) during
// teardown. SIGTERM first so squid can flush its access log; SIGKILL to
// escalate. See teardownFirecrackerRun in firecracker_state.go.
//
// These live behind build tags because syscall.Kill is undefined for
// GOOS=windows. The Firecracker backend is Linux-only at runtime, but the
// package must still COMPILE on Windows (cmd/constle imports it) — hence the
// windows counterpart in firecracker_signal_windows.go. Do not call
// syscall.Kill directly from a shared .go file (that regression is what this
// split prevents).
func termProcess(pid int) error { return syscall.Kill(pid, syscall.SIGTERM) }
func killProcess(pid int) error { return syscall.Kill(pid, syscall.SIGKILL) }

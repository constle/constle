package sandbox

import (
	"time"

	"github.com/constle/constle/pkg/manifest"
)

// SandboxBackend is the interface every isolation backend must implement.
// The CLI talks only to this interface — not to any backend directly.
//
// Current and planned backends:
//
//	v0.2: DockerBackend     — Docker + Squid proxy
//	v0.5: FirecrackerBackend — Firecracker microVM (planned)
//	v1.5+: WasmBackend      — WebAssembly runtime (planned)
type SandboxBackend interface {
	// Start provisions the sandbox and returns a RunContext for subsequent calls.
	Start(m *manifest.AgentManifest) (*RunContext, error)

	// Wait blocks until the agent exits and returns its exit code.
	Wait(ctx *RunContext) (int, error)

	// Kill terminates the running agent (graceful first, force after a short
	// grace period) WITHOUT cleaning up resources — Wait unblocks and the
	// normal Stop path still runs. Used for Ctrl+C and max_duration_seconds.
	Kill(ctx *RunContext) error

	// Stop terminates and cleans up all resources for a run.
	// Always called — even after Wait and on error paths.
	Stop(ctx *RunContext) error

	// Logs returns the combined stdout+stderr of the agent container.
	Logs(ctx *RunContext) ([]byte, error)
}

// RunContext holds all state for a single agent run.
// Created by Start() and passed to all subsequent calls.
type RunContext struct {
	// RunID is the unique identifier for this run, present in every audit log line.
	RunID string

	AgentName string

	// Backend identifies which backend created this context.
	Backend BackendType

	// AgentContainerID is the Docker container ID used for wait/logs/stop.
	AgentContainerID string

	// ProxyContainerID is the Docker container ID of the Squid proxy.
	ProxyContainerID string

	// NetworkName is the internal Docker network for this run.
	NetworkName string

	// SquidConfigPath is the path to the temporary Squid config; deleted by Stop.
	SquidConfigPath string

	StartTime time.Time

	IsolationLevel string

	// VMPid is the firecracker process ID (Firecracker backend only).
	VMPid int

	// TAPDevice is the host TAP interface name (Firecracker backend only).
	TAPDevice string

	// SquidPID is the per-run host Squid process (Firecracker backend only).
	SquidPID int

	// SquidAccessLog is the host path of the per-run Squid access log
	// (Firecracker backend only). Non-empty means network audit events are
	// read from this file instead of from a proxy container.
	SquidAccessLog string

	// RunDir is the per-run state directory (Firecracker backend only).
	RunDir string

	// externalNetworkName is the outward-facing network (proxy ↔ internet).
	// Package-internal; only Stop needs it for cleanup.
	externalNetworkName string
}

// BackendType is a human-readable backend identifier used in audit logs and CLI output.
type BackendType string

const (
	BackendDocker      BackendType = "docker"
	BackendFirecracker BackendType = "firecracker"
	BackendWasm        BackendType = "wasm"
)

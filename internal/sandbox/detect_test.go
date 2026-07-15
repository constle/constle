package sandbox

import (
	"bytes"
	"strings"
	"testing"

	"github.com/constle/constle/pkg/manifest"
)

// withStubbedDocker forces dockerAvailable to a fixed value and captures
// warning output for the duration of one test, restoring both afterwards.
func withStubbedDocker(t *testing.T, available bool) *bytes.Buffer {
	t.Helper()

	origDocker := dockerAvailable
	origOut := detectOut
	t.Cleanup(func() {
		dockerAvailable = origDocker
		detectOut = origOut
	})

	dockerAvailable = func() bool { return available }
	buf := &bytes.Buffer{}
	detectOut = buf
	return buf
}

// TestExplicitDockerOverrideWarnsOnKernelIsolation is the regression guard for
// the mismatch between an explicit --backend=docker override and a manifest
// that requires kernel isolation: the override path must warn just as loudly
// as the automatic path, not run silently.
func TestExplicitDockerOverrideWarnsOnKernelIsolation(t *testing.T) {
	buf := withStubbedDocker(t, true)

	backend, backendType, err := DetectBestBackend(manifest.IsolationKernel, string(BackendDocker))
	if err != nil {
		t.Fatalf("DetectBestBackend() error = %v, want nil", err)
	}
	if backendType != BackendDocker {
		t.Errorf("backend type = %q, want %q", backendType, BackendDocker)
	}
	if _, ok := backend.(*DockerBackend); !ok {
		t.Errorf("backend = %T, want *DockerBackend", backend)
	}

	out := buf.String()
	if !strings.Contains(out, "⚠️") {
		t.Errorf("expected a ⚠️ warning on kernel+docker override, got:\n%s", out)
	}
	if !strings.Contains(out, "NOT kernel-level isolation") {
		t.Errorf("warning should state Docker is NOT kernel-level isolation, got:\n%s", out)
	}
}

// TestExplicitDockerOverrideQuietForNonKernel makes sure the new warning is
// scoped to kernel isolation only — weaker levels must stay silent.
func TestExplicitDockerOverrideQuietForNonKernel(t *testing.T) {
	for _, level := range []manifest.IsolationLevel{
		manifest.IsolationNone,
		manifest.IsolationProcess,
		manifest.IsolationNetwork,
	} {
		buf := withStubbedDocker(t, true)

		_, backendType, err := DetectBestBackend(level, string(BackendDocker))
		if err != nil {
			t.Fatalf("DetectBestBackend(%q) error = %v, want nil", level, err)
		}
		if backendType != BackendDocker {
			t.Errorf("isolation %q: backend type = %q, want %q", level, backendType, BackendDocker)
		}
		if out := buf.String(); out != "" {
			t.Errorf("isolation %q should not warn on --backend=docker, got:\n%s", level, out)
		}
	}
}

// TestExplicitDockerOverrideErrorsWhenDaemonDown confirms the override still
// fails hard (never warns-then-continues) when Docker itself is unreachable.
func TestExplicitDockerOverrideErrorsWhenDaemonDown(t *testing.T) {
	buf := withStubbedDocker(t, false)

	if _, _, err := DetectBestBackend(manifest.IsolationKernel, string(BackendDocker)); err == nil {
		t.Fatal("DetectBestBackend() error = nil, want an error when the Docker daemon is down")
	}
	if out := buf.String(); out != "" {
		t.Errorf("no warning should be printed when Docker is unavailable, got:\n%s", out)
	}
}

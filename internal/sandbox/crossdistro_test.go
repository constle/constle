package sandbox

// Tests for the cross-distro hardening: no hardcoded install path for the
// firecracker binary, no external-command failure that loses its cause when
// the tool is simply not on this distro, and no dependency on GNU cp.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCmdErrorKeepsCauseWhenToolProducedNoOutput(t *testing.T) {
	// The missing-binary case: exec fails before the tool can say anything.
	cause := errors.New(`exec: "nft": executable file not found in $PATH`)
	err := cmdError("nft -f", cause, nil)
	if !errors.Is(err, cause) {
		t.Errorf("cmdError dropped the exec error: %v", err)
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error hides the cause: %v", err)
	}

	// The tool-spoke case: its stderr is the better message.
	err = cmdError("nft -f", errors.New("exit status 1"), []byte("syntax error, line 3\n"))
	if !strings.Contains(err.Error(), "syntax error, line 3") {
		t.Errorf("error lost the tool's own output: %v", err)
	}
}

func TestSparseFlagUnsupported(t *testing.T) {
	cases := []struct {
		out  string
		want bool
	}{
		{"cp: unrecognized option '--sparse=always'\nBusyBox v1.36.1", true},
		{"cp: unrecognized option: sparse", true},
		{"cp: invalid option -- sparse", true},
		{"cp: illegal option -- -sparse=always", true},
		// Real copy failures must not trigger a retry, even ones that
		// happen to mention "sparse" in a filename.
		{"cp: cannot stat '/var/lib/constle/firecracker/images/default.ext4': No such file or directory", false},
		{"cp: cannot create regular file 'sparse.img': Permission denied", false},
		{"", false},
	}
	for _, c := range cases {
		if got := sparseFlagUnsupported([]byte(c.out)); got != c.want {
			t.Errorf("sparseFlagUnsupported(%q) = %v, want %v", c.out, got, c.want)
		}
	}
}

func TestCopyImageCopiesContent(t *testing.T) {
	if _, err := fcLookPath("cp"); err != nil {
		t.Skip("no cp on this host")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "src.ext4")
	dst := filepath.Join(dir, "dst.ext4")
	if err := os.WriteFile(src, []byte("image-bytes"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := copyImage(src, dst); err != nil {
		t.Fatalf("copyImage: %v", err)
	}
	data, err := os.ReadFile(dst)
	if err != nil || string(data) != "image-bytes" {
		t.Fatalf("dst content = %q, err = %v", data, err)
	}
}

func TestCopyImageReportsRealFailures(t *testing.T) {
	dir := t.TempDir()
	err := copyImage(filepath.Join(dir, "does-not-exist"), filepath.Join(dir, "dst"))
	if err == nil {
		t.Fatal("copyImage of a missing source must fail")
	}
	if strings.TrimSpace(strings.TrimPrefix(err.Error(), "cannot copy rootfs:")) == "" {
		t.Errorf("failure carries no cause: %v", err)
	}
}

// stubFCResolution swaps the resolution inputs for one test.
func stubFCResolution(t *testing.T, lookPath func(string) (string, error), fallback string) {
	t.Helper()
	origLook, origFallback := fcLookPath, fcFallbackBinary
	fcLookPath, fcFallbackBinary = lookPath, fallback
	t.Cleanup(func() { fcLookPath, fcFallbackBinary = origLook, origFallback })
}

func TestResolveFirecrackerBinaryPrefersPATH(t *testing.T) {
	dir := t.TempDir()
	installed := filepath.Join(dir, "firecracker")
	if err := os.WriteFile(installed, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	stubFCResolution(t, func(string) (string, error) { return installed, nil }, "/nonexistent/firecracker")

	got, err := resolveFirecrackerBinary()
	if err != nil {
		t.Fatalf("resolveFirecrackerBinary: %v", err)
	}
	if got != installed {
		t.Errorf("resolved %q, want the PATH hit %q", got, installed)
	}
	if !filepath.IsAbs(got) {
		t.Errorf("jailer needs an absolute --exec-file, got %q", got)
	}
}

func TestResolveFirecrackerBinaryFallsBackToInstallPath(t *testing.T) {
	dir := t.TempDir()
	fallback := filepath.Join(dir, "firecracker")
	if err := os.WriteFile(fallback, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	stubFCResolution(t, func(string) (string, error) { return "", errors.New("not in PATH") }, fallback)

	got, err := resolveFirecrackerBinary()
	if err != nil {
		t.Fatalf("resolveFirecrackerBinary: %v", err)
	}
	if got != fallback {
		t.Errorf("resolved %q, want fallback %q", got, fallback)
	}
}

func TestResolveFirecrackerBinaryActionableWhenAbsent(t *testing.T) {
	stubFCResolution(t, func(string) (string, error) { return "", errors.New("not in PATH") },
		filepath.Join(t.TempDir(), "no-such-binary"))

	_, err := resolveFirecrackerBinary()
	if err == nil {
		t.Fatal("expected an error with no firecracker anywhere")
	}
	if !strings.Contains(err.Error(), "scripts/setup-firecracker") {
		t.Errorf("error must point at the setup script: %v", err)
	}
}

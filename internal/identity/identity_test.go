package identity

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/constle/constle/pkg/did"
)

// withTempRoot points identity storage at a temp directory for one test.
func withTempRoot(t *testing.T) {
	t.Helper()
	rootOverride = t.TempDir()
	t.Cleanup(func() { rootOverride = "" })
}

func TestCreateAndLoadRoundTrip(t *testing.T) {
	withTempRoot(t)

	created, err := Create("test-agent", "owner@example.com")
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	if err := did.Validate(created.DID()); err != nil {
		t.Fatalf("created DID %q is not well-formed: %v", created.DID(), err)
	}

	loaded, err := Load("test-agent")
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if loaded.DID() != created.DID() {
		t.Errorf("loaded DID %q != created DID %q", loaded.DID(), created.DID())
	}
	if loaded.Owner != "owner@example.com" {
		t.Errorf("loaded owner = %q, want %q", loaded.Owner, "owner@example.com")
	}

	// A signature must verify against the public key recovered from the DID
	// string alone — the property everything else builds on.
	msg := []byte("audit log entry")
	sig := loaded.Sign(msg)
	pub, err := did.PublicKey(loaded.DID())
	if err != nil {
		t.Fatalf("PublicKey() error: %v", err)
	}
	if !ed25519.Verify(pub, msg, sig) {
		t.Error("signature does not verify against the DID-recovered public key")
	}
}

func TestCreateSetsRestrictivePermissions(t *testing.T) {
	withTempRoot(t)

	if _, err := Create("perm-agent", ""); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	keyPath := filepath.Join(Dir("perm-agent"), "key.pem")
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("Stat() error: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("key.pem mode = %04o, want 0600", perm)
	}

	dirInfo, err := os.Stat(Dir("perm-agent"))
	if err != nil {
		t.Fatalf("Stat() error: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0700 {
		t.Errorf("identity dir mode = %04o, want 0700", perm)
	}
}

func TestCreateRefusesOverwrite(t *testing.T) {
	withTempRoot(t)

	if _, err := Create("dup-agent", ""); err != nil {
		t.Fatalf("first Create() error: %v", err)
	}
	if _, err := Create("dup-agent", ""); err == nil {
		t.Fatal("second Create() succeeded, want error — keys must never be silently overwritten")
	}
}

func TestLoadMissingIdentityIsNotFound(t *testing.T) {
	withTempRoot(t)

	_, err := Load("ghost-agent")
	var nf *NotFoundError
	if !errors.As(err, &nf) {
		t.Fatalf("Load() error = %v, want *NotFoundError", err)
	}
}

func TestLoadRejectsLoosePermissions(t *testing.T) {
	withTempRoot(t)

	if _, err := Create("loose-agent", ""); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	keyPath := filepath.Join(Dir("loose-agent"), "key.pem")
	// A key that became readable by others after creation (umask drift,
	// restored backup) must not be silently trusted.
	for _, mode := range []os.FileMode{0644, 0640, 0666, 0400} {
		if err := os.Chmod(keyPath, mode); err != nil {
			t.Fatalf("Chmod(%04o) error: %v", mode, err)
		}
		if _, err := Load("loose-agent"); err == nil {
			t.Errorf("Load() with key mode %04o succeeded, want error", mode)
		} else if !strings.Contains(err.Error(), "chmod 600") {
			t.Errorf("Load() error %q does not tell the user how to fix the mode", err)
		}
	}

	if err := os.Chmod(keyPath, 0600); err != nil {
		t.Fatalf("Chmod(0600) error: %v", err)
	}
	if _, err := Load("loose-agent"); err != nil {
		t.Errorf("Load() with restored 0600 error: %v", err)
	}
}

func TestLoadDetectsSwappedKey(t *testing.T) {
	withTempRoot(t)

	if _, err := Create("victim-agent", ""); err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	if _, err := Create("attacker-agent", ""); err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	// Replace the victim's key file with the attacker's. identity.json still
	// records the victim's DID, so the mismatch must be caught.
	attackerKey, err := os.ReadFile(filepath.Join(Dir("attacker-agent"), "key.pem"))
	if err != nil {
		t.Fatalf("ReadFile() error: %v", err)
	}
	victimKeyPath := filepath.Join(Dir("victim-agent"), "key.pem")
	if err := os.WriteFile(victimKeyPath, attackerKey, 0600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	if _, err := Load("victim-agent"); err == nil {
		t.Fatal("Load() with swapped key succeeded, want DID mismatch error")
	} else if !strings.Contains(err.Error(), "identity mismatch") {
		t.Errorf("Load() error %q, want identity mismatch", err)
	}
}

func TestAgentNameValidation(t *testing.T) {
	withTempRoot(t)

	for _, name := range []string{"", "..", "a/b", `a\b`, ".hidden"} {
		if _, err := Create(name, ""); err == nil {
			t.Errorf("Create(%q) succeeded, want error", name)
		}
		if _, err := Load(name); err == nil {
			t.Errorf("Load(%q) succeeded, want error", name)
		}
	}
}

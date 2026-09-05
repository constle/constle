// Package webhookkey generates and loads the Ed25519 keypair used to sign
// human-gates webhook decisions (spec/human-gates-webhook.md).
//
// This keypair is deliberately separate from internal/identity. identity.Create
// issues one keypair per agent, authenticating "the agent that's boxed";
// this package issues keypairs for the human approver deciding what that
// agent may do. Conflating the two would let an agent's own identity stand
// in for the human approving its actions — the fusion the spec's trust
// model exists to avoid (spec §2). Storage, file layout, and error types
// below intentionally mirror internal/identity's fail-closed posture without
// sharing any code or state with it.
//
// The public half is expressed as a did:key identifier (pkg/did), the same
// wire format internal/identity uses — a formatting convenience, not a
// trust relationship: pkg/did decodes any Ed25519 public key regardless of
// who holds it.
package webhookkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/constle/constle/internal/homedir"
	"github.com/constle/constle/pkg/did"
)

const (
	keyFileName  = "key.pem"
	metaFileName = "key.json"

	// keyFileMode is the only permission mode accepted for key.pem — checked
	// at creation AND at every load, matching internal/identity: a key that
	// became group- or world-readable after creation must never be silently
	// trusted, because it is meant to leave this machine (handed to whoever
	// operates the decision endpoint) and a loose mode here is the last
	// local check before that handoff.
	keyFileMode = os.FileMode(0600)

	dirMode = os.FileMode(0700)

	pemBlockType = "PRIVATE KEY" // PKCS#8
)

// Keypair is a loaded webhook signing key: the did:key public identifier
// plus the private key needed to sign decisions with it. The private key is
// never serialized by this struct.
type Keypair struct {
	Name      string
	CreatedAt time.Time

	did  string
	priv ed25519.PrivateKey
}

// metadata is the on-disk key.json — public information only.
type metadata struct {
	DID       string    `json:"did"`
	CreatedAt time.Time `json:"created_at"`
}

// rootOverride redirects key storage in tests (same pattern as identity's
// rootOverride).
var rootOverride string

// Root returns the directory that holds all webhook signing keys.
func Root() string {
	if rootOverride != "" {
		return rootOverride
	}
	return filepath.Join(homedir.InvokingUserHome(), ".constle", "webhook-keys")
}

// Dir returns the storage directory for one named webhook signing key.
func Dir(name string) string {
	return filepath.Join(Root(), name)
}

// DID returns the did:key identifier of the keypair's public half — the
// value that belongs in the Agentfile's human_gates.approver_pubkey field.
func (k *Keypair) DID() string { return k.did }

// Sign signs a message with the keypair's private key.
func (k *Keypair) Sign(message []byte) []byte {
	return ed25519.Sign(k.priv, message)
}

// Generate creates a new Ed25519 keypair for the human-gates webhook flow
// and stores it under Dir(name) with restrictive permissions. It refuses to
// overwrite an existing key — keys are persistent, and rotation is manual
// (spec §3: "changing the approver means editing this field and
// redeploying").
func Generate(name string) (*Keypair, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}

	dir := Dir(name)
	if _, err := os.Stat(filepath.Join(dir, keyFileName)); err == nil {
		return nil, fmt.Errorf("webhook signing key %q already exists at %s", name, dir)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cannot generate Ed25519 keypair: %w", err)
	}

	didStr, err := did.FromPublicKey(pub)
	if err != nil {
		return nil, err
	}

	if err := homedir.MkdirAllOwned(dir, dirMode); err != nil {
		return nil, fmt.Errorf("cannot create webhook key directory: %w", err)
	}

	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal private key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: pemBlockType, Bytes: pkcs8})

	keyPath := filepath.Join(dir, keyFileName)
	if err := writeFileExclusive(keyPath, pemBytes, keyFileMode); err != nil {
		return nil, fmt.Errorf("cannot write private key: %w", err)
	}

	now := time.Now().UTC()
	meta, err := json.MarshalIndent(metadata{DID: didStr, CreatedAt: now}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("cannot marshal webhook key metadata: %w", err)
	}
	metaPath := filepath.Join(dir, metaFileName)
	if err := os.WriteFile(metaPath, append(meta, '\n'), keyFileMode); err != nil {
		return nil, fmt.Errorf("cannot write webhook key metadata: %w", err)
	}

	// Under sudo (the Firecracker backend requires it) the files above were
	// created as root inside the invoking user's home. Hand them back, or
	// the user's next non-sudo command finds a key it cannot read.
	if err := homedir.ChownToInvokingUser(dir, keyPath, metaPath); err != nil {
		return nil, fmt.Errorf("cannot restore webhook key ownership to the invoking user: %w", err)
	}

	return &Keypair{Name: name, CreatedAt: now, did: didStr, priv: priv}, nil
}

// Load reads a previously generated webhook signing key from disk, failing
// closed on anything that would make it untrustworthy — the same checks
// internal/identity.Load applies to agent identities:
//
//   - no key directory or key file → ErrNotFound
//   - key.pem permissions are not exactly 0600
//   - the key is not a valid PKCS#8 Ed25519 private key
//   - the DID recorded in key.json does not match the DID derived from the
//     private key (a swapped or corrupted key file)
func Load(name string) (*Keypair, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}

	dir := Dir(name)
	keyPath := filepath.Join(dir, keyFileName)

	info, err := os.Stat(keyPath)
	if os.IsNotExist(err) {
		return nil, &NotFoundError{Name: name, Dir: dir}
	}
	if err != nil {
		return nil, fmt.Errorf("cannot stat private key %s: %w", keyPath, err)
	}

	if perm := info.Mode().Perm(); perm != keyFileMode {
		return nil, fmt.Errorf(
			"private key %s has mode %04o, want %04o — refusing to use a key readable by others; run: chmod 600 %s",
			keyPath, perm, keyFileMode, keyPath,
		)
	}

	pemBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read private key %s: %w", keyPath, err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != pemBlockType {
		return nil, fmt.Errorf("private key %s is not a %s PEM block", keyPath, pemBlockType)
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cannot parse private key %s: %w", keyPath, err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key %s is not an Ed25519 key", keyPath)
	}

	didStr, err := did.FromPublicKey(priv.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}

	kp := &Keypair{Name: name, did: didStr, priv: priv}

	metaBytes, err := os.ReadFile(filepath.Join(dir, metaFileName))
	if err != nil {
		return nil, fmt.Errorf("cannot read webhook key metadata for %q: %w", name, err)
	}
	var meta metadata
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return nil, fmt.Errorf("corrupt webhook key metadata for %q: %w", name, err)
	}
	if meta.DID != didStr {
		return nil, fmt.Errorf(
			"webhook key mismatch for %q: %s records DID %s but the private key derives %s — the key file was replaced or corrupted",
			name, metaFileName, meta.DID, didStr,
		)
	}
	kp.CreatedAt = meta.CreatedAt

	return kp, nil
}

// NotFoundError reports that no local webhook signing key exists under the
// given name.
type NotFoundError struct {
	Name string
	Dir  string
}

func (e *NotFoundError) Error() string {
	return fmt.Sprintf("no webhook signing key %q (looked in %s)", e.Name, e.Dir)
}

// writeFileExclusive writes a new file with the given mode, failing if the
// file already exists. O_EXCL plus an explicit mode guarantees the key never
// exists with wider permissions, even transiently.
func writeFileExclusive(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		// The write failure is the one worth reporting; the close only
		// releases a handle to a file that is already incomplete.
		_ = f.Close()
		return err
	}
	return f.Close()
}

// validateName rejects names that would escape the webhook-keys directory or
// produce surprising paths. The name is used directly as a directory name.
func validateName(name string) error {
	if name == "" {
		return fmt.Errorf("webhook key name is required")
	}
	if strings.ContainsAny(name, "/\\") || name == "." || name == ".." || strings.HasPrefix(name, ".") {
		return fmt.Errorf("invalid webhook key name %q: must not contain path separators or start with a dot", name)
	}
	return nil
}

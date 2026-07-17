// Package identity manages per-agent cryptographic identities.
//
// An identity is an Ed25519 keypair stored locally under
// ~/.constle/identities/<agent-name>/, persistent across runs and bound to
// the agent's name and owner. The public half is expressed as a did:key
// identifier (pkg/did); only that DID string ever appears in an Agentfile —
// the private key stays on this machine, following the same indirection
// pattern as url_secret_ref (secrets are referenced, never embedded).
//
// Loading fails closed: a missing key, malformed PEM, permissions other than
// 0600, or a stored DID that does not match the stored private key are all
// hard errors — a declared identity must never look real when it isn't.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/constle/constle/internal/homedir"
	"github.com/constle/constle/pkg/did"
)

const (
	keyFileName  = "key.pem"
	metaFileName = "identity.json"

	// keyFileMode is the only permission mode accepted for key.pem — checked
	// at creation AND at every load, so a key that became group- or
	// world-readable after creation (umask drift, backup restore, shared
	// machine) is never silently trusted.
	keyFileMode = os.FileMode(0600)

	dirMode = os.FileMode(0700)

	pemBlockType = "PRIVATE KEY" // PKCS#8
)

// Identity is a loaded agent identity: the DID plus the private key needed
// to sign with it. The private key is never serialized by this struct.
type Identity struct {
	Name      string
	Owner     string
	CreatedAt time.Time

	did  string
	priv ed25519.PrivateKey
}

// metadata is the on-disk identity.json — public information only.
type metadata struct {
	DID       string    `json:"did"`
	Owner     string    `json:"owner,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// rootOverride redirects identity storage in tests (same pattern as
// gatesWarnOut in cmd/constle).
var rootOverride string

// Root returns the directory that holds all agent identities.
func Root() string {
	if rootOverride != "" {
		return rootOverride
	}
	return filepath.Join(homedir.InvokingUserHome(), ".constle", "identities")
}

// Dir returns the storage directory for one agent's identity.
func Dir(agentName string) string {
	return filepath.Join(Root(), agentName)
}

// DID returns the agent's did:key identifier.
func (id *Identity) DID() string { return id.did }

// Sign signs a message with the identity's private key.
func (id *Identity) Sign(message []byte) []byte {
	return ed25519.Sign(id.priv, message)
}

// Create generates a new Ed25519 identity for the agent and stores it under
// Dir(agentName) with restrictive permissions. It refuses to overwrite an
// existing identity — keys are persistent, and rotation is out of scope.
func Create(agentName, owner string) (*Identity, error) {
	if err := validateAgentName(agentName); err != nil {
		return nil, err
	}

	dir := Dir(agentName)
	if _, err := os.Stat(filepath.Join(dir, keyFileName)); err == nil {
		return nil, fmt.Errorf("identity for agent %q already exists at %s", agentName, dir)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cannot generate Ed25519 keypair: %w", err)
	}

	didStr, err := did.FromPublicKey(pub)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(dir, dirMode); err != nil {
		return nil, fmt.Errorf("cannot create identity directory: %w", err)
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
	meta, err := json.MarshalIndent(metadata{DID: didStr, Owner: owner, CreatedAt: now}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("cannot marshal identity metadata: %w", err)
	}
	metaPath := filepath.Join(dir, metaFileName)
	if err := os.WriteFile(metaPath, append(meta, '\n'), keyFileMode); err != nil {
		return nil, fmt.Errorf("cannot write identity metadata: %w", err)
	}

	// Under sudo (the Firecracker backend requires it) the files above were
	// created as root inside the invoking user's home. Hand them back, or
	// the user's next non-sudo command finds an identity it cannot read.
	if err := chownToInvokingUser(Root(), dir, keyPath, metaPath); err != nil {
		return nil, fmt.Errorf("cannot restore identity ownership to the invoking user: %w", err)
	}

	return &Identity{Name: agentName, Owner: owner, CreatedAt: now, did: didStr, priv: priv}, nil
}

// chownToInvokingUser transfers ownership of the given paths to the user who
// invoked constle via sudo. Outside sudo (or as a real root user) it is a
// no-op.
func chownToInvokingUser(paths ...string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	uid, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
	gid, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
	if err1 != nil || err2 != nil || uid == 0 {
		return nil
	}
	for _, p := range paths {
		if err := os.Chown(p, uid, gid); err != nil {
			return err
		}
	}
	return nil
}

// Load reads an agent's identity from disk, failing closed on anything that
// would make the identity untrustworthy:
//
//   - no identity directory or key file → ErrNotFound (callers print how to
//     create one)
//   - key.pem permissions are not exactly 0600
//   - the key is not a valid PKCS#8 Ed25519 private key
//   - the DID recorded in identity.json does not match the DID derived from
//     the private key (a swapped or corrupted key file)
func Load(agentName string) (*Identity, error) {
	if err := validateAgentName(agentName); err != nil {
		return nil, err
	}

	dir := Dir(agentName)
	keyPath := filepath.Join(dir, keyFileName)

	info, err := os.Stat(keyPath)
	if os.IsNotExist(err) {
		return nil, &NotFoundError{AgentName: agentName, Dir: dir}
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

	id := &Identity{Name: agentName, did: didStr, priv: priv}

	metaBytes, err := os.ReadFile(filepath.Join(dir, metaFileName))
	if err != nil {
		return nil, fmt.Errorf("cannot read identity metadata for agent %q: %w", agentName, err)
	}
	var meta metadata
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return nil, fmt.Errorf("corrupt identity metadata for agent %q: %w", agentName, err)
	}
	if meta.DID != didStr {
		return nil, fmt.Errorf(
			"identity mismatch for agent %q: %s records DID %s but the private key derives %s — the key file was replaced or corrupted",
			agentName, metaFileName, meta.DID, didStr,
		)
	}
	id.Owner = meta.Owner
	id.CreatedAt = meta.CreatedAt

	return id, nil
}

// NotFoundError reports that no local identity exists for an agent.
type NotFoundError struct {
	AgentName string
	Dir       string
}

func (e *NotFoundError) Error() string {
	return fmt.Sprintf("no local identity for agent %q (looked in %s)", e.AgentName, e.Dir)
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
		f.Close()
		return err
	}
	return f.Close()
}

// validateAgentName rejects names that would escape the identities directory
// or produce surprising paths. The agent name comes from identity.name in the
// Agentfile and is used directly as a directory name.
func validateAgentName(name string) error {
	if name == "" {
		return fmt.Errorf("agent name is required")
	}
	if strings.ContainsAny(name, "/\\") || name == "." || name == ".." || strings.HasPrefix(name, ".") {
		return fmt.Errorf("invalid agent name %q: must not contain path separators or start with a dot", name)
	}
	return nil
}

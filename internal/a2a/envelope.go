// Package a2a implements signed agent-to-agent communication between
// explicitly declared peers.
//
// ============================================================
// a2a — host-side signing gate for agent-to-agent calls
//
// Trust model (the MCP gate's model, applied in both directions): the host
// constle process is the trusted party. The agent's private key never enters
// the sandbox, so the HOST signs every outbound call and verifies every
// inbound one. The sandbox only ever exchanges plaintext with the per-run
// gate; a peer's real endpoint never enters it, and unverified bytes never
// reach it.
//
// Inbound delivery is pull-based: the public listener (the host side of
// a2a.listen) verifies and authorizes a call, then parks it in an inbox that
// the sandboxed agent drains over a connection IT initiates to the gate —
// the same outbound-only route already enforced for the MCP gate (Squid ACL
// on Docker, nftables accept on Firecracker). No inbound network path into
// the sandbox exists on either backend.
//
// There is deliberately no discovery mechanism anywhere in this package: the
// only peers that exist are the ones declared in the Agentfile.
// ============================================================
package a2a

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/constle/constle/pkg/did"
)

// Envelope is the signed wire format of every A2A request and response.
//
// The signing convention is adopted verbatim from audit.Entry: Sig is the
// last declared field, the signature covers the serialized envelope with Sig
// absent, and a verifier recovers those bytes by trimming the `,"sig":"…"}`
// suffix from the exact bytes received on the wire — no re-canonicalization,
// so verification is over the very bytes that traveled.
type Envelope struct {
	// From and To are did:key identifiers. The verification key is recovered
	// from the From string itself (pkg/did) — no registry, no resolution.
	From string `json:"from"`
	To   string `json:"to"`

	// MsgID is a random per-message id. Receivers reject an id they have
	// already seen — see replayGuard for the (per-run) scope of that check.
	MsgID string `json:"msg_id"`

	// InReplyTo binds a response to the MsgID of the request it answers; the
	// caller rejects a response that does not quote its request's id.
	InReplyTo string `json:"in_reply_to,omitempty"`

	// Timestamp is the sender's UTC send time, bounded by replayWindow at
	// the receiver.
	Timestamp time.Time `json:"timestamp"`

	// Body is the application payload, opaque to constle. Must be valid
	// JSON (enforced at the gate) so the envelope serializes exactly.
	Body json.RawMessage `json:"body,omitempty"`

	// Sig is the base64 (std) Ed25519 signature over the serialized envelope
	// with Sig itself absent. MUST remain the last declared field.
	Sig string `json:"sig,omitempty"`
}

// Signer signs A2A envelopes on behalf of an agent identity. Implemented by
// *identity.Identity; declared here so a2a does not depend on the identity
// package (same pattern as audit.Signer).
type Signer interface {
	// DID returns the signer's did:key identifier.
	DID() string
	// Sign returns the Ed25519 signature over message.
	Sign(message []byte) []byte
}

// Seal builds and signs an envelope from the signer's identity to a peer
// DID, returning the wire bytes plus the parsed form. body must be valid
// JSON; inReplyTo is empty for requests and the request's MsgID for
// responses.
func Seal(signer Signer, to, inReplyTo string, body []byte) (wire []byte, env *Envelope, err error) {
	if len(body) > 0 && !json.Valid(body) {
		return nil, nil, fmt.Errorf("A2A body must be valid JSON")
	}

	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, nil, fmt.Errorf("cannot generate message id: %w", err)
	}

	e := Envelope{
		From:      signer.DID(),
		To:        to,
		MsgID:     fmt.Sprintf("%x", idBytes),
		InReplyTo: inReplyTo,
		Timestamp: time.Now().UTC(),
		Body:      json.RawMessage(body),
	}

	unsigned, err := json.Marshal(e)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot marshal envelope: %w", err)
	}
	e.Sig = base64.StdEncoding.EncodeToString(signer.Sign(unsigned))

	wire, err = json.Marshal(e)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot marshal signed envelope: %w", err)
	}
	return wire, &e, nil
}

// RejectReason classifies why an envelope was refused — the value recorded
// in a2a_call_rejected audit events.
type RejectReason string

const (
	ReasonMalformed      RejectReason = "malformed_envelope"
	ReasonBadSignature   RejectReason = "bad_signature"
	ReasonUnknownPeer    RejectReason = "unknown_peer"
	ReasonWrongRecipient RejectReason = "wrong_recipient"
	ReasonStaleTimestamp RejectReason = "stale_timestamp"
	ReasonReplay         RejectReason = "replay"
)

// RejectError reports a refused envelope with a machine-readable reason.
type RejectError struct {
	Reason RejectReason
	Detail string
}

func (e *RejectError) Error() string {
	return fmt.Sprintf("%s: %s", e.Reason, e.Detail)
}

// Open parses a wire envelope and verifies its signature against the public
// key recovered from its own From DID. It deliberately does NOT check peer
// authorization, recipient, or replay — callers apply those checks against
// their declared peers list and replayGuard, in that order, so every
// rejection is attributed to the precise failing check.
//
// Everything that fails returns a *RejectError; a signature that does not
// verify is reported as forged/tampered, not merely invalid.
func Open(wire []byte) (*Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(wire, &env); err != nil {
		return nil, &RejectError{ReasonMalformed, fmt.Sprintf("not valid JSON: %v", err)}
	}
	if env.From == "" || env.To == "" || env.MsgID == "" || env.Sig == "" {
		return nil, &RejectError{ReasonMalformed, "envelope is missing from, to, msg_id, or sig"}
	}

	pub, err := did.PublicKey(env.From)
	if err != nil {
		return nil, &RejectError{ReasonMalformed, fmt.Sprintf("sender DID: %v", err)}
	}

	sig, err := base64.StdEncoding.DecodeString(env.Sig)
	if err != nil {
		return nil, &RejectError{ReasonMalformed, fmt.Sprintf("signature is not valid base64: %v", err)}
	}

	// The signature covers the wire bytes minus the trailing `,"sig":"…"}` —
	// the sender always emits sig as the last field, so the signed bytes are
	// recovered exactly, with no re-serialization (audit.VerifyFile's rule).
	trimmed := bytes.TrimRight(wire, " \t\r\n")
	suffix := []byte(`,"sig":"` + env.Sig + `"}`)
	if !bytes.HasSuffix(trimmed, suffix) {
		return nil, &RejectError{ReasonMalformed,
			`envelope does not end with the "sig" field the sender emits — the message was rewritten`}
	}
	signed := make([]byte, 0, len(trimmed)-len(suffix)+1)
	signed = append(signed, trimmed[:len(trimmed)-len(suffix)]...)
	signed = append(signed, '}')

	if !ed25519.Verify(pub, signed, sig) {
		return nil, &RejectError{ReasonBadSignature,
			fmt.Sprintf("signature does not verify against %s — forged or tampered", env.From)}
	}

	return &env, nil
}

// replayWindow bounds how far an envelope's timestamp may drift from the
// receiver's clock, in either direction. Within one run, msg_id dedup below
// makes a replayed envelope fail even inside the window.
const replayWindow = 5 * time.Minute

// replayGuard rejects duplicate and stale envelopes.
//
// LIMITATION (by design, stated rather than implied): this protection is
// in-memory and per-run only. The seen set does not survive a constle
// process restart and is not shared across runs — a validly signed envelope
// captured in one run can be replayed against a LATER run while still
// inside the timestamp window. Durable, cross-run replay state is out of
// scope for this version; operators who need it must rotate identities or
// keep runs apart by more than replayWindow.
type replayGuard struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func newReplayGuard() *replayGuard {
	return &replayGuard{seen: map[string]time.Time{}}
}

// check admits an envelope at most once per run and only within
// replayWindow of the local clock. Expired ids are pruned on the way, so
// the set stays bounded by the traffic of one window.
func (g *replayGuard) check(env *Envelope) error {
	now := time.Now().UTC()

	drift := now.Sub(env.Timestamp)
	if drift < 0 {
		drift = -drift
	}
	if drift > replayWindow {
		return &RejectError{ReasonStaleTimestamp,
			fmt.Sprintf("timestamp %s is outside the ±%s replay window", env.Timestamp.Format(time.RFC3339), replayWindow)}
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	for id, ts := range g.seen {
		if now.Sub(ts) > replayWindow {
			delete(g.seen, id)
		}
	}

	if _, dup := g.seen[env.MsgID]; dup {
		return &RejectError{ReasonReplay,
			fmt.Sprintf("msg_id %s was already accepted in this run", env.MsgID)}
	}
	g.seen[env.MsgID] = now
	return nil
}

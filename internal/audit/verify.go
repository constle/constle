package audit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/constle/constle/pkg/did"
)

// TamperKind classifies what a failed verification found, so the verifier
// can report the kind of tampering — not just "something is wrong somewhere".
type TamperKind string

const (
	// TamperMalformed — the line is not a well-formed signed entry (bad JSON,
	// missing did/prev_hash/sig, or undecodable signature).
	TamperMalformed TamperKind = "malformed_entry"

	// TamperInvalidSignature — the signature does not verify against the
	// entry bytes: the line was edited after signing (or signed by a
	// different key).
	TamperInvalidSignature TamperKind = "invalid_signature"

	// TamperMissingEntry — the line's prev_hash matches no line in the file:
	// the entry it chained to was deleted (or itself altered).
	TamperMissingEntry TamperKind = "chain_break_missing_entry"

	// TamperReordered — the line's prev_hash matches some other line in the
	// file, not the one directly above it: lines were reordered.
	TamperReordered TamperKind = "chain_break_reordered"

	// TamperDIDMismatch — the entry names a different DID than the rest of
	// the log (or than the expected DID the caller pinned).
	TamperDIDMismatch TamperKind = "did_mismatch"
)

// TamperError localizes a verification failure to one line of the log.
type TamperError struct {
	Line   int // 1-based line number in the file
	Kind   TamperKind
	Detail string
}

func (e *TamperError) Error() string {
	return fmt.Sprintf("line %d: %s — %s", e.Line, e.Kind, e.Detail)
}

// VerifyReport summarizes a successful verification.
type VerifyReport struct {
	Entries int
	DID     string
}

// VerifyFile reads a signed audit log and verifies it end to end: every
// line's Ed25519 signature checks out against the public key recovered
// directly from the DID string (no external resolution), and the hash chain
// is intact from the genesis sentinel to the last line.
//
// expectedDID pins the identity the log must be signed with; pass "" to
// accept the DID the log itself declares (still verified for internal
// consistency — every line must use the same one).
//
// On tampering the returned error is a *TamperError naming the exact line
// and the kind of tampering.
func VerifyFile(path, expectedDID string) (*VerifyReport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read log file: %w", err)
	}

	var lines [][]byte
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(line)) > 0 {
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("log file %q has no entries", path)
	}

	// Hash every raw line up front so chain breaks can distinguish "points
	// at a line that is no longer above it" (reordering) from "points at a
	// line that no longer exists" (deletion).
	lineHash := make([]string, len(lines))
	hashToLine := make(map[string]int, len(lines))
	for i, line := range lines {
		sum := sha256.Sum256(line)
		lineHash[i] = hex.EncodeToString(sum[:])
		hashToLine[lineHash[i]] = i
	}

	logDID := expectedDID
	var pub ed25519.PublicKey
	if logDID != "" {
		if pub, err = did.PublicKey(logDID); err != nil {
			return nil, fmt.Errorf("invalid expected DID: %w", err)
		}
	}

	prevHash := GenesisHash
	for i, line := range lines {
		lineNo := i + 1

		var entry Entry
		if err := json.Unmarshal(line, &entry); err != nil {
			return nil, &TamperError{lineNo, TamperMalformed, fmt.Sprintf("not valid JSON: %v", err)}
		}
		if entry.DID == "" || entry.PrevHash == "" || entry.Sig == "" {
			return nil, &TamperError{lineNo, TamperMalformed,
				"entry is not signed (missing did, prev_hash, or sig) — was this log written without an identity?"}
		}

		if logDID == "" {
			// First entry fixes the identity for the whole log.
			logDID = entry.DID
			if pub, err = did.PublicKey(logDID); err != nil {
				return nil, &TamperError{lineNo, TamperMalformed, fmt.Sprintf("entry DID is invalid: %v", err)}
			}
		} else if entry.DID != logDID {
			return nil, &TamperError{lineNo, TamperDIDMismatch,
				fmt.Sprintf("entry is attributed to %s, expected %s", entry.DID, logDID)}
		}

		sig, err := base64.StdEncoding.DecodeString(entry.Sig)
		if err != nil {
			return nil, &TamperError{lineNo, TamperMalformed, fmt.Sprintf("signature is not valid base64: %v", err)}
		}

		// The signature covers the raw line bytes minus the trailing
		// `,"sig":"…"}` — the writer always emits sig as the last field, so
		// the signed bytes are recovered exactly, with no re-serialization.
		suffix := []byte(`,"sig":"` + entry.Sig + `"}`)
		if !bytes.HasSuffix(line, suffix) {
			return nil, &TamperError{lineNo, TamperMalformed,
				`entry does not end with the "sig" field the writer emits — the line was rewritten`}
		}
		signed := make([]byte, 0, len(line)-len(suffix)+1)
		signed = append(signed, line[:len(line)-len(suffix)]...)
		signed = append(signed, '}')

		if !ed25519.Verify(pub, signed, sig) {
			return nil, &TamperError{lineNo, TamperInvalidSignature,
				fmt.Sprintf("signature does not verify against %s — the entry was edited after signing", logDID)}
		}

		if entry.PrevHash != prevHash {
			if j, ok := hashToLine[entry.PrevHash]; ok && j != i-1 {
				return nil, &TamperError{lineNo, TamperReordered,
					fmt.Sprintf("prev_hash points at line %d, but the entry directly above is line %d — lines were reordered", j+1, i)}
			}
			return nil, &TamperError{lineNo, TamperMissingEntry,
				fmt.Sprintf("prev_hash matches no line in this file — the entry between lines %d and %d was deleted or altered", i, lineNo)}
		}
		prevHash = lineHash[i]
	}

	return &VerifyReport{Entries: len(lines), DID: logDID}, nil
}

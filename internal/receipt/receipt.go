// Package receipt stores signed cycle records and verifies them against a
// caller-supplied public key.
package receipt

import (
	"crypto/sha256"
	"encoding/hex"
)

const (
	// LegacyVersion used deterministic Go struct order. It remains readable so
	// upgrading cycleseal does not invalidate existing signed chains.
	LegacyVersion = 1
	// Version is the current receipt schema and uses JCS-compatible bytes.
	Version = 2
)

// Decision is the policy outcome recorded on a cycle.
const (
	DecisionAllow = "allow"
	DecisionDeny  = "deny"
)

// Receipt is one cycle, as it will be signed.
type Receipt struct {
	Version        int      `json:"version"`
	Seq            uint64   `json:"seq"`
	PrevHash       string   `json:"prev_hash"`
	StartedAt      string   `json:"started_at"`
	EndedAt        string   `json:"ended_at"`
	Engine         string   `json:"engine"`
	Argv           []string `json:"argv"`
	PermissionMode string   `json:"permission_mode"`
	PromptSHA256   string   `json:"prompt_sha256"`
	PolicySHA256   string   `json:"policy_sha256"`
	PolicyDecision string   `json:"policy_decision"`
	PolicyReason   string   `json:"policy_reason,omitempty"`
	ExitCode       int      `json:"exit_code"`
	OutputSHA256   string   `json:"output_sha256"`
	OutputBytes    int64    `json:"output_bytes"`
	PublicKey      string   `json:"public_key"`
}

// Sealed is a receipt with its hash and signature.
type Sealed struct {
	Receipt   Receipt `json:"receipt"`
	Hash      string  `json:"hash"`
	Signature string  `json:"signature"`
}

// Hash returns the hex SHA-256 of the receipt's canonical bytes.
func (r Receipt) Hash() (string, error) {
	b, err := r.Canonical()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// SHA256Hex is the hex SHA-256 of b, the same digest form used throughout.
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

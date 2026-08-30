// Package receipt is an append-only, signed chain of cycle records.
//
// It replaces the markdown handoff file that autonomous loops usually carry
// between cycles. A markdown baton can be rewritten by the agent that produced
// it, and nothing downstream can tell. A chain can be rewritten too — but not
// without the rewrite being detectable, which is the whole difference.
//
// Trust model: the verifier trusts the cryptographic primitives and a public
// key supplied from outside the chain. It never trusts the key recorded inside
// a receipt, because a key that travels with the artifact it signs proves only
// that the artifact is internally consistent.
package receipt

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Version is the receipt schema version.
const Version = 1

// Decision is the policy outcome recorded on a cycle.
const (
	DecisionAllow = "allow"
	DecisionDeny  = "deny"
)

// Receipt is one cycle, as it will be signed.
//
// Field order is the canonical order: encoding/json emits struct fields in
// declaration order, which makes the serialisation deterministic without a
// sorting pass.
//
// ponytail: struct-order JSON, not full RFC 8785 JCS. Sufficient while this
// chain is only ever produced and verified by this tool; move onto the kernel's
// canonicalize package the moment these receipts must interoperate with
// anything else.
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

// Canonical returns the bytes that are hashed and signed.
func (r Receipt) Canonical() ([]byte, error) { return json.Marshal(r) }

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

// Store is a chain on disk: an append-only JSONL file plus a key pair.
type Store struct{ Dir string }

func (s Store) chainPath() string   { return filepath.Join(s.Dir, "chain.jsonl") }
func (s Store) keyPath() string     { return filepath.Join(s.Dir, "key.ed25519") }
func (s Store) trustedPath() string { return filepath.Join(s.Dir, "trusted.pub") }

// Keygen creates a signing key and records its public half as the trust root.
// It refuses to overwrite an existing key: replacing the key silently would
// orphan every receipt already in the chain.
func (s Store) Keygen() (ed25519.PublicKey, error) {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return nil, err
	}
	if _, err := os.Stat(s.keyPath()); err == nil {
		return nil, fmt.Errorf("a signing key already exists at %s; remove it deliberately if you mean to break the chain", s.keyPath())
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(s.keyPath(), []byte(hex.EncodeToString(priv)+"\n"), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(s.trustedPath(), []byte(hex.EncodeToString(pub)+"\n"), 0o644); err != nil {
		return nil, err
	}
	return pub, nil
}

// PrivateKey loads the signing key.
func (s Store) PrivateKey() (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(s.keyPath())
	if err != nil {
		return nil, fmt.Errorf("no signing key: run `cycleseal keygen` first (%w)", err)
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("signing key is not hex: %w", err)
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("signing key is %d bytes, want %d", len(b), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(b), nil
}

// TrustedKey loads the public key the chain is verified against. It lives
// beside the chain for convenience; supplying it out of band is stronger, and
// Verify accepts one either way.
func (s Store) TrustedKey() (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(s.trustedPath())
	if err != nil {
		return nil, err
	}
	return ParsePublicKey(strings.TrimSpace(string(raw)))
}

// ParsePublicKey decodes a hex-encoded Ed25519 public key.
func ParsePublicKey(h string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(strings.TrimSpace(h))
	if err != nil {
		return nil, fmt.Errorf("public key is not hex: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key is %d bytes, want %d", len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

// Read returns the chain in order.
func (s Store) Read() ([]Sealed, error) {
	f, err := os.Open(s.chainPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Sealed
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var sealed Sealed
		if err := json.Unmarshal([]byte(line), &sealed); err != nil {
			return nil, fmt.Errorf("chain line %d is not a receipt: %w", len(out)+1, err)
		}
		out = append(out, sealed)
	}
	return out, sc.Err()
}

// Tip returns the last sealed receipt, or false when the chain is empty.
func (s Store) Tip() (Sealed, bool, error) {
	chain, err := s.Read()
	if err != nil || len(chain) == 0 {
		return Sealed{}, false, err
	}
	return chain[len(chain)-1], true, nil
}

// Append signs r and adds it to the chain. Callers set every field except
// PrevHash, Seq and PublicKey, which are derived from the chain and the key.
func (s Store) Append(r Receipt) (Sealed, error) {
	priv, err := s.PrivateKey()
	if err != nil {
		return Sealed{}, err
	}
	tip, ok, err := s.Tip()
	if err != nil {
		return Sealed{}, err
	}
	r.Version = Version
	r.Seq = 0
	r.PrevHash = ""
	if ok {
		r.Seq = tip.Receipt.Seq + 1
		r.PrevHash = tip.Hash
	}
	r.PublicKey = hex.EncodeToString(priv.Public().(ed25519.PublicKey))

	canonical, err := r.Canonical()
	if err != nil {
		return Sealed{}, err
	}
	sum := sha256.Sum256(canonical)
	sealed := Sealed{
		Receipt:   r,
		Hash:      hex.EncodeToString(sum[:]),
		Signature: hex.EncodeToString(ed25519.Sign(priv, sum[:])),
	}

	line, err := json.Marshal(sealed)
	if err != nil {
		return Sealed{}, err
	}
	f, err := os.OpenFile(s.chainPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return Sealed{}, err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return Sealed{}, err
	}
	return sealed, nil
}

// Problem is one thing wrong with a chain.
type Problem struct {
	Seq    uint64 `json:"seq"`
	Reason string `json:"reason"`
}

// VerifyReport is the result of checking a chain.
type VerifyReport struct {
	Verified bool      `json:"verified"`
	Length   int       `json:"length"`
	TipHash  string    `json:"tip_hash,omitempty"`
	Problems []Problem `json:"problems"`
}

// Verify checks a chain against a public key supplied by the caller.
//
// The key recorded inside each receipt is checked for agreement but is never
// the authority: a chain that vouches for itself with its own key establishes
// only that it is internally consistent, which is not what anyone reading it
// wants to know.
func Verify(chain []Sealed, trusted ed25519.PublicKey) VerifyReport {
	rep := VerifyReport{Verified: true, Length: len(chain), Problems: []Problem{}}
	fail := func(seq uint64, format string, args ...any) {
		rep.Verified = false
		rep.Problems = append(rep.Problems, Problem{Seq: seq, Reason: fmt.Sprintf(format, args...)})
	}
	if len(chain) == 0 {
		fail(0, "chain is empty: there is nothing here to establish anything")
		return rep
	}

	trustedHex := hex.EncodeToString(trusted)
	prevHash := ""
	for i, sealed := range chain {
		r := sealed.Receipt
		want := uint64(i)

		if r.Version != Version {
			fail(r.Seq, "receipt version %d, this verifier understands %d", r.Version, Version)
		}
		if r.Seq != want {
			fail(r.Seq, "sequence %d where %d was expected: the chain has a gap or a reorder", r.Seq, want)
		}
		if r.PrevHash != prevHash {
			fail(r.Seq, "prev_hash %q does not match the previous receipt's hash %q: the chain forks or was rewritten here",
				short(r.PrevHash), short(prevHash))
		}
		if r.PublicKey != trustedHex {
			fail(r.Seq, "signed by key %s, which is not the trusted key %s", short(r.PublicKey), short(trustedHex))
		}

		canonical, err := r.Canonical()
		if err != nil {
			fail(r.Seq, "receipt cannot be canonicalised: %v", err)
			continue
		}
		sum := sha256.Sum256(canonical)
		gotHash := hex.EncodeToString(sum[:])
		if gotHash != sealed.Hash {
			fail(r.Seq, "recorded hash %s does not match the receipt body (%s): the body was edited after sealing",
				short(sealed.Hash), short(gotHash))
		}

		sig, err := hex.DecodeString(sealed.Signature)
		if err != nil || !ed25519.Verify(trusted, sum[:], sig) {
			fail(r.Seq, "signature does not verify against the trusted key")
		}

		prevHash = sealed.Hash
	}
	rep.TipHash = chain[len(chain)-1].Hash
	return rep
}

func short(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12] + "…"
}

// WriteJSON writes any value as indented JSON, for reports.
func WriteJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

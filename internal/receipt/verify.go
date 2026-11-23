package receipt

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
)

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

// Verify checks the receipts and their links against a caller-supplied public
// key. It also checks that each receipt records the same key.
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

		if r.Version != LegacyVersion && r.Version != Version {
			fail(r.Seq, "receipt version %d, this verifier understands %d and %d", r.Version, LegacyVersion, Version)
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

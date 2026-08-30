package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newStore(t *testing.T) (Store, ed25519.PublicKey) {
	t.Helper()
	s := Store{Dir: t.TempDir()}
	pub, err := s.Keygen()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return s, pub
}

func appendN(t *testing.T, s Store, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := s.Append(Receipt{Engine: "claude", PolicyDecision: DecisionAllow}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
}

func TestChainLinksAndVerifies(t *testing.T) {
	s, pub := newStore(t)
	appendN(t, s, 3)

	chain, err := s.Read()
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 3 {
		t.Fatalf("length %d, want 3", len(chain))
	}
	if chain[0].Receipt.PrevHash != "" {
		t.Error("genesis receipt has a prev_hash")
	}
	for i := 1; i < len(chain); i++ {
		if chain[i].Receipt.PrevHash != chain[i-1].Hash {
			t.Errorf("receipt %d does not link to its predecessor", i)
		}
		if chain[i].Receipt.Seq != uint64(i) {
			t.Errorf("receipt %d has seq %d", i, chain[i].Receipt.Seq)
		}
	}
	if rep := Verify(chain, pub); !rep.Verified {
		t.Fatalf("fresh chain failed to verify: %+v", rep.Problems)
	}
}

// The point of the whole exercise: editing a sealed receipt is detectable.
func TestEditedBodyIsCaught(t *testing.T) {
	s, pub := newStore(t)
	appendN(t, s, 2)

	path := filepath.Join(s.Dir, "chain.jsonl")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(raw), `"engine":"claude"`, `"engine":"codex"`, 1)
	if edited == string(raw) {
		t.Fatal("test could not edit the chain")
	}
	if err := os.WriteFile(path, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}

	chain, err := s.Read()
	if err != nil {
		t.Fatal(err)
	}
	rep := Verify(chain, pub)
	if rep.Verified {
		t.Fatal("an edited receipt verified")
	}
	if len(rep.Problems) == 0 {
		t.Error("failure carries no reason")
	}
}

// A chain verified with a key taken from inside itself establishes only that
// it is internally consistent. The verifier must answer to a key from outside.
func TestKeyInsideTheChainIsNotAuthority(t *testing.T) {
	s, _ := newStore(t)
	appendN(t, s, 1)

	// An attacker with the file can re-sign everything with their own key and
	// rewrite the embedded public_key to match. Verified against the real trust
	// root, that must fail.
	attackerPub, attackerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	forged := Receipt{
		Version: Version, Engine: "claude", PolicyDecision: DecisionAllow,
		PublicKey: hex.EncodeToString(attackerPub),
	}
	canonical, err := forged.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	hash, err := forged.Hash()
	if err != nil {
		t.Fatal(err)
	}
	sumBytes, _ := hex.DecodeString(hash)
	sealed := Sealed{Receipt: forged, Hash: hash, Signature: hex.EncodeToString(ed25519.Sign(attackerPriv, sumBytes))}
	_ = canonical

	// Self-consistent: verifying against the key the chain carries succeeds.
	if rep := Verify([]Sealed{sealed}, attackerPub); !rep.Verified {
		t.Fatalf("forged chain is not self-consistent, so the test proves nothing: %+v", rep.Problems)
	}
	// Against the real trust root it must fail.
	real, err := s.TrustedKey()
	if err != nil {
		t.Fatal(err)
	}
	rep := Verify([]Sealed{sealed}, real)
	if rep.Verified {
		t.Fatal("a chain signed by an untrusted key verified against the trust root")
	}
}

func TestTruncationAndReorderAreCaught(t *testing.T) {
	s, pub := newStore(t)
	appendN(t, s, 3)
	chain, err := s.Read()
	if err != nil {
		t.Fatal(err)
	}

	// Dropping the middle receipt breaks both the sequence and the link.
	truncated := []Sealed{chain[0], chain[2]}
	if rep := Verify(truncated, pub); rep.Verified {
		t.Error("a chain with a receipt removed verified")
	}

	reordered := []Sealed{chain[1], chain[0], chain[2]}
	if rep := Verify(reordered, pub); rep.Verified {
		t.Error("a reordered chain verified")
	}
}

// Absence must not read as success — the failure this whole family of tools
// exists to object to.
func TestEmptyChainIsNotVerified(t *testing.T) {
	_, pub := newStore(t)
	rep := Verify(nil, pub)
	if rep.Verified {
		t.Fatal("an empty chain verified: absence read as evidence")
	}
}

func TestKeygenRefusesToOverwrite(t *testing.T) {
	s, _ := newStore(t)
	if _, err := s.Keygen(); err == nil {
		t.Fatal("keygen overwrote an existing key, orphaning the chain")
	}
}

func TestCanonicalBytesAreStable(t *testing.T) {
	r := Receipt{Version: Version, Seq: 4, Engine: "claude", PolicyDecision: DecisionAllow}
	a, err := r.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatal("canonical bytes differ between calls")
	}
	var back Receipt
	if err := json.Unmarshal(a, &back); err != nil {
		t.Fatalf("canonical form is not valid JSON: %v", err)
	}
	if back.Seq != 4 || back.Engine != "claude" {
		t.Errorf("round trip lost data: %+v", back)
	}
}

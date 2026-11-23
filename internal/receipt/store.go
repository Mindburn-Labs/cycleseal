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
	"os"
	"path/filepath"
	"strings"
)

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

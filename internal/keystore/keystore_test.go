package keystore

import (
	"bytes"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/Taresu/auto-repo-package-integrity-checker/internal/pgp"
)

func testPubKey(t *testing.T) ([]byte, string) {
	t.Helper()
	e, err := openpgp.NewEntity("K", "", "k@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := e.Serialize(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), pgp.Fingerprint(e.PrimaryKey.Fingerprint)
}

func TestTrustAndLoad(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	key, fpr := testPubKey(t)

	if s.IsTrusted(fpr) {
		t.Fatal("key should not be trusted before adding")
	}
	added, err := s.Trust(key)
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != 1 || added[0] != fpr {
		t.Fatalf("Trust added %v, want [%s]", added, fpr)
	}
	if !s.IsTrusted(fpr) {
		t.Fatal("key should be trusted after adding")
	}

	// Reopen to confirm persistence, and confirm the keyring round-trips.
	s2, err := Open(dirOf(t, s))
	if err != nil {
		t.Fatal(err)
	}
	kr, err := s2.Keyring()
	if err != nil {
		t.Fatal(err)
	}
	if len(kr) != 1 {
		t.Fatalf("keyring has %d keys, want 1", len(kr))
	}
	if got := pgp.Fingerprint(kr[0].PrimaryKey.Fingerprint); got != fpr {
		t.Fatalf("persisted fingerprint = %s, want %s", got, fpr)
	}

	trusted, err := s2.Trusted()
	if err != nil {
		t.Fatal(err)
	}
	if len(trusted) != 1 || trusted[0] != fpr {
		t.Fatalf("Trusted() = %v, want [%s]", trusted, fpr)
	}
}

func TestTrustBadInput(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Trust([]byte("not a key")); err == nil {
		t.Fatal("expected error for junk input")
	}
}

// dirOf recovers the parent config dir from a store (keys live under dir/keys).
func dirOf(t *testing.T, s *Store) string {
	t.Helper()
	return s.dir[:len(s.dir)-len("/keys")]
}

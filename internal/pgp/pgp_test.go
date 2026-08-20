package pgp

import (
	"bytes"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
)

// newTestEntity creates an in-memory signing keypair.
func newTestEntity(t *testing.T) *openpgp.Entity {
	t.Helper()
	e, err := openpgp.NewEntity("Test Signer", "veripkg test", "signer@example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// pubKeyring serializes an entity's public key and reads it back as a keyring,
// mirroring how a user-supplied public key would be loaded.
func pubKeyring(t *testing.T, e *openpgp.Entity) Keyring {
	t.Helper()
	var buf bytes.Buffer
	if err := e.Serialize(&buf); err != nil {
		t.Fatal(err)
	}
	kr, err := ReadKeys(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

func signDetached(t *testing.T, e *openpgp.Entity, msg []byte) []byte {
	t.Helper()
	var sig bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&sig, e, bytes.NewReader(msg), nil); err != nil {
		t.Fatal(err)
	}
	return sig.Bytes()
}

func TestVerifyDetachedGood(t *testing.T) {
	e := newTestEntity(t)
	kr := pubKeyring(t, e)
	msg := []byte("SHA256SUMS content\n")
	sig := signDetached(t, e, msg)

	fpr, err := VerifyDetached(kr, msg, sig)
	if err != nil {
		t.Fatalf("expected valid signature: %v", err)
	}
	want := Fingerprint(e.PrimaryKey.Fingerprint)
	if fpr != want {
		t.Fatalf("fingerprint = %q, want %q", fpr, want)
	}
}

func TestVerifyDetachedTamperedContent(t *testing.T) {
	e := newTestEntity(t)
	kr := pubKeyring(t, e)
	sig := signDetached(t, e, []byte("original\n"))

	if _, err := VerifyDetached(kr, []byte("tampered\n"), sig); err == nil {
		t.Fatal("expected failure for tampered content")
	}
}

func TestVerifyDetachedWrongKey(t *testing.T) {
	signer := newTestEntity(t)
	other := newTestEntity(t)
	msg := []byte("data\n")
	sig := signDetached(t, signer, msg)

	// Keyring contains only the unrelated key.
	if _, err := VerifyDetached(pubKeyring(t, other), msg, sig); err == nil {
		t.Fatal("expected failure when signer key absent from keyring")
	}
}

func TestVerifyDetachedNoKeys(t *testing.T) {
	if _, err := VerifyDetached(Keyring{}, []byte("x"), []byte("y")); err == nil {
		t.Fatal("expected failure with empty keyring")
	}
}

// TestVerifyDetachedSubkeySignature locks in the real-world case (observed with
// HashiCorp Terraform): the signature is made by a dedicated *signing subkey*,
// not the primary key. Verification must still succeed against a keyring holding
// the primary, and must report the PRIMARY fingerprint — that's the identity a
// user trusts with `trust-key` and requires via `--key`.
func TestVerifyDetachedSubkeySignature(t *testing.T) {
	e := newTestEntity(t)
	if err := e.AddSigningSubkey(nil); err != nil {
		t.Fatal(err)
	}

	// Sanity: ArmoredDetachSign will pick a signing subkey over the primary, so
	// confirm the chosen signing key is actually a subkey (different key id).
	sk, ok := e.SigningKey(time.Now())
	if !ok {
		t.Fatal("no signing key selected")
	}
	if sk.PublicKey.KeyId == e.PrimaryKey.KeyId {
		t.Fatal("expected signing to use a subkey, but the primary was selected")
	}

	kr := pubKeyring(t, e)
	msg := []byte("SHA256SUMS content signed by a subkey\n")
	sig := signDetached(t, e, msg)

	fpr, err := VerifyDetached(kr, msg, sig)
	if err != nil {
		t.Fatalf("subkey signature should verify: %v", err)
	}
	if want := Fingerprint(e.PrimaryKey.Fingerprint); fpr != want {
		t.Fatalf("fingerprint = %q, want primary %q", fpr, want)
	}
}

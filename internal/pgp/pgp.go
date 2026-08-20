// Package pgp verifies detached OpenPGP signatures using a pure-Go
// implementation (ProtonMail go-crypto), so veripkg needs no system gpg.
//
// It answers one question: was this signed content signed by one of these
// trusted keys, and if so, which one? It does not manage trust — the caller
// supplies only keys it already trusts (see internal/keystore).
package pgp

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
)

// Keyring is a set of trusted public keys.
type Keyring = openpgp.EntityList

// ReadArmoredKeys parses one or more ASCII-armored ("-----BEGIN PGP PUBLIC
// KEY BLOCK-----") public keys.
func ReadArmoredKeys(r io.Reader) (Keyring, error) {
	el, err := openpgp.ReadArmoredKeyRing(r)
	if err != nil {
		return nil, fmt.Errorf("reading armored key: %w", err)
	}
	return el, nil
}

// ReadKeys parses public keys, trying armored form first and falling back to
// binary keyring form.
func ReadKeys(data []byte) (Keyring, error) {
	if el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(data)); err == nil {
		return el, nil
	}
	el, err := openpgp.ReadKeyRing(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("reading key: not valid armored or binary OpenPGP key")
	}
	return el, nil
}

// VerifyDetached checks that sig is a valid detached signature over signed,
// made by one of the keys in keyring. On success it returns the uppercase hex
// fingerprint of the signing key. Both armored (.asc) and binary (.sig)
// signatures are accepted.
func VerifyDetached(keyring Keyring, signed, sig []byte) (fingerprint string, err error) {
	if len(keyring) == 0 {
		return "", fmt.Errorf("no trusted keys provided")
	}

	// Try armored signature first, then binary.
	signer, aerr := openpgp.CheckArmoredDetachedSignature(
		keyring, bytes.NewReader(signed), bytes.NewReader(sig), nil)
	if aerr != nil {
		var berr error
		signer, berr = openpgp.CheckDetachedSignature(
			keyring, bytes.NewReader(signed), bytes.NewReader(sig), nil)
		if berr != nil {
			return "", fmt.Errorf("signature verification failed: %v", berr)
		}
	}
	if signer == nil || signer.PrimaryKey == nil {
		return "", fmt.Errorf("signature valid but signer key is unknown")
	}
	return Fingerprint(signer.PrimaryKey.Fingerprint), nil
}

// Fingerprint renders a key fingerprint as uppercase hex with no separators.
func Fingerprint(fp []byte) string {
	return strings.ToUpper(hex.EncodeToString(fp))
}

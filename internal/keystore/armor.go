package keystore

import (
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

// armorEncoder wraps w to write an ASCII-armored PGP public key block. The
// returned WriteCloser must be closed to flush the armor trailer.
func armorEncoder(w io.Writer) (io.WriteCloser, error) {
	return armor.Encode(w, "PGP PUBLIC KEY BLOCK", nil)
}

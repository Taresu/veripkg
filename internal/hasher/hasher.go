// Package hasher computes content digests for verification.
//
// v1 supports only SHA-256. The small indirection here (an explicit algorithm
// name in the API) keeps the door open for adding algorithms later without
// forcing that complexity on callers now.
package hasher

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// Algo is the only digest algorithm supported in v1.
const Algo = "sha256"

// SHA256File returns the lowercase hex SHA-256 of the file at path.
func SHA256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }() // read-only; close error is not actionable

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// SHA256Bytes returns the lowercase hex SHA-256 of b.
func SHA256Bytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

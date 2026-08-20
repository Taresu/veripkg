// Package verify holds the trust-tier decision logic — the security core of
// veripkg. It is deliberately free of I/O: callers fetch bytes, compute the
// file digest, and verify signatures elsewhere, then hand the results here to
// decide which trust tier (if any) was achieved.
//
// The guiding rule: never report success unless the expected value came from a
// source independent of the download. A bare hash pasted from the same page as
// the file is NOT such a source and must land in TierUnverified.
package verify

import (
	"fmt"
	"strings"

	"github.com/tsalada/veripkg/internal/sumsfile"
)

// Tier is the trust level of a verification result, ordered weakest→strongest.
type Tier int

const (
	// TierUnverified means no independent trusted source established the file.
	// This is a refusal, not a success.
	TierUnverified Tier = iota
	// TierPinnedHash means the file matched a hash the user recorded earlier.
	// Integrity against that pin only — no authenticity guarantee.
	TierPinnedHash
	// TierSigned means the file's hash appeared in a SHA256SUMS whose GPG
	// signature verified against a pinned, trusted key. Integrity + authenticity.
	TierSigned
)

func (t Tier) String() string {
	switch t {
	case TierSigned:
		return "VERIFIED (signed)"
	case TierPinnedHash:
		return "VERIFIED (pinned hash)"
	default:
		return "UNVERIFIED"
	}
}

// OK reports whether the tier represents a passing verification.
func (t Tier) OK() bool { return t >= TierPinnedHash }

// Result is the outcome of a verification attempt.
type Result struct {
	Tier           Tier
	File           string // the file that was checked
	ActualHash     string // computed sha256 of the file (lowercase hex)
	ExpectedHash   string // the trusted expected hash, when one was available
	KeyFingerprint string // signing key fingerprint, for TierSigned
	Reason         string // human-readable explanation, esp. for refusals
}

// PinnedHash decides the pinned-hash tier: the file's actual digest is
// compared against a user-recorded expected digest.
func PinnedHash(file, actualHash, expectedHash string) Result {
	r := Result{File: file, ActualHash: actualHash, ExpectedHash: normalize(expectedHash)}
	if r.ExpectedHash == "" {
		r.Tier = TierUnverified
		r.Reason = "no pinned hash provided"
		return r
	}
	if !hashEqual(actualHash, r.ExpectedHash) {
		r.Tier = TierUnverified
		r.Reason = fmt.Sprintf("hash mismatch: file is %s, pinned %s", actualHash, r.ExpectedHash)
		return r
	}
	r.Tier = TierPinnedHash
	r.Reason = "matched pinned hash"
	return r
}

// SignedSums decides the signed tier. It assumes the caller has ALREADY
// verified that the SHA256SUMS content carries a valid GPG signature made by a
// trusted key (keyFpr, non-empty). This function then confirms the file's hash
// is the one recorded in those sums for the given name.
//
// keyFpr must be non-empty: an empty fingerprint means no trusted key vouched
// for the sums, so this can never reach TierSigned.
func SignedSums(file, name, actualHash string, sums sumsfile.Sums, keyFpr string) Result {
	r := Result{File: file, ActualHash: actualHash, KeyFingerprint: strings.ToUpper(strings.TrimSpace(keyFpr))}

	if r.KeyFingerprint == "" {
		r.Tier = TierUnverified
		r.Reason = "sums file not signed by a trusted key"
		return r
	}
	expected, ok := sums.Lookup(name)
	if !ok {
		r.Tier = TierUnverified
		r.Reason = fmt.Sprintf("%q not listed in signed sums", name)
		return r
	}
	r.ExpectedHash = expected
	if !hashEqual(actualHash, expected) {
		r.Tier = TierUnverified
		r.Reason = fmt.Sprintf("hash mismatch: file is %s, signed sums list %s", actualHash, expected)
		return r
	}
	r.Tier = TierSigned
	r.Reason = fmt.Sprintf("matched signed sums (key %s)", r.KeyFingerprint)
	return r
}

func normalize(h string) string { return strings.ToLower(strings.TrimSpace(h)) }

func hashEqual(a, b string) bool { return normalize(a) == normalize(b) && normalize(a) != "" }

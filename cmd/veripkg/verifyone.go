package main

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/tsalada/veripkg/internal/fetcher"
	"github.com/tsalada/veripkg/internal/hasher"
	"github.com/tsalada/veripkg/internal/keystore"
	"github.com/tsalada/veripkg/internal/pgp"
	"github.com/tsalada/veripkg/internal/sumsfile"
	"github.com/tsalada/veripkg/internal/verify"
)

// verifyInput fully describes one verification attempt.
type verifyInput struct {
	file      string // local path or file:// URL of the artifact
	name      string // name to look up in sums; defaults to base(file)
	sumsRef   string // URL/path to SHA256SUMS
	sigRef    string // URL/path to detached signature over the sums
	keyReq    string // required signing-key fingerprint (optional)
	hash      string // pinned expected hash (optional)
	configDir string
}

// verifyOne runs the trust-tier orchestration. The returned error signals an
// operational failure (bad input, missing file, fetch error) — exit code 1.
// A non-error return always carries a Result whose tier decides success vs.
// refusal. Signed verification is attempted first; a user-pinned hash is only
// a fallback when signing material is absent or the signed attempt refuses.
func verifyOne(ctx context.Context, in verifyInput) (verify.Result, error) {
	path, ok := fetcher.LocalPath(in.file)
	if !ok {
		return verify.Result{}, fmt.Errorf("%s: the file to verify must be local (got a remote URL)", in.file)
	}
	actual, err := hasher.SHA256File(path)
	if err != nil {
		return verify.Result{}, err
	}
	name := in.name
	if name == "" {
		name = filepath.Base(path)
	}

	hasSigned := in.sumsRef != "" && in.sigRef != ""
	hasPin := in.hash != ""

	if !hasSigned && !hasPin {
		return verify.Result{
			Tier:       verify.TierUnverified,
			File:       path,
			ActualHash: actual,
			Reason:     "no trusted source given; pass --sums with --sig, or --hash",
		}, nil
	}

	if hasSigned {
		r, opErr := attemptSigned(ctx, in, path, name, actual)
		if opErr != nil {
			return verify.Result{}, opErr
		}
		if r.Tier.OK() || !hasPin {
			return r, nil
		}
		// Signed attempt refused but a pinned hash is available: fall back.
	}
	return verify.PinnedHash(path, actual, in.hash), nil
}

// attemptSigned fetches the sums + signature, verifies the signature against the
// trusted keystore, and checks the file's hash against the signed sums.
func attemptSigned(ctx context.Context, in verifyInput, path, name, actual string) (verify.Result, error) {
	sumsData, err := fetcher.Fetch(ctx, in.sumsRef)
	if err != nil {
		return verify.Result{}, err
	}
	sigData, err := fetcher.Fetch(ctx, in.sigRef)
	if err != nil {
		return verify.Result{}, err
	}

	store, err := keystore.Open(in.configDir)
	if err != nil {
		return verify.Result{}, err
	}
	keyring, err := store.Keyring()
	if err != nil {
		return verify.Result{}, err
	}

	base := verify.Result{File: path, ActualHash: actual}
	if len(keyring) == 0 {
		base.Tier = verify.TierUnverified
		base.Reason = "no trusted keys; import the signer's key with 'veripkg trust-key <keyfile>'"
		return base, nil
	}

	fpr, err := pgp.VerifyDetached(keyring, sumsData, sigData)
	if err != nil {
		base.Tier = verify.TierUnverified
		base.Reason = "sums signature did not verify against any trusted key; import the signer's key with 'veripkg trust-key <keyfile>' if you trust it"
		return base, nil
	}
	if req := strings.ToUpper(strings.TrimSpace(in.keyReq)); req != "" && !strings.HasSuffix(fpr, req) {
		base.Tier = verify.TierUnverified
		base.KeyFingerprint = fpr
		base.Reason = fmt.Sprintf("sums signed by %s, but --key required %s", fpr, req)
		return base, nil
	}

	sums, err := sumsfile.Parse(strings.NewReader(string(sumsData)))
	if err != nil {
		return verify.Result{}, fmt.Errorf("parsing sums: %w", err)
	}
	return verify.SignedSums(path, name, actual, sums, fpr), nil
}
